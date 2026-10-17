"""Bounded HTTPS artifact downloads and private cache verification."""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .artifacts import ArtifactError
from .state import StateError, _require_private_dir

DOWNLOAD_TIMEOUT_SECONDS = 600
DOWNLOAD_READ_TIMEOUT_SECONDS = 30


class DownloadError(ArtifactError):
    pass


def _check_fetch_target(url):
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise DownloadError("refusing malformed URL") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or port is not None
        or parts.username is not None
        or parts.password is not None
        or any(ord(c) < 0x20 or ord(c) == 0x7f for c in url)
    ):
        raise DownloadError("refusing unsafe URL")


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_fetch_target(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url, dest, max_bytes, timeout=DOWNLOAD_TIMEOUT_SECONDS):
    _check_fetch_target(url)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _HttpsOnlyRedirect
    )
    req = urllib.request.Request(
        url, headers={"User-Agent": "secure-local-llm/0.1"}
    )
    deadline = time.monotonic() + timeout
    try:
        with opener.open(
            req, timeout=min(DOWNLOAD_READ_TIMEOUT_SECONDS, timeout)
        ) as resp:
            fd = os.open(
                dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            try:
                with os.fdopen(fd, "wb") as fh:
                    total = 0
                    while True:
                        if time.monotonic() > deadline:
                            raise DownloadError("download timed out")
                        chunk = resp.read(1 << 20)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            raise DownloadError("download exceeds bound")
                        fh.write(chunk)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(dest)
                raise
    except DownloadError:
        raise
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc.__class__.__name__)
        raise DownloadError(f"download failed: {reason}") from exc
    except OSError as exc:
        raise DownloadError(
            f"download failed: {exc.strerror or exc.__class__.__name__}"
        ) from exc
    return dest


def _verify_file(path, spec, label):
    try:
        fd = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
    except OSError as exc:
        raise DownloadError(
            f"{label}: cannot open cache file: {exc.strerror or exc}"
        ) from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600
        ):
            raise DownloadError(f"{label}: unsafe cache file: {path}")
        if st.st_size > spec["max_bytes"]:
            raise DownloadError(f"{label}: exceeds bound")
        digest = hashlib.new(spec["hash"]["algorithm"])
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != spec["hash"]["hex"]:
            raise DownloadError(f"{label}: digest mismatch")
    finally:
        if fd >= 0:
            os.close(fd)


def _stage_file(cache, name, spec, fetcher, cached_path=None, status=None):
    try:
        _require_private_dir(cache)
    except StateError as exc:
        raise DownloadError(f"unsafe cache directory: {exc}") from exc
    dest = cache / f"{name}-{spec['hash']['hex'][:16]}"
    for candidate in (cached_path, dest):
        if candidate is None or not os.path.lexists(candidate):
            continue
        try:
            _verify_file(candidate, spec, name)
        except DownloadError:
            if candidate == cached_path:
                continue
            raise
        status and status(name, "verified")
        return Path(candidate)
    fd, tmp_name = tempfile.mkstemp(prefix=f".tmp-{name}-", dir=str(cache))
    os.close(fd)
    os.unlink(tmp_name)
    tmp = Path(tmp_name)
    try:
        status and status(name, "downloading")
        fetcher(spec["url"], tmp, spec["max_bytes"])
        _verify_file(tmp, spec, name)
        os.replace(tmp, dest)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
    status and status(name, "verified")
    return dest
