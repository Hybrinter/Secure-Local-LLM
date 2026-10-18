"""Pinned artifact lock validation and bounded hostile-archive-safe extraction."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import stat
import tarfile
import urllib.parse
from pathlib import Path

from .config import ConfigError, MAX_FILE_BYTES, parse_json, read_secure_file

LOCK_SCHEMA = "secure-local-llm/artifacts@1"
LOCK_PLATFORM = "linux/amd64"
ARTIFACT_NAMES = ("opencode", "model", "inference_source")
ARTIFACT_FORMATS = ("binary-tar", "file", "source-tar")
REQUIRED_FORMATS = {
    "opencode": "binary-tar",
    "model": "file",
    "inference_source": "source-tar",
}
HASH_HEX_LENGTHS = {"sha256": 64, "sha512": 128}
MAX_ARTIFACT_BYTES = 3 << 30
MAX_TAR_MEMBERS = 10000
_BASE_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")
_BINARY_TAR_EXECUTABLE = "package/bin/opencode"
_BINARY_TAR_ALLOWED = frozenset({"package/package.json", _BINARY_TAR_EXECUTABLE})
_BINARY_TAR_DIRS = frozenset({"package", "package/bin"})


class ArtifactError(Exception):
    pass


def _expect_keys(obj, keys, label):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise ArtifactError(f"{label}: expected exactly keys {sorted(keys)}")


def _expect_int(value, lo, hi, label):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArtifactError(f"{label}: integer required")
    if not lo <= value <= hi:
        raise ArtifactError(f"{label}: {value} outside [{lo}, {hi}]")
    return value


def _has_control(value):
    return any(ord(c) < 0x20 or ord(c) == 0x7f for c in value)


def _check_url(url, label):
    if not isinstance(url, str):
        raise ArtifactError(f"{label}: URL must be a string")
    if _has_control(url):
        raise ArtifactError(f"{label}: control characters in URL")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ArtifactError(f"{label}: malformed URL") from exc
    if parts.scheme != "https" or not parts.hostname:
        raise ArtifactError(f"{label}: HTTPS URL required")
    if (
        parts.username is not None
        or parts.password is not None
        or port is not None
    ):
        raise ArtifactError(f"{label}: URL userinfo/port not allowed")


def _check_member_name(name, label):
    if not isinstance(name, str) or not name:
        raise ArtifactError(f"{label}: empty member name")
    if name.endswith("/"):
        name = name[:-1]
    if (
        not name
        or "\\" in name
        or _has_control(name)
    ):
        raise ArtifactError(f"{label}: unsafe member name {name!r}")
    if any(p in ("", ".", "..") for p in name.split("/")):
        raise ArtifactError(f"{label}: unsafe member name {name!r}")
    return name


_FORMAT_KEYS = {
    "binary-tar": ("member", "max_unpacked_bytes"),
    "file": (),
    "source-tar": ("root", "max_unpacked_bytes"),
}


def _parse_artifact(name, spec):
    if not isinstance(spec, dict):
        raise ArtifactError(f"artifacts.{name}: object required")
    fmt = spec.get("format")
    if fmt not in ARTIFACT_FORMATS:
        raise ArtifactError(f"artifacts.{name}: unsupported format {fmt!r}")
    if fmt != REQUIRED_FORMATS[name]:
        raise ArtifactError(
            f"artifacts.{name}: format must be {REQUIRED_FORMATS[name]!r}"
        )
    _expect_keys(
        spec,
        ("version", "url", "hash", "max_bytes", "format") + _FORMAT_KEYS[fmt],
        f"artifacts.{name}",
    )
    if not isinstance(spec["version"], str) or not spec["version"]:
        raise ArtifactError(f"artifacts.{name}: version must be a string")
    _check_url(spec["url"], f"artifacts.{name}.url")
    digest = spec["hash"]
    _expect_keys(digest, ("algorithm", "hex"), f"artifacts.{name}.hash")
    algo = digest["algorithm"]
    if algo not in HASH_HEX_LENGTHS:
        raise ArtifactError(f"artifacts.{name}.hash: unsupported algorithm {algo!r}")
    hexv = digest["hex"]
    if (
        not isinstance(hexv, str)
        or len(hexv) != HASH_HEX_LENGTHS[algo]
        or any(c not in "0123456789abcdef" for c in hexv)
    ):
        raise ArtifactError(f"artifacts.{name}.hash: bad {algo} hex digest")
    _expect_int(spec["max_bytes"], 1, MAX_ARTIFACT_BYTES, f"artifacts.{name}.max_bytes")
    out = dict(spec)
    if fmt == "binary-tar":
        if spec["member"] != _BINARY_TAR_EXECUTABLE:
            raise ArtifactError(f"artifacts.{name}.member: unexpected member")
    if fmt == "source-tar":
        root = spec["root"]
        if (
            not isinstance(root, str)
            or not root
            or "/" in root
            or root in (".", "..")
            or "\\" in root
            or root.startswith("/")
            or _has_control(root)
        ):
            raise ArtifactError(f"artifacts.{name}.root: unsafe root name")
    if fmt != "file":
        _expect_int(
            spec["max_unpacked_bytes"], 1, MAX_ARTIFACT_BYTES,
            f"artifacts.{name}.max_unpacked_bytes",
        )
    return out


def parse_lock(raw):
    _expect_keys(raw, ("schema", "platform", "base_image", "artifacts"), "lock")
    if raw["schema"] != LOCK_SCHEMA:
        raise ArtifactError(f"lock: schema must be {LOCK_SCHEMA!r}")
    if raw["platform"] != LOCK_PLATFORM:
        raise ArtifactError(f"lock: platform must be {LOCK_PLATFORM!r}")
    base = raw["base_image"]
    if not isinstance(base, str) or not _BASE_IMAGE_RE.fullmatch(base):
        raise ArtifactError("lock.base_image: digest-pinned reference required")
    arts = raw["artifacts"]
    _expect_keys(arts, ARTIFACT_NAMES, "lock.artifacts")
    return {
        "schema": raw["schema"],
        "platform": raw["platform"],
        "base_image": base,
        "artifacts": {
            name: _parse_artifact(name, arts[name]) for name in ARTIFACT_NAMES
        },
    }


def load_lock(path):
    try:
        data = read_secure_file(path, MAX_FILE_BYTES)
        raw = parse_json(data, str(path))
    except ConfigError as exc:
        raise ArtifactError(str(exc)) from exc
    lock = parse_lock(raw)
    fingerprint = {
        "path": str(Path(path)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
    return lock, fingerprint


def _safe_dest(base, rel):
    dest = Path(base, *rel.split("/"))
    if not str(dest).startswith(str(base) + os.sep):
        raise ArtifactError(f"member escapes destination: {rel!r}")
    return dest


def _ensure_dir(path):
    try:
        st = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise ArtifactError(f"unsafe output dir: {path}")
        except OSError as exc:
            raise ArtifactError(f"cannot create dir {path}: {exc}") from exc
        return
    except OSError as exc:
        raise ArtifactError(f"cannot inspect dir {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ArtifactError(f"unsafe output dir: {path}")


def _ensure_parent(base, dest):
    cur = Path(base)
    for part in dest.relative_to(base).parts[:-1]:
        cur = cur / part
        _ensure_dir(cur)


def _write_member(tar, member, base, dest, mode):
    if member.size < 0:
        raise ArtifactError(f"bad member size: {member.name!r}")
    src = tar.extractfile(member)
    if src is None:
        raise ArtifactError(f"cannot read member: {member.name!r}")
    _ensure_parent(base, dest)
    try:
        fd = os.open(
            dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
        )
    except FileExistsError as exc:
        raise ArtifactError(f"duplicate output path: {member.name!r}") from exc
    except OSError as exc:
        raise ArtifactError(f"cannot create {member.name!r}: {exc}") from exc
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while written < member.size:
                chunk = src.read(min(1 << 20, member.size - written))
                if not chunk:
                    raise ArtifactError(f"truncated member: {member.name!r}")
                out.write(chunk)
                written += len(chunk)
    except BaseException:
        with contextlib.suppress(OSError):
            dest.unlink()
        raise
    return written


def extract_tar(tar_path, dest_dir, spec, fmt):
    dest_dir = Path(dest_dir)
    seen = set()
    total = 0
    count = 0
    required_seen = False
    try:
        tf = tarfile.open(tar_path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ArtifactError(f"cannot open archive: {exc}") from exc
    with tf:
        for member in tf:
            count += 1
            if count > MAX_TAR_MEMBERS:
                raise ArtifactError("archive exceeds member bound")
            if member.islnk() or member.issym() or member.isdev() or member.isfifo():
                raise ArtifactError(f"unsafe member type: {member.name!r}")
            name = _check_member_name(member.name, "tar member")
            if name in seen:
                raise ArtifactError(f"duplicate member: {member.name!r}")
            seen.add(name)
            if fmt == "binary-tar":
                rel = name
                if member.isdir():
                    if rel not in _BINARY_TAR_DIRS:
                        raise ArtifactError(
                            f"unexpected member dir: {member.name!r}")
                    dest = _safe_dest(dest_dir, rel)
                    _ensure_parent(dest_dir, dest)
                    _ensure_dir(dest)
                    continue
                if rel not in _BINARY_TAR_ALLOWED:
                    raise ArtifactError(f"unexpected member: {member.name!r}")
            else:
                root = spec["root"]
                if name == root:
                    if not member.isdir():
                        raise ArtifactError(
                            f"source root not a directory: {member.name!r}")
                    continue
                prefix = root + "/"
                if not name.startswith(prefix):
                    raise ArtifactError(
                        f"member outside source root: {member.name!r}")
                rel = name[len(prefix):]
                if member.isdir():
                    dest = _safe_dest(dest_dir, rel)
                    _ensure_parent(dest_dir, dest)
                    _ensure_dir(dest)
                    continue
            if member.isdir():
                raise ArtifactError(f"unexpected member dir: {member.name!r}")
            if not member.isreg():
                raise ArtifactError(f"unsupported member type: {member.name!r}")
            total += member.size
            if total > spec["max_unpacked_bytes"]:
                raise ArtifactError("archive exceeds unpacked bound")
            dest = _safe_dest(dest_dir, rel)
            mode = (
                0o755
                if fmt == "binary-tar" and rel == spec["member"]
                else 0o600
            )
            _write_member(tf, member, dest_dir, dest, mode)
            if fmt == "binary-tar" and rel == spec["member"]:
                required_seen = True
    if fmt == "binary-tar" and not required_seen:
        raise ArtifactError(f"required member missing: {spec['member']!r}")
    return {"members": count, "unpacked_bytes": total}
