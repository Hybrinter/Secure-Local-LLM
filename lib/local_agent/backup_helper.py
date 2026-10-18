"""Hardened in-container helper scripts and bounded process execution.

Both helpers run offline (--network=none) as uid 1000 with cap-drop ALL,
read-only root, no-new-privileges, bounded cpu/memory/pids/tmpfs. Export
emits strict USTAR on stdout; import extracts via dirfd/O_NOFOLLOW with
duplicate and type refusal. No user repository code executes.
"""

from __future__ import annotations

import os
import select
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path

from .runtime_record import RuntimeFault

HELPER_TIMEOUT = 600
MAX_LOG_BYTES = 1 << 20
_ERR_DETAIL_BYTES = 4096

EXPORT_PY = r"""
import os, stat, sys, tarfile
ROOT = "/data"
MAX_MEMBERS = 20000
MAX_FILE = 268435456
MAX_TOTAL = 536870912

def fail(msg):
    print("export:", msg, file=sys.stderr)
    sys.exit(1)

def check_name(name):
    if not name or name.startswith("/") or "\\" in name:
        fail("unsafe name")
    if any(p in ("", ".", "..") for p in name.split("/")):
        fail("unsafe name")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        fail("control character")

def encodable(name):
    try:
        data = name.encode("utf-8")
    except UnicodeEncodeError:
        fail("name not USTAR encodable")
    if len(data) <= 100:
        return
    start = 0
    while True:
        slash = data.find(b"/", start)
        if slash < 0 or slash > 155:
            fail("name exceeds USTAR limit")
        if len(data) - slash - 1 <= 100:
            return
        start = slash + 1

out = tarfile.open(fileobj=sys.stdout.buffer, mode="w|",
                   format=tarfile.USTAR_FORMAT)
count = [0]
total = [0]

def add_dir(name, mode):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    ti.mode = mode & 0o777
    ti.uid = ti.gid = 1000
    ti.mtime = 0
    out.addfile(ti)

def walk(dpath, rel):
    try:
        entries = sorted(os.scandir(dpath), key=lambda e: e.name)
    except OSError as exc:
        fail(f"cannot scan {rel!r}: {exc}")
    for e in entries:
        name = f"{rel}/{e.name}" if rel else e.name
        check_name(name)
        try:
            st = e.stat(follow_symlinks=False)
        except OSError as exc:
            fail(f"cannot stat {name!r}: {exc}")
        encodable(name + "/" if stat.S_ISDIR(st.st_mode) else name)
        if stat.S_ISLNK(st.st_mode):
            fail(f"symlink refused: {name!r}")
        count[0] += 1
        if count[0] > MAX_MEMBERS:
            fail("member bound exceeded")
        if stat.S_ISDIR(st.st_mode):
            add_dir(name, st.st_mode)
            walk(e.path, name)
            continue
        if not stat.S_ISREG(st.st_mode):
            fail(f"special member refused: {name!r}")
        if st.st_nlink != 1:
            fail(f"hardlink refused: {name!r}")
        total[0] += st.st_size
        if st.st_size > MAX_FILE or total[0] > MAX_TOTAL:
            fail("size bound exceeded")
        try:
            fd = os.open(
                e.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as exc:
            fail(f"cannot open {name!r}: {exc}")
        try:
            fst = os.fstat(fd)
            if (not stat.S_ISREG(fst.st_mode)
                    or fst.st_nlink != 1
                    or fst.st_uid != 1000
                    or (fst.st_dev, fst.st_ino)
                    != (st.st_dev, st.st_ino)):
                fail(f"file changed under us: {name!r}")
            ti = tarfile.TarInfo(name)
            ti.size = fst.st_size
            ti.mode = st.st_mode & 0o777
            ti.uid = ti.gid = 1000
            ti.mtime = 0
            with os.fdopen(fd, "rb", closefd=False) as fh:
                out.addfile(ti, fh)
        finally:
            os.close(fd)

walk(ROOT, "")
out.close()
"""


IMPORT_PY = r"""
import hashlib, os, stat, sys, tarfile
SRC = "/archive/" + sys.argv[2]
DST = "/data"
MAX_MEMBERS = 20000
MAX_FILE = 268435456
MAX_TOTAL = 536870912

def fail(msg):
    print("import:", msg, file=sys.stderr)
    sys.exit(1)

def check_name(name):
    if not name or name.startswith("/") or "\\" in name:
        fail("unsafe name")
    if any(p in ("", ".", "..") for p in name.split("/")):
        fail("unsafe name")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        fail("control character")

if len(sys.argv) < 3:
    fail("usage: import <sha256> <member>")
expected = sys.argv[1]
check_name(sys.argv[2])
st = os.lstat(SRC)
if not stat.S_ISREG(st.st_mode):
    fail("archive input not regular")
h = hashlib.sha256()
with open(SRC, "rb") as fh:
    while True:
        chunk = fh.read(4 << 20)
        if not chunk:
            break
        h.update(chunk)
if h.hexdigest() != expected:
    fail("archive sha256 mismatch")

seen = set()
count = 0
total = 0

def parent_fd(name):
    parts = name.split("/")[:-1]
    fd = os.open(DST, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for comp in parts:
            try:
                os.mkdir(comp, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            try:
                nfd = os.open(
                    comp,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd)
            except OSError as exc:
                fail(f"parent {comp!r} unsafe: {exc}")
            os.close(fd)
            fd = nfd
    except BaseException:
        os.close(fd)
        raise
    return fd

with open(SRC, "rb") as fh:
    try:
        tf = tarfile.open(fileobj=fh, mode="r|")
    except tarfile.TarError as exc:
        fail(f"not a tar: {exc}")
    with tf:
        for member in tf:
            count += 1
            if count > MAX_MEMBERS:
                fail("member bound exceeded")
            mname = member.name.rstrip("/") if member.isdir() \
                else member.name
            check_name(mname)
            if mname in seen:
                fail(f"duplicate member {mname!r}")
            seen.add(mname)
            mode = member.mode & 0o777
            pfd = parent_fd(mname)
            base = mname.split("/")[-1]
            try:
                if member.isdir():
                    if member.size != 0:
                        fail(f"dir payload {member.name!r}")
                    try:
                        os.mkdir(base, mode or 0o755, dir_fd=pfd)
                    except FileExistsError:
                        try:
                            est = os.stat(
                                base, dir_fd=pfd,
                                follow_symlinks=False)
                        except OSError as exc:
                            fail(f"stat {member.name!r}: {exc}")
                        if not stat.S_ISDIR(est.st_mode):
                            fail(f"non-dir collision {member.name!r}")
                    continue
                if not (member.isreg() or member.type == b"0"):
                    fail(f"special member refused: {member.name!r}")
                total += member.size
                if member.size > MAX_FILE or total > MAX_TOTAL:
                    fail("size bound exceeded")
                try:
                    fd = os.open(
                        base,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW,
                        mode or 0o600, dir_fd=pfd)
                except OSError as exc:
                    fail(f"cannot create {member.name!r}: {exc}")
                src = tf.extractfile(member)
                if src is None:
                    os.close(fd)
                    fail(f"cannot read {member.name!r}")
                try:
                    with os.fdopen(fd, "wb") as dst:
                        remaining = member.size
                        while remaining > 0:
                            chunk = src.read(min(1 << 20, remaining))
                            if not chunk:
                                break
                            dst.write(chunk)
                            remaining -= len(chunk)
                        if remaining:
                            fail(f"truncated member {member.name!r}")
                finally:
                    src.close()
            finally:
                os.close(pfd)
print(f"imported {count} members")
"""


def helper_argv(image, vol, vol_mode, code, extra_args=(),
                extra_vol=None):
    argv = [
        "podman", "--remote=false", "run", "--rm", "--pull=never",
        "--network", "none", "--userns", "keep-id:uid=1000,gid=1000",
        "--user", "1000:1000", "--cap-drop", "ALL", "--read-only",
        "--security-opt", "no-new-privileges",
        "--ulimit", "core=0",
        "--memory", "512m", "--memory-swap", "512m",
        "--cpus", "1", "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
    ]
    if extra_vol:
        argv += ["-v", extra_vol]
    argv += ["-v", f"{vol}:/data:{vol_mode}", image,
             "python3", "-I", "-B", "-c", code, *extra_args]
    return argv


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _exclusive_out(path):
    return os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def _spawn(argv):
    from .runner import base_env
    return subprocess.Popen(
        argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=base_env(), start_new_session=True)


def run_helper(argv, out_path, err_path, out_cap,
               timeout=HELPER_TIMEOUT):
    """Spawn helper, streaming stdout to an exclusive 0600 file with a
    byte cap and an absolute deadline covering all child work; stderr
    drained bounded to its own exclusive file. Only files created by
    this invocation are removed on failure."""
    created = []
    out_fd = err_fd = None
    proc = None
    try:
        out_fd = _exclusive_out(out_path)
        created.append(Path(out_path))
        err_fd = _exclusive_out(err_path)
        created.append(Path(err_path))
        try:
            proc = _spawn(argv)
        except OSError as exc:
            raise RuntimeFault(f"cannot spawn helper: {exc}") from exc
        deadline = time.monotonic() + timeout
        drain_error = []

        def drain():
            remaining = MAX_LOG_BYTES
            try:
                while True:
                    chunk = proc.stderr.read(65536)
                    if not chunk:
                        return
                    if remaining > 0:
                        take = chunk[:remaining]
                        _write_all(err_fd, take)
                        remaining -= len(take)
            except OSError as exc:
                drain_error.append(exc)

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        try:
            written = 0
            outf = proc.stdout.fileno()
            os.set_blocking(outf, False)
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise _HelperTimeout
                ready, _, _ = select.select(
                    [outf], [], [], min(left, 0.25))
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue
                chunk = os.read(outf, 1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > out_cap:
                    raise RuntimeFault("helper output exceeded bound")
                _write_all(out_fd, chunk)
            left = deadline - time.monotonic()
            if left <= 0:
                raise _HelperTimeout
            try:
                rc = proc.wait(timeout=left)
            except subprocess.TimeoutExpired:
                raise _HelperTimeout from None
        except _HelperTimeout:
            _kill_group(proc)
            raise RuntimeFault("helper timed out") from None
        except BaseException:
            _kill_group(proc)
            raise
        finally:
            thread.join(timeout=15)
        if drain_error:
            raise RuntimeFault(f"stderr drain failed: {drain_error[0]}")
        if rc != 0:
            detail = _read_err_detail(err_path)
            raise RuntimeFault(f"helper failed rc={rc}: {detail}")
        return Path(out_path)
    except BaseException:
        if proc is not None and proc.poll() is None:
            _kill_group(proc)
        for p in created:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        raise
    finally:
        for fd in (out_fd, err_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


class _HelperTimeout(Exception):
    pass


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass


def _read_err_detail(path):
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return ""
    try:
        return os.read(fd, _ERR_DETAIL_BYTES).decode(
            "utf-8", "replace").strip()[:300]
    finally:
        os.close(fd)
