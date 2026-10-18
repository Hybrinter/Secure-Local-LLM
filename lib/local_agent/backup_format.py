"""Strict USTAR archive format validation for secure-local-llm backups.

Format is intentionally narrow: POSIX USTAR headers only — no PAX
extensions, GNU long names, sparse files, ACLs, or xattrs. Paths that
cannot be USTAR-encoded fail clearly rather than being dropped. Symlinked
or hardlinked trees (e.g. Python venvs) are unsupported and require a
separate strategy.
"""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime

from .config import ConfigError, parse_json, validate_instance_name
from .runtime_record import RuntimeFault

BACKUP_SCHEMA = "secure-local-llm/backup@1"
DATA_ROLES = ("workspace", "state", "repo")
MEMBER_NAMES = tuple(f"{r}.tar" for r in DATA_ROLES)
MAX_MEMBERS_TOTAL = 20000
MAX_FILE_BYTES = 256 << 20
MAX_ROLE_BYTES = 512 << 20
MAX_MEMBERS_PER_TAR = 20000
MAX_ROLE_TAR_BYTES = (
    MAX_ROLE_BYTES + MAX_MEMBERS_PER_TAR * 1024 + 10240)
MAX_OUTER_BYTES = 2 << 30
MAX_MANIFEST_BYTES = 64 * 1024

BLOCK = 512
_USTAR_MAGIC = b"ustar\x00"
_USTAR_VERSION = b"00"
_REG_TYPES = (b"0", b"\0")
_DIR_TYPE = b"5"
_ALLOWED_TYPES = _REG_TYPES + (_DIR_TYPE,)


def safe_member_name(name):
    """Return name if a safe archive member name, else None.

    Rejects absolute/traversal/empty/dot components, backslashes, and
    control characters; ordinary spaces and valid UTF-8 are allowed.
    """
    if (
        not isinstance(name, str)
        or not name
        or name.startswith("/")
        or "\\" in name
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
    ):
        return None
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return name


def ustar_encodable(name):
    try:
        data = name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(data) <= 100:
        return True
    start = 0
    while True:
        slash = data.find(b"/", start)
        if slash < 0 or slash > 155:
            return False
        if len(data) - slash - 1 <= 100:
            return True
        start = slash + 1


def _octal(block, off, length):
    raw = block[off:off + length].rstrip(b"\0 ")
    if not raw or any(c < 48 or c > 55 for c in raw):
        raise RuntimeFault("malformed octal field in tar header")
    return int(raw, 8)


def _decode_name(raw):
    raw = raw.split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeFault("non-UTF-8 member name") from exc


def _parse_header(block):
    """Parse one 512-byte USTAR header; strict, no extensions."""
    magic = block[257:263]
    if magic != _USTAR_MAGIC:
        raise RuntimeFault(
            f"non-USTAR header (magic {magic!r}); extensions refused")
    if block[263:265] != _USTAR_VERSION:
        raise RuntimeFault("unexpected USTAR version")
    if block[124] & 0x80:
        raise RuntimeFault("base-256 size field refused")
    stored = _octal(block, 148, 8)
    chk = block[:148] + b"        " + block[156:]
    if sum(chk) != stored:
        raise RuntimeFault("tar header checksum mismatch")
    _octal(block, 136, 12)
    typeflag = block[156:157]
    if typeflag not in _ALLOWED_TYPES:
        raise RuntimeFault(
            f"unsupported member type {typeflag!r}")
    name = _decode_name(block[0:100])
    prefix = _decode_name(block[345:500])
    if prefix:
        name = f"{prefix}/{name}"
    linkname = _decode_name(block[157:257])
    if linkname:
        raise RuntimeFault("link member refused")
    return {
        "name": name,
        "mode": _octal(block, 100, 8),
        "uid": _octal(block, 108, 8),
        "gid": _octal(block, 116, 8),
        "size": _octal(block, 124, 12),
        "type": "dir" if typeflag == _DIR_TYPE else "reg",
    }


def _read_exact(fd, count):
    data = b""
    while len(data) < count:
        chunk = os.read(fd, count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def scan_ustar_fd(fd, max_members, max_total, label):
    """Walk raw USTAR headers on a stable fd; return (members, size)."""
    members = []
    pos = 0
    zero_blocks = 0
    while True:
        block = _read_exact(fd, BLOCK)
        if block is None:
            raise RuntimeFault(f"{label}: truncated archive")
        pos += BLOCK
        if block == b"\0" * BLOCK:
            zero_blocks += 1
            if zero_blocks == 2:
                while True:
                    rest = os.read(fd, 4 << 20)
                    if not rest:
                        return members, pos
                    pos += len(rest)
                    if pos > max_total:
                        raise RuntimeFault(
                            f"{label}: size bound exceeded")
                    if rest.strip(b"\0"):
                        raise RuntimeFault(
                            f"{label}: data after end markers")
            continue
        if zero_blocks:
            raise RuntimeFault(f"{label}: header after end marker")
        if len(members) >= max_members:
            raise RuntimeFault(f"{label}: member bound exceeded")
        hdr = _parse_header(block)
        if hdr["type"] == "dir" and hdr["size"] != 0:
            raise RuntimeFault(f"{label}: dir with payload")
        members.append(hdr)
        skip = (hdr["size"] + BLOCK - 1) // BLOCK * BLOCK
        os.lseek(fd, skip, os.SEEK_CUR)
        pos += skip
        if pos > max_total:
            raise RuntimeFault(f"{label}: size bound exceeded")


def validate_inner_inventory(members, label):
    """Check names/types/bounds of one role tar's header inventory."""
    seen = set()
    dirs = set()
    parents = set()
    logical = 0
    for m in members:
        name = m["name"]
        if m["type"] == "dir" and name.endswith("/"):
            name = name[:-1]
        if safe_member_name(name) is None or name in seen:
            raise RuntimeFault(
                f"{label}: unsafe member {m['name']!r}")
        if m["type"] != "dir" and name in parents:
            raise RuntimeFault(
                f"{label}: file-dir collision {name!r}")
        seen.add(name)
        if m["type"] == "dir":
            dirs.add(name)
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            parent = "/".join(parts[:i])
            if parent in seen and parent not in dirs:
                raise RuntimeFault(
                    f"{label}: file-parent collision {parent!r}")
            parents.add(parent)
        if m["type"] == "dir":
            continue
        logical += m["size"]
        if m["size"] > MAX_FILE_BYTES:
            raise RuntimeFault(f"{label}: file bound exceeded")
        if logical > MAX_ROLE_BYTES:
            raise RuntimeFault(f"{label}: role bound exceeded")
    return {"members": len(members), "logical_bytes": logical}


def validate_manifest(raw):
    if not isinstance(raw, dict) or set(raw) != {
            "schema", "created_utc", "profile_name", "profile_sha256",
            "artifacts_lock_sha256", "seed_main", "volumes"}:
        raise RuntimeFault("backup manifest: unexpected keys")
    if raw["schema"] != BACKUP_SCHEMA:
        raise RuntimeFault("backup manifest: bad schema")
    created = raw["created_utc"]
    if not isinstance(created, str):
        raise RuntimeFault("backup manifest: created_utc")
    try:
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RuntimeFault("backup manifest: created_utc") from exc
    try:
        validate_instance_name(raw["profile_name"])
    except ConfigError as exc:
        raise RuntimeFault("backup manifest: profile_name") from exc
    for key in ("profile_sha256", "artifacts_lock_sha256"):
        value = raw[key]
        if not isinstance(value, str) or len(value) != 64 \
                or set(value) - set("0123456789abcdef"):
            raise RuntimeFault(f"backup manifest: {key}")
    if not isinstance(raw["seed_main"], str) \
            or len(raw["seed_main"]) != 40 \
            or set(raw["seed_main"]) - set("0123456789abcdef"):
        raise RuntimeFault("backup manifest: seed_main")
    vols = raw["volumes"]
    if not isinstance(vols, dict) or set(vols) != set(DATA_ROLES):
        raise RuntimeFault("backup manifest: volumes")
    for role in DATA_ROLES:
        entry = vols[role]
        if not isinstance(entry, dict) or set(entry) != {
                "member", "sha256", "bytes"}:
            raise RuntimeFault(f"backup manifest volumes.{role}: keys")
        if entry["member"] != f"{role}.tar":
            raise RuntimeFault(
                f"backup manifest volumes.{role}: member name")
        if not isinstance(entry["sha256"], str) \
                or len(entry["sha256"]) != 64 \
                or set(entry["sha256"]) - set("0123456789abcdef"):
            raise RuntimeFault(
                f"backup manifest volumes.{role}: sha256")
        size = entry["bytes"]
        if not isinstance(size, int) or isinstance(size, bool) \
                or size < 0 or size > MAX_ROLE_TAR_BYTES:
            raise RuntimeFault(
                f"backup manifest volumes.{role}: bytes")
    return raw


def parse_manifest_bytes(data):
    try:
        raw = parse_json(data, "backup manifest")
    except ConfigError as exc:
        raise RuntimeFault(str(exc)) from exc
    return validate_manifest(raw)


def open_archive(path):
    """Open an untrusted archive: O_NOFOLLOW, stable fd, owner/mode/
    nlink/size policy. Returns fd; caller closes."""
    fd = os.open(
        str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_size > MAX_OUTER_BYTES
        ):
            raise RuntimeFault("archive: unsafe outer file")
        return fd
    except BaseException:
        os.close(fd)
        raise


def hash_stream(fd):
    """SHA-256 of fd content from current offset; bounded reads."""
    h = hashlib.sha256()
    while True:
        chunk = os.read(fd, 4 << 20)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()
