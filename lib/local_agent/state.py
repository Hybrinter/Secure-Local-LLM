"""Private instance state: owned 0700/0600 paths, bounded fcntl-locked atomic writes."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import stat
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import ConfigError, parse_json, validate_instance_name

APP_NAME = "secure-local-llm"
MANIFEST_SCHEMA = "secure-local-llm/instance@1"
MAX_MANIFEST_BYTES = 64 * 1024
LOCK_TIMEOUT_SECONDS = 10.0
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


class StateError(Exception):
    pass


def _validate_name(name):
    try:
        return validate_instance_name(name)
    except ConfigError as exc:
        raise StateError(str(exc)) from exc


def _require_absolute(path, label="state path"):
    if not Path(path).is_absolute():
        raise StateError(f"{label} must be absolute: {path!r}")
    return Path(path)


def state_root(environ=None):
    environ = os.environ if environ is None else environ
    base = environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return _require_absolute(Path(base) / APP_NAME)


def cache_root(environ=None):
    environ = os.environ if environ is None else environ
    base = environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return _require_absolute(Path(base) / APP_NAME)


def _check_dir_chain(path):
    for comp in (Path(path), *Path(path).parents):
        try:
            st = comp.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise StateError(f"cannot inspect state path {comp}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise StateError(f"unsafe state path component: {comp}")


def _require_private_dir(path):
    path = _require_absolute(path)
    _check_dir_chain(path.parent)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise StateError(f"unsafe state path: {path}")
    if st.st_uid != os.geteuid():
        raise StateError(f"state path not owned by current user: {path}")
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise StateError(f"state path has insecure permissions: {path}")


def _fsync_directory(path):
    fd = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ensure_ancestors(path):
    _check_dir_chain(Path(path).parent)
    missing = []
    cur = Path(path).parent
    while True:
        try:
            st = cur.lstat()
            break
        except FileNotFoundError:
            missing.append(cur)
            if cur.parent == cur:
                raise StateError(f"no existing ancestor for state path: {path}")
            cur = cur.parent
        except OSError as exc:
            raise StateError(f"cannot inspect state path {cur}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise StateError(f"unsafe state path component: {cur}")
    for d in reversed(missing):
        try:
            d.mkdir(mode=0o700)
            os.chmod(d, 0o700)
        except FileExistsError:
            st = d.lstat()
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise StateError(f"unsafe state path component: {d}")
        except OSError as exc:
            raise StateError(f"cannot create state dir {d}: {exc}") from exc
        _fsync_directory(d)
        _fsync_directory(d.parent)


def _ensure_private_dir(path):
    path = _require_absolute(path)
    _ensure_ancestors(path)
    try:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise StateError(f"cannot create state dir {path}: {exc}") from exc
    _require_private_dir(path)
    _fsync_directory(path)
    _fsync_directory(path.parent)
    return path


def _instance_dir(root, name):
    return Path(root) / "instances" / name


def manifest_path(root, name):
    _require_absolute(root)
    _validate_name(name)
    return _instance_dir(root, name) / "manifest.json"


def _read_private_file(path, max_bytes):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise StateError(f"cannot open {path}: {exc.strerror or exc}") from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600
        ):
            raise StateError(f"unsafe state file: {path}")
        if st.st_size > max_bytes:
            raise StateError(f"state file too large: {path}")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise StateError(f"state file too large: {path}")
        return data
    finally:
        os.close(fd)


def _is_hex(value, length):
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _is_hex64(value):
    return _is_hex(value, 64)


def _expect_keys(obj, keys, label):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise StateError(f"{label}: expected exactly keys {sorted(keys)}")


def validate_manifest(raw, expected_name=None):
    _expect_keys(
        raw,
        ("schema", "identity", "profile", "artifacts_lock", "exceptions",
         "resources"),
        "manifest",
    )
    if raw["schema"] != MANIFEST_SCHEMA:
        raise StateError(f"manifest: schema must be {MANIFEST_SCHEMA!r}")
    ident = raw["identity"]
    _expect_keys(ident, ("name", "uuid", "created_utc"), "manifest.identity")
    _validate_name(ident["name"])
    if expected_name is not None and ident["name"] != expected_name:
        raise StateError("manifest.identity.name does not match instance name")
    try:
        canonical = str(uuid.UUID(ident["uuid"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise StateError("manifest.identity.uuid: not a valid UUID") from exc
    if canonical != ident["uuid"]:
        raise StateError("manifest.identity.uuid: not canonical form")
    if not isinstance(ident["created_utc"], str):
        raise StateError("manifest.identity.created_utc: string required")
    try:
        datetime.fromisoformat(ident["created_utc"])
    except ValueError as exc:
        raise StateError("manifest.identity.created_utc: invalid timestamp") from exc
    profile = raw["profile"]
    _expect_keys(profile, ("name", "sha256"), "manifest.profile")
    _validate_name(profile["name"])
    if not _is_hex64(profile["sha256"]):
        raise StateError("manifest.profile.sha256: hex64 required")
    lock = raw["artifacts_lock"]
    _expect_keys(lock, ("path", "sha256", "bytes"), "manifest.artifacts_lock")
    if not isinstance(lock["path"], str) or not Path(lock["path"]).is_absolute():
        raise StateError("manifest.artifacts_lock.path: absolute path required")
    if not _is_hex64(lock["sha256"]):
        raise StateError("manifest.artifacts_lock.sha256: hex64 required")
    if isinstance(lock["bytes"], bool) or not isinstance(lock["bytes"], int):
        raise StateError("manifest.artifacts_lock.bytes: integer required")
    if lock["bytes"] < 0:
        raise StateError("manifest.artifacts_lock.bytes: must be non-negative")
    exc = raw["exceptions"]
    _expect_keys(exc, ("prototype_no_lsm_acknowledged",), "manifest.exceptions")
    if exc["prototype_no_lsm_acknowledged"] is not True:
        raise StateError(
            "manifest.exceptions.prototype_no_lsm_acknowledged: must be true"
        )
    res = raw["resources"]
    _expect_keys(
        res, ("pod_id", "container_ids", "volume_names", "network_id"),
        "manifest.resources",
    )
    for key in ("pod_id", "network_id"):
        if res[key] is not None and not _is_hex64(res[key]):
            raise StateError(f"manifest.resources.{key}: null or hex64 required")
    if not isinstance(res["container_ids"], dict) or not all(
        isinstance(k, str) and k and _is_hex64(v)
        for k, v in res["container_ids"].items()
    ):
        raise StateError(
            "manifest.resources.container_ids: role->hex64 mapping required"
        )
    if not isinstance(res["volume_names"], dict) or not all(
        isinstance(k, str) and k and isinstance(v, str) and v
        for k, v in res["volume_names"].items()
    ):
        raise StateError(
            "manifest.resources.volume_names: string mapping required"
        )
    return raw


def load_manifest(root, name):
    root = _require_absolute(root)
    _validate_name(name)
    inst = _instance_dir(root, name)
    _check_dir_chain(inst)
    for d in (root, root / "instances", inst):
        try:
            _require_private_dir(d)
        except FileNotFoundError:
            continue
    target = manifest_path(root, name)
    try:
        data = _read_private_file(target, MAX_MANIFEST_BYTES)
    except FileNotFoundError:
        return None
    try:
        raw = parse_json(data, str(target))
    except ConfigError as exc:
        raise StateError(f"manifest {target}: corrupt data: {exc}") from exc
    return validate_manifest(raw, expected_name=name)


@contextlib.contextmanager
def _locked(path, timeout=None):
    timeout = LOCK_TIMEOUT_SECONDS if timeout is None else timeout
    fresh = not path.exists() and not path.is_symlink()
    try:
        fd = os.open(
            path,
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600,
        )
    except OSError as exc:
        raise StateError(f"cannot open lock {path}: {exc.strerror or exc}") from exc
    try:
        if fresh:
            os.fchmod(fd, 0o600)
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600
        ):
            raise StateError(f"unsafe lock file: {path}")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StateError(f"timed out acquiring lock: {path}")
                time.sleep(0.05)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _atomic_write(path, payload, mode=0o600, *, replace=True):
    parent = path.parent
    _require_private_dir(parent)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        if replace:
            try:
                st = path.lstat()
            except FileNotFoundError:
                st = None
            if st is not None and (
                not stat.S_ISREG(st.st_mode)
                or st.st_nlink != 1
                or st.st_uid != os.geteuid()
            ):
                raise StateError(
                    f"refusing to replace unexpected file: {path}")
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            except FileExistsError as exc:
                raise StateError(
                    f"refusing to overwrite existing file: {path}"
                ) from exc
            os.unlink(tmp)
        _fsync_directory(parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def init_instance(root, name, profile, profile_fp, lock_fp, no_lsm_acknowledged):
    root = _require_absolute(root)
    _validate_name(name)
    if no_lsm_acknowledged is not True:
        raise StateError(
            "init requires --acknowledge-prototype-no-lsm: no active LSM "
            "confinement on this host; the exception is prototype-only"
        )
    _ensure_private_dir(root)
    _ensure_private_dir(root / "instances")
    inst = _ensure_private_dir(_instance_dir(root, name))
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "identity": {
            "name": name,
            "uuid": str(uuid.uuid4()),
            "created_utc": datetime.now(timezone.utc).isoformat(),
        },
        "profile": {"name": profile["name"], "sha256": profile_fp["sha256"]},
        "artifacts_lock": lock_fp,
        "exceptions": {"prototype_no_lsm_acknowledged": True},
        "resources": {
            "pod_id": None,
            "container_ids": {},
            "volume_names": {},
            "network_id": None,
        },
    }
    validate_manifest(manifest, expected_name=name)
    target = manifest_path(root, name)
    with _locked(inst / ".lock"):
        try:
            st = target.lstat()
        except FileNotFoundError:
            st = None
        if st is not None:
            raise StateError(f"instance already initialized: {name}")
        payload = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
        _atomic_write(target, payload)
    return manifest


PREPARED_SCHEMA = "secure-local-llm/prepared@1"
_PREPARED_ARTIFACTS = ("model", "opencode", "inference_source")
_HASH_HEX_LENGTHS = {"sha256": 64, "sha512": 128}


def validate_prepared(raw, expected_name=None):
    _expect_keys(
        raw,
        ("schema", "instance", "created_utc", "fingerprints", "artifacts",
         "images", "packages"),
        "prepared",
    )
    if raw["schema"] != PREPARED_SCHEMA:
        raise StateError(f"prepared: schema must be {PREPARED_SCHEMA!r}")
    _validate_name(raw["instance"])
    if expected_name is not None and raw["instance"] != expected_name:
        raise StateError("prepared.instance does not match instance name")
    if not isinstance(raw["created_utc"], str):
        raise StateError("prepared.created_utc: string required")
    try:
        datetime.fromisoformat(raw["created_utc"])
    except ValueError as exc:
        raise StateError("prepared.created_utc: invalid timestamp") from exc
    fps = raw["fingerprints"]
    _expect_keys(
        fps,
        ("artifacts_lock", "profile", "harness_containerfile",
         "inference_containerfile"),
        "prepared.fingerprints",
    )
    for key, value in fps.items():
        if not _is_hex64(value):
            raise StateError(f"prepared.fingerprints.{key}: hex64 required")
    arts = raw["artifacts"]
    _expect_keys(arts, _PREPARED_ARTIFACTS, "prepared.artifacts")
    for key in _PREPARED_ARTIFACTS:
        entry = arts[key]
        if not isinstance(entry, dict):
            raise StateError(f"prepared.artifacts.{key}: object required")
        algos = [a for a in _HASH_HEX_LENGTHS if a in entry]
        if len(algos) != 1 or set(entry) != {"path", algos[0]}:
            raise StateError(
                f"prepared.artifacts.{key}: exactly path and one hash required"
            )
        if not _is_hex(entry[algos[0]], _HASH_HEX_LENGTHS[algos[0]]):
            raise StateError(
                f"prepared.artifacts.{key}.{algos[0]}: bad hex digest"
            )
        path = entry["path"]
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise StateError(
                f"prepared.artifacts.{key}.path: absolute string required"
            )
    images = raw["images"]
    _expect_keys(images, ("harness", "inference"), "prepared.images")
    for key, value in images.items():
        if not _is_hex64(value):
            raise StateError(f"prepared.images.{key}: hex64 required")
    packages = raw["packages"]
    _expect_keys(packages, ("harness", "inference"), "prepared.packages")
    for key, value in packages.items():
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise StateError(
                f"prepared.packages.{key}: non-empty string list required"
            )
    return raw


@contextlib.contextmanager
def locked_instance(root, name):
    root = _require_absolute(root)
    _validate_name(name)
    inst = _instance_dir(root, name)
    _require_private_dir(inst)
    with _locked(inst / ".lock"):
        yield inst


def _prepared_payload(name, record):
    validate_prepared(record, expected_name=name)
    payload = json.dumps(record, indent=2, sort_keys=True).encode() + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise StateError("prepared record too large")
    return payload


def save_prepared(root, name, record):
    payload = _prepared_payload(name, record)
    with locked_instance(root, name) as inst:
        _atomic_write(inst / "prepared.json", payload)


def save_prepared_locked(root, name, record):
    root = _require_absolute(root)
    _validate_name(name)
    payload = _prepared_payload(name, record)
    _atomic_write(_instance_dir(root, name) / "prepared.json", payload)


def save_manifest_locked(root, name, manifest):
    root = _require_absolute(root)
    _validate_name(name)
    validate_manifest(manifest, expected_name=name)
    payload = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise StateError("manifest too large")
    _atomic_write(_instance_dir(root, name) / "manifest.json", payload)


def load_prepared(root, name):
    root = _require_absolute(root)
    _validate_name(name)
    inst = _instance_dir(root, name)
    _check_dir_chain(inst)
    for d in (root, root / "instances", inst):
        try:
            _require_private_dir(d)
        except FileNotFoundError:
            continue
    target = inst / "prepared.json"
    try:
        data = _read_private_file(target, MAX_MANIFEST_BYTES)
    except FileNotFoundError:
        return None
    try:
        raw = parse_json(data, str(target))
    except ConfigError as exc:
        raise StateError(f"prepared {target}: corrupt data: {exc}") from exc
    return validate_prepared(raw, expected_name=name)


GIT_PREPARED_SCHEMA = "secure-local-llm/git-prepared@1"
GIT_PREPARED_FILES = (
    "containers/git-fixture.Containerfile",
    "git-fixture/pre_receive.py",
    "git-fixture/serve_git.py",
    "git-fixture/sshd_config",
)


def _uuid_canonical(value, label):
    if not isinstance(value, str):
        raise StateError(f"{label}: string required")
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise StateError(f"{label}: not a valid UUID") from exc
    if canonical != value:
        raise StateError(f"{label}: not canonical form")


def validate_git_prepared(raw, expected_name=None):
    _expect_keys(
        raw,
        ("schema", "instance", "instance_uuid", "created_utc",
         "artifacts_lock_sha256", "profile_sha256", "files", "image_id",
         "packages"),
        "git-prepared",
    )
    if raw["schema"] != GIT_PREPARED_SCHEMA:
        raise StateError(
            f"git-prepared: schema must be {GIT_PREPARED_SCHEMA!r}"
        )
    _validate_name(raw["instance"])
    if expected_name is not None and raw["instance"] != expected_name:
        raise StateError("git-prepared.instance does not match instance name")
    _uuid_canonical(raw["instance_uuid"], "git-prepared.instance_uuid")
    if not isinstance(raw["created_utc"], str):
        raise StateError("git-prepared.created_utc: string required")
    try:
        datetime.fromisoformat(raw["created_utc"])
    except ValueError as exc:
        raise StateError(
            "git-prepared.created_utc: invalid timestamp"
        ) from exc
    for key in ("artifacts_lock_sha256", "profile_sha256", "image_id"):
        if not _is_hex64(raw[key]):
            raise StateError(f"git-prepared.{key}: hex64 required")
    files = raw["files"]
    _expect_keys(files, GIT_PREPARED_FILES, "git-prepared.files")
    for key, value in files.items():
        if not _is_hex64(value):
            raise StateError(f"git-prepared.files.{key}: hex64 required")
    packages = raw["packages"]
    if not isinstance(packages, list) or not all(
        isinstance(item, str) and item for item in packages
    ):
        raise StateError(
            "git-prepared.packages: non-empty string list required"
        )
    return raw


def _git_prepared_payload(name, record):
    validate_git_prepared(record, expected_name=name)
    payload = json.dumps(record, indent=2, sort_keys=True).encode() + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise StateError("git-prepared record too large")
    return payload


def save_git_prepared(root, name, record):
    payload = _git_prepared_payload(name, record)
    with locked_instance(root, name) as inst:
        _atomic_write(inst / "git-prepared.json", payload)


def save_git_prepared_locked(root, name, record):
    root = _require_absolute(root)
    _validate_name(name)
    payload = _git_prepared_payload(name, record)
    _atomic_write(_instance_dir(root, name) / "git-prepared.json", payload)


def load_git_prepared(root, name):
    root = _require_absolute(root)
    _validate_name(name)
    inst = _instance_dir(root, name)
    _check_dir_chain(inst)
    for d in (root, root / "instances", inst):
        try:
            _require_private_dir(d)
        except FileNotFoundError:
            continue
    target = inst / "git-prepared.json"
    try:
        data = _read_private_file(target, MAX_MANIFEST_BYTES)
    except FileNotFoundError:
        return None
    try:
        raw = parse_json(data, str(target))
    except ConfigError as exc:
        raise StateError(f"git-prepared {target}: corrupt data: {exc}") from exc
    return validate_git_prepared(raw, expected_name=name)
