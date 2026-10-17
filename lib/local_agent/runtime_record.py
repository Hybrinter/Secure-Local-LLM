"""Frozen runtime record validation and private control-file material."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
from datetime import datetime
from pathlib import Path

from . import runtime_spec as spec
from . import state
from .config import parse_json
from .state import (
    StateError,
    _atomic_write,
    _ensure_private_dir,
)

RUNTIME_SCHEMA = "secure-local-llm/runtime@1"
RUNTIME_MAX_BYTES = 64 * 1024
_MAX_CONTROL_BYTES = 64 * 1024
_CONTROL_MODES = {
    "ssh_host_ed25519_key": {0o600},
    "ssh_host_ed25519_key.pub": {0o400, 0o600, 0o644},
    "client_key": {0o600},
    "client_key.pub": {0o400, 0o600, 0o644},
    "authorized_keys": {0o400, 0o600},
    "model-api-key": {0o600},
    "service.json": {0o600},
    "gitconfig": {0o400},
    "ssh_config": {0o400},
    "known_hosts": {0o400},
    "opencode.json": {0o400},
}
_HEX40_RE = re.compile(r"[0-9a-f]{40}")


class RuntimeFault(Exception):
    pass


def _is_hex64(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _is_hex40(value):
    return isinstance(value, str) and bool(_HEX40_RE.fullmatch(value))


def _uuid_ok(value):
    import uuid as _uuid
    if not isinstance(value, str):
        return False
    try:
        return str(_uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _ts_ok(value):
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _check_keys(obj, keys, label):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise StateError(f"{label}: expected exactly keys {sorted(keys)}")


POLICY_SCHEMA = "secure-local-llm/netpol@1"


def _check_policy(rec, label, role, table, peer_ip):
    _check_keys(
        rec,
        ("schema", "table", "role", "peer_ip", "peer_port",
         "canonical_sha256"),
        label)
    if rec["schema"] != POLICY_SCHEMA:
        raise StateError(f"{label}: schema must be {POLICY_SCHEMA!r}")
    if rec["role"] != role:
        raise StateError(f"{label}.role: expected {role!r}")
    if rec["table"] != table:
        raise StateError(f"{label}.table does not match runtime tables")
    try:
        ip = ipaddress.ip_address(rec["peer_ip"])
    except (ValueError, TypeError) as exc:
        raise StateError(f"{label}.peer_ip: IPv4 required") from exc
    if str(ip) != peer_ip:
        raise StateError(f"{label}.peer_ip does not match runtime record")
    if rec["peer_port"] != spec.GIT_PORT:
        raise StateError(f"{label}.peer_port: must be {spec.GIT_PORT}")
    if not _is_hex64(rec["canonical_sha256"]):
        raise StateError(f"{label}.canonical_sha256: hex64 required")


def validate_runtime(raw, expected_name=None):
    _check_keys(
        raw,
        ("schema", "instance", "instance_uuid", "created_utc", "subnet",
         "pod_ip", "git_ip", "network", "tables", "policy", "objects",
         "images", "fingerprints", "control_sha256", "seed_sha256",
         "seed_main"),
        "runtime",
    )
    if raw["schema"] != RUNTIME_SCHEMA:
        raise StateError(f"runtime: schema must be {RUNTIME_SCHEMA!r}")
    if not isinstance(raw["instance"], str):
        raise StateError("runtime.instance: string required")
    if expected_name is not None and raw["instance"] != expected_name:
        raise StateError("runtime.instance does not match instance name")
    if not _uuid_ok(raw["instance_uuid"]):
        raise StateError("runtime.instance_uuid: canonical UUID required")
    if not _ts_ok(raw["created_utc"]):
        raise StateError("runtime.created_utc: invalid timestamp")
    try:
        subnet = ipaddress.ip_network(raw["subnet"])
    except (ValueError, TypeError) as exc:
        raise StateError("runtime.subnet: IPv4 CIDR required") from exc
    if subnet.version != 4 or subnet.prefixlen != 28 or not subnet.is_private:
        raise StateError("runtime.subnet: private IPv4 /28 required")
    for key, offset in (("pod_ip", spec.POD_OFFSET), ("git_ip", spec.GIT_OFFSET)):
        try:
            ip = ipaddress.ip_address(raw[key])
        except (ValueError, TypeError) as exc:
            raise StateError(f"runtime.{key}: IPv4 address required") from exc
        if ip != subnet[offset]:
            raise StateError(f"runtime.{key}: must be subnet offset {offset}")
    expected = spec.names(raw["instance_uuid"])
    net = raw["network"]
    _check_keys(net, ("id", "name"), "runtime.network")
    if not _is_hex64(net["id"]):
        raise StateError("runtime.network.id: hex64 required")
    if net["name"] != expected["net"]:
        raise StateError("runtime.network.name does not match instance names")
    tables = raw["tables"]
    _check_keys(tables, ("workload", "git"), "runtime.tables")
    short = raw["instance_uuid"].replace("-", "")[:12]
    for key, suffix in (("workload", "00"), ("git", "01")):
        want = "sllm_" + short + suffix
        if tables[key] != want:
            raise StateError(f"runtime.tables.{key}: expected {want}")
    _check_keys(raw["policy"], ("workload", "git"), "runtime.policy")
    for key, peer in (("workload", raw["git_ip"]), ("git", raw["pod_ip"])):
        _check_policy(
            raw["policy"][key], f"runtime.policy.{key}", key,
            tables[key], peer)
    objects = raw["objects"]
    _check_keys(
        objects, ("pod", "infra", "containers", "volumes"), "runtime.objects")
    for key in ("pod", "infra"):
        if not _is_hex64(objects[key]):
            raise StateError(f"runtime.objects.{key}: hex64 required")
    _check_keys(
        objects["containers"], ("inference", "harness", "git"),
        "runtime.objects.containers")
    for key, val in objects["containers"].items():
        if not _is_hex64(val):
            raise StateError(f"runtime.objects.containers.{key}: hex64")
    _check_keys(
        objects["volumes"], ("workspace", "state", "model", "repo"),
        "runtime.objects.volumes")
    for key, val in objects["volumes"].items():
        if val != expected["vol_" + key]:
            raise StateError(
                f"runtime.objects.volumes.{key}: expected "
                f"{expected['vol_' + key]}")
    images = raw["images"]
    _check_keys(images, ("harness", "inference", "git"), "runtime.images")
    for key, val in images.items():
        if not _is_hex64(val):
            raise StateError(f"runtime.images.{key}: hex64 required")
    fps = raw["fingerprints"]
    _check_keys(
        fps,
        ("profile", "artifacts_lock", "source_config"),
        "runtime.fingerprints")
    for key, val in fps.items():
        if not _is_hex64(val):
            raise StateError(f"runtime.fingerprints.{key}: hex64 required")
    ctrl = raw["control_sha256"]
    _check_keys(ctrl, spec.CONTROL_FILES, "runtime.control_sha256")
    for key, val in ctrl.items():
        if not _is_hex64(val):
            raise StateError(f"runtime.control_sha256.{key}: hex64 required")
    if not _is_hex64(raw["seed_sha256"]):
        raise StateError("runtime.seed_sha256: hex64 required")
    if not _is_hex40(raw["seed_main"]):
        raise StateError("runtime.seed_main: hex40 required")
    return raw


def load_runtime(inst, name):
    target = inst / "runtime.json"
    try:
        data = state._read_private_file(target, RUNTIME_MAX_BYTES)
    except FileNotFoundError:
        return None
    try:
        raw = parse_json(data, str(target))
    except Exception as exc:
        raise StateError(f"runtime {target}: corrupt data: {exc}") from exc
    return validate_runtime(raw, expected_name=name)


def save_runtime(inst, name, record):
    validate_runtime(record, expected_name=name)
    payload = json.dumps(record, indent=2, sort_keys=True).encode() + b"\n"
    if len(payload) > RUNTIME_MAX_BYTES:
        raise StateError("runtime record too large")
    _atomic_write(inst / "runtime.json", payload)


def _read_control(path, modes, label):
    try:
        fd = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeFault(f"cannot open control file {label}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) not in modes
        ):
            raise RuntimeFault(f"unsafe control file: {label}")
        if st.st_size > _MAX_CONTROL_BYTES:
            raise RuntimeFault(f"control file too large: {label}")
        return os.read(fd, st.st_size)
    finally:
        os.close(fd)


def _gen_key(runner, path, comment):
    for cand in (path, Path(str(path) + ".pub")):
        try:
            cand.lstat()
        except FileNotFoundError:
            continue
        raise RuntimeFault(
            f"refusing to generate key over existing path: {cand}")
    res = runner.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-C", comment,
         "-f", str(path)],
        timeout=30,
        stdin_text="\n\n",
    )
    if res.returncode != 0 or res.timed_out:
        raise RuntimeFault(f"ssh-keygen failed for {path.name}")


def _write_once(path, data, mode):
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        return
    payload = data if isinstance(data, bytes) else data.encode()
    _atomic_write(Path(path), payload, mode)


def _ensure_control(inst, runner, rendered_config, git_ip):
    control = _ensure_private_dir(inst / "control")
    host_key = control / "ssh_host_ed25519_key"
    client = control / "client_key"
    try:
        host_key.lstat()
    except FileNotFoundError:
        _gen_key(runner, host_key, "secure-local-llm-test")
    try:
        client.lstat()
    except FileNotFoundError:
        _gen_key(runner, client, "secure-local-llm-test")
    pubs = {}
    for base in (host_key, client):
        pub = Path(str(base) + ".pub")
        pubs[base.name] = _read_control(pub, {0o400, 0o600, 0o644},
                                      base.name + ".pub")
    _write_once(
        control / "authorized_keys", pubs["client_key"], 0o400)
    _write_once(
        control / "model-api-key", secrets.token_hex(32) + "\n", 0o600)
    _write_once(
        control / "service.json",
        json.dumps({
            "hostname": "127.0.0.1",
            "port": 4096,
            "password": secrets.token_hex(32),
        }, separators=(",", ":")) + "\n",
        0o600)
    _write_once(control / "gitconfig", spec.GITCONFIG, 0o400)
    _write_once(control / "opencode.json", rendered_config, 0o400)
    host_pub = pubs["ssh_host_ed25519_key"].decode().strip()
    _write_once(
        control / "known_hosts",
        f"[{git_ip}]:{spec.GIT_PORT} {host_pub}\n", 0o400)
    _write_once(
        control / "ssh_config", spec.SSH_CONFIG.format(git_ip=git_ip), 0o400)
    fps = {}
    for name in spec.CONTROL_FILES:
        fps[name] = hashlib.sha256(
            _read_control(
                control / name, _CONTROL_MODES[name], name)).hexdigest()
    svc = parse_json(
        _read_control(
            control / "service.json", _CONTROL_MODES["service.json"],
            "service.json"),
        "service.json")
    if (
        not isinstance(svc, dict)
        or set(svc) != {"hostname", "port", "password"}
        or svc["hostname"] != "127.0.0.1"
        or svc["port"] != 4096
        or not isinstance(svc["password"], str)
        or len(svc["password"]) < 32
    ):
        raise RuntimeFault("service.json malformed")
    return control, fps


def _ensure_seed_dir(control):
    seed = _ensure_private_dir(control / "seed")
    for name, content in spec.SEED_FILES.items():
        target = seed / name
        try:
            data = _read_control(target, {0o400, 0o600}, name)
        except FileNotFoundError:
            _atomic_write(target, content.encode(), 0o600)
            continue
        except (OSError, RuntimeFault):
            raise RuntimeFault(f"unsafe seed file: {name}")
        if data != content.encode():
            raise RuntimeFault(
                f"seed file {name} drifted; refusing to rewrite")
    return seed
