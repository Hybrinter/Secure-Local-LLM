"""Strict versioned configuration: instance names, profiles, artifact fingerprints."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

INSTANCE_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
PROFILE_SCHEMA = "secure-local-llm/profile@1"
MAX_FILE_BYTES = 1 << 20


class ConfigError(Exception):
    pass


def validate_instance_name(name):
    if not isinstance(name, str) or not INSTANCE_NAME_RE.fullmatch(name):
        raise ConfigError(
            f"invalid instance name {name!r}: must match [a-z][a-z0-9-]{{0,31}}"
        )
    return name


def _bounded_int(key, value, lo, hi):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key}: integer required")
    if not lo <= value <= hi:
        raise ConfigError(f"{key}: {value} outside allowed range [{lo}, {hi}]")
    return value


def read_secure_file(path, max_bytes=MAX_FILE_BYTES):
    p = Path(path)
    if not p.is_absolute():
        raise ConfigError(f"path must be absolute: {path!r}")
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise ConfigError(f"cannot open {p}: {exc.strerror or exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ConfigError(f"not a regular single-link file: {p}")
        if st.st_size > max_bytes:
            raise ConfigError(f"file too large: {p}")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ConfigError(f"file too large: {p}")
    finally:
        os.close(fd)
    return data


def fingerprint_file(path):
    data = read_secure_file(path)
    return {
        "path": str(Path(path)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ConfigError(f"duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def parse_json(data, label):
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        return json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{label}: not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{label}: invalid JSON: {exc}") from exc


_PROFILE_BOUNDS = {
    "model": {
        "context_tokens": (512, 262144),
        "max_output_tokens": (64, 65536),
        "parallel": (1, 1),
        "threads": (1, 64),
    },
    "resources": {"memory_mb": (1024, 262144), "cpus": (1, 64), "pids": (64, 8192)},
    "timeouts": {"startup_seconds": (5, 3600), "request_seconds": (5, 3600)},
}
_PROFILE_TOP_KEYS = frozenset({"schema", "name"} | set(_PROFILE_BOUNDS))


def parse_profile(raw, expected_name=None):
    if not isinstance(raw, dict):
        raise ConfigError("profile must be a JSON object")
    unknown = set(raw) - _PROFILE_TOP_KEYS
    if unknown:
        raise ConfigError(f"profile: unknown keys {sorted(unknown)}")
    if raw.get("schema") != PROFILE_SCHEMA:
        raise ConfigError(f"profile: schema must be {PROFILE_SCHEMA!r}")
    name = validate_instance_name(raw.get("name"))
    if expected_name is not None and name != expected_name:
        raise ConfigError(f"profile name {name!r} does not match {expected_name!r}")
    out = {"schema": PROFILE_SCHEMA, "name": name}
    for section, fields in _PROFILE_BOUNDS.items():
        sub = raw.get(section)
        if not isinstance(sub, dict):
            raise ConfigError(f"profile.{section}: object required")
        extra = set(sub) - set(fields)
        if extra:
            raise ConfigError(f"profile.{section}: unknown keys {sorted(extra)}")
        missing = set(fields) - set(sub)
        if missing:
            raise ConfigError(f"profile.{section}: missing keys {sorted(missing)}")
        out[section] = {
            k: _bounded_int(f"{section}.{k}", sub[k], *bounds)
            for k, bounds in fields.items()
        }
    if out["model"]["max_output_tokens"] > out["model"]["context_tokens"]:
        raise ConfigError(
            "profile.model: max_output_tokens must not exceed context_tokens"
        )
    return out


def load_profile(repo_root, name):
    validate_instance_name(name)
    path = Path(repo_root) / ".devin" / "profiles" / f"{name}.json"
    data = read_secure_file(str(path))
    profile = parse_profile(parse_json(data, str(path)), expected_name=name)
    fingerprint = {
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
    return profile, fingerprint
