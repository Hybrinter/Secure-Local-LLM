#!/usr/bin/env python3
"""pre-receive hook: only new commits on refs/heads/agent/*, fast-forward only."""

import os
import re
import subprocess
import sys

MAX_STDIN_BYTES = 64 * 1024
MAX_UPDATES = 128
ZERO = "0" * 40
HEX40 = re.compile(r"[0-9a-f]{40}")
REF_PREFIX = "refs/heads/agent/"
REF_SUFFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
_GIT_ENV = {
    "PATH": "/usr/bin:/bin",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}
_PASSTHROUGH = (
    "GIT_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
)


def _fail(msg):
    print(f"pre-receive rejected: {msg}", file=sys.stderr)
    sys.exit(1)


def _git(*args):
    env = dict(_GIT_ENV)
    for key in _PASSTHROUGH:
        value = os.environ.get(key)
        if value:
            env[key] = value
    try:
        return subprocess.run(
            ["git", *args],
            capture_output=True, text=True, timeout=10, env=env,
        )
    except subprocess.TimeoutExpired:
        _fail(f"git {' '.join(args)} timed out")


def _check(update):
    old, new, ref = update
    if not HEX40.fullmatch(old) or not HEX40.fullmatch(new):
        _fail(f"malformed object ids in update for {ref!r}")
    if not ref.startswith(REF_PREFIX):
        _fail(f"ref not permitted: {ref!r}")
    suffix = ref[len(REF_PREFIX):]
    if (
        not REF_SUFFIX.fullmatch(suffix)
        or ".." in suffix
        or "//" in suffix
        or suffix.endswith("/")
        or suffix.endswith(".")
    ):
        _fail(f"ref not permitted: {ref!r}")
    if new == ZERO:
        _fail(f"deletion not permitted: {ref}")
    res = _git("check-ref-format", "--branch", ref[len("refs/heads/"):])
    if res.returncode != 0:
        _fail(f"invalid ref name: {ref!r}")
    res = _git("cat-file", "-t", new)
    if res.returncode != 0 or res.stdout.strip() != "commit":
        _fail(f"new object is not a commit: {ref}")
    if old != ZERO:
        res = _git("merge-base", "--is-ancestor", old, new)
        if res.returncode != 0:
            _fail(f"non-fast-forward rejected: {ref}")


def main():
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        _fail("update stream exceeds bound")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _fail("update stream not ASCII")
    if len(lines) > MAX_UPDATES:
        _fail("too many updates")
    updates = []
    for line in lines:
        parts = line.split()
        if len(parts) != 3:
            _fail(f"malformed update line: {line!r}")
        updates.append(tuple(parts))
    for update in updates:
        _check(update)


if __name__ == "__main__":
    main()
