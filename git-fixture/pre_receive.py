#!/usr/bin/env python3
"""pre-receive hook: only new commits on refs/heads/agent/*, fast-forward only."""

import os
import re
import subprocess
import sys
from types import SimpleNamespace

MAX_STDIN_BYTES = 64 * 1024
MAX_UPDATES = 128
MAX_COMMITS = 128
MAX_BLOB_BYTES = 65536
ZERO = "0" * 40
HEX40 = re.compile(r"[0-9a-f]{40}")
REF_PREFIX = "refs/heads/agent/"
REF_SUFFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
SEED_FILES = ("calculator.py", "test_calculator.py")
CALC_MINUS = "def add(left, right):\n    return left - right\n"
CALC_PLUS = "def add(left, right):\n    return left + right\n"
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
        result = subprocess.run(
            ["git", "--no-replace-objects", *args],
            capture_output=True, timeout=10, env=env)
        return SimpleNamespace(
            returncode=result.returncode,
            stdout=result.stdout.decode("utf-8"),
            stderr=result.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        _fail(f"git {' '.join(args)} timed out")
    except UnicodeDecodeError:
        _fail(f"git {' '.join(args)} produced undecodable output")


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


def _tree(commit):
    res = _git("ls-tree", commit)
    if res.returncode != 0:
        _fail(f"cannot read root tree: {commit}")
    entries = {}
    for line in res.stdout.splitlines():
        meta, sep, name = line.partition("\t")
        parts = meta.split()
        if not sep or len(parts) != 3 or not name:
            _fail(f"malformed tree output for {commit}")
        mode, kind, oid = parts
        if name in entries:
            _fail(f"duplicate root entry {name!r} in {commit}")
        entries[name] = (mode, kind, oid)
    if set(entries) != set(SEED_FILES):
        _fail(f"commit {commit} does not match the permitted file set")
    for name, (mode, kind, oid) in entries.items():
        if mode != "100644" or kind != "blob" or not HEX40.fullmatch(oid):
            _fail(f"commit {commit} has a non-regular or malformed entry")
    return entries


def _blob(oid):
    res = _git("cat-file", "-s", oid)
    size = res.stdout.strip()
    if res.returncode != 0 or not re.fullmatch(r"[0-9]+", size) \
            or int(size) > MAX_BLOB_BYTES:
        _fail(f"cannot read bounded blob size: {oid}")
    res = _git("cat-file", "blob", oid)
    if res.returncode != 0:
        _fail(f"cannot read blob: {oid}")
    return res.stdout


def _seed():
    res = _git("rev-parse", "--verify", "refs/heads/main")
    seed = res.stdout.strip()
    if res.returncode != 0 or not HEX40.fullmatch(seed):
        _fail("protected main is missing or invalid")
    res = _git("cat-file", "-t", seed)
    if res.returncode != 0 or res.stdout.strip() != "commit":
        _fail("protected main is not a commit")
    entries = _tree(seed)
    if _blob(entries["calculator.py"][2]) != CALC_MINUS:
        _fail("protected main calculator is not the trusted seed")
    return seed, entries["test_calculator.py"][2]


def _content(new, seed, test_oid, checked):
    res = _git("merge-base", "--is-ancestor", seed, new)
    if res.returncode != 0:
        _fail(f"tip does not contain protected main: {new}")
    res = _git("rev-list", "--max-count=129", new, f"^{seed}")
    if res.returncode != 0:
        _fail(f"cannot enumerate new commits: {new}")
    commits = res.stdout.split()
    if len(commits) > MAX_COMMITS:
        _fail(f"too many new commits on {new}")
    for commit in commits:
        if not HEX40.fullmatch(commit):
            _fail(f"malformed commit list on {new}")
        if commit in checked:
            continue
        checked.add(commit)
        entries = _tree(commit)
        if entries["test_calculator.py"][2] != test_oid:
            _fail(f"commit {commit} changes the protected test file")
        if _blob(entries["calculator.py"][2]) not in (CALC_MINUS, CALC_PLUS):
            _fail(f"commit {commit} changes calculator.py outside the "
                  "permitted fix")


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
    seed, test_oid = _seed()
    checked = set()
    for update in updates:
        _content(update[1], seed, test_oid, checked)


if __name__ == "__main__":
    main()
