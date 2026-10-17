#!/usr/bin/env python3
"""Standalone namespace-join helper, run via `podman unshare python3 -I -B`.

Reads one bounded JSON request on stdin: {"op": "apply"|"read", "pid": int,
"expect_user": "user:[inode]", "expect_net": "net:[inode]",
"policy": <nft text, apply only>}. Opens /proc/<pid>/ns/{user,net}, verifies
fstat inodes and the netns owner userns via NS_GET_USERNS, then invokes
nsenter --net --setuid 0 --setgid 0 nft with the verified FDs passed through.
--user is added only when the target userns differs from the helper's current
one, which the kernel refuses to re-enter. Emits one JSON result on stdout:
{"ok": bool, "ruleset"|"error"}.
"""

import fcntl
import json
import os
import re
import subprocess
import sys

MAX_STDIN_BYTES = 64 * 1024
MAX_POLICY_BYTES = 32 * 1024
NFT_TIMEOUT_SECONDS = 30
NS_GET_USERNS = 0xB701
_EXPECT_RE = re.compile(r"^(user|net):\[([0-9]+)\]$")
_APPLY_KEYS = {"op", "pid", "expect_user", "expect_net", "policy"}
_READ_KEYS = {"op", "pid", "expect_user", "expect_net"}
_CLEAN_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}


def _emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _fail(message):
    _emit({"ok": False, "error": message})
    sys.exit(0)


def _expect_inode(value, kind):
    if not isinstance(value, str):
        _fail(f"expect_{kind}: string required")
    match = _EXPECT_RE.fullmatch(value)
    if not match or match.group(1) != kind:
        _fail(f"expect_{kind}: must look like {kind}:[inode]")
    return int(match.group(2))


def _open_ns(pid, kind, inode):
    try:
        fd = os.open(
            f"/proc/{pid}/ns/{kind}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
    except OSError as exc:
        _fail(f"cannot open {kind} namespace of pid {pid}: {exc.strerror}")
    st = os.fstat(fd)
    if st.st_ino != inode:
        os.close(fd)
        _fail(f"{kind} namespace inode mismatch for pid {pid}")
    return fd


def _check_net_owner(net_fd, user_inode):
    try:
        owner_fd = fcntl.ioctl(net_fd, NS_GET_USERNS, 0)
    except OSError as exc:
        _fail(f"NS_GET_USERNS failed: {exc.strerror}")
    try:
        st = os.fstat(owner_fd)
    finally:
        os.close(owner_fd)
    if st.st_ino != user_inode:
        _fail("network namespace owner userns mismatch")


def _nft(user_fd, net_fd, args, text):
    try:
        target = os.fstat(user_fd)
        current = os.stat("/proc/self/ns/user")
        target_id = (target.st_dev, target.st_ino)
        current_id = (current.st_dev, current.st_ino)
        argv = ["nsenter"]
        # setns(2) rejects entering the caller's current user namespace.
        if target_id != current_id:
            argv.append(f"--user=/proc/self/fd/{user_fd}")
        argv += [
            f"--net=/proc/self/fd/{net_fd}",
            "--setuid", "0", "--setgid", "0",
            "nft", *args,
        ]
        return subprocess.run(
            argv,
            input=text,
            capture_output=True,
            text=True,
            timeout=NFT_TIMEOUT_SECONDS,
            pass_fds=(user_fd, net_fd),
            env=_CLEAN_ENV,
        )
    except subprocess.TimeoutExpired:
        _fail("nft invocation timed out")
    except OSError as exc:
        _fail(f"cannot run nsenter/nft: {exc.strerror}")


def _parse_request(raw):
    try:
        req = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        _fail("malformed JSON request")
    if not isinstance(req, dict):
        _fail("request must be an object")
    op = req.get("op")
    if op == "apply":
        if set(req) != _APPLY_KEYS:
            _fail("apply request: unexpected keys")
        policy = req["policy"]
        if not isinstance(policy, str):
            _fail("policy: string required")
        if len(policy.encode("utf-8")) > MAX_POLICY_BYTES:
            _fail("policy exceeds bound")
    elif op == "read":
        if set(req) != _READ_KEYS:
            _fail("read request: unexpected keys")
    else:
        _fail("op must be apply or read")
    pid = req["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or not 0 < pid < 1 << 22:
        _fail("pid: invalid")
    return req


def main():
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        _fail("request exceeds bound")
    req = _parse_request(raw)
    user_inode = _expect_inode(req["expect_user"], "user")
    net_inode = _expect_inode(req["expect_net"], "net")
    user_fd = _open_ns(req["pid"], "user", user_inode)
    try:
        net_fd = _open_ns(req["pid"], "net", net_inode)
        try:
            _check_net_owner(net_fd, user_inode)
            if req["op"] == "apply":
                res = _nft(user_fd, net_fd, ["-f", "-"], req["policy"])
                if res.returncode != 0:
                    _fail(f"nft apply rc={res.returncode}: "
                          f"{res.stderr.strip()[-400:]}")
            res = _nft(user_fd, net_fd, ["-j", "list", "ruleset"], "")
            if res.returncode != 0:
                _fail(f"nft list rc={res.returncode}: "
                      f"{res.stderr.strip()[-400:]}")
            _emit({"ok": True, "ruleset": res.stdout})
        finally:
            os.close(net_fd)
    finally:
        os.close(user_fd)


if __name__ == "__main__":
    main()
