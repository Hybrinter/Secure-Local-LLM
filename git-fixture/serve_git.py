#!/usr/bin/env python3
"""sshd ForceCommand: permit exactly git upload/receive-pack on one repo."""

import os
import shlex
import sys

REPO = "/repos/demo.git"
_SUBCOMMANDS = {
    "git-upload-pack": "upload-pack",
    "git-receive-pack": "receive-pack",
}
_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/srv/git",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}


def _fail(msg):
    print(f"local-agent git fixture: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    raw = os.environ.get("SSH_ORIGINAL_COMMAND") or ""
    try:
        args = shlex.split(raw)
    except ValueError:
        _fail("unparseable command")
    if len(args) != 2:
        _fail("expected exactly <git command> <repo>")
    exe, repo = args
    sub = _SUBCOMMANDS.get(exe)
    if sub is None:
        _fail(f"command not permitted: {exe!r}")
    if repo != REPO:
        _fail("repository not permitted")
    os.execve(
        "/usr/bin/git",
        [
            "git",
            "-c", "core.hooksPath=/opt/local-agent/hooks",
            "-c", "receive.maxInputSize=33554432",
            sub, REPO,
        ],
        _ENV,
    )


if __name__ == "__main__":
    main()
