"""Interactive chat: verify first, then exec the opencode TUI in harness."""

from __future__ import annotations

import os
from pathlib import Path

from . import verify as _verify
from .runner import base_env
from .runtime_record import RuntimeFault, load_runtime
from .state import _instance_dir


def chat_argv(harness_id):
    return [
        "podman", "--remote=false", "exec", "-it",
        "-w", "/workspace/repo",
        "-e", "PWD=/workspace/repo",
        harness_id,
        "opencode", "/workspace/repo",
    ]


def chat(root_dir, name, repo, runner, is_tty=None, exec_fn=None,
         verify_fn=None):
    """Run shared verification, refuse on failure, then exec the TUI.

    ``exec_fn`` defaults to ``os.execvpe`` so the interactive session
    inherits the operator's terminal; no output is captured and no
    credentials appear in argv or environment.
    """
    if verify_fn is None:
        verify_fn = _verify.verify
    result = verify_fn(root_dir, name, repo, runner)
    if not result.ok:
        from .runtime import stop as _rt_stop
        try:
            _rt_stop(root_dir, name, runner)
        except Exception:
            pass
        raise RuntimeFault(
            "verify failed; refusing chat (affected owned members "
            "stopped if verifiable)")
    inst = _instance_dir(Path(root_dir), name)
    record = load_runtime(inst, name)
    if record is None:
        raise RuntimeFault(f'instance "{name}": no runtime record')
    harness_id = record["objects"]["containers"]["harness"]
    if is_tty is None:
        is_tty = os.isatty(0) and os.isatty(1)
    if not is_tty:
        raise RuntimeFault("chat requires an interactive terminal (TTY)")
    argv = chat_argv(harness_id)
    env = base_env()
    if exec_fn is not None:
        return exec_fn(argv, env)
    os.execvpe(argv[0], argv, env)
    raise RuntimeFault("exec failed")
