"""Interactive chat: verify first, then exec the opencode TUI in harness."""

from __future__ import annotations

import os
from pathlib import Path

from . import verify as _verify
from .runner import base_env
from .runtime import stop as _rt_stop
from .runtime_record import RuntimeFault, load_runtime
from .state import _instance_dir

TUI_TMPDIR = "/state/.cache/opencode-tui"

_SETUP_PY = (
    "import os,stat,sys\n"
    "base,uid=sys.argv[1],os.geteuid()\n"
    "def ent(pfd,name,strict):\n"
    " try: st=os.stat(name,dir_fd=pfd,follow_symlinks=False)\n"
    " except FileNotFoundError:\n"
    "  os.mkdir(name,0o700,dir_fd=pfd)\n"
    "  st=os.stat(name,dir_fd=pfd,follow_symlinks=False)\n"
    " if not stat.S_ISDIR(st.st_mode):sys.exit('not dir: '+name)\n"
    " if st.st_uid!=uid:sys.exit('owner mismatch: '+name)\n"
    " if strict and stat.S_IMODE(st.st_mode)!=0o700:\n"
    "  sys.exit('mode mismatch: '+name)\n"
    "fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n"
    "try:\n"
    " ent(fd,'.cache',False)\n"
    " fd2=os.open('.cache',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,"
    "dir_fd=fd)\n"
    " try:\n"
    "  ent(fd2,'opencode-tui',True)\n"
    " finally:\n"
    "  os.close(fd2)\n"
    "finally:\n"
    " os.close(fd)\n"
)


def _setup_tui_tmpdir(runner, harness_id):
    res = runner.podman(
        ["exec", harness_id, "python3", "-I", "-B", "-c",
         _SETUP_PY, "/state"],
        timeout=30)
    if res.returncode != 0:
        raise RuntimeFault(
            f"TUI scratch dir setup failed: {res.stderr.strip()[:200]}")


def chat_argv(harness_id):
    return [
        "podman", "--remote=false", "exec", "-it",
        "-w", "/workspace/repo",
        "-e", "PWD=/workspace/repo",
        "-e", f"TMPDIR={TUI_TMPDIR}",
        harness_id,
        "opencode", "/workspace/repo",
    ]


def chat(root_dir, name, repo, runner, is_tty=None, exec_fn=None,
         verify_fn=None, setup_fn=None):
    """Run shared verification, refuse on failure, then exec the TUI.

    ``exec_fn`` defaults to ``os.execvpe`` so the interactive session
    inherits the operator's terminal; no output is captured and no
    credentials appear in argv or environment.
    """
    if verify_fn is None:
        verify_fn = _verify.verify
    result = verify_fn(root_dir, name, repo, runner)
    if not result.ok:
        try:
            _rt_stop(root_dir, name, runner)
        except Exception as exc:
            raise RuntimeFault(
                "verify failed; refusing chat; cleanup stop failed "
                f"({type(exc).__name__}: {exc})") from exc
        raise RuntimeFault(
            "verify failed; refusing chat; owned-member stop "
            "completed (termination not independently verified)")
    inst = _instance_dir(Path(root_dir), name)
    record = load_runtime(inst, name)
    if record is None:
        raise RuntimeFault(f'instance "{name}": no runtime record')
    harness_id = record["objects"]["containers"]["harness"]
    if is_tty is None:
        is_tty = os.isatty(0) and os.isatty(1)
    if not is_tty:
        raise RuntimeFault("chat requires an interactive terminal (TTY)")
    if setup_fn is None:
        setup_fn = _setup_tui_tmpdir
    setup_fn(runner, harness_id)
    argv = chat_argv(harness_id)
    env = base_env()
    if exec_fn is not None:
        return exec_fn(argv, env)
    os.execvpe(argv[0], argv, env)
    raise RuntimeFault("exec failed")
