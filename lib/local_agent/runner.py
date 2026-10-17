"""Injectable subprocess runner: argv arrays, bounded timeouts, allowlisted env."""

from __future__ import annotations

import os
import signal
import subprocess

ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM",
    "TMPDIR", "XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CACHE_HOME",
)
REMOTE_ENGINE_VARS = (
    "PODMAN_HOST", "CONTAINER_HOST", "CONTAINER_SSHKEY", "DOCKER_HOST",
    "PODMAN_MACHINE", "PODMAN_VARLINK_BRIDGE",
)
DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 600
MAX_STDIN_BYTES = 64 * 1024


class RunnerError(Exception):
    pass


class RemoteEngineError(RunnerError):
    pass


class CommandResult:
    __slots__ = ("argv", "returncode", "stdout", "stderr", "timed_out")

    def __init__(self, argv, returncode, stdout, stderr, timed_out=False):
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


def base_env(extra=None, environ=None):
    environ = os.environ if environ is None else environ
    rejected = sorted(n for n in REMOTE_ENGINE_VARS if environ.get(n))
    if rejected:
        raise RemoteEngineError(
            f"remote container engine variables set: {', '.join(rejected)}"
        )
    env = {k: environ[k] for k in ENV_ALLOWLIST if k in environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    for key, value in (extra or {}).items():
        if key in REMOTE_ENGINE_VARS:
            raise RemoteEngineError(
                f"remote container engine variable not allowed: {key}"
            )
        if key not in ENV_ALLOWLIST or not isinstance(value, str):
            raise RunnerError(f"environment override not allowed: {key!r}")
        env[key] = value
    return env


def _as_text(value):
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return value.decode("utf-8", "replace")


class Runner:
    def run(self, argv, timeout=DEFAULT_TIMEOUT_SECONDS, extra_env=None,
            stdin_text=None, pass_fds=()):
        if (
            not isinstance(argv, (list, tuple))
            or not argv
            or not all(isinstance(a, str) and a for a in argv)
        ):
            raise RunnerError("argv must be a non-empty list of strings")
        if stdin_text is not None:
            if not isinstance(stdin_text, str):
                raise RunnerError("stdin_text must be a string")
            if len(stdin_text.encode("utf-8")) > MAX_STDIN_BYTES:
                raise RunnerError("stdin_text exceeds bound")
        if not isinstance(pass_fds, (list, tuple)) or not all(
            isinstance(fd, int) and not isinstance(fd, bool) and fd >= 0
            for fd in pass_fds
        ):
            raise RunnerError("pass_fds must be a list of ints")
        timeout = max(1, min(int(timeout), MAX_TIMEOUT_SECONDS))
        try:
            proc = subprocess.Popen(
                list(argv),
                env=base_env(extra_env),
                stdin=subprocess.DEVNULL if stdin_text is None
                    else subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                pass_fds=pass_fds,
            )
        except OSError as exc:
            raise RunnerError(f"cannot execute {argv[0]!r}: {exc}") from exc
        communicate_kwargs = {"timeout": timeout}
        if stdin_text is not None:
            communicate_kwargs["input"] = stdin_text
        try:
            stdout, stderr = proc.communicate(**communicate_kwargs)
        except subprocess.TimeoutExpired as exc:
            self._reap_group(proc)
            return CommandResult(
                list(argv), 124, _as_text(exc.stdout),
                _as_text(exc.stderr) + f"timed out after {timeout}s",
                timed_out=True,
            )
        except BaseException:
            self._reap_group(proc)
            raise
        return CommandResult(list(argv), proc.returncode, stdout, stderr)

    def _reap_group(self, proc):
        error = None
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            error = exc
        try:
            proc.wait(timeout=5)
        except Exception as exc:
            if error is None:
                error = exc
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except Exception as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise RunnerError(
                f"cannot terminate process group {proc.pid}: {error}"
            )

    def podman(self, args, timeout=DEFAULT_TIMEOUT_SECONDS, extra_env=None,
               stdin_text=None):
        if (
            not isinstance(args, (list, tuple))
            or not args
            or not all(isinstance(a, str) and a for a in args)
        ):
            raise RunnerError(
                "podman args must be a non-empty list of strings"
            )
        if args[0].startswith("-"):
            raise RemoteEngineError(
                "podman args must begin with a subcommand, "
                f"not a global option: {args[0]!r}"
            )
        kwargs = {}
        if stdin_text is not None:
            kwargs["stdin_text"] = stdin_text
        return self.run(
            ["podman", "--remote=false", *args],
            timeout=timeout,
            extra_env=extra_env,
            **kwargs,
        )
