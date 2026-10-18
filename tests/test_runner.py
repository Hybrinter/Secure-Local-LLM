import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import runner


class FakeRunner(runner.Runner):
    def __init__(self, result):
        self.calls = []
        self.result = result

    def run(self, argv, timeout=runner.DEFAULT_TIMEOUT_SECONDS, extra_env=None):
        self.calls.append(list(argv))
        return self.result


class ArgvContract(unittest.TestCase):
    def test_podman_forces_remote_false(self):
        fake = FakeRunner(runner.CommandResult(["x"], 0, "{}", ""))
        fake.podman(["info", "--format", "json"])
        self.assertEqual(fake.calls[0][:2], ["podman", "--remote=false"])

    def test_argv_rejects_non_list(self):
        r = runner.Runner()
        for bad in ("echo hi", b"echo", None, 7, {"a": 1}):
            with self.assertRaises(runner.RunnerError, msg=repr(bad)):
                r.run(bad)
        for bad in ([], ["ok", ""], ["ok", 3], [b"byte"]):
            with self.assertRaises(runner.RunnerError, msg=repr(bad)):
                r.run(bad)

    def test_argv_tuple_accepted(self):
        fake = FakeRunner(runner.CommandResult(["x"], 0, "", ""))
        fake.run(("true",))
        self.assertEqual(fake.calls[0], ["true"])

    def test_timeout_bounded(self):
        res = runner.Runner().run(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertTrue(res.timed_out)
        self.assertEqual(res.returncode, 124)

    def test_stdin_text_bounded(self):
        r = runner.Runner()
        res = r.run(["cat"], stdin_text="payload")
        self.assertEqual(res.stdout, "payload")
        for bad in ("x" * (runner.MAX_STDIN_BYTES + 1), 5, b"bin"):
            with self.assertRaises(runner.RunnerError, msg=repr(bad)[:40]):
                r.run(["cat"], stdin_text=bad)

    def test_pass_fds_validated(self):
        r = runner.Runner()
        for bad in ((-1,), ("x",), (True,), (False,), "fd", 5, None):
            with self.assertRaises(runner.RunnerError, msg=repr(bad)[:40]):
                r.run(["true"], pass_fds=bad)
        read_fd, write_fd = os.pipe()
        try:
            res = r.run(
                [sys.executable, "-c",
                 "import os,sys;"
                 "fds=[int(f) for f in os.listdir('/proc/self/fd')];"
                 "sys.exit(0 if max(fds)>3 else 1)"],
                pass_fds=(read_fd,))
            self.assertEqual(res.returncode, 0)
        finally:
            os.close(read_fd)
            os.close(write_fd)


class PodmanArgsContract(unittest.TestCase):
    def fake(self):
        return FakeRunner(runner.CommandResult(["x"], 0, "", ""))

    def test_podman_rejects_malformed_args(self):
        for bad in ("info", b"info", None, 7, {"a": 1}, [],
                    ["info", ""], ["", "info"], ["info", 3], [b"info"]):
            fake = self.fake()
            with self.assertRaises(runner.RunnerError, msg=repr(bad)) as cm:
                fake.podman(bad)
            self.assertNotIsInstance(cm.exception, runner.RemoteEngineError)
            self.assertEqual(fake.calls, [], repr(bad))

    def test_podman_rejects_leading_global_options(self):
        cases = [
            ["--url", "ssh://host/socket", "info"],
            ["--url=ssh://host/socket", "info"],
            ["--connection", "remote", "info"],
            ["--connection=remote", "info"],
            ["-c", "remote", "info"],
            ["-cremote", "info"],
            ["--host", "ssh://host", "info"],
            ["-H", "ssh://host", "info"],
            ["-Hssh://host", "info"],
            ["--context", "remote", "info"],
            ["--context=remote", "info"],
            ["--remote", "info"],
            ["--remote=true", "info"],
            ["-r", "info"],
            ["-r=true", "info"],
            ["-rv", "info"],
            ["-rvc", "remote", "info"],
            ["--", "info"],
            ["--identity", "/keys/id", "info"],
            ["--ssh", "native", "info"],
            ["--log-level", "debug", "info"],
            ["-l", "debug", "info"],
        ]
        for args in cases:
            fake = self.fake()
            with self.assertRaises(runner.RemoteEngineError, msg=repr(args)):
                fake.podman(args)
            self.assertEqual(fake.calls, [], repr(args))

    def test_podman_accepts_list_and_tuple(self):
        fake = self.fake()
        fake.podman(["info"])
        fake.podman(("ps", "-a"))
        self.assertEqual(fake.calls, [
            ["podman", "--remote=false", "info"],
            ["podman", "--remote=false", "ps", "-a"],
        ])

    def test_podman_preserves_command_args(self):
        fake = self.fake()
        fake.podman(["info", "--format", "json"])
        fake.podman(["exec", "ctr", "python3", "-c", "print(1)"])
        fake.podman(["run", "img", "sh", "-c", "echo --url --remote"])
        fake.podman(["exec", "ctr", "tool", "--url=ssh://h", "--remote"])
        fake.podman(["build", "--ssh", "default", "-t", "img", "."])
        self.assertEqual(fake.calls, [
            ["podman", "--remote=false", "info", "--format", "json"],
            ["podman", "--remote=false", "exec", "ctr", "python3", "-c",
             "print(1)"],
            ["podman", "--remote=false", "run", "img", "sh", "-c",
             "echo --url --remote"],
            ["podman", "--remote=false", "exec", "ctr", "tool",
             "--url=ssh://h", "--remote"],
            ["podman", "--remote=false", "build", "--ssh", "default", "-t",
             "img", "."],
        ])


class RunLifecycleContract(unittest.TestCase):
    def _live(self, pid):
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                return f.read().rsplit(b")", 1)[-1].split()[0] != b"Z"
        except OSError:
            return False

    def _wait_dead(self, pid):
        for _ in range(50):
            if not self._live(pid):
                return True
            time.sleep(0.1)
        return not self._live(pid)

    def _kill_tracked(self, pids):
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    def _ledger(self, path):
        try:
            return [int(p) for p in path.read_text().split()]
        except (OSError, ValueError):
            return []

    def _cleanup_ledger(self, path):
        pids = self._ledger(path)
        if not pids:
            return
        if len(pids) == 3 and pids[0] == pids[1] \
                and pids[1] != os.getpgrp():
            try:
                os.killpg(pids[1], signal.SIGKILL)
            except OSError:
                pass
        self._kill_tracked((pids[0], pids[-1]))

    def _proc(self, communicate=None, wait=None):
        proc = mock.MagicMock()
        proc.pid = 4321
        if communicate is None:
            proc.communicate.return_value = ("", "")
        else:
            proc.communicate.side_effect = communicate
        if wait is None:
            proc.wait.return_value = -9
        else:
            proc.wait.side_effect = wait
        return proc

    def test_timeout_kills_spawned_group(self):
        script = (
            "import os,signal,subprocess,sys,time\n"
            "c=subprocess.Popen([sys.executable,'-c',"
            "\"import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "print('child-ready',flush=True);"
            "time.sleep(30)\"])\n"
            "with open(sys.argv[1],'w') as f:\n"
            " f.write('%d %d %d' % (os.getpid(),os.getpgrp(),c.pid))\n"
            "print('ready-out', flush=True)\n"
            "print('ready-err', file=sys.stderr, flush=True)\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "pids"
            try:
                start = time.monotonic()
                res = runner.Runner().run(
                    [sys.executable, "-c", script, str(ledger)], timeout=1)
                self.assertLess(time.monotonic() - start, 15)
                self.assertTrue(res.timed_out)
                self.assertEqual(res.returncode, 124)
                self.assertIn("ready-out", res.stdout)
                self.assertIn("child-ready", res.stdout)
                self.assertIn("ready-err", res.stderr)
                self.assertIn("timed out after 1s", res.stderr)
                pids = self._ledger(ledger)
                self.assertEqual(len(pids), 3)
                leader, group, child = pids
                self.assertEqual(group, leader)
                self.assertNotEqual(group, os.getpgrp())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(leader, os.WNOHANG)
                self.assertTrue(self._wait_dead(child))
            finally:
                self._cleanup_ledger(ledger)

    def test_timeout_kills_group_after_leader_exit(self):
        script = (
            "import os,subprocess,sys\n"
            "c=subprocess.Popen([sys.executable,'-c',"
            "\"import time;time.sleep(30)\"])\n"
            "with open(sys.argv[1],'w') as f:\n"
            " f.write('%d %d %d' % (os.getpid(),os.getpgrp(),c.pid))\n"
            "print('leader-out', flush=True)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "pids"
            try:
                start = time.monotonic()
                res = runner.Runner().run(
                    [sys.executable, "-c", script, str(ledger)], timeout=1)
                self.assertLess(time.monotonic() - start, 15)
                self.assertTrue(res.timed_out)
                self.assertEqual(res.returncode, 124)
                self.assertIn("leader-out", res.stdout)
                pids = self._ledger(ledger)
                self.assertEqual(len(pids), 3)
                leader, group, child = pids
                self.assertEqual(group, leader)
                self.assertNotEqual(group, os.getpgrp())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(leader, os.WNOHANG)
                self.assertTrue(self._wait_dead(child))
            finally:
                self._cleanup_ledger(ledger)

    def test_timeout_preserves_stdin_and_fd_payloads(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"fd-payload")
        finally:
            os.close(write_fd)
        script = (
            "import os,subprocess,sys,time\n"
            "stdin_data=sys.stdin.read()\n"
            f"fd_data=os.read({read_fd},1024).decode()\n"
            "print('stdin-marker '+stdin_data, flush=True)\n"
            "print('fd-marker '+fd_data, flush=True)\n"
            "c=subprocess.Popen([sys.executable,'-c',"
            "\"import time;time.sleep(30)\"])\n"
            "with open(sys.argv[1],'w') as f:\n"
            " f.write('%d %d %d' % (os.getpid(),os.getpgrp(),c.pid))\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "pids"
            try:
                start = time.monotonic()
                res = runner.Runner().run(
                    [sys.executable, "-c", script, str(ledger)],
                    timeout=1, stdin_text="stdin-payload",
                    pass_fds=(read_fd,))
                self.assertLess(time.monotonic() - start, 15)
                self.assertTrue(res.timed_out)
                self.assertEqual(res.returncode, 124)
                self.assertIn("stdin-marker stdin-payload", res.stdout)
                self.assertIn("fd-marker fd-payload", res.stdout)
                pids = self._ledger(ledger)
                self.assertEqual(len(pids), 3)
                leader, group, child = pids
                self.assertEqual(group, leader)
                self.assertNotEqual(group, os.getpgrp())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(leader, os.WNOHANG)
                self.assertTrue(self._wait_dead(child))
            finally:
                self._cleanup_ledger(ledger)
                os.close(read_fd)

    def test_timeout_tolerates_vanished_group(self):
        proc = self._proc(communicate=subprocess.TimeoutExpired(
            ["x"], 3, output=b"out", stderr=b"err"))
        with mock.patch.object(runner.subprocess, "Popen",
                               return_value=proc), \
                mock.patch.object(runner.os, "killpg",
                                  side_effect=ProcessLookupError) as killpg:
            res = runner.Runner().run(["sleep", "30"], timeout=3)
        killpg.assert_called_once_with(4321, signal.SIGKILL)
        proc.wait.assert_called_once_with(timeout=5)
        self.assertTrue(res.timed_out)
        self.assertEqual(res.returncode, 124)
        self.assertEqual(res.stdout, "out")
        self.assertEqual(res.stderr, "errtimed out after 3s")

    def test_timeout_reports_kill_failure(self):
        proc = self._proc(
            communicate=subprocess.TimeoutExpired(["x"], 1))
        with mock.patch.object(runner.subprocess, "Popen",
                               return_value=proc), \
                mock.patch.object(runner.os, "killpg",
                                  side_effect=OSError("denied")):
            with self.assertRaises(runner.RunnerError):
                runner.Runner().run(["sleep", "30"], timeout=1)
        proc.wait.assert_called_once_with(timeout=5)
        proc.stdout.close.assert_called_once_with()
        proc.stderr.close.assert_called_once_with()

    def test_timeout_reports_reap_failure(self):
        proc = self._proc(
            communicate=subprocess.TimeoutExpired(["x"], 1),
            wait=subprocess.TimeoutExpired(["x"], 5))
        with mock.patch.object(runner.subprocess, "Popen",
                               return_value=proc), \
                mock.patch.object(runner.os, "killpg") as killpg:
            with self.assertRaises(runner.RunnerError):
                runner.Runner().run(["sleep", "30"], timeout=1)
        killpg.assert_called_once_with(4321, signal.SIGKILL)
        proc.communicate.assert_called_once_with(timeout=1)
        proc.wait.assert_called_once_with(timeout=5)

    def test_communicate_error_cleans_group(self):
        proc = self._proc(communicate=ValueError("boom"))
        with mock.patch.object(runner.subprocess, "Popen",
                               return_value=proc), \
                mock.patch.object(runner.os, "killpg") as killpg:
            with self.assertRaises(ValueError):
                runner.Runner().run(["x"])
        killpg.assert_called_once_with(4321, signal.SIGKILL)
        proc.wait.assert_called_once_with(timeout=5)

    def test_popen_invocation_contract(self):
        proc = self._proc()
        proc.communicate.return_value = ("out", "err")
        proc.returncode = 3
        with mock.patch.object(runner.subprocess, "Popen",
                               return_value=proc) as popen:
            res = runner.Runner().run(["cmd", "-x"], timeout=7)
        popen.assert_called_once()
        args, kw = popen.call_args
        self.assertEqual(args[0], ["cmd", "-x"])
        self.assertTrue(kw["start_new_session"])
        self.assertIs(kw["stdin"], runner.subprocess.DEVNULL)
        self.assertIs(kw["stdout"], runner.subprocess.PIPE)
        self.assertIs(kw["stderr"], runner.subprocess.PIPE)
        self.assertTrue(kw["text"])
        self.assertEqual(kw["pass_fds"], ())
        self.assertIn("PATH", kw["env"])
        proc.communicate.assert_called_once_with(timeout=7)
        self.assertEqual(res.argv, ["cmd", "-x"])
        self.assertEqual(res.returncode, 3)
        self.assertEqual(res.stdout, "out")
        self.assertEqual(res.stderr, "err")
        self.assertFalse(res.timed_out)

    def test_run_real_tuple_and_devnull_stdin(self):
        res = runner.Runner().run((
            sys.executable, "-c",
            "import sys; print('out'); print('err', file=sys.stderr); "
            "print('eof' if sys.stdin.read() == '' else 'data')"))
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.argv[0], sys.executable)
        self.assertIn("out", res.stdout)
        self.assertIn("eof", res.stdout)
        self.assertIn("err", res.stderr)
        self.assertFalse(res.timed_out)

    def test_run_nonzero_exit(self):
        res = runner.Runner().run(
            [sys.executable, "-c", "import sys; sys.exit(3)"])
        self.assertEqual(res.returncode, 3)
        self.assertFalse(res.timed_out)

    def test_run_missing_executable(self):
        with self.assertRaises(runner.RunnerError):
            runner.Runner().run(["local-agent-nonexistent-binary"])


class EnvContract(unittest.TestCase):
    def test_allowlist_strips_secrets(self):
        cleaned = runner.base_env(
            environ={"PATH": "/usr/bin", "AWS_SECRET_ACCESS_KEY": "s",
                     "GH_TOKEN": "t"})
        self.assertEqual(cleaned["PATH"], "/usr/bin")
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", cleaned)
        self.assertNotIn("GH_TOKEN", cleaned)

    def test_remote_env_rejected(self):
        for var in runner.REMOTE_ENGINE_VARS:
            with self.assertRaises(runner.RemoteEngineError, msg=var):
                runner.base_env(environ={var: "ssh://other"})

    def test_extra_env_restrictions(self):
        env = {"PATH": "/usr/bin"}
        ok = runner.base_env(extra={"HOME": "/tmp/h"}, environ=env)
        self.assertEqual(ok["HOME"], "/tmp/h")
        with self.assertRaises(runner.RemoteEngineError):
            runner.base_env(extra={"CONTAINER_HOST": ""}, environ=env)
        with self.assertRaises(runner.RunnerError):
            runner.base_env(extra={"AWS_SECRET": "x"}, environ=env)
        with self.assertRaises(runner.RunnerError):
            runner.base_env(extra={"HOME": 5}, environ=env)


if __name__ == "__main__":
    unittest.main()
