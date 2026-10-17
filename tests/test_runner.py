import sys
import tempfile
import unittest
from pathlib import Path

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
