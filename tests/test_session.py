"""Unit tests for chat session argv, TTY requirement, fail-closed entry."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import session  # noqa: E402
from local_agent.runtime_record import RuntimeFault  # noqa: E402
from local_agent.verify_spec import Result  # noqa: E402

UUID = "01234567-89ab-4cde-8f01-23456789abcd"
HARNESS = "b" * 64


class ChatArgv(unittest.TestCase):
    def test_argv_shape(self):
        argv = session.chat_argv(HARNESS)
        self.assertEqual(argv[:5], [
            "podman", "--remote=false", "exec", "-it", "-w"])
        self.assertIn("-w", argv)
        self.assertIn("/workspace/repo", argv)
        self.assertIn("-e", argv)
        self.assertIn("PWD=/workspace/repo", argv)
        self.assertEqual(argv[-2:], ["opencode", "/workspace/repo"])
        self.assertEqual(argv[-3], HARNESS)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("-t", argv[:-3])
        joined = " ".join(argv)
        self.assertNotIn("password", joined)
        self.assertNotIn("key", joined)


class ChatEntry(unittest.TestCase):
    def _record_root(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        inst = root / "instances" / "demo"
        inst.mkdir(parents=True)
        for d in (root, root / "instances", inst):
            os.chmod(d, 0o700)
        record = {
            "schema": "secure-local-llm/runtime@1",
            "instance": "demo",
            "instance_uuid": UUID,
            "created_utc": "2026-10-17T00:00:00+00:00",
            "subnet": "10.240.0.0/28",
            "pod_ip": "10.240.0.2",
            "git_ip": "10.240.0.3",
            "network": {"id": "c" * 64, "name": "sll-01234567-net"},
            "tables": {"workload": "sllm_0123456789ab00",
                       "git": "sllm_0123456789ab01"},
            "policy": {
                "workload": {
                    "schema": "secure-local-llm/netpol@1",
                    "table": "sllm_0123456789ab00", "role": "workload",
                    "peer_ip": "10.240.0.3", "peer_port": 2222,
                    "canonical_sha256": "d" * 64},
                "git": {
                    "schema": "secure-local-llm/netpol@1",
                    "table": "sllm_0123456789ab01", "role": "git",
                    "peer_ip": "10.240.0.2", "peer_port": 2222,
                    "canonical_sha256": "e" * 64},
            },
            "objects": {
                "pod": "f" * 64, "infra": "0" * 64,
                "containers": {"inference": "1" * 64,
                               "harness": HARNESS, "git": "2" * 64},
                "volumes": {"workspace": "sll-01234567-ws",
                            "state": "sll-01234567-state",
                            "model": "sll-01234567-model",
                            "repo": "sll-01234567-repo"},
            },
            "images": {"harness": "3" * 64, "inference": "4" * 64,
                       "git": "5" * 64},
            "fingerprints": {"profile": "6" * 64,
                             "artifacts_lock": "7" * 64,
                             "source_config": "8" * 64},
            "control_sha256": {
                k: "9" * 64 for k in (
                    "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub",
                    "client_key", "client_key.pub", "authorized_keys",
                    "model-api-key", "service.json", "gitconfig",
                    "ssh_config", "known_hosts", "opencode.json")},
            "seed_sha256": "a" * 64,
            "seed_main": "b" * 40,
        }
        (inst / "runtime.json").write_text(json.dumps(record))
        os.chmod(inst / "runtime.json", 0o600)
        self.addCleanup(td.cleanup)
        return root

    def test_verify_failure_refuses_and_stops(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        bad = Result()
        bad.add("x", "fail")
        with self.assertRaises(RuntimeFault) as ctx:
            session.chat(root, "demo", "/repo", None,
                         verify_fn=lambda *a: bad)
        self.assertIn("refusing", str(ctx.exception))

    def test_non_tty_refused(self):
        root = self._record_root()
        ok = Result()
        ok.add("x", "pass")
        with self.assertRaises(RuntimeFault) as ctx:
            session.chat(root, "demo", "/repo", None, is_tty=False,
                         verify_fn=lambda *a: ok)
        self.assertIn("TTY", str(ctx.exception))

    def test_exec_argv_and_env(self):
        root = self._record_root()
        ok = Result()
        ok.add("x", "pass")
        captured = {}
        session.chat(
            root, "demo", "/repo", None, is_tty=True,
            exec_fn=lambda argv, env: captured.update(
                argv=argv, env=env),
            verify_fn=lambda *a: ok)
        self.assertEqual(captured["argv"], session.chat_argv(HARNESS))
        self.assertNotIn("PODMAN_HOST", captured["env"])
        self.assertNotIn("CONTAINER_HOST", captured["env"])
        self.assertIn("PATH", captured["env"])


class ChatCleanup(unittest.TestCase):
    """Failed verification must preserve cleanup-stop diagnostics."""

    def _failed_verify(self, *args):
        bad = Result()
        bad.add("containment", "fail")
        return bad

    def _chat_refused(self, stop_mock):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        runner = object()
        exec_calls = []
        with mock.patch.object(session, "_rt_stop", stop_mock), \
                mock.patch.object(session, "load_runtime") as load_mock:
            with self.assertRaises(RuntimeFault) as ctx:
                session.chat(
                    root, "demo", "/repo", runner, is_tty=True,
                    exec_fn=lambda argv, env: exec_calls.append(argv),
                    verify_fn=self._failed_verify)
        load_mock.assert_not_called()
        self.assertEqual(exec_calls, [])
        stop_mock.assert_called_once_with(root, "demo", runner)
        return ctx.exception

    def test_stop_success_reports_completed_not_verified(self):
        exc = self._chat_refused(
            mock.Mock(return_value={"stopped": ["git", "inference",
                                                "pod"]}))
        msg = str(exc)
        self.assertIn("verify failed", msg)
        self.assertIn("refusing chat", msg)
        self.assertIn("stop", msg)
        self.assertIn("not independently verified", msg)

    def test_stop_nonzero_diagnostic_preserved(self):
        diag = RuntimeFault(
            "stop failures: ['inference rc=1'] "
            "(stopped: ['git', 'pod'])")
        exc = self._chat_refused(mock.Mock(side_effect=diag))
        msg = str(exc)
        self.assertIn("verify failed", msg)
        self.assertIn("refusing chat", msg)
        self.assertIn("cleanup", msg)
        self.assertIn("inference rc=1", msg)
        self.assertIs(exc.__cause__, diag)

    def test_stop_timeout_diagnostic_preserved(self):
        diag = RuntimeFault("podman timed out after 30s")
        exc = self._chat_refused(mock.Mock(side_effect=diag))
        msg = str(exc)
        self.assertIn("refusing chat", msg)
        self.assertIn("timed out", msg)
        self.assertIs(exc.__cause__, diag)

    def test_stop_ownership_refusal_preserved(self):
        diag = RuntimeFault(
            "recorded pod labels drifted; refusing stop")
        exc = self._chat_refused(mock.Mock(side_effect=diag))
        msg = str(exc)
        self.assertIn("refusing chat", msg)
        self.assertIn("refusing stop", msg)
        self.assertIs(exc.__cause__, diag)

    def test_stop_unexpected_exception_preserved(self):
        diag = ValueError("corrupt inspect payload")
        exc = self._chat_refused(mock.Mock(side_effect=diag))
        msg = str(exc)
        self.assertIn("refusing chat", msg)
        self.assertIn("ValueError", msg)
        self.assertIn("corrupt inspect payload", msg)
        self.assertIs(exc.__cause__, diag)


if __name__ == "__main__":
    unittest.main()
