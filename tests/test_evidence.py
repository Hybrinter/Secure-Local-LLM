"""Unit tests for sanitized evidence projection."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import evidence
from local_agent.verify_spec import Result

REPO = Path(__file__).resolve().parents[1]
DEMO_FILE = "demo-20260101T000000Z-deadbeef.json"


class WorkflowProjection(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.inst = Path(self.td.name)
        self.addCleanup(self.td.cleanup)

    def _write(self, name, payload, mode=0o600):
        p = self.inst / name
        p.write_bytes(
            payload if isinstance(payload, bytes)
            else json.dumps(payload).encode())
        os.chmod(p, mode)
        return p

    def _demo(self, **over):
        d = {
            "schema": "secure-local-llm/demo@1",
            "instance": "demo",
            "status": "pass",
            "exceptions": ["lsm confinement"],
            "checks": ["runtime_and_tool_protocol",
                       "repository_tests", "bogus_phase"],
            "protocol": {"status": "pass", "reused": True,
                         "response_sha256": "a" * 64,
                         "prompt": "SECRET-PROMPT",
                         "raw_log": "/home/x/private"},
            "agent_trace": "secret",
            "branch": "agent/demo-1a2b3c4d",
            "seed_commit": "b" * 40,
            "result_commit": "c" * 40,
            "remote_commit": "d" * 40,
        }
        d.update(over)
        return d

    def test_absent(self):
        self.assertIsNone(evidence._workflow_projection(self.inst))

    def test_allowlisted_projection(self):
        self._write(DEMO_FILE, self._demo())
        out = evidence._workflow_projection(self.inst)
        self.assertEqual(out["status"], "pass")
        self.assertEqual(out["exceptions"], ["lsm confinement"])
        self.assertEqual(
            out["checks"],
            [{"name": "runtime_and_tool_protocol", "status": "pass"},
             {"name": "repository_tests", "status": "pass"}])
        self.assertEqual(
            out["protocol"],
            {"status": "pass", "reused": True,
             "response_sha256": "a" * 64})
        self.assertEqual(out["branch"], "agent/demo-1a2b3c4d")
        self.assertEqual(out["seed_commit"], "b" * 40)
        blob = json.dumps(out)
        self.assertNotIn("SECRET-PROMPT", blob)
        self.assertNotIn("secret", blob)
        self.assertNotIn("/home/x/private", blob)
        self.assertNotIn("bogus_phase", blob)

    def test_preflight_and_other_files_ignored(self):
        self._write("demo-preflight.json", {"ready": True})
        self._write("demo-20261201T000000Z-notjson.json",
                    {"schema": "secure-local-llm/demo@1"})
        self._write(DEMO_FILE, self._demo(status="fail"))
        out = evidence._workflow_projection(self.inst)
        self.assertEqual(out["file"], DEMO_FILE)
        self.assertEqual(out["status"], "fail")

    def test_symlink_unreadable(self):
        target = self._write(DEMO_FILE, self._demo())
        link = self.inst / "demo-20261018T000000Z-badbad00.json"
        link.symlink_to(target)
        out = evidence._workflow_projection(self.inst)
        self.assertEqual(out["file"], link.name)
        self.assertFalse(out["readable"])

    def test_wrong_mode_unreadable(self):
        self._write(DEMO_FILE, self._demo(), mode=0o644)
        out = evidence._workflow_projection(self.inst)
        self.assertFalse(out["readable"])

    def test_oversize_unreadable(self):
        self._write(DEMO_FILE, b"x" * (70 * 1024))
        out = evidence._workflow_projection(self.inst)
        self.assertFalse(out["readable"])

    def test_bad_status_and_instance_rejected(self):
        for over in ({"status": "great"},
                     {"instance": "Bad Name"},
                     {"instance": {"nested": "demo"}},
                     {"status": {"nested": "pass"}},
                     {"exceptions": [{"nested": 1}]},
                     {"exceptions": ["lsm confinement", "made up"]}):
            self._write(DEMO_FILE, self._demo(**over))
            out = evidence._workflow_projection(self.inst)
            self.assertFalse(out["readable"], over)
            os.unlink(self.inst / DEMO_FILE)

    def test_fifo_unreadable(self):
        fifo = self.inst / DEMO_FILE
        os.mkfifo(fifo)
        out = evidence._workflow_projection(self.inst)
        self.assertFalse(out["readable"])

    def test_protocol_field_types(self):
        self._write(DEMO_FILE, self._demo(
            protocol={"status": "pass", "reused": "yes",
                      "response_sha256": "nothex",
                      "secret": {"nested": "value"}}))
        out = evidence._workflow_projection(self.inst)
        self.assertEqual(out["protocol"], {"status": "pass"})
        self.assertNotIn("secret", out["protocol"])

    def test_bad_branch_and_commit_dropped(self):
        self._write(DEMO_FILE, self._demo(
            branch="../escape", result_commit="z" * 40))
        out = evidence._workflow_projection(self.inst)
        self.assertNotIn("branch", out)
        self.assertNotIn("result_commit", out)
        self.assertEqual(out["seed_commit"], "b" * 40)


class UpstreamProjection(unittest.TestCase):
    def test_exact_pin_shape(self):
        manifest_lock = Path(REPO / ".devin" / "artifacts.lock.json")
        if not manifest_lock.exists():
            self.skipTest("lock absent")
        from local_agent.artifacts import load_lock
        lock, _ = load_lock(manifest_lock)
        upstream = {
            "base_image": lock["base_image"],
            "platform": lock["platform"],
            "artifacts": {
                n: {"version": s["version"],
                    "algorithm": s["hash"]["algorithm"],
                    "digest": s["hash"]["hex"]}
                for n, s in lock["artifacts"].items()},
        }
        self.assertEqual(upstream["platform"], "linux/amd64")
        self.assertIn("@sha256:", upstream["base_image"])
        self.assertEqual(
            upstream["artifacts"]["opencode"]["algorithm"], "sha512")
        self.assertEqual(
            len(upstream["artifacts"]["opencode"]["digest"]), 128)
        for n, s in upstream["artifacts"].items():
            self.assertEqual(set(s), {"version", "algorithm", "digest"})
            self.assertNotIn("url", s)


class StatusMapping(unittest.TestCase):
    def test_fail(self):
        r = Result()
        r.add("a", "fail")
        self.assertEqual(evidence._status(r), "fail")

    def test_pass_with_exceptions(self):
        r = Result()
        r.add("a", "pass")
        r.add("b", "degraded")
        self.assertEqual(evidence._status(r), "pass-with-exceptions")

    def test_pass_clean(self):
        r = Result()
        r.add("a", "pass")
        self.assertEqual(evidence._status(r), "pass")


if __name__ == "__main__":
    unittest.main()
