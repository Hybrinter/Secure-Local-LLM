"""Unit tests for sanitized evidence projection."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_agent import evidence, state
from local_agent.artifacts import load_lock
from local_agent.verify_spec import Result
from verify_fixtures import verify_env

REPO = Path(__file__).resolve().parents[1]
DEMO_FILE = "demo-20260101T000000Z-deadbeef.json"
MISMATCH_ERROR = "artifacts lock fingerprint mismatch: pins withheld"


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


class EvidenceReport(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.tmp = Path(self.td.name)
        self.root = self.tmp / "state"
        self.name = "evidence-test"
        src = REPO / ".devin" / "artifacts.lock.json"
        if not src.exists():
            self.skipTest("artifacts lock absent")
        self.lock_bytes = src.read_bytes()
        self.lock_path = self.tmp / "artifacts.lock.json"
        self.lock_path.write_bytes(self.lock_bytes)
        self.lock_sha = hashlib.sha256(self.lock_bytes).hexdigest()
        state.init_instance(
            self.root, self.name, {"name": "cpu"},
            {"sha256": "a" * 64},
            {"path": str(self.lock_path), "sha256": self.lock_sha,
             "bytes": len(self.lock_bytes)},
            True)
        self.inst = self.root / "instances" / self.name

    def _verify(self, root_dir, name, repo, runner):
        r = Result()
        r.add("runtime controls", "pass")
        return r

    def _run(self):
        return evidence.evidence(
            self.root, self.name, self.tmp, None,
            verify_fn=self._verify)

    def _rewrite_lock(self, mutate):
        raw = json.loads(self.lock_bytes)
        mutate(raw)
        self.lock_path.write_bytes(
            json.dumps(raw, indent=2, sort_keys=True).encode() + b"\n")

    def test_matching_lock_projects_exact_pins(self):
        report, out_json, out_md = self._run()
        upstream = report["upstream"]
        self.assertEqual(
            upstream["artifacts_lock_sha256"], self.lock_sha)
        self.assertNotIn("error", upstream)
        lock, fp = load_lock(self.lock_path)
        self.assertEqual(fp["sha256"], self.lock_sha)
        self.assertEqual(upstream["base_image"], lock["base_image"])
        self.assertEqual(upstream["platform"], lock["platform"])
        self.assertEqual(
            upstream["artifacts"],
            {n: {"version": s["version"],
                 "algorithm": s["hash"]["algorithm"],
                 "digest": s["hash"]["hex"]}
             for n, s in lock["artifacts"].items()})
        for spec in upstream["artifacts"].values():
            self.assertEqual(set(spec), {"version", "algorithm",
                                         "digest"})
        self.assertEqual(report["status"], "pass")
        saved = json.loads(out_json.read_bytes())
        self.assertEqual(saved["upstream"], upstream)
        self.assertEqual(saved["schema"], evidence.EVIDENCE_SCHEMA)
        self.assertEqual(saved["instance"], self.name)

    def test_changed_lock_withholds_pins(self):
        mutations = (
            ("version", "9.9.9-tampered",
             lambda raw: raw["artifacts"]["model"].update(
                 {"version": "9.9.9-tampered"})),
            ("digest", "f" * 128,
             lambda raw: raw["artifacts"]["opencode"]["hash"].update(
                 {"hex": "f" * 128})),
        )
        for label, marker, mutate in mutations:
            with self.subTest(mutation=label):
                self._rewrite_lock(mutate)
                report, out_json, out_md = self._run()
                upstream = report["upstream"]
                self.assertEqual(upstream["artifacts_lock_sha256"],
                                 self.lock_sha)
                self.assertNotIn("base_image", upstream)
                self.assertNotIn("platform", upstream)
                self.assertNotIn("artifacts", upstream)
                self.assertEqual(upstream["error"], MISMATCH_ERROR)
                blob = (
                    json.dumps(report, sort_keys=True)
                    + out_json.read_text() + out_md.read_text())
                self.assertNotIn(marker, blob)
                self.assertNotIn("debian@sha256:", blob)
                self.assertNotIn(str(self.lock_path), blob)
                saved = json.loads(out_json.read_bytes())
                self.assertEqual(saved["upstream"], upstream)


class EvidenceDefaultVerifier(unittest.TestCase):
    def test_drifted_lock_fails_verifier_and_withholds_pins(self):
        with verify_env() as env:
            env.manifest["identity"]["name"] = env.name
            inst = env.root / "instances" / env.name
            for d in (env.root, env.root / "instances", inst):
                state._ensure_private_dir(d)
            lock_path = env.repo / ".devin" / "artifacts.lock.json"
            raw = json.loads(lock_path.read_bytes())
            raw["artifacts"]["model"]["version"] = "9.9.9-tampered"
            lock_path.write_bytes(
                json.dumps(raw, indent=2, sort_keys=True).encode()
                + b"\n")
            with mock.patch(
                    "local_agent.evidence.load_manifest",
                    return_value=env.manifest), mock.patch(
                    "local_agent.evidence.load_runtime",
                    return_value=env.record):
                report, out_json, _ = evidence.evidence(
                    env.root, env.name, env.repo, env.runner)
            upstream = report["upstream"]
            self.assertEqual(
                upstream["artifacts_lock_sha256"],
                env.manifest["artifacts_lock"]["sha256"])
            self.assertNotIn("base_image", upstream)
            self.assertNotIn("platform", upstream)
            self.assertNotIn("artifacts", upstream)
            self.assertEqual(upstream["error"], MISMATCH_ERROR)
            fp_check = [
                c for c in report["checks"]
                if c["name"] == "artifacts lock fingerprint"]
            self.assertEqual(
                [c["status"] for c in fp_check], ["fail"])
            self.assertEqual(report["status"], "fail")
            self.assertNotIn("9.9.9-tampered", out_json.read_text())
            saved = json.loads(out_json.read_bytes())
            self.assertEqual(saved["upstream"], upstream)


if __name__ == "__main__":
    unittest.main()
