"""Unit tests for sanitized evidence projection."""

import hashlib
import json
import os
import select
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_agent import artifacts, evidence, state
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
        self.assertIsNone(evidence._workflow_projection(self.inst, "demo"))

    def test_allowlisted_projection(self):
        self._write(DEMO_FILE, self._demo())
        out = evidence._workflow_projection(self.inst, "demo")
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
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertEqual(out["file"], DEMO_FILE)
        self.assertEqual(out["status"], "fail")

    def test_symlink_unreadable(self):
        target = self._write(DEMO_FILE, self._demo())
        link = self.inst / "demo-20261018T000000Z-badbad00.json"
        link.symlink_to(target)
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertEqual(out["file"], link.name)
        self.assertFalse(out["readable"])

    def test_wrong_mode_unreadable(self):
        self._write(DEMO_FILE, self._demo(), mode=0o644)
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertFalse(out["readable"])

    def test_oversize_unreadable(self):
        self._write(DEMO_FILE, b"x" * (70 * 1024))
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertFalse(out["readable"])

    def test_bad_status_and_instance_rejected(self):
        for over in ({"status": "great"},
                     {"instance": "Bad Name"},
                     {"instance": {"nested": "demo"}},
                     {"status": {"nested": "pass"}},
                     {"exceptions": [{"nested": 1}]},
                     {"exceptions": ["lsm confinement", "made up"]}):
            self._write(DEMO_FILE, self._demo(**over))
            out = evidence._workflow_projection(self.inst, "demo")
            self.assertFalse(out["readable"], over)
            os.unlink(self.inst / DEMO_FILE)

    def test_fifo_unreadable(self):
        fifo = self.inst / DEMO_FILE
        os.mkfifo(fifo)
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertFalse(out["readable"])

    def test_protocol_field_types(self):
        self._write(DEMO_FILE, self._demo(
            protocol={"status": "pass", "reused": "yes",
                      "response_sha256": "nothex",
                      "secret": {"nested": "value"}}))
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertEqual(out["protocol"], {"status": "pass"})
        self.assertNotIn("secret", out["protocol"])

    def test_bad_branch_and_commit_dropped(self):
        self._write(DEMO_FILE, self._demo(
            branch="../escape", result_commit="z" * 40))
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertNotIn("branch", out)
        self.assertNotIn("result_commit", out)
        self.assertEqual(out["seed_commit"], "b" * 40)

    def test_foreign_instance_record_unreadable(self):
        self._write(DEMO_FILE, self._demo(instance="other-inst"))
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertEqual(out, {"file": DEMO_FILE, "readable": False})

    def test_missing_instance_name_rejected(self):
        payload = self._demo()
        del payload["instance"]
        self._write(DEMO_FILE, payload)
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertEqual(out, {"file": DEMO_FILE, "readable": False})

    def test_newest_foreign_record_not_overridden_by_older(self):
        self._write(DEMO_FILE, self._demo(instance="demo",
                                         status="pass"))
        newer = "demo-20260202T000000Z-aaaa1111.json"
        self._write(newer, self._demo(instance="other-inst",
                                      status="fail"))
        out = evidence._workflow_projection(self.inst, "demo")
        self.assertEqual(out, {"file": newer, "readable": False})


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

    def test_foreign_workflow_record_not_attributed(self):
        record = self.inst / DEMO_FILE
        record.write_bytes(json.dumps({
            "schema": "secure-local-llm/demo@1",
            "instance": "other-inst",
            "status": "pass",
            "exceptions": ["lsm confinement"],
            "checks": ["repository_tests"],
            "protocol": {"status": "pass", "reused": True,
                         "response_sha256": "e" * 64},
            "seed_commit": "f" * 40,
            "result_commit": "0" * 40,
        }).encode())
        os.chmod(record, 0o600)
        report, out_json, out_md = self._run()
        self.assertEqual(
            report["workflow"], {"file": DEMO_FILE, "readable": False})
        blob = (json.dumps(report, sort_keys=True)
                + out_json.read_text() + out_md.read_text())
        self.assertNotIn("other-inst", blob)
        self.assertNotIn("e" * 64, blob)
        self.assertNotIn("f" * 40, blob)
        self.assertNotIn("0" * 40, blob)
        saved = json.loads(out_json.read_bytes())
        self.assertEqual(saved["workflow"], report["workflow"])


class EvidenceDefaultVerifier(unittest.TestCase):
    def _private_instance(self, env):
        env.manifest["identity"]["name"] = env.name
        inst = env.root / "instances" / env.name
        for d in (env.root, env.root / "instances", inst):
            state._ensure_private_dir(d)
        return inst

    def _run_default(self, env):
        with mock.patch(
                "local_agent.evidence.load_manifest",
                return_value=env.manifest), mock.patch(
                "local_agent.evidence.load_runtime",
                return_value=env.record):
            return evidence.evidence(
                env.root, env.name, env.repo, env.runner)

    def _assert_failed_report_preserved(self, env, report, out_json,
                                        out_md, error):
        upstream = report["upstream"]
        self.assertEqual(
            upstream["artifacts_lock_sha256"],
            env.manifest["artifacts_lock"]["sha256"])
        self.assertNotIn("base_image", upstream)
        self.assertNotIn("platform", upstream)
        self.assertNotIn("artifacts", upstream)
        self.assertEqual(upstream["error"], error)
        self.assertEqual(report["status"], "fail")
        fp = [c for c in report["checks"]
              if c["name"] == "artifacts lock fingerprint"]
        self.assertEqual([c["status"] for c in fp], ["fail"])
        self.assertEqual(env.runner.calls, [])
        for out in (out_json, out_md):
            self.assertTrue(out.is_file())
            self.assertEqual(stat.S_IMODE(out.lstat().st_mode), 0o600)
        saved = json.loads(out_json.read_bytes())
        self.assertEqual(saved["upstream"], upstream)
        blob = (json.dumps(report, sort_keys=True)
                + out_json.read_text() + out_md.read_text())
        self.assertNotIn(str(env.repo), blob)
        self.assertNotIn("read denied", blob)

    def test_missing_lock_preserves_failed_report(self):
        with verify_env() as env:
            self._private_instance(env)
            (env.repo / ".devin" / "artifacts.lock.json").unlink()
            report, out_json, out_md = self._run_default(env)
            self._assert_failed_report_preserved(
                env, report, out_json, out_md,
                "artifacts lock pins unavailable: ArtifactError")

    def test_malformed_lock_preserves_failed_report(self):
        with verify_env() as env:
            self._private_instance(env)
            (env.repo / ".devin" / "artifacts.lock.json").write_bytes(
                b"{not json")
            report, out_json, out_md = self._run_default(env)
            self._assert_failed_report_preserved(
                env, report, out_json, out_md,
                "artifacts lock pins unavailable: ArtifactError")

    def test_schema_invalid_lock_preserves_failed_report(self):
        with verify_env() as env:
            self._private_instance(env)
            (env.repo / ".devin" / "artifacts.lock.json").write_bytes(
                json.dumps({"schema": "bogus"}).encode())
            report, out_json, out_md = self._run_default(env)
            self._assert_failed_report_preserved(
                env, report, out_json, out_md,
                "artifacts lock pins unavailable: ArtifactError")

    def test_unreadable_lock_preserves_failed_report(self):
        with verify_env() as env:
            self._private_instance(env)
            lock_path = env.repo / ".devin" / "artifacts.lock.json"
            real = artifacts.read_secure_file

            def deny(path, *args, **kwargs):
                if Path(path) == lock_path:
                    raise PermissionError("read denied")
                return real(path, *args, **kwargs)

            with mock.patch(
                    "local_agent.artifacts.read_secure_file",
                    side_effect=deny):
                report, out_json, out_md = self._run_default(env)
            self._assert_failed_report_preserved(
                env, report, out_json, out_md,
                "artifacts lock pins unavailable: PermissionError")

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


_LOCK_PROBE_SRC = (
    "import fcntl, sys\n"
    "fd = open(sys.argv[1], 'rb')\n"
    "try:\n"
    "    fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
    "except BlockingIOError:\n"
    "    print('blocked')\n"
    "else:\n"
    "    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)\n"
    "    print('acquired')\n"
)

_WRITER_SRC = (
    "import fcntl, os, sys\n"
    "lock_path, record_path, payload = sys.argv[1:4]\n"
    "fd = open(lock_path, 'r+b')\n"
    "fcntl.flock(fd.fileno(), fcntl.LOCK_EX)\n"
    "with open(record_path, 'wb') as out:\n"
    "    out.write(payload.encode())\n"
    "os.chmod(record_path, 0o600)\n"
    "print('HOLDING', flush=True)\n"
    "sys.stdin.readline()\n"
    "fcntl.flock(fd.fileno(), fcntl.LOCK_UN)\n"
    "print('RELEASED', flush=True)\n"
)


class EvidenceLocking(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.tmp = Path(self.td.name)
        self.root = self.tmp / "state"
        self.name = "evidence-test"
        src = REPO / ".devin" / "artifacts.lock.json"
        if not src.exists():
            self.skipTest("artifacts lock absent")
        self.lock_path = self.tmp / "artifacts.lock.json"
        lock_bytes = src.read_bytes()
        self.lock_path.write_bytes(lock_bytes)
        state.init_instance(
            self.root, self.name, {"name": "cpu"},
            {"sha256": "a" * 64},
            {"path": str(self.lock_path),
             "sha256": hashlib.sha256(lock_bytes).hexdigest(),
             "bytes": len(lock_bytes)},
            True)
        self.inst = self.root / "instances" / self.name

    def _verify(self, root_dir, name, repo, runner):
        r = Result()
        r.add("runtime controls", "pass")
        return r

    def _lock_probe(self, timeout=10):
        res = subprocess.run(
            [sys.executable, "-I", "-B", "-c", _LOCK_PROBE_SRC,
             str(self.inst / ".lock")],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout.strip()

    def _read_line(self, stream, timeout=15):
        ready, _, _ = select.select([stream], [], [], timeout)
        self.assertTrue(ready, "timed out waiting for child output")
        return stream.readline().strip()

    def _probed(self, probes, tag, fn):
        def wrapper(*args, **kwargs):
            probes.append((tag, self._lock_probe()))
            return fn(*args, **kwargs)
        return wrapper

    def test_lock_held_across_snapshot_and_released(self):
        probes = []

        def verify_fn(*args, **kwargs):
            probes.append(("verify", self._lock_probe()))
            return self._verify(*args, **kwargs)

        reals = {
            name: getattr(evidence, name)
            for name in ("load_manifest", "load_runtime", "load_lock",
                         "_workflow_projection", "_atomic_write")
        }
        with mock.patch(
                "local_agent.evidence.load_manifest",
                self._probed(probes, "manifest",
                             reals["load_manifest"])), mock.patch(
                "local_agent.evidence.load_runtime",
                self._probed(probes, "runtime",
                             reals["load_runtime"])), mock.patch(
                "local_agent.evidence.load_lock",
                self._probed(probes, "lock",
                             reals["load_lock"])), mock.patch(
                "local_agent.evidence._workflow_projection",
                self._probed(probes, "workflow",
                             reals["_workflow_projection"])), mock.patch(
                "local_agent.evidence._atomic_write",
                self._probed(probes, "write",
                             reals["_atomic_write"])):
            report, out_json, out_md = evidence.evidence(
                self.root, self.name, self.tmp, None,
                verify_fn=verify_fn)
        self.assertEqual(
            probes,
            [("manifest", "blocked"), ("runtime", "blocked"),
             ("verify", "blocked"), ("lock", "blocked"),
             ("workflow", "blocked"), ("write", "blocked"),
             ("write", "blocked")])
        self.assertEqual(report["status"], "pass")
        self.assertTrue(out_json.exists())
        self.assertTrue(out_md.exists())
        self.assertEqual(self._lock_probe(), "acquired")

    def test_lock_released_on_verifier_failure(self):
        def boom(*args, **kwargs):
            raise RuntimeError("injected verifier failure")

        with self.assertRaises(RuntimeError):
            evidence.evidence(
                self.root, self.name, self.tmp, None, verify_fn=boom)
        self.assertEqual(self._lock_probe(), "acquired")
        self.assertFalse(list(self.inst.glob("evidence-*.json")))

    def test_waits_for_competing_writer_and_sees_completed_record(self):
        demo_payload = json.dumps({
            "schema": "secure-local-llm/demo@1",
            "instance": self.name,
            "status": "pass",
            "exceptions": ["lsm confinement"],
            "checks": ["repository_tests"],
        })
        record_path = (
            self.inst / "demo-20260102T000000Z-cafef00d.json")
        proc = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", _WRITER_SRC,
             str(self.inst / ".lock"), str(record_path), demo_payload],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        manifest_read = threading.Event()
        done, errors = [], []
        t = None
        try:
            self.assertEqual(
                self._read_line(proc.stdout), "HOLDING")
            real_lm = state.load_manifest

            def lm(*args, **kwargs):
                manifest_read.set()
                return real_lm(*args, **kwargs)

            def run():
                try:
                    with mock.patch(
                            "local_agent.evidence.load_manifest", lm):
                        done.append(evidence.evidence(
                            self.root, self.name, self.tmp, None,
                            verify_fn=self._verify))
                except Exception as exc:
                    errors.append(exc)

            t = threading.Thread(target=run, daemon=True)
            t.start()
            self.assertFalse(
                manifest_read.wait(timeout=1.0),
                "state read observed while writer held the lock")
            proc.stdin.write("release\n")
            proc.stdin.flush()
            self.assertEqual(
                self._read_line(proc.stdout), "RELEASED")
            self.assertTrue(
                manifest_read.wait(timeout=15),
                "evidence did not proceed after lock release")
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
            stderr_data = proc.stderr.read()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
            if t is not None:
                t.join(timeout=30)
        self.assertFalse(errors, errors)
        self.assertFalse(t.is_alive())
        self.assertEqual(proc.returncode, 0, stderr_data)
        report, out_json, out_md = done[0]
        self.assertEqual(report["workflow"]["file"], record_path.name)
        self.assertEqual(report["workflow"]["status"], "pass")

    def test_invalid_inputs_rejected_before_state_access(self):
        for bad in (123, None, "", "../escape", "Bad Name", "-x",
                    "a" * 33):
            with self.subTest(name=bad), mock.patch(
                    "local_agent.evidence._require_private_dir"
                    ) as dir_spy, mock.patch(
                    "local_agent.evidence.locked_instance") as lock_spy:
                with self.assertRaises(state.StateError):
                    evidence.evidence(
                        self.root, bad, self.tmp, None,
                        verify_fn=self._verify)
                dir_spy.assert_not_called()
                lock_spy.assert_not_called()
        with mock.patch(
                "local_agent.evidence._require_private_dir"
                ) as dir_spy, mock.patch(
                "local_agent.evidence.locked_instance") as lock_spy:
            with self.assertRaises(state.StateError):
                evidence.evidence(
                    Path("rel-root"), self.name, self.tmp, None,
                    verify_fn=self._verify)
            dir_spy.assert_not_called()
            lock_spy.assert_not_called()
        self.assertEqual(
            sorted(p.name for p in
                   (self.root / "instances").iterdir()),
            [self.name])

    def test_uninitialized_fails_without_creating_state(self):
        with self.assertRaises(state.StateError):
            evidence.evidence(
                self.root, "ghost", self.tmp, None,
                verify_fn=self._verify)
        self.assertFalse(
            (self.root / "instances" / "ghost").exists())
        self.assertFalse(
            (self.root / "instances" / "ghost" / ".lock").exists())


class EvidenceCollision(unittest.TestCase):
    STAMP = "20260101T000000Z"
    NONCE = "cafebabe"

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.tmp = Path(self.td.name)
        self.root = self.tmp / "state"
        self.name = "evidence-test"
        src = REPO / ".devin" / "artifacts.lock.json"
        if not src.exists():
            self.skipTest("artifacts lock absent")
        self.lock_path = self.tmp / "artifacts.lock.json"
        lock_bytes = src.read_bytes()
        self.lock_path.write_bytes(lock_bytes)
        state.init_instance(
            self.root, self.name, {"name": "cpu"},
            {"sha256": "a" * 64},
            {"path": str(self.lock_path),
             "sha256": hashlib.sha256(lock_bytes).hexdigest(),
             "bytes": len(lock_bytes)},
            True)
        self.inst = self.root / "instances" / self.name

    def _verify(self, root_dir, name, repo, runner):
        r = Result()
        r.add("runtime controls", "pass")
        return r

    def _dests(self):
        return (
            self.inst / f"evidence-{self.STAMP}-{self.NONCE}.json",
            self.inst / f"evidence-{self.STAMP}-{self.NONCE}.md")

    def _run_fixed(self):
        with mock.patch("local_agent.evidence.datetime") as mdt, \
                mock.patch("local_agent.evidence.secrets") as msec:
            mdt.now.return_value.strftime.return_value = self.STAMP
            msec.token_hex.return_value = self.NONCE
            return evidence.evidence(
                self.root, self.name, self.tmp, None,
                verify_fn=self._verify)

    def _remove(self, dest):
        if stat.S_ISDIR(dest.lstat().st_mode):
            dest.rmdir()
        else:
            dest.unlink()

    def _assert_preserved(self, dest, before, payload):
        after = dest.lstat()
        self.assertEqual(after.st_ino, before.st_ino)
        self.assertEqual(after.st_mode, before.st_mode)
        if stat.S_ISREG(after.st_mode) and payload is not None:
            self.assertEqual(dest.read_bytes(), payload)

    def test_json_only_collision_preserves_original(self):
        out_json, out_md = self._dests()
        out_json.write_bytes(b'{"prior": true}\n')
        os.chmod(out_json, 0o600)
        before = out_json.lstat()
        with self.assertRaises(state.StateError):
            self._run_fixed()
        self._assert_preserved(out_json, before, b'{"prior": true}\n')
        self.assertFalse(out_md.exists() or out_md.is_symlink())
        self.assertEqual(list(self.inst.glob(".tmp-*")), [])

    def test_md_only_collision_creates_no_json_sibling(self):
        out_json, out_md = self._dests()
        out_md.write_bytes(b"# prior\n")
        os.chmod(out_md, 0o600)
        before = out_md.lstat()
        with self.assertRaises(state.StateError):
            self._run_fixed()
        self._assert_preserved(out_md, before, b"# prior\n")
        self.assertFalse(out_json.exists() or out_json.is_symlink())
        self.assertEqual(list(self.inst.glob(".tmp-*")), [])

    def test_both_destinations_collision_preserved(self):
        out_json, out_md = self._dests()
        prior = ((out_json, b"json-prior"), (out_md, b"md-prior"))
        for dest, payload in prior:
            dest.write_bytes(payload)
            os.chmod(dest, 0o600)
        befores = {d: d.lstat() for d, _ in prior}
        with self.assertRaises(state.StateError):
            self._run_fixed()
        for dest, payload in prior:
            self._assert_preserved(dest, befores[dest], payload)
        self.assertEqual(list(self.inst.glob(".tmp-*")), [])

    def test_nonregular_destinations_refused(self):
        victim = self.inst / "victim-file"
        victim.write_bytes(b"victim")
        os.chmod(victim, 0o600)
        out_json, out_md = self._dests()
        kinds = (
            ("symlink", lambda d: d.symlink_to(victim)),
            ("dangling_symlink",
             lambda d: d.symlink_to("absent-target")),
            ("directory", lambda d: d.mkdir(0o700)),
            ("fifo", lambda d: os.mkfifo(d)),
            ("hardlink", lambda d: os.link(victim, d)),
        )
        for label, make in kinds:
            for dest in (out_json, out_md):
                with self.subTest(kind=label, dest=dest.suffix):
                    make(dest)
                    before = dest.lstat()
                    with self.assertRaises(state.StateError):
                        self._run_fixed()
                    self._assert_preserved(dest, before, None)
                    other = out_md if dest == out_json else out_json
                    self.assertFalse(
                        other.exists() or other.is_symlink())
                    self._remove(dest)
        self.assertEqual(list(self.inst.glob(".tmp-*")), [])

    def test_post_preflight_race_no_overwrite(self):
        out_json, out_md = self._dests()
        real_write = state._atomic_write
        for slot in ("json", "md"):
            with self.subTest(raced=slot):
                raced = out_json if slot == "json" else out_md
                created = []

                def racing_write(path, payload, mode=0o600, **kw):
                    if Path(path) == raced and not created:
                        path.write_bytes(b"raced-bytes")
                        os.chmod(path, 0o600)
                        created.append(path.lstat().st_ino)
                    return real_write(path, payload, mode, **kw)

                with mock.patch("local_agent.evidence._atomic_write",
                                side_effect=racing_write):
                    with self.assertRaises(state.StateError):
                        self._run_fixed()
                self.assertEqual(len(created), 1)
                self.assertEqual(raced.lstat().st_ino, created[0])
                self.assertEqual(raced.read_bytes(), b"raced-bytes")
                if slot == "json":
                    self.assertFalse(
                        out_md.exists() or out_md.is_symlink())
                else:
                    self.assertTrue(out_json.is_file())
                    saved = json.loads(out_json.read_bytes())
                    self.assertEqual(
                        saved["schema"], evidence.EVIDENCE_SCHEMA)
                    self.assertEqual(saved["instance"], self.name)
                self._remove(raced)
                if out_json.exists():
                    out_json.unlink()
                self.assertEqual(list(self.inst.glob(".tmp-*")), [])


if __name__ == "__main__":
    unittest.main()
