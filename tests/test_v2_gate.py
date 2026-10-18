"""Pure assertions for the opt-in native OpenCode V2 gate."""

import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
sys.path.insert(
    0, str(Path(__file__).resolve().parent / "integration"))

import v2_gate as gate

from local_agent import artifacts, state

HARNESS_IMG = "4" * 64
INFERENCE_IMG = "5" * 64
OTHER_FP = "9" * 64


def _file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _repo_fps():
    return (
        _file_sha(gate.REPO / ".devin" / "artifacts.lock.json"),
        _file_sha(gate.REPO / "containers" / "harness.Containerfile"),
    )


def _prepared(lock_fp, cf_fp):
    return {
        "schema": state.PREPARED_SCHEMA,
        "instance": "demo",
        "created_utc": "2026-10-18T00:00:00+00:00",
        "fingerprints": {
            "artifacts_lock": lock_fp,
            "profile": "1" * 64,
            "harness_containerfile": cf_fp,
            "inference_containerfile": "2" * 64,
        },
        "artifacts": {
            "model": {"path": "/nonexistent/model", "sha256": "3" * 64},
            "opencode": {"path": "/nonexistent/opencode",
                         "sha512": "6" * 128},
            "inference_source": {"path": "/nonexistent/src",
                                 "sha256": "7" * 64},
        },
        "images": {"harness": HARNESS_IMG, "inference": INFERENCE_IMG},
        "packages": {"harness": ["opencode"], "inference": ["llama"]},
    }


def _state_root(tmp, record):
    root = Path(tmp) / "state"
    state._ensure_private_dir(root)
    state._ensure_private_dir(root / "instances")
    state._ensure_private_dir(root / "instances" / "demo")
    if record is not None:
        state.save_prepared(root, "demo", record)
    return root


class FailingRunner:
    def __init__(self):
        self.calls = []

    def podman(self, args, timeout=60, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        raise AssertionError(f"unexpected podman argv {args}")

    def run(self, argv, timeout=60, extra_env=None, stdin_text=None,
            pass_fds=()):
        self.calls.append(list(argv))
        raise AssertionError(f"unexpected run argv {argv}")


class LoadGateImages(unittest.TestCase):
    def test_matching_fingerprints_select_recorded_images(self):
        lock_fp, cf_fp = _repo_fps()
        expected_base = artifacts.load_lock(
            gate.REPO / ".devin" / "artifacts.lock.json"
        )[0]["base_image"]
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, _prepared(lock_fp, cf_fp))
            self.assertEqual(
                gate.load_gate_images(root), (HARNESS_IMG, expected_base))

    def test_lock_fingerprint_mismatch_rejected(self):
        _, cf_fp = _repo_fps()
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, _prepared(OTHER_FP, cf_fp))
            with self.assertRaises(RuntimeError) as ctx:
                gate.load_gate_images(root)
            self.assertIn("artifacts lock", str(ctx.exception))

    def test_recipe_fingerprint_mismatch_rejected(self):
        lock_fp, _ = _repo_fps()
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, _prepared(lock_fp, OTHER_FP))
            with self.assertRaises(RuntimeError) as ctx:
                gate.load_gate_images(root)
            self.assertIn("Containerfile", str(ctx.exception))

    def test_absent_prepared_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, None)
            with self.assertRaises(RuntimeError) as ctx:
                gate.load_gate_images(root)
            self.assertIn("not prepared", str(ctx.exception))

    def test_malformed_lock_rejected(self):
        lock_fp, cf_fp = _repo_fps()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            root = _state_root(tmp, _prepared(lock_fp, cf_fp))
            repo = tmp / "repo"
            (repo / ".devin").mkdir(parents=True)
            (repo / ".devin" / "artifacts.lock.json").write_text(
                "{ not json")
            with mock.patch.object(gate, "REPO", repo):
                with self.assertRaises(artifacts.ArtifactError):
                    gate.load_gate_images(root)


class MainAdmission(unittest.TestCase):
    def test_mismatch_never_reaches_run_gate_or_podman(self):
        lock_fp, _ = _repo_fps()
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, _prepared(OTHER_FP, lock_fp))
            fake = FailingRunner()
            out = io.StringIO()
            with mock.patch.object(
                    state, "state_root", return_value=root), \
                    mock.patch.object(
                    gate.runner, "Runner", return_value=fake), \
                    mock.patch.object(
                    sys, "argv", ["v2_gate.py", "--run"]), \
                    contextlib.redirect_stdout(out):
                rc = gate.main()
            self.assertEqual(rc, 1)
            self.assertEqual(fake.calls, [])
            self.assertIn("artifacts lock", out.getvalue())
            written = [p.name for p in root.iterdir()
                       if p.name.startswith("v2-gate-")]
            self.assertEqual(len(written), 2)


if __name__ == "__main__":
    unittest.main()
