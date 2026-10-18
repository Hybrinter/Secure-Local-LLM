"""Pure assertions for the opt-in native OpenCode V2 gate."""

import contextlib
import errno
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
sys.path.insert(
    0, str(Path(__file__).resolve().parent / "integration"))

import v2_gate as gate

from local_agent import artifacts, runner, state

HARNESS_IMG = "4" * 64
INFERENCE_IMG = "5" * 64
BASE_IMG = "registry.test/base@sha256:" + "7" * 64
OTHER_FP = "9" * 64


@contextlib.contextmanager
def _umask(mask):
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


def _ok(stdout):
    return runner.CommandResult([], 0, stdout, "")


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


class LaunchRunner:
    """Fake podman surface covering every command run_gate issues."""

    def __init__(self):
        self.calls = []

    def podman(self, args, timeout=60, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        return self._dispatch(list(args), " ".join(args))

    def run(self, argv, timeout=60, extra_env=None, stdin_text=None,
            pass_fds=()):
        self.calls.append(list(argv))
        raise AssertionError(f"unexpected run argv {argv}")

    def _dispatch(self, args, joined):
        if args[:2] == ["pod", "create"]:
            return _ok("podid\n")
        if args[:1] == ["run"]:
            return _ok("wlid\n")
        if args[:1] == ["logs"]:
            return _ok("")
        if args[:1] == ["exec"]:
            return self._exec(args, joined)
        return _ok("")

    def _exec(self, args, joined):
        if args[2] == "python3" and args[3:6] == ["-I", "-B", "-c"]:
            if args[6] == gate.HTTP_PROBE_SRC:
                mode, path = args[7], args[8]
                body = ""
                if mode == "good" and path == "/api/config":
                    body = json.dumps([{"info": {"providers": {
                        "local": {"settings": {
                            "baseURL": "http://127.0.0.1:8080/v1"}}}}}])
                status = 200 if mode == "good" else 401
                return _ok(json.dumps({"status": status, "body": body}))
            if args[6] == gate.TOPOLOGY_PROBE:
                return _ok(repr([
                    ("/run/local-agent", 0, 0o755),
                    ("/run/local-agent/opencode", 0, 0o755),
                    "WRITE-DENIED", "CREATE-DENIED", "RENAME-DENIED"]))
        if args[2:] == ["ss", "-tln"]:
            return _ok("tcp LISTEN 0 128 127.0.0.1:4096 0.0.0.0:*\n")
        if args[2:4] == ["opencode", "models"]:
            return _ok("local/granite-cpu\n")
        if args[2:4] == ["opencode", "api"]:
            return _ok('{"data": []}\n')
        if args[2] == "sh" and "opencode models" in joined:
            return _ok("local/granite-cpu\n")
        if args[2] == "sh" and "debug config" in joined:
            return _ok("config /run/local-agent/opencode/opencode.json\n"
                       '{"providerID": "local"}\n')
        if args[2] == "ip":
            return _ok("1: lo    inet 127.0.0.1/8 scope host lo\n")
        if args[2] == "grep":
            return _ok("CapEff:\t0000000000000000\n"
                       "CapBnd:\t0000000000000000\n"
                       "NoNewPrivs:\t1\nSeccomp:\t2\n")
        return _ok("")


class WriteExclusive(unittest.TestCase):
    def test_refuses_collision_and_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            victim = tmp / "victim"
            victim.write_text("keep")
            os.chmod(victim, 0o644)
            with self.assertRaises(FileExistsError):
                gate.write_exclusive(victim, "overwrite")
            self.assertEqual(victim.read_text(), "keep")
            self.assertEqual(
                stat.S_IMODE(os.lstat(victim).st_mode), 0o644)
            link = tmp / "link"
            link.symlink_to(victim)
            with self.assertRaises(FileExistsError):
                gate.write_exclusive(link, "overwrite")
            self.assertTrue(link.is_symlink())
            self.assertEqual(victim.read_text(), "keep")
            self.assertEqual(
                stat.S_IMODE(os.lstat(victim).st_mode), 0o644)

    def test_written_payload_has_exact_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "payload"
            with _umask(0):
                gate.write_exclusive(target, "secret-bytes")
            self.assertEqual(target.read_text(), "secret-bytes")
            self.assertEqual(
                stat.S_IMODE(os.lstat(target).st_mode), 0o600)

    def test_fchmod_failure_closes_newly_created_fd(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "payload"
            opened = []

            def boom(fd, mode):
                opened.append(fd)
                raise OSError("fchmod denied")

            with mock.patch.object(gate.os, "fchmod", boom):
                with self.assertRaises(OSError):
                    gate.write_exclusive(target, "x")
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError) as ctx:
                os.fstat(opened[0])
            self.assertEqual(ctx.exception.errno, errno.EBADF)


class StagedCredentials(unittest.TestCase):
    def _gate(self):
        g = gate.Gate(FailingRunner())
        g.note = lambda msg: None
        return g

    def _modes(self, cfg):
        self.assertEqual(stat.S_IMODE(os.lstat(cfg).st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE(os.lstat(cfg / "opencode").st_mode), 0o700)
        for p in (cfg / "model-api-key",
                  cfg / "opencode" / "service.json",
                  cfg / "opencode" / "opencode.json"):
            self.assertTrue(stat.S_ISREG(os.lstat(p).st_mode))
            self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), 0o600)

    def test_staged_modes_and_contents_under_permissive_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, None)
            g = self._gate()
            with _umask(0), mock.patch.object(
                    state, "state_root", return_value=root):
                pw = g.stage_config()
            cfg = root / f"v2gate-{g.nonce}"
            self._modes(cfg)
            service = json.loads(
                (cfg / "opencode" / "service.json").read_text())
            self.assertEqual(service, {"hostname": "127.0.0.1",
                                       "port": 4096, "password": pw})
            self.assertEqual(
                (cfg / "opencode" / "opencode.json").read_text(),
                gate.TEMPLATE.read_text())
            self.assertEqual(len((cfg / "model-api-key").read_text()), 48)

    def test_partial_staging_failure_is_cleaned_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, None)
            g = self._gate()
            calls = []
            real_mkdir = Path.mkdir

            def flaky_mkdir(self, *args, **kwargs):
                calls.append(str(self))
                if len(calls) == 2:
                    raise OSError("inner mkdir failed")
                return real_mkdir(self, *args, **kwargs)

            with mock.patch.object(
                    state, "state_root", return_value=root), \
                    mock.patch.object(Path, "mkdir", flaky_mkdir):
                with self.assertRaises(OSError):
                    g.stage_config()
            g.cleanup()
            self.assertFalse((root / f"v2gate-{g.nonce}").exists())
            self.assertIsNone(g.cfg_dir)


class LaunchArgv(unittest.TestCase):
    def test_mapping_user_ro_binds_and_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, None)
            g = gate.Gate(LaunchRunner())
            g.note = lambda msg: None
            with mock.patch.object(state, "state_root",
                                   return_value=root):
                g.run_gate(HARNESS_IMG, BASE_IMG)
            pod_argv = [c for c in g.r.calls
                        if c[:2] == ["pod", "create"]][0]
            self.assertEqual(
                pod_argv[pod_argv.index("--userns") + 1],
                "keep-id:uid=1000,gid=1000")
            self.assertIn("--network", pod_argv)
            self.assertIn("none", pod_argv)
            run_argv = [c for c in g.r.calls if c[:1] == ["run"]][0]
            self.assertEqual(
                run_argv[run_argv.index("--user") + 1], "1000:1000")
            self.assertIn("--pull=never", run_argv)
            self.assertIn("--cap-drop", run_argv)
            self.assertIn("ALL", run_argv)
            self.assertIn("--read-only", run_argv)
            self.assertIn("no-new-privileges", run_argv)
            self.assertIn("--memory", run_argv)
            self.assertIn("--pids-limit", run_argv)
            binds = [run_argv[i + 1] for i, a in enumerate(run_argv)
                     if a == "-v"]
            self.assertEqual(len(binds), 3)
            for bind in binds:
                self.assertTrue(bind.endswith(":ro"))
            self.assertTrue(all(r["ok"] for r in g.results))


class KeepRetention(unittest.TestCase):
    def test_keep_retains_fixture_without_altering_modes(self):
        lock_fp, cf_fp = _repo_fps()
        with tempfile.TemporaryDirectory() as tmp:
            root = _state_root(tmp, _prepared(lock_fp, cf_fp))

            def fake_run_gate(self, harness, base):
                self.stage_config()
                self.check("stub launch", True)

            out = io.StringIO()
            with _umask(0), mock.patch.object(
                    state, "state_root", return_value=root), \
                    mock.patch.object(
                    gate.runner, "Runner", return_value=FailingRunner()), \
                    mock.patch.object(gate.Gate, "run_gate",
                                      fake_run_gate), \
                    mock.patch.object(
                    sys, "argv", ["v2_gate.py", "--run", "--keep"]), \
                    contextlib.redirect_stdout(out):
                rc = gate.main()
            self.assertEqual(rc, 0)
            retained = [d for d in root.iterdir()
                        if d.name.startswith("v2gate-")]
            self.assertEqual(len(retained), 1)
            cfg = retained[0]
            self.assertEqual(
                stat.S_IMODE(os.lstat(cfg).st_mode), 0o700)
            for p in sorted(cfg.rglob("*")):
                mode = stat.S_IMODE(os.lstat(p).st_mode)
                self.assertEqual(mode, 0o700 if p.is_dir() else 0o600)


if __name__ == "__main__":
    unittest.main()
