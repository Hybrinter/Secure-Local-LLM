"""Pure assertions for the opt-in native OpenCode V2 gate."""

import contextlib
import errno
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
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

    def __init__(self, fail=None):
        self.calls = []
        self.fail = dict(fail or {})

    def podman(self, args, timeout=60, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        joined = " ".join(args)
        for key, res in self.fail.items():
            if key in joined:
                if isinstance(res, BaseException):
                    raise res
                return res
        return self._dispatch(list(args), joined)

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
            if args[6] == gate.MARKER_PROBE_SRC:
                return _ok("markers-absent\n")
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
            names = [r["name"] for r in g.results]
            markers = names.index("hostile markers absent")
            self.assertEqual(markers, names.index(
                "hostile local-redir: config resolves template only")
                + 1)
            self.assertLess(markers, names.index(
                "hostile dirs: baseURL stays loopback"))


class MarkerProbeSrc(unittest.TestCase):
    def _run(self, path):
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c",
             gate.MARKER_PROBE_SRC, str(path)],
            timeout=10, capture_output=True, text=True)

    def test_empty_directory_reports_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._run(tmp)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout, "markers-absent\n")

    def test_unrelated_entries_report_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "notes.txt").write_text("x")
            (tmp / "subdir").mkdir()
            res = self._run(tmp)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout, "markers-absent\n")

    def test_marker_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "MARKER-plugin").write_text("pwned")
            res = self._run(tmp)
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("markers-absent", res.stdout)

    def test_marker_directory_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "MARKER-dir").mkdir()
            res = self._run(tmp)
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("markers-absent", res.stdout)

    def test_missing_path_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = self._run(Path(tmp) / "absent")
            self.assertNotEqual(res.returncode, 0)

    def test_non_directory_path_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "regular"
            f.write_text("x")
            res = self._run(f)
            self.assertNotEqual(res.returncode, 0)


class HostileMarkers(unittest.TestCase):
    class StubRunner:
        def __init__(self, res=None, exc=None):
            self.res = res
            self.exc = exc
            self.calls = []

        def podman(self, args, timeout=60, extra_env=None,
                   stdin_text=None):
            self.calls.append(list(args))
            if self.exc is not None:
                raise self.exc
            return self.res

    def _gate(self, res=None, exc=None):
        g = gate.Gate(self.StubRunner(res=res, exc=exc))
        g.note = lambda msg: None
        return g

    def _result(self, g):
        marks = [r for r in g.results
                 if r["name"] == "hostile markers absent"]
        self.assertEqual(len(marks), 1)
        return marks[0]

    def _probe_argv(self, g):
        call = g.r.calls[0]
        self.assertEqual(call[2:6],
                         ["python3", "-I", "-B", "-c"])
        self.assertEqual(call[6], gate.MARKER_PROBE_SRC)
        self.assertEqual(call[7], "/state")

    def test_nonzero_empty_stdout_fails(self):
        g = self._gate(res=runner.CommandResult([], 1, "", "ls err"))
        g.check_hostile_markers("wl")
        self.assertFalse(self._result(g)["ok"])
        self._probe_argv(g)

    def test_nonzero_with_sentinel_fails(self):
        g = self._gate(res=runner.CommandResult(
            [], 1, "markers-absent\n", ""))
        g.check_hostile_markers("wl")
        self.assertFalse(self._result(g)["ok"])

    def test_timeout_with_rc0_sentinel_fails(self):
        g = self._gate(res=runner.CommandResult(
            [], 0, "markers-absent\n", "timed out", timed_out=True))
        g.check_hostile_markers("wl")
        self.assertFalse(self._result(g)["ok"])

    def test_rc0_without_sentinel_fails(self):
        g = self._gate(res=runner.CommandResult([], 0, "", ""))
        g.check_hostile_markers("wl")
        self.assertFalse(self._result(g)["ok"])

    def test_rc0_with_sentinel_passes(self):
        g = self._gate(res=runner.CommandResult(
            [], 0, "markers-absent\n", ""))
        g.check_hostile_markers("wl")
        self.assertTrue(self._result(g)["ok"])
        self._probe_argv(g)

    def test_spawn_error_cannot_pass(self):
        g = self._gate(exc=runner.RunnerError("cannot execute"))
        with self.assertRaises(runner.RunnerError):
            g.check_hostile_markers("wl")
        self.assertFalse(
            any(r["name"] == "hostile markers absent" and r["ok"]
                for r in g.results))


def _discoverable(cfg, cwd):
    if cfg.parent == cwd or cfg.parent in cwd.parents:
        return True
    return (cfg.parent.name == ".opencode"
            and (cfg.parent.parent == cwd
                 or cfg.parent.parent in cwd.parents))


class HostileFixtures(unittest.TestCase):
    CASES = ("proj-json", "proj-jsonc", "root-json", "nested",
             "local-redir")

    def _gate(self, fail=None):
        g = gate.Gate(LaunchRunner(fail=fail))
        g.note = lambda msg: None
        return g

    def _fixtures(self, g):
        writes, cwds = {}, {}
        for call in g.r.calls:
            joined = " ".join(call)
            if "cat > /work/" in joined and "src-plugin" not in joined:
                cfg = PurePosixPath(
                    joined.split("cat > ", 1)[1].split()[0])
                writes[cfg.parts[2]] = cfg
            if "cd /work/" in joined and "opencode " in joined:
                tail = joined.split("cd ", 1)[1]
                cwd = PurePosixPath(tail.split(" && ", 1)[0])
                probe = ("models" if "opencode models" in tail
                         else "debug")
                cwds.setdefault(cwd.parts[2], {})[probe] = cwd
        return writes, cwds

    def test_all_five_cases_run_from_discoverable_cwd(self):
        g = self._gate()
        g.check_hostile_fixtures("wl")
        writes, cwds = self._fixtures(g)
        self.assertEqual(set(writes), set(self.CASES))
        self.assertEqual(set(cwds), set(self.CASES))
        for case in self.CASES:
            with self.subTest(case=case):
                self.assertIn("models", cwds[case])
                self.assertIn("debug", cwds[case])
                self.assertEqual(cwds[case]["models"],
                                 cwds[case]["debug"])
                self.assertTrue(
                    _discoverable(writes[case], cwds[case]["models"]),
                    f"{writes[case]} vs {cwds[case]['models']}")
        self.assertEqual(cwds["nested"]["models"],
                         PurePosixPath("/work/nested/deep/nested/child"))
        self.assertEqual(writes["nested"], PurePosixPath(
            "/work/nested/deep/nested/.opencode/opencode.json"))
        nested_cmd = " ".join(
            [c for c in g.r.calls
             if "cat > /work/nested/" in " ".join(c)][0])
        self.assertIn("mkdir", nested_cmd)
        self.assertIn("/work/nested/deep/nested/child", nested_cmd)
        self.assertTrue(all(r["ok"] for r in g.results))

    def test_setup_failures_stop_without_success_evidence(self):
        first_blocked = {
            "cat > /work/src-plugin": "proj-json",
            "ln -sf": "proj-json",
            "cat > /work/nested/": "nested",
        }
        for key, blocked in first_blocked.items():
            for res in (
                    runner.CommandResult([], 1, "", "setup denied"),
                    runner.CommandResult([], 124, "", "timed out",
                                         timed_out=True)):
                with self.subTest(key=key, rc=res.returncode):
                    g = self._gate(fail={key: res})
                    with self.assertRaises(RuntimeError):
                        g.check_hostile_fixtures("wl")
                    checked = {r["name"].split(":")[0].split()[-1]
                               for r in g.results}
                    idx = self.CASES.index(blocked)
                    self.assertFalse(set(self.CASES[idx:]) & checked)
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
