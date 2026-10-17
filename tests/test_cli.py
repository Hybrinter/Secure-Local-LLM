import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import cli, runner

REPO = Path(__file__).resolve().parents[1]
PODMAN_INFO = json.dumps({
    "host": {
        "security": {"rootless": True, "seccompEnabled": True,
                     "selinuxEnabled": False, "apparmorEnabled": False},
        "cgroupVersion": "v2",
        "cgroupControllers": ["cpu", "cpuset", "io", "memory", "pids"],
    },
    "version": {"Version": "4.9.3"},
})


class FakeRunner(runner.Runner):
    def __init__(self, result):
        self.calls = []
        self.result = result

    def run(self, argv, timeout=runner.DEFAULT_TIMEOUT_SECONDS, extra_env=None):
        self.calls.append(list(argv))
        return self.result


def run_cli(argv, runner_obj=None, xdg=None):
    out, err = io.StringIO(), io.StringIO()
    xdg = xdg or tempfile.mkdtemp()
    with unittest.mock.patch.dict(os.environ, {"XDG_STATE_HOME": xdg}):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv, runner=runner_obj)
    return rc, out.getvalue(), err.getvalue(), Path(xdg) / "secure-local-llm"


class Doctor(unittest.TestCase):
    def doctor(self, stdout=PODMAN_INFO, rc=0, *, missing_tools=()):
        fake = FakeRunner(runner.CommandResult(["x"], rc, stdout, ""))
        missing = set(missing_tools)

        def which(tool):
            return None if tool in missing else f"/mock/bin/{tool}"

        with unittest.mock.patch("local_agent.cli.shutil.which",
                                 side_effect=which) as mock_which:
            result = run_cli(["doctor"], runner_obj=fake)
        self.assertEqual(
            mock_which.call_args_list,
            [unittest.mock.call(tool) for tool in cli.REQUIRED_TOOLS])
        return result

    def test_healthy_host_readonly(self):
        rc, out, err, root = self.doctor()
        self.assertEqual(rc, 0)
        self.assertIn("ok: podman rootless", out)
        self.assertIn("ok: podman 4.9.3 (tested version)", out)
        self.assertIn("no LSM", out)
        self.assertFalse(root.exists())

    def test_rootful_fails(self):
        info = json.loads(PODMAN_INFO)
        info["host"]["security"]["rootless"] = False
        rc, out, err, root = self.doctor(stdout=json.dumps(info))
        self.assertEqual(rc, 1)
        self.assertIn("fail: podman rootless", out)

    def test_malformed_and_nonobject_json(self):
        for bad in ("{broken", "[1,2]", '"x"', "null"):
            rc, out, err, root = self.doctor(stdout=bad)
            self.assertEqual(rc, 1, bad)
            self.assertIn("fail:", out)

    def test_unsupported_and_malformed_version(self):
        for ver, expect in (("4.8.0", "fail"), ("garbage", "fail"),
                            ("4.9.3.garbage", "fail"), ("4.9", "fail"),
                            ("4.9.4", "warn"), ("5.0.0", "warn")):
            info = json.loads(PODMAN_INFO)
            info["version"]["Version"] = ver
            rc, out, err, root = self.doctor(stdout=json.dumps(info))
            if expect == "fail":
                self.assertEqual(rc, 1, ver)
                self.assertIn("unsupported", out)
            else:
                self.assertEqual(rc, 0, ver)
                self.assertIn("untested", out)
                self.assertIn("4.9.3", out)

    def test_malformed_info_shapes(self):
        mutations = [
            lambda i: i.update(version=["4.9.3"]),
            lambda i: i.update(version="4.9.3"),
            lambda i: i.update(version={"Version": 4.9}),
            lambda i: i["host"].update(security=["rootless"]),
            lambda i: i["host"].update(security="yes"),
            lambda i: i["host"]["security"].update(rootless="false"),
            lambda i: i["host"]["security"].update(seccompEnabled=1),
            lambda i: i["host"].update(cgroupControllers="cpu"),
            lambda i: i["host"].update(cgroupControllers=[1, "cpu"]),
            lambda i: i.update(host=["not", "dict"]),
        ]
        for i, mutate in enumerate(mutations):
            info = json.loads(PODMAN_INFO)
            mutate(info)
            with self.subTest(case=i):
                rc, out, err, root = self.doctor(stdout=json.dumps(info))
                self.assertEqual(rc, 1)
                self.assertNotIn("Traceback", err)

    def test_tool_discovery_independent_of_path(self):
        with unittest.mock.patch.dict(os.environ, {"PATH": ""}):
            for ver in ("4.9.3", "4.9.4", "5.0.0"):
                info = json.loads(PODMAN_INFO)
                info["version"]["Version"] = ver
                with self.subTest(version=ver):
                    rc, out, err, root = self.doctor(stdout=json.dumps(info))
                    self.assertEqual(rc, 0)
                    lines = out.splitlines()
                    for tool in cli.REQUIRED_TOOLS:
                        self.assertIn(f"ok: tool present: {tool}", lines)
                    self.assertFalse(
                        any(l.startswith("fail: tool present:") for l in lines))
                    if ver == "4.9.3":
                        self.assertIn("ok: podman 4.9.3 (tested version)", out)
                    else:
                        self.assertIn(f"warn: podman {ver} untested", out)
                    self.assertEqual(err, "")
                    self.assertFalse(root.exists())

    def test_missing_required_tools_fail(self):
        cases = [(tool,) for tool in cli.REQUIRED_TOOLS]
        cases.append(tuple(cli.REQUIRED_TOOLS))
        for missing in cases:
            with self.subTest(missing=missing):
                rc, out, err, root = self.doctor(missing_tools=missing)
                self.assertEqual(rc, 1)
                lines = out.splitlines()
                for tool in cli.REQUIRED_TOOLS:
                    if tool in missing:
                        self.assertIn(f"fail: tool present: {tool}", lines)
                    else:
                        self.assertIn(f"ok: tool present: {tool}", lines)
                        self.assertNotIn(
                            f"fail: tool present: {tool}", lines)
                self.assertIn("ok: podman rootless", out)
                self.assertIn("ok: podman 4.9.3 (tested version)", out)
                self.assertEqual(err, "")
                self.assertFalse(root.exists())


class CliCommands(unittest.TestCase):
    def test_status_readonly_no_state_created(self):
        rc, out, err, root = run_cli(["status"])
        self.assertEqual((rc, "not initialized" in out, root.exists()),
                         (0, True, False))

    def test_unsafe_instance_name(self):
        rc, out, err, root = run_cli(["status", "--instance", "Bad Name"])
        self.assertEqual((rc, "invalid instance name" in err, root.exists()),
                         (1, True, False))

    def test_unavailable_commands_fail_closed(self):
        for cmd in ("up", "stop", "verify", "chat", "demo",
                    "backup", "restore", "evidence"):
            rc, out, err, root = run_cli([cmd])
            self.assertEqual((rc, "not implemented" in err, root.exists()),
                             (3, True, False), cmd)

    def test_init_requires_ack(self):
        lock = REPO / ".devin" / "artifacts.lock.json"
        rc, out, err, root = run_cli(["init", "--artifacts-lock", str(lock)])
        self.assertEqual(rc, 1)
        self.assertIn("acknowledge-prototype-no-lsm", err)

    def test_init_missing_lock_fails(self):
        rc, out, err, root = run_cli(
            ["init", "--acknowledge-prototype-no-lsm",
             "--artifacts-lock", "/nonexistent/lock.json"])
        self.assertEqual(rc, 1)
        self.assertIn("cannot", err)
        self.assertNotIn("Traceback", err)

    def test_init_invalid_lock_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as lock:
            lock.write(b"{}")
        rc, out, err, root = run_cli(
            ["init", "--acknowledge-prototype-no-lsm",
             "--artifacts-lock", lock.name])
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", err)
        os.unlink(lock.name)

    def test_prepare_requires_allow_network(self):
        rc, out, err, root = run_cli(["prepare"])
        self.assertEqual(rc, 1)
        self.assertIn("--allow-network", err)
        self.assertNotIn("Traceback", err)

    def test_prepare_missing_instance_fails(self):
        rc, out, err, root = run_cli(["prepare", "--allow-network"])
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", err)

    def test_init_success_then_status(self):
        xdg = tempfile.mkdtemp()
        lock = REPO / ".devin" / "artifacts.lock.json"
        rc, out, err, root = run_cli(
            ["init", "--acknowledge-prototype-no-lsm",
             "--artifacts-lock", str(lock)], xdg=xdg)
        self.assertEqual(rc, 0)
        mp = root / "instances" / "demo" / "manifest.json"
        self.assertEqual(stat.S_IMODE(mp.lstat().st_mode), 0o600)
        manifest = json.loads(mp.read_text())
        self.assertEqual(manifest["schema"], "secure-local-llm/instance@1")
        self.assertTrue(manifest["exceptions"]["prototype_no_lsm_acknowledged"])
        rc, out, err, _ = run_cli(["status"], xdg=xdg)
        self.assertEqual((rc, "initialized" in out), (0, True))


class LauncherIsolation(unittest.TestCase):
    def test_hostile_cwd_and_pythonpath_cannot_inject(self):
        with tempfile.TemporaryDirectory() as hostile:
            pkg = Path(hostile) / "local_agent"
            pkg.mkdir()
            marker = Path(hostile) / "PWNED"
            (pkg / "__init__.py").write_text(
                f"open({str(marker)!r}, 'w').write('pwned')\n"
                "print('MARKER EXECUTED')\n")
            (pkg / "cli.py").write_text(
                "def main(argv):\n    print('MARKER EXECUTED')\n")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/tmp"),
                "PYTHONPATH": hostile,
                "XDG_STATE_HOME": tempfile.mkdtemp(),
            }
            proc = subprocess.run(
                ["bash", str(REPO / "scripts" / "local-agent.sh"), "status"],
                cwd=hostile, env=env, capture_output=True, text=True, timeout=30)
            self.assertNotIn("MARKER EXECUTED", proc.stdout + proc.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("not initialized", proc.stdout)


if __name__ == "__main__":
    unittest.main()
