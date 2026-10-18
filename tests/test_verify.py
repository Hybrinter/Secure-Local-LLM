"""Live-verifier unit tests: probe failures and probe isolation."""

import importlib.util
import inspect as _inspect_mod
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_agent import verify  # noqa: E402
from local_agent import verify_spec as vspec  # noqa: E402
from verify_fixtures import (  # noqa: E402
    FakeRes, FakeRunner, _expects, _fail_names,
)


class LiveProbeFailures(unittest.TestCase):
    def test_proc_probe_failure(self):
        r = verify.Result()
        verify._proc_status_checks(
            r, FakeRunner({"exec": FakeRes(1, "", "dead")}), "c" * 8,
            "harness")
        self.assertIn("harness /proc/1/status", _fail_names(r))

    def test_proc_empty_output_fails(self):
        r = verify.Result()
        verify._proc_status_checks(r, FakeRunner(), "c" * 8, "harness")
        fails = _fail_names(r)
        self.assertIn("harness uid", fails)
        self.assertIn("harness CapEff zero", fails)

    def test_uid_parse(self):
        status = ("Name:\topencode\nUid:\t1000\t1000\t1000\t1000\n"
                  "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
                  "NoNewPrivs:\t1\nSeccomp:\t2\n")
        r = verify.Result()
        verify._proc_status_checks(
            r, FakeRunner({"exec": FakeRes(0, status)}), "c" * 8,
            "harness")
        self.assertEqual(_fail_names(r), [])

    def test_uid_partial_rejected(self):
        status = ("Uid:\t1000\t0\t1000\t1000\n"
                  "CapEff:\t0\nCapBnd:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n")
        r = verify.Result()
        verify._proc_status_checks(
            r, FakeRunner({"exec": FakeRes(0, status)}), "c" * 8,
            "harness")
        self.assertIn("harness uid", _fail_names(r))

    def test_swap_max_positive_fails(self):
        exp = _expects()["git"]

        def fn(args, **kw):
            joined = " ".join(args)
            if "memory.max" in joined:
                return FakeRes(0, "536870912\n")
            if "memory.swap.max" in joined:
                return FakeRes(0, "268435456\n")
            if "pids.max" in joined:
                return FakeRes(0, "64\n")
            if "cpu.max" in joined:
                return FakeRes(0, "100000 100000\n")
            return FakeRes(1, "")
        runner = FakeRunner()
        runner.podman = fn
        r = verify.Result()
        verify._cgroup_checks(r, runner, "c" * 8, "git", exp)
        self.assertIn("git cgroup swap.max (no extra swap)",
                      _fail_names(r))

    def test_missing_cgroup_file_fails(self):
        exp = _expects()["git"]

        def fn(args, **kw):
            joined = " ".join(args)
            if "memory.max" in joined:
                return FakeRes(0, "536870912\n")
            return FakeRes(1, "", "no such file")
        runner = FakeRunner()
        runner.podman = fn
        r = verify.Result()
        verify._cgroup_checks(r, runner, "c" * 8, "git", exp)
        fails = _fail_names(r)
        self.assertIn("git cgroup swap.max", fails)
        self.assertIn("git cgroup pids.max", fails)
        self.assertIn("git cgroup cpu.max", fails)

    def test_ns_probe_failure(self):
        r = verify.Result()
        out = verify._ns_inventory(r, FakeRunner(), "git", "c" * 8)
        self.assertIsNone(out)
        self.assertIn("git namespace readlinks", _fail_names(r))

    def test_ns_inventory_parses(self):
        lines = "\n".join(f"{t}:[{i}]" for i, t in
                          enumerate(vspec.NS_TYPES))
        r = verify.Result()
        out = verify._ns_inventory(
            r, FakeRunner({"exec": FakeRes(0, lines + "\n")}), "git",
            "c" * 8)
        self.assertEqual(out["net"], "net:[0]")
        self.assertEqual(_fail_names(r), [])


class ProbeIsolation(unittest.TestCase):
    def test_probes_isolated_python_only(self):
        mods = ["verify"]
        if importlib.util.find_spec("local_agent.runtime") is not None:
            mods.append("runtime")
        for mod in mods:
            src = _inspect_mod.getsource(
                __import__(f"local_agent.{mod}", fromlist=["x"]))
            self.assertNotIn('"python3", "-c"', src)
            self.assertNotIn("'python3', '-c'", src)
            self.assertIn('"-I"', src)
            self.assertIn('"-B"', src)

    def test_exec_py_isolated_argv(self):
        seen = []

        def fn(args, **kw):
            seen.append((list(args), kw.get("timeout")))
            return FakeRes(0, "ok")
        runner = FakeRunner()
        runner.podman = fn
        out = verify._exec_py(runner, "c" * 8, "print(1)", timeout=17)
        self.assertEqual(out, "ok")
        self.assertEqual(
            seen[0],
            (["exec", "c" * 8, "python3", "-I", "-B", "-c",
              "print(1)"], 17))
        verify._exec_py(runner, "d" * 8, "print(2)")
        self.assertEqual(
            seen[1],
            (["exec", "d" * 8, "python3", "-I", "-B", "-c",
              "print(2)"], 30))


if __name__ == "__main__":
    unittest.main()
