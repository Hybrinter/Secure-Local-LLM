"""Live-verifier unit tests: probe failures and probe isolation."""

import contextlib
import importlib.util
import inspect as _inspect_mod
import io
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


class ListenerProbeExec(unittest.TestCase):
    EXPECTED = [("0100007F", 8080), ("0100007F", 4096)]
    HDR = "  sl  local_address rem_address   st\n"

    @staticmethod
    def _row(addr, port, state="0A"):
        return (f"  0: {addr}:{port:04X} 00000000:0000 {state}"
                " 0 0 0 0\n")

    def _good4(self):
        return (self.HDR + self._row("0100007F", 8080)
                + self._row("0100007F", 4096)
                + self._row("0100007F", 12345, "01"))

    def _probe_script(self):
        runner = FakeRunner()
        verify._listener_check(
            verify.Result(), runner, "c" * 8, "pod netns", [])
        return runner.calls[0][-1]

    def _exec_probe(self, script, files):
        def fake_open(path, *args, **kwargs):
            entry = files[path]
            if isinstance(entry, BaseException):
                raise entry
            return io.StringIO(entry)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(compile(script, "<listener-probe>", "exec"),
                     {"open": fake_open})
        except Exception:
            return 1, ""
        return 0, buf.getvalue()

    def _run_check(self, files):
        script = self._probe_script()
        rc, out = self._exec_probe(script, files)
        runner = FakeRunner()
        runner.podman = lambda args, **kw: FakeRes(rc, out)
        r = verify.Result()
        verify._listener_check(
            r, runner, "c" * 8, "pod netns", self.EXPECTED)
        return r

    def test_correct_ipv4_absent_tcp6_passes(self):
        r = self._run_check({
            "/proc/net/tcp": self._good4(),
            "/proc/net/tcp6": FileNotFoundError(),
        })
        self.assertEqual(_fail_names(r), [])

    def test_empty_tcp6_passes(self):
        r = self._run_check({
            "/proc/net/tcp": self._good4(),
            "/proc/net/tcp6": self.HDR,
        })
        self.assertEqual(_fail_names(r), [])

    def test_unexpected_ipv6_listen_fails(self):
        r = self._run_check({
            "/proc/net/tcp": self._good4(),
            "/proc/net/tcp6":
                self.HDR + self._row("0" * 32, 8080),
        })
        self.assertIn("pod netns listeners", _fail_names(r))

    def test_non_listen_ipv6_ignored(self):
        r = self._run_check({
            "/proc/net/tcp": self._good4(),
            "/proc/net/tcp6":
                self.HDR + self._row("0" * 32, 8080, "01"),
        })
        self.assertEqual(_fail_names(r), [])

    def test_ipv4_mismatch_fails(self):
        r = self._run_check({
            "/proc/net/tcp": self.HDR + self._row("0100007F", 8080),
            "/proc/net/tcp6": FileNotFoundError(),
        })
        self.assertIn("pod netns listeners", _fail_names(r))

    def test_missing_ipv4_fails(self):
        r = self._run_check({
            "/proc/net/tcp": FileNotFoundError(),
            "/proc/net/tcp6": FileNotFoundError(),
        })
        self.assertIn("pod netns listeners", _fail_names(r))

    def test_unreadable_ipv4_fails(self):
        r = self._run_check({
            "/proc/net/tcp": PermissionError("denied"),
            "/proc/net/tcp6": self.HDR,
        })
        self.assertIn("pod netns listeners", _fail_names(r))

    def test_tcp6_permission_error_fails(self):
        r = self._run_check({
            "/proc/net/tcp": self._good4(),
            "/proc/net/tcp6": PermissionError("denied"),
        })
        self.assertIn("pod netns listeners", _fail_names(r))

    def test_tcp6_io_error_fails(self):
        r = self._run_check({
            "/proc/net/tcp": self._good4(),
            "/proc/net/tcp6": OSError("io error"),
        })
        self.assertIn("pod netns listeners", _fail_names(r))


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
