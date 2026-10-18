"""Pure assertions for the opt-in network gate."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
sys.path.insert(
    0, str(Path(__file__).resolve().parent / "integration"))

import network_gate as gate

from local_agent import podman, runner

IMG_ID = "ab" * 32
POD_ID = "cd" * 32


class GateRunner:
    """Records podman argv; image-inspect result is programmable."""

    def __init__(self, inspect=None, create=POD_ID):
        self.calls = []
        self.inspect = inspect
        self.create = create

    def podman(self, args, timeout=60, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        if args[:2] == ["image", "inspect"]:
            if isinstance(self.inspect, BaseException):
                raise self.inspect
            return self.inspect
        if args[:2] == ["pod", "create"]:
            return runner.CommandResult(
                list(args), 0, self.create + "\n", "")
        if args[:1] == ["run"]:
            return runner.CommandResult(list(args), 0, "wl123\n", "")
        return runner.CommandResult(list(args), 0, "", "")

    def run(self, argv, timeout=60, extra_env=None, stdin_text=None,
            pass_fds=()):
        raise AssertionError(f"unexpected non-podman argv {argv}")


def _ok(stdout):
    return runner.CommandResult([], 0, stdout, "")


class MakePod(unittest.TestCase):
    def _gate(self, inspect=None):
        g = gate.Gate(GateRunner(
            inspect=_ok(IMG_ID + "\n") if inspect is None else inspect))
        g.note = lambda msg: None
        return g

    def _pod_argv(self, g):
        for call in g.r.calls:
            if call[:2] == ["pod", "create"]:
                return call
        self.fail("no pod create issued")

    def _no_pod_create(self, g):
        return not any(c[:2] == ["pod", "create"] for c in g.r.calls)

    def test_inspect_precedes_create_and_passes_validated_id(self):
        g = self._gate()
        pod_id = g.make_pod("p", "net", "base")
        self.assertEqual(g.r.calls[0][:2], ["image", "inspect"])
        self.assertEqual(g.r.calls[1][:2], ["pod", "create"])
        argv = self._pod_argv(g)
        self.assertEqual(argv[argv.index("--infra-image") + 1], IMG_ID)
        self.assertEqual(pod_id, POD_ID)

    def test_sha256_prefixed_inspect_output_yields_bare_id(self):
        g = self._gate(inspect=_ok("sha256:" + IMG_ID + "\n"))
        g.make_pod("p", "net", "base")
        argv = self._pod_argv(g)
        self.assertEqual(argv[argv.index("--infra-image") + 1], IMG_ID)

    def test_custom_pinned_ref_resolves_its_own_id(self):
        other = "ef" * 32
        ref = "registry.test/base@sha256:" + "12" * 32
        g = self._gate(inspect=_ok(other + "\n"))
        g.make_pod("p", "net", ref)
        self.assertIn(ref, g.r.calls[0])
        argv = self._pod_argv(g)
        self.assertEqual(argv[argv.index("--infra-image") + 1], other)

    def test_missing_image_blocks_pod_create(self):
        g = self._gate(inspect=runner.CommandResult(
            [], 1, "", "Error: no such image"))
        with self.assertRaises(podman.PodmanError):
            g.make_pod("p", "net", "base")
        self.assertTrue(self._no_pod_create(g))

    def test_invalid_inspect_ids_block_pod_create(self):
        for out in ("not-an-id\n", "ab" * 8 + "\n", "zz" * 32 + "\n", "\n"):
            with self.subTest(out=out):
                g = self._gate(inspect=_ok(out))
                with self.assertRaises(podman.PodmanError):
                    g.make_pod("p", "net", "base")
                self.assertTrue(self._no_pod_create(g))

    def test_inspect_timeout_blocks_pod_create(self):
        g = self._gate(inspect=runner.CommandResult(
            [], 1, "", "timed out", timed_out=True))
        with self.assertRaises(podman.PodmanError):
            g.make_pod("p", "net", "base")
        self.assertTrue(self._no_pod_create(g))

    def test_inspect_spawn_failure_blocks_pod_create(self):
        g = self._gate(inspect=runner.RunnerError("cannot execute"))
        with self.assertRaises(podman.PodmanError):
            g.make_pod("p", "net", "base")
        self.assertTrue(self._no_pod_create(g))

    def test_pod_create_has_no_unsupported_pull_flag(self):
        g = self._gate()
        g.make_pod("p", "net", "base")
        argv = self._pod_argv(g)
        self.assertFalse(any(a.startswith("--pull") for a in argv))

    def test_run_container_keeps_pull_never(self):
        g = self._gate()
        g.run_container("wl", "podname", "img", True)
        argv = [c for c in g.r.calls if c[:1] == ["run"]][0]
        self.assertIn("--pull=never", argv)


if __name__ == "__main__":
    unittest.main()
