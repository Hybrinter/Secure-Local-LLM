"""Pure assertions for the opt-in isolation gate."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
sys.path.insert(
    0, str(Path(__file__).resolve().parent / "integration"))

import isolation_gate as gate


class Constants(unittest.TestCase):
    def test_expected_dests_complete(self):
        self.assertIn("/workspace", gate.EXPECTED_HARNESS_DESTS)
        self.assertIn("/state", gate.EXPECTED_HARNESS_DESTS)
        self.assertEqual(len(gate.EXPECTED_HARNESS_DESTS), 9)
        self.assertNotIn("/models", gate.EXPECTED_HARNESS_DESTS)
        self.assertNotIn("/other-workspace", gate.EXPECTED_HARNESS_DESTS)

    def test_probe_argv_isolated_python(self):
        calls = []

        class R:
            def podman(self, args, timeout=60):
                calls.append(args)
                from local_agent.runner import CommandResult
                return CommandResult(args, 0, "{}", "", False)

        g = gate.Gate(R())
        g.exec_probe("cid123", ["python3", "-I", "-B", "-c", "x"])
        self.assertEqual(
            calls[0][:5],
            ["exec", "cid123", "python3", "-I", "-B"])
        self.assertIn("O_NOFOLLOW", gate.H_PROBE)
        self.assertNotIn("password", gate.H_PROBE)

    def test_model_probe_no_trunc(self):
        self.assertIn("O_WRONLY|O_NOFOLLOW", gate.MODEL_WRITE_PROBE)
        self.assertNotIn("O_TRUNC", gate.MODEL_WRITE_PROBE)
        self.assertNotIn("O_CREAT", gate.MODEL_WRITE_PROBE)


class Parser(unittest.TestCase):
    def test_requires_run_flag(self):
        args = gate.build_parser().parse_args(["--run"])
        self.assertTrue(args.run)
        self.assertEqual(args.instance, "demo")

    def test_instance_selectable(self):
        args = gate.build_parser().parse_args(
            ["--run", "--instance", "demo-restored"])
        self.assertEqual(args.instance, "demo-restored")

    def test_main_without_run_prints_help(self):
        self.assertEqual(gate.main([]), 2)


class Labels(unittest.TestCase):
    def test_labels_ok(self):
        self.assertTrue(gate._labels_ok(
            {gate.TEST_LABEL: "isolation-gate",
             f"{gate.TEST_LABEL}.nonce": "abc"}, "abc"))
        self.assertFalse(gate._labels_ok(
            {gate.TEST_LABEL: "isolation-gate"}, "abc"))
        self.assertFalse(gate._labels_ok({}, "abc"))


if __name__ == "__main__":
    unittest.main()
