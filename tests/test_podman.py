"""Unit tests for shared podman helpers: subnets, routes, labels."""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import podman  # noqa: E402

UUID = "01234567-89ab-4cde-8f01-23456789abcd"


class FakeRes:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = False


class FakeRunner:
    def podman(self, args, timeout=None, extra_env=None, stdin_text=None,
               pass_fds=()):
        return FakeRes(0, "")

    def run(self, argv, timeout=None, extra_env=None, stdin_text=None,
            pass_fds=()):
        return FakeRes(0, "")


class RouteParsing(unittest.TestCase):
    def test_route_nets(self):
        text = (
            "default via 192.168.1.1 dev eth0 proto dhcp\n"
            "192.168.1.0/24 dev eth0 proto kernel scope link\n"
            "10.88.0.0/16 dev podman0 proto kernel scope link\n"
            "nexthop via 10.0.0.1 dev x\n"
        )
        nets = podman._route_nets(text)
        self.assertEqual(len(nets), 2)

    def test_route_nets_unparsable_fails(self):
        with self.assertRaises(podman.PodmanError):
            podman._route_nets("garbage line here\n")


class SubnetSelection(unittest.TestCase):
    def test_free_subnet_picks_unused(self):
        runner = FakeRunner()

        def run(argv, **kw):
            if argv[:2] == ["ip", "-4"]:
                return FakeRes(
                    0, "default via 192.168.1.1 dev e\n"
                       "192.168.1.0/24 dev e proto kernel scope link\n")
            return FakeRes(0, "")
        runner.run = run

        def podman_fn(args, **kw):
            joined = " ".join(args)
            if joined.startswith("network ls"):
                return FakeRes(0, "podman\n")
            if "Subnets" in joined:
                return FakeRes(
                    0, '[{"subnet":"10.240.0.0/28","gateway":"x"}]')
            if joined.startswith("unshare"):
                return FakeRes(0, "10.88.0.0/16 dev tap0\n")
            return FakeRes(0, "")
        runner.podman = podman_fn
        net = podman.free_subnet4(runner)
        self.assertEqual(str(net), "10.240.0.16/28")

    def test_unparsable_network_subnet_fails(self):
        runner = FakeRunner()

        def podman_fn(args, **kw):
            joined = " ".join(args)
            if joined.startswith("network ls"):
                return FakeRes(0, "podman\n")
            if "Subnets" in joined:
                return FakeRes(0, "not json")
            return FakeRes(0, "")
        runner.podman = podman_fn
        with self.assertRaises(podman.PodmanError):
            podman.podman_subnets(runner)


class ObjectLabels(unittest.TestCase):
    def test_label_source(self):
        runner = FakeRunner()
        runner.podman = lambda args, **kw: (
            FakeRes(0, '[{"labels":{"a":"b"}}]')
            if args[0] == "network" else FakeRes(0, '{"a":"c"}'))
        self.assertEqual(
            podman.object_labels(runner, "network", "x"), {"a": "b"})
        self.assertEqual(
            podman.object_labels(runner, "container", "x"), {"a": "c"})


if __name__ == "__main__":
    unittest.main()
