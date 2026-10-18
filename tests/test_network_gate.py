"""Pure assertions for the opt-in network gate."""

import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
sys.path.insert(
    0, str(Path(__file__).resolve().parent / "integration"))

import network_gate as gate

from local_agent import podman, runner

IMG_ID = "ab" * 32
POD_ID = "cd" * 32
NET_ID = "9e" * 32
NET6_ID = "77" * 32


class GateRunner:
    """Records podman argv; inspect/create results are programmable."""

    def __init__(self, inspect=None, create=POD_ID, net_create=None,
                 net_inspect=None, routes4=None, routes6=None,
                 ns_routes4=None, ns_routes6=None, nets="",
                 subnets=None):
        self.calls = []
        self.run_calls = []
        self.inspect = inspect
        self.create = create
        self.net_create = net_create
        self.net_inspect = net_inspect
        self.routes4 = routes4
        self.routes6 = routes6
        self.ns_routes4 = ns_routes4
        self.ns_routes6 = ns_routes6
        self.nets = nets
        self.subnets = subnets
        self.net_name = None

    def podman(self, args, timeout=60, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        if args[:2] == ["image", "inspect"]:
            if isinstance(self.inspect, BaseException):
                raise self.inspect
            return self.inspect if self.inspect is not None else _ok(
                IMG_ID + "\n")
        if args[:2] == ["network", "create"]:
            self.net_name = args[-1]
            if isinstance(self.net_create, BaseException):
                raise self.net_create
            return self.net_create if self.net_create is not None else _ok(
                "net\n")
        if args[:2] == ["network", "inspect"]:
            if "--format" in args:
                if isinstance(self.subnets, BaseException):
                    raise self.subnets
                return self.subnets if self.subnets is not None else _ok(
                    "[]\n")
            if isinstance(self.net_inspect, BaseException):
                raise self.net_inspect
            return self.net_inspect if self.net_inspect is not None else _ok(
                "[]\n")
        if args[:2] == ["network", "ls"]:
            return _ok(self.nets)
        if args[:1] == ["unshare"]:
            res = self.ns_routes4 if args[3] == "-4" else self.ns_routes6
            if isinstance(res, BaseException):
                raise res
            return res if res is not None else _ok("[]\n")
        if args[:2] == ["pod", "create"]:
            return _ok(self.create + "\n")
        if args[:2] == ["pod", "inspect"]:
            if "--format" in args:
                return _ok("infra123\n")
            return runner.CommandResult(list(args), 1, "", "absent")
        if args[:1] in (["run"], ["rm"]):
            return _ok("wl123\n")
        if args[:1] == ["inspect"]:
            if "--format" in args:
                return _ok(json.dumps(
                    {self.net_name or "net": {"IPAddress": "10.7.7.7"}}))
            return runner.CommandResult(list(args), 1, "", "absent")
        return _ok("")

    def run(self, argv, timeout=60, extra_env=None, stdin_text=None,
            pass_fds=()):
        self.run_calls.append(list(argv))
        if argv[:1] == ["ip"]:
            res = self.routes4 if argv[1] == "-4" else self.routes6
            if isinstance(res, BaseException):
                raise res
            return res if res is not None else _ok("[]\n")
        raise AssertionError(f"unexpected run argv {argv}")


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


class NetworkRegistration(unittest.TestCase):
    """Successful creates register the name before inspecting it."""

    def _gate(self, net_inspect=None, net_create=None):
        g = gate.Gate(GateRunner(
            net_inspect=net_inspect, net_create=net_create))
        g.note = lambda msg: None
        return g

    def _v4(self, g, name="net-a"):
        return g.make_network(
            ["--internal", "--disable-dns", "--subnet", "10.253.9.0/28"],
            name)

    def _v6(self, g):
        return g.ipv6_gate("harness", "base")

    def _bad_inspects(self):
        return (
            runner.CommandResult([], 1, "", "boom"),
            runner.CommandResult([], 124, "", "timed out", timed_out=True),
            _ok("not json\n"),
            _ok(json.dumps([{}]) + "\n"),
            _ok(json.dumps([{"id": "short"}]) + "\n"),
            _ok(json.dumps([{"id": "zz" * 32}]) + "\n"),
        )

    def test_v4_success_replaces_name_with_validated_id(self):
        info = json.dumps([{"id": NET_ID}])
        g = self._gate(net_inspect=_ok(info + "\n"))
        net_id = self._v4(g, "net-a")
        self.assertEqual(net_id, NET_ID)
        self.assertEqual(g.created["networks"], [NET_ID])
        self.assertNotIn("net-a", g.created["networks"])
        self.assertEqual(
            g.network_meta,
            {NET_ID: hashlib.sha256(info.encode()).hexdigest()})

    def test_v4_inspect_failures_retain_name(self):
        for res in self._bad_inspects():
            with self.subTest(rc=res.returncode, out=res.stdout[:20]):
                g = self._gate(net_inspect=res)
                with self.assertRaises(RuntimeError):
                    self._v4(g)
                self.assertEqual(g.created["networks"], ["net-a"])

    def test_v4_inspect_spawn_failure_retains_name(self):
        g = self._gate(net_inspect=runner.RunnerError("cannot exec"))
        with self.assertRaises(runner.RunnerError):
            self._v4(g)
        self.assertEqual(g.created["networks"], ["net-a"])

    def test_v4_failed_create_registers_nothing(self):
        for res in (runner.CommandResult([], 1, "", "denied"),
                    runner.CommandResult([], 124, "", "t", timed_out=True)):
            g = self._gate(net_create=res)
            with self.assertRaises(RuntimeError):
                self._v4(g)
            self.assertEqual(g.created["networks"], [])
            self.assertFalse(any(
                c[:2] == ["network", "inspect"] for c in g.r.calls))

    def test_v4_cleanup_targets_retained_name(self):
        g = self._gate(
            net_inspect=runner.CommandResult([], 1, "", "boom"))
        with self.assertRaises(RuntimeError):
            self._v4(g)
        g.cleanup()
        self.assertIn(["network", "rm", "net-a"], g.r.calls)

    def test_v6_success_replaces_name_with_validated_id(self):
        info = json.dumps([{"id": NET6_ID}])
        g = self._gate(net_inspect=_ok(info + "\n"))
        self._v6(g)
        name = f"sllmg6-{g.nonce}"
        self.assertEqual(g.created["networks"], [NET6_ID])
        self.assertNotIn(name, g.created["networks"])
        self.assertEqual(
            g.network_meta,
            {NET6_ID: hashlib.sha256(info.encode()).hexdigest()})

    def test_v6_inspect_failures_retain_name(self):
        for res in self._bad_inspects():
            with self.subTest(rc=res.returncode, out=res.stdout[:20]):
                g = self._gate(net_inspect=res)
                with self.assertRaises(RuntimeError):
                    self._v6(g)
                self.assertEqual(
                    g.created["networks"], [f"sllmg6-{g.nonce}"])

    def test_v6_inspect_spawn_failure_retains_name(self):
        g = self._gate(net_inspect=runner.RunnerError("cannot exec"))
        with self.assertRaises(runner.RunnerError):
            self._v6(g)
        self.assertEqual(g.created["networks"], [f"sllmg6-{g.nonce}"])

    def test_v6_failed_create_records_blocked_and_registers_nothing(self):
        g = self._gate(net_create=runner.CommandResult(
            [], 1, "", "no v6 support"))
        self._v6(g)
        self.assertEqual(g.created["networks"], [])
        res = [r for r in g.results if r["name"] == "ipv6 gate"]
        self.assertEqual(len(res), 1)
        self.assertFalse(res[0]["ok"])
        self.assertIn("blocked", res[0]["detail"])

    def test_v6_cleanup_targets_retained_name(self):
        g = self._gate(
            net_inspect=runner.CommandResult([], 1, "", "boom"))
        name = f"sllmg6-{g.nonce}"
        with self.assertRaises(RuntimeError):
            self._v6(g)
        g.cleanup()
        self.assertIn(["network", "rm", name], g.r.calls)


class SubnetSelection(unittest.TestCase):
    """used_networks reads host and rootless-namespace routes."""

    def _gate(self, **kw):
        g = gate.Gate(GateRunner(**kw))
        g.note = lambda msg: None
        return g

    def test_collects_networks_and_all_four_route_views(self):
        g = self._gate(
            nets="othernet\n",
            subnets=_ok(json.dumps([{"subnet": "10.11.0.0/16"}]) + "\n"),
            routes4=_ok(json.dumps([{"dst": "10.9.0.0/16"}]) + "\n"),
            routes6=_ok(json.dumps([{"dst": "fd00:9::/64"}]) + "\n"),
            ns_routes4=_ok(json.dumps([{"dst": "10.10.0.0/16"}]) + "\n"),
            ns_routes6=_ok(json.dumps([{"dst": "fd00:10::/64"}]) + "\n"))
        used = {str(u) for u in g.used_networks()}
        self.assertEqual(used, {"10.11.0.0/16", "10.9.0.0/16",
                                "fd00:9::/64", "10.10.0.0/16",
                                "fd00:10::/64"})
        self.assertTrue(any(
            c[:3] == ["unshare", "--rootless-netns", "ip"]
            for c in g.r.calls))

    def test_rootless_v4_overlap_rejects_first_candidate(self):
        g = self._gate(ns_routes4=_ok(
            json.dumps([{"dst": "10.253.0.0/28"}]) + "\n"))
        with mock.patch.object(gate.secrets, "randbelow",
                               side_effect=[0, 1]) as rb:
            self.assertEqual(g.free_subnet4(), "10.253.1.0/28")
        self.assertEqual(rb.call_count, 2)

    def test_rootless_v6_overlap_rejects_first_candidate(self):
        g = self._gate(ns_routes6=_ok(
            json.dumps([{"dst": "fd00:5354:4c4d::/64"}]) + "\n"))
        with mock.patch.object(gate.secrets, "randbelow",
                               side_effect=[0, 1]) as rb:
            self.assertEqual(g.free_subnet6(), "fd00:5354:4c4d:1::/64")
        self.assertEqual(rb.call_count, 2)

    def test_host_route_collision_still_rejects(self):
        g = self._gate(routes4=_ok(
            json.dumps([{"dst": "10.253.0.0/28"}]) + "\n"))
        with mock.patch.object(gate.secrets, "randbelow",
                               side_effect=[0, 1]):
            self.assertEqual(g.free_subnet4(), "10.253.1.0/28")

    def test_podman_network_collision_still_rejects(self):
        g = self._gate(nets="othernet\n",
                       subnets=_ok(json.dumps(
                           [{"subnet": "10.253.0.0/28"}]) + "\n"))
        with mock.patch.object(gate.secrets, "randbelow",
                               side_effect=[0, 1]):
            self.assertEqual(g.free_subnet4(), "10.253.1.0/28")

    def test_default_routes_ignored(self):
        doc = json.dumps([{"dst": "default", "via": "x"},
                          {"dst": None}, {"note": "no-dst"}]) + "\n"
        g = self._gate(routes4=_ok(doc), routes6=_ok(doc),
                       ns_routes4=_ok(doc), ns_routes6=_ok(doc))
        with mock.patch.object(gate.secrets, "randbelow",
                               return_value=7) as rb:
            self.assertEqual(g.free_subnet4(), "10.253.7.0/28")
        self.assertEqual(rb.call_count, 1)

    def test_route_failures_fail_closed(self):
        cases = [
            runner.CommandResult([], 1, "", "denied"),
            runner.CommandResult([], 124, "", "t", timed_out=True),
            runner.RunnerError("spawn failure"),
            _ok("not json\n"),
            _ok(json.dumps({"not": "list"}) + "\n"),
            _ok(json.dumps(["not-an-object"]) + "\n"),
            _ok(json.dumps([{"dst": "999.1.2.0/28"}]) + "\n"),
            _ok(json.dumps([{"dst": 16909060}]) + "\n"),
            _ok(json.dumps([{"dst": True}]) + "\n"),
            _ok(json.dumps([{"dst": ["10.9.0.0/16"]}]) + "\n"),
            _ok(json.dumps([{"dst": {"x": "y"}}]) + "\n"),
        ]
        for res in cases:
            with self.subTest(res=repr(res)[:40]):
                for kw in ({"routes4": res}, {"routes6": res},
                           {"ns_routes4": res}, {"ns_routes6": res}):
                    g = self._gate(**kw)
                    with self.assertRaises(
                            (RuntimeError, runner.RunnerError)):
                        g.free_subnet4()


if __name__ == "__main__":
    unittest.main()
