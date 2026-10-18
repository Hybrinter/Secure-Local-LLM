"""Pure assertions for the opt-in network gate."""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
sys.path.insert(
    0, str(Path(__file__).resolve().parent / "integration"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import network_gate as gate
import test_network as tn

from local_agent import network, podman, runner

IMG_ID = "ab" * 32
POD_ID = "cd" * 32
NET_ID = "9e" * 32
NET6_ID = "77" * 32


class GateRunner:
    """Records podman argv; inspect/create results are programmable."""

    def __init__(self, inspect=None, create=POD_ID, net_create=None,
                 net_inspect=None, routes4=None, routes6=None,
                 ns_routes4=None, ns_routes6=None, nets="",
                 subnets=None, ns_exec=None, pid_res=None,
                 helper_apply=None, helper_read=None, exists=None,
                 fail_remove=(), nets_v6=None, connect_map=None):
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
        self.ns_exec = ns_exec
        self.pid_res = pid_res
        self.helper_apply = helper_apply
        self.helper_read = helper_read
        self.exists = dict(exists or {})
        self.fail_remove = set(fail_remove)
        self.nets_v6 = nets_v6
        self.connect_map = dict(connect_map or {})
        self.net_name = None
        self.events = []

    def podman(self, args, timeout=60, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        self.events.append(("podman", list(args)))
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
        if len(args) >= 2 and args[1] == "exists":
            res = self.exists.get(args[0])
            if isinstance(res, BaseException):
                raise res
            return res if res is not None else runner.CommandResult(
                list(args), 1, "", "absent")
        if args[:1] == ["run"]:
            return _ok("wl123\n")
        if args[0] == "rm" or (len(args) > 1 and args[1] == "rm"):
            if args[-1] in self.fail_remove:
                raise runner.RunnerError("cannot execute rm")
            return _ok("")
        if args[:1] == ["exec"]:
            if len(args) > 2 and args[2] == "readlink":
                res = self.ns_exec
                if isinstance(res, BaseException):
                    raise res
                return res if res is not None else _ok(
                    "user:[4026]\nnet:[4027]\n")
            if len(args) > 1 and args[1] == "-d":
                return _ok("")
            if len(args) > 6 and args[5] == "-c":
                res = self.connect_map.get(args[-3])
                if isinstance(res, BaseException):
                    raise res
                return res if res is not None else _ok("echo-ok\n")
            return _ok("")
        if args[:1] == ["inspect"]:
            if "{{.State.Pid}}" in args:
                res = self.pid_res
                if isinstance(res, BaseException):
                    raise res
                return res if res is not None else _ok("4321\n")
            if "{{json .NetworkSettings.Networks}}" in args:
                entry = {"IPAddress": "10.7.7.7"}
                if self.nets_v6:
                    entry["GlobalIPv6Address"] = self.nets_v6
                return _ok(json.dumps({self.net_name or "net": entry}))
            if "--format" in args:
                return _ok("wl123\n")
            return runner.CommandResult(list(args), 1, "", "absent")
        return _ok("")

    def run(self, argv, timeout=60, extra_env=None, stdin_text=None,
            pass_fds=()):
        self.run_calls.append(list(argv))
        self.events.append(("run", list(argv)))
        if argv[:1] == ["ip"]:
            res = self.routes4 if argv[1] == "-4" else self.routes6
            if isinstance(res, BaseException):
                raise res
            return res if res is not None else _ok("[]\n")
        if argv[:1] == ["podman"]:
            op = json.loads(stdin_text or "{}").get("op", "")
            res = self.helper_apply if op == "apply" else self.helper_read
            if isinstance(res, BaseException):
                raise res
            return res if res is not None else _ok(
                json.dumps({"ok": True, "ruleset": "{}"}) + "\n")
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


class PolicyDrift(unittest.TestCase):
    """check_policy_drift accepts only a typed policy mismatch."""

    def _gate(self, **kw):
        g = gate.Gate(GateRunner(**kw))
        g.note = lambda msg: None
        return g

    def _record(self):
        canon = network.canonicalize_ruleset(
            json.dumps(tn.ruleset_doc()))
        return {"schema": "secure-local-llm/netpol@1", "table": tn.TABLE,
                "role": "workload", "peer_ip": tn.PEER, "peer_port": 2222,
                "canonical_sha256": network.canonical_hash(canon)}

    def _helper_ok(self, doc):
        return _ok(json.dumps(
            {"ok": True, "ruleset": json.dumps(doc)}) + "\n")

    def _drift_checks(self, g):
        return [r for r in g.results
                if r["name"] == "policy drift detected and refused"]

    def test_injected_rule_mismatch_records_pass(self):
        doc = tn.ruleset_doc(rule_edit=lambda e: e.append(
            tn._rule("output", [{"accept": None}])))
        g = self._gate(helper_read=self._helper_ok(doc))
        g.check_policy_drift("b" * 12, tn.TABLE, self._record())
        res = self._drift_checks(g)
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0]["ok"])

    def test_unchanged_policy_records_fail(self):
        g = self._gate(helper_read=self._helper_ok(tn.ruleset_doc()))
        g.check_policy_drift("b" * 12, tn.TABLE, self._record())
        res = self._drift_checks(g)
        self.assertEqual(len(res), 1)
        self.assertFalse(res[0]["ok"])

    def test_injection_failures_propagate(self):
        for res in (
            _ok(json.dumps({"ok": False, "error": "nft rc1"}) + "\n"),
            _ok("not json\n"),
            runner.CommandResult([], 124, "", "t", timed_out=True),
            runner.RunnerError("spawn"),
        ):
            with self.subTest(res=repr(res)[:40]):
                g = self._gate(helper_apply=res)
                with self.assertRaises(network.NetworkError):
                    g.check_policy_drift(
                        "b" * 12, tn.TABLE, self._record())
                self.assertEqual(self._drift_checks(g), [])

    def test_verify_failures_propagate_untyped(self):
        for res in (
            self._helper_ok({"nftables": [{"metainfo": {}}]}),
            self._helper_ok({"nftables": [{"odd": {}}]}),
            _ok(json.dumps({"ok": False, "error": "nft rc1"}) + "\n"),
            _ok("not json\n"),
            _ok(json.dumps({"ok": True, "ruleset": "not json"}) + "\n"),
            runner.CommandResult([], 124, "", "t", timed_out=True),
            runner.RunnerError("spawn"),
        ):
            with self.subTest(res=repr(res)[:40]):
                g = self._gate(helper_read=res)
                with self.assertRaises(network.NetworkError) as cm:
                    g.check_policy_drift(
                        "b" * 12, tn.TABLE, self._record())
                self.assertNotIsInstance(
                    cm.exception, network.PolicyMismatch)
                self.assertEqual(self._drift_checks(g), [])

    def test_namespace_inspect_failures_propagate(self):
        for res in (runner.CommandResult([], 1, "", "dead"),
                    runner.CommandResult([], 124, "", "t",
                                         timed_out=True)):
            g = self._gate(ns_exec=res)
            with self.assertRaises(network.NetworkError):
                g.check_policy_drift("b" * 12, tn.TABLE, self._record())
            self.assertEqual(self._drift_checks(g), [])

    def test_podman_pid_failure_propagates(self):
        g = self._gate(pid_res=runner.CommandResult([], 1, "", "x"))
        with self.assertRaises(network.NetworkError):
            g.check_policy_drift("b" * 12, tn.TABLE, self._record())
        self.assertEqual(self._drift_checks(g), [])


class CleanupVerification(unittest.TestCase):
    """Only a non-timeout exists status 1 proves absence."""

    KIND_KEY = {"container": "containers", "pod": "pods",
                "network": "networks"}

    def _gate(self, **kw):
        g = gate.Gate(GateRunner(**kw))
        g.note = lambda msg: None
        return g

    def _residue_check(self, g):
        return [r for r in g.results
                if r["name"] == "cleanup residue absent"]

    def test_exists_status_classification(self):
        for kind in ("container", "pod", "network"):
            for res, expect in (
                (runner.CommandResult([], 0, "", ""), "present"),
                (runner.CommandResult([], 1, "", ""), "absent"),
                (runner.CommandResult([], 125, "", "op err"),
                 "unknown"),
                (runner.CommandResult([], 2, "", "weird"),
                 "unknown"),
                (runner.CommandResult([], 1, "", "", timed_out=True),
                 "unknown"),
                (runner.RunnerError("spawn"), "unknown"),
            ):
                with self.subTest(kind=kind, res=repr(res)[:40]):
                    ident = "obj-" + kind
                    g = self._gate(exists={kind: res})
                    g.created[self.KIND_KEY[kind]].append(ident)
                    g.verify_cleanup()
                    chk = self._residue_check(g)
                    self.assertEqual(len(chk), 1)
                    if expect == "absent":
                        self.assertEqual(g.residual, [])
                        self.assertTrue(chk[0]["ok"])
                    elif expect == "present":
                        self.assertEqual(
                            g.residual, [f"{kind} {ident}"])
                        self.assertFalse(chk[0]["ok"])
                    else:
                        self.assertEqual(len(g.residual), 1)
                        self.assertIn("unknown", g.residual[0])
                        self.assertFalse(chk[0]["ok"])

    def test_removal_failure_continues_and_absence_passes(self):
        g = self._gate(fail_remove={"pod9"})
        g.created = {"pods": ["pod9"], "containers": ["c1"],
                     "networks": ["n1"]}
        g.cleanup()
        exists_calls = [c for c in g.r.calls
                        if len(c) > 1 and c[1] == "exists"]
        self.assertEqual(
            sorted(c[0] for c in exists_calls),
            ["container", "network", "pod"])
        self.assertTrue(any(
            c[:2] == ["pod", "rm"] and c[-1] == "pod9"
            for c in g.r.calls))
        self.assertTrue(any(
            c[:2] == ["network", "rm"] for c in g.r.calls))
        self.assertTrue(any(
            c[:1] == ["rm"] and c[-1] == "c1" for c in g.r.calls))
        self.assertEqual(g.residual, [])
        self.assertTrue(self._residue_check(g)[0]["ok"])

    def test_removal_failure_with_unknown_probe_records_unknown(self):
        g = self._gate(
            fail_remove={"c1"},
            exists={"container": runner.CommandResult(
                [], 125, "", "storage error")})
        g.created = {"pods": [], "containers": ["c1"],
                     "networks": ["n1"]}
        g.cleanup()
        self.assertEqual(len(g.residual), 1)
        self.assertIn("unknown", g.residual[0])
        self.assertIn("c1", g.residual[0])
        self.assertTrue(any(
            c[:2] == ["network", "exists"] for c in g.r.calls))
        self.assertFalse(self._residue_check(g)[0]["ok"])

    def test_main_unknown_cleanup_blocks_previously_passing_run(self):
        repo = Path(gate.__file__).resolve().parents[2]
        fake = GateRunner(exists={
            "container": runner.CommandResult([], 125, "", "op err")})

        def fake_run(g, harness, base):
            g.created["containers"].append("c" * 12)
            g.check("dummy check", True)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "state"
            old_cwd = os.getcwd()
            os.chdir(repo)
            try:
                with mock.patch.object(
                        sys, "argv", ["network_gate.py", "--run"]), \
                        mock.patch.object(
                            runner, "Runner", return_value=fake), \
                        mock.patch.object(
                            gate.state, "state_root",
                            return_value=root), \
                        mock.patch.object(
                            gate.state, "load_prepared",
                            return_value={"images":
                                          {"harness": "h" * 64}}), \
                        mock.patch.object(
                            gate.Gate, "run_gate",
                            lambda self, h, b: fake_run(self, h, b)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    rc = gate.main()
            finally:
                os.chdir(old_cwd)
            self.assertEqual(rc, 1)
            out = next(root.glob("network-gate-*.json"))
            payload = json.loads(out.read_text())
            self.assertEqual(payload["status"], "blocked")
            self.assertTrue(any(
                "unknown" in r for r in payload["residual"]))
            chk = [r for r in payload["results"]
                   if r["name"] == "cleanup residue absent"]
            self.assertTrue(chk)
            self.assertFalse(chk[0]["ok"])


class ListenerSource(unittest.TestCase):
    """TCP_LISTENER_SRC pins IPV6_V6ONLY on v6 sockets only."""

    class _Done(Exception):
        pass

    def _events(self, bind_addr):
        events = []

        class Sock:
            def setsockopt(self, *args):
                events.append(("setsockopt", args))

            def bind(self, addr):
                events.append(("bind", addr))

            def listen(self, backlog):
                events.append(("listen", backlog))
                raise ListenerSource._Done()

            def accept(self):
                raise AssertionError("accept reached")

        fake = types.SimpleNamespace(
            AF_INET6=10, AF_INET=2, SOL_SOCKET=1, SO_REUSEADDR=2,
            IPPROTO_IPV6=41, IPV6_V6ONLY=26, socket=lambda af: Sock())
        with mock.patch.dict(sys.modules, {"socket": fake}), \
                mock.patch.object(sys, "argv",
                                  ["x", bind_addr, "2222"]), \
                self.assertRaises(ListenerSource._Done):
            exec(compile(gate.TCP_LISTENER_SRC, "listener", "exec"), {})
        return events

    def test_ipv6_listener_sets_v6only_before_bind(self):
        events = self._events("::")
        v6only = ("setsockopt", (41, 26, 1))
        bind = ("bind", ("::", 2222))
        self.assertIn(v6only, events)
        self.assertIn(bind, events)
        self.assertLess(events.index(v6only), events.index(bind))

    def test_ipv4_listener_has_no_v6only(self):
        events = self._events("0.0.0.0")
        self.assertNotIn(("setsockopt", (41, 26, 1)), events)
        self.assertIn(("setsockopt", (1, 2, 1)), events)
        self.assertIn(("bind", ("0.0.0.0", 2222)), events)


class Ipv6Witnesses(unittest.TestCase):
    """Separate :: and 0.0.0.0 witnesses with pre-policy baselines."""

    def _gate(self, **kw):
        kw.setdefault(
            "net_inspect", _ok(json.dumps([{"id": NET6_ID}]) + "\n"))
        kw.setdefault("nets_v6", "fd00::7")
        g = gate.Gate(GateRunner(**kw))
        g.note = lambda msg: None
        return g

    def _connect_ev(self, g):
        return [(i, e[1][-3]) for i, e in enumerate(g.r.events)
                if e[0] == "podman" and e[1][0] == "exec"
                and len(e[1]) > 6 and e[1][5] == "-c"
                and e[1][1] != "-d"]

    def test_both_families_listen_and_baseline_before_policy(self):
        g = self._gate()
        order = []
        with mock.patch.object(gate.time, "sleep"), \
                mock.patch.object(
                    network, "install_policy",
                    side_effect=lambda *a: order.append(
                        len(g.r.events)) or {"table": "t"}) as inst:
            g.ipv6_gate("harness", "base")
        binds = [(c[-2], c[-1]) for c in g.r.calls
                 if c[:2] == ["exec", "-d"]]
        self.assertIn(("::", "2222"), binds)
        self.assertIn(("0.0.0.0", "2222"), binds)
        connects = self._connect_ev(g)
        self.assertEqual([ip for _, ip in connects[:2]],
                         ["fd00::7", "10.7.7.7"])
        self.assertEqual(len(order), 1)
        self.assertLess(connects[1][0], order[0])
        names = [r["name"] for r in g.results]
        self.assertIn("ipv6 baseline wl6->peer6 v6:2222", names)
        self.assertIn("ipv6 baseline wl6->peer6 v4:2222", names)
        self.assertIn("ipv6 non-lo denied after policy", names)
        self.assertIn("ipv6 policy wl6->peer6 v4:2222 allowed", names)

    def test_failed_baseline_blocks_policy_evidence(self):
        for ip, ver in (("fd00::7", "v6"), ("10.7.7.7", "v4")):
            other = "10.7.7.7" if ver == "v6" else "fd00::7"
            over = "v4" if ver == "v6" else "v6"
            with self.subTest(failed=ver):
                g = self._gate(connect_map={
                    ip: runner.CommandResult([], 1, "", "refused")})
                with mock.patch.object(gate.time, "sleep"), \
                        mock.patch.object(
                            network, "install_policy") as inst:
                    g.ipv6_gate("harness", "base")
                inst.assert_not_called()
                ips = {i for _, i in self._connect_ev(g)}
                self.assertIn(ip, ips)
                self.assertIn(other, ips)
                names = {r["name"]: r["ok"] for r in g.results}
                self.assertFalse(
                    names[f"ipv6 baseline wl6->peer6 {ver}:2222"])
                self.assertTrue(
                    names[f"ipv6 baseline wl6->peer6 {over}:2222"])
                self.assertFalse(names["ipv6 gate"])
                self.assertNotIn("ipv6 non-lo denied after policy", names)
                self.assertNotIn(
                    "ipv6 policy wl6->peer6 v4:2222 allowed", names)


if __name__ == "__main__":
    unittest.main()
