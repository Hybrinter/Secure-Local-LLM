import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import network, runner

TABLE = "sllm_0123456789ab"
PEER = "10.88.0.5"
UUID = "01234567-89ab-4cde-8f01-23456789abcd"

EMPTY_RULESET = json.dumps({"nftables": [{"metainfo": {}}]})


def _match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def _meta(key, right):
    return _match({"meta": {"key": key}}, right)


def _ct(state):
    return {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                      "right": state}}


def _payload(proto, field, right):
    return _match({"payload": {"protocol": proto, "field": field}}, right)


def _rule(chain, exprs, table=TABLE):
    return {"rule": {"family": "inet", "table": table, "chain": chain,
                     "handle": 9, "expr": exprs}}


def _chain(name, table=TABLE, policy="drop", prio=-10):
    return {"chain": {"family": "inet", "table": table, "name": name,
                      "handle": 2, "type": "filter", "hook": name,
                      "prio": prio, "policy": policy}}


def ruleset_doc(table=TABLE, role="workload", peer=PEER, port=2222,
                chain_edit=None, rule_edit=None):
    if role == "workload":
        out_extra = [_rule("output", [
            _payload("ip", "daddr", peer),
            _payload("tcp", "dport", port),
            _ct("new"), {"accept": None}], table)]
        in_extra = []
    else:
        in_extra = [_rule("input", [
            _payload("ip", "saddr", peer),
            _payload("tcp", "dport", port),
            _ct("new"), {"accept": None}], table)]
        out_extra = []
    entries = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": table, "handle": 1}},
        _chain("input", table), _chain("output", table),
        _rule("input", [_meta("iifname", "lo"), {"accept": None}], table),
        _rule("input", [_ct("invalid"), {"drop": None}], table),
        _rule("input", [_ct(["established", "related"]),
                        {"accept": None}], table),
        *in_extra,
        _rule("output", [_meta("oifname", "lo"), {"accept": None}], table),
        _rule("output", [_ct("invalid"), {"drop": None}], table),
        _rule("output", [_ct(["established", "related"]),
                         {"accept": None}], table),
        *out_extra,
    ]
    for fn in (chain_edit, rule_edit):
        if fn:
            fn(entries)
    return {"nftables": entries}


def canonical_of(doc):
    return network.canonicalize_ruleset(json.dumps(doc))


class Render(unittest.TestCase):
    def test_table_name_from_uuid(self):
        self.assertEqual(network.table_name(UUID), "sllm_0123456789ab")
        for bad in ("not-a-uuid", "ABCDEF67-89AB-4CDE-8F01-23456789ABCD",
                    123, None):
            with self.assertRaises(network.NetworkError, msg=repr(bad)):
                network.table_name(bad)

    def test_render_workload(self):
        text = network.render_policy(TABLE, PEER, 2222, "workload")
        self.assertIn(f"table inet {TABLE}", text)
        self.assertIn("type filter hook input priority -10; policy drop;",
                      text)
        self.assertIn("type filter hook output priority -10; policy drop;",
                      text)
        self.assertIn('iifname "lo" accept', text)
        self.assertIn("ct state invalid drop", text)
        self.assertIn("ct state established,related accept", text)
        self.assertIn(
            f"ip daddr {PEER} tcp dport 2222 ct state new accept", text)
        self.assertNotIn("saddr", text)

    def test_render_git_inverse(self):
        text = network.render_policy(TABLE, PEER, 2222, "git")
        self.assertIn(
            f"ip saddr {PEER} tcp dport 2222 ct state new accept", text)
        self.assertNotIn("daddr", text)

    def test_render_rejects_injection(self):
        bad_tables = ["evil", "sllm_", "sllm_gg1122", f"{TABLE};flush",
                      f"{TABLE} x", "SLLM_0123456789ab", TABLE + "\nx"]
        for t in bad_tables:
            with self.assertRaises(network.NetworkError, msg=t):
                network.render_policy(t, PEER)
        for ip in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "0.0.0.0",
                   "224.0.0.1", "::1", "10.0.0.1/24", "host", None, 7):
            with self.assertRaises(network.NetworkError, msg=repr(ip)):
                network.render_policy(TABLE, ip)
        for port in (0, 65536, -1, "2222", True, 2222.5, None):
            with self.assertRaises(network.NetworkError, msg=repr(port)):
                network.render_policy(TABLE, PEER, port)
        with self.assertRaises(network.NetworkError):
            network.render_policy(TABLE, PEER, 2222, "evil")

    def test_no_nonloopback_or_v6_targets(self):
        for role in ("workload", "git"):
            text = network.render_policy(TABLE, PEER, 2222, role)
            self.assertNotIn("ip6", text)
            self.assertNotIn("udp", text)
            self.assertNotIn("domain", text)


class Canonical(unittest.TestCase):
    def test_canonicalize_drops_metainfo_and_handles(self):
        canon = canonical_of(ruleset_doc())
        for entry in canon:
            body = next(iter(entry.values()))
            self.assertNotIn("handle", body)
        self.assertFalse(any("metainfo" in e for e in canon))
        self.assertEqual(len(canon), 10)

    def test_canonicalize_normalizes_set_wrapper(self):
        doc = ruleset_doc(rule_edit=lambda e: e[6]["rule"]["expr"]
                          .__setitem__(0, {"match": {
                              "op": "in",
                              "left": {"ct": {"key": "state"}},
                              "right": {"set": ["established",
                                                "related"]}}}))
        network.verify_canonical(
            canonical_of(doc), TABLE, "workload",
            peer_ip=PEER, peer_port=2222)
        bad = ruleset_doc(rule_edit=lambda e: e[6]["rule"]["expr"]
                          .__setitem__(0, {"match": {
                              "op": "in",
                              "left": {"ct": {"key": "state"}},
                              "right": {"set": "new"}}}))
        with self.assertRaises(network.NetworkError):
            network.verify_canonical(
                canonical_of(bad), TABLE, "workload",
                peer_ip=PEER, peer_port=2222)

    def test_verify_canonical_accepts_rendered_shape(self):
        for role in ("workload", "git"):
            canon = canonical_of(ruleset_doc(role=role))
            network.verify_canonical(
                canon, TABLE, role, peer_ip=PEER, peer_port=2222)

    def test_verify_canonical_rejections(self):
        cases = [
            lambda e: e.append({"table": {"family": "inet", "name": "other",
                                          "handle": 4}}),
            lambda e: e[1]["table"].update(family="ip"),
            lambda e: e[1]["table"].update(comment="x"),
            lambda e: e[2]["chain"].update(policy="accept"),
            lambda e: e[2]["chain"].update(prio=0),
            lambda e: e[2]["chain"].update(hook="forward"),
            lambda e: e[2]["chain"].update(table="other"),
            lambda e: e[2]["chain"].update(family="ip6"),
            lambda e: e[2]["chain"].update(comment="x"),
            lambda e: e[3].pop("chain"),
            lambda e: e.append(_chain("input")),
            lambda e: e.append(_chain("forward")),
            lambda e: e[4]["rule"]["expr"].__setitem__(
                0, _meta("iifname", "eth0")),
            lambda e: e[4]["rule"]["expr"].__setitem__(1, {"drop": None}),
            lambda e: e[4]["rule"]["expr"].append({"accept": None}),
            lambda e: e[5]["rule"]["expr"].__setitem__(0, _ct("established")),
            lambda e: e[5]["rule"]["expr"].__setitem__(1, {"accept": None}),
            lambda e: e[6]["rule"]["expr"].__setitem__(0, _ct("established")),
            lambda e: e[6]["rule"]["expr"].__setitem__(
                0, _ct(["related", "established"])),
            lambda e: e[7]["rule"]["expr"].__setitem__(
                0, _meta("oifname", "eth0")),
            lambda e: e[7]["rule"]["expr"].__setitem__(1, {"drop": None}),
            lambda e: e[7]["rule"].update(comment="x"),
            lambda e: e[7]["rule"].update(family="ip6"),
            lambda e: e[7]["rule"].update(table="other"),
            lambda e: e[7]["rule"].update(chain="forward"),
            lambda e: e[7]["rule"].update(expr="junk"),
            lambda e: e.pop(7),
            lambda e: e.append({"rule": {"family": "inet", "table": TABLE,
                                         "chain": "input", "handle": 9,
                                         "expr": [{"accept": None}]}}),
            lambda e: e[10]["rule"]["expr"].__setitem__(
                0, _payload("ip", "daddr", "10.0.0.9")),
            lambda e: e[10]["rule"]["expr"].__setitem__(
                1, _payload("tcp", "dport", 9999)),
            lambda e: e[10]["rule"]["expr"].__setitem__(
                0, _payload("ip", "saddr", PEER)),
            lambda e: e[10]["rule"]["expr"].__setitem__(
                2, _ct("established")),
            lambda e: e[10]["rule"]["expr"].__setitem__(3, {"drop": None}),
            lambda e: e[10]["rule"]["expr"].pop(2),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                with self.assertRaises(network.NetworkError):
                    network.verify_canonical(
                        canonical_of(ruleset_doc(rule_edit=mutate)),
                        TABLE, "workload", peer_ip=PEER, peer_port=2222)

    def test_verify_requires_peer_params(self):
        canon = canonical_of(ruleset_doc())
        with self.assertRaises(network.NetworkError):
            network.verify_canonical(canon, TABLE, "workload")
        with self.assertRaises(network.NetworkError):
            network.verify_canonical(canon, TABLE, "workload",
                                     peer_ip=PEER, peer_port=None)
        with self.assertRaises(network.NetworkError):
            network.verify_canonical(canon, TABLE, "workload",
                                     peer_ip="10.0.0.9", peer_port=2222)
        with self.assertRaises(network.NetworkError):
            network.verify_canonical(canon, TABLE, "workload",
                                     peer_ip=PEER, peer_port=9999)

    def test_canonicalize_rejections(self):
        for raw in (b"{bad", b'"str"', b'{"nftables": {}}',
                    json.dumps({"nftables": [{"a": {}, "b": {}}]}),
                    json.dumps({"nftables": [{"counter": {}}]})):
            with self.assertRaises(network.NetworkError, msg=raw[:30]):
                network.canonicalize_ruleset(raw)

    def test_canonical_hash_detects_drift(self):
        a = canonical_of(ruleset_doc())
        tampered = canonical_of(ruleset_doc(rule_edit=lambda e: e[9][
            "rule"]["expr"].__setitem__(1, _payload("tcp", "dport", 9999))))
        self.assertNotEqual(network.canonical_hash(a),
                            network.canonical_hash(tampered))


class NetRunner(runner.Runner):
    def __init__(self, read_ruleset, apply_ruleset=None):
        self.read_ruleset = read_ruleset
        self.apply_ruleset = apply_ruleset
        self.calls = []

    def run(self, argv, timeout=runner.DEFAULT_TIMEOUT_SECONDS,
            extra_env=None, stdin_text=None, pass_fds=()):
        self.calls.append((list(argv), stdin_text))
        op = ""
        if stdin_text:
            op = json.loads(stdin_text).get("op", "")
        if op == "apply":
            ruleset = (
                self.apply_ruleset
                if self.apply_ruleset is not None else self.read_ruleset)
        else:
            ruleset = self.read_ruleset
        return runner.CommandResult(
            argv, 0, json.dumps({"ok": True, "ruleset": ruleset}), "")

    def podman(self, args, timeout=runner.DEFAULT_TIMEOUT_SECONDS,
               extra_env=None, stdin_text=None):
        if "exec" in args:
            return runner.CommandResult(
                args, 0, "user:[4026]\nnet:[4027]\n", "")
        if "inspect" in args:
            return runner.CommandResult(args, 0, "4321\n", "")
        return runner.CommandResult(args, 0, "", "")

    def ops(self):
        return [json.loads(stdin).get("op") for _, stdin in self.calls
                if stdin]


class Orchestration(unittest.TestCase):
    def test_inspect_namespaces(self):
        ns = network.inspect_namespaces(NetRunner(""), "a" * 12)
        self.assertEqual(
            ns, {"pid": 4321, "user": "user:[4026]", "net": "net:[4027]"})
        for bad in ("x", "A" * 64, "f" * 65, ""):
            with self.assertRaises(network.NetworkError):
                network.inspect_namespaces(NetRunner(""), bad)

    def test_fresh_install_applies_then_verifies(self):
        fake = NetRunner(EMPTY_RULESET, json.dumps(ruleset_doc()))
        record = network.install_policy(
            fake, "b" * 12, TABLE, PEER, 2222, "workload")
        self.assertEqual(record["schema"], "secure-local-llm/netpol@1")
        self.assertEqual(len(record["canonical_sha256"]), 64)
        self.assertEqual(fake.ops(), ["read", "apply"])
        apply_req = [json.loads(stdin) for _, stdin in fake.calls
                     if stdin and json.loads(stdin)["op"] == "apply"][0]
        self.assertIn("table inet sllm_", apply_req["policy"])
        fake.read_ruleset = json.dumps(ruleset_doc())
        network.verify_policy(fake, "b" * 12, record)

    def test_existing_identical_policy_reused_no_apply(self):
        fake = NetRunner(json.dumps(ruleset_doc()))
        record = network.install_policy(
            fake, "b" * 12, TABLE, PEER, 2222, "workload")
        self.assertEqual(len(record["canonical_sha256"]), 64)
        self.assertEqual(fake.ops(), ["read"])

    def test_existing_drift_fails_without_apply(self):
        drifted = ruleset_doc(rule_edit=lambda e: e.append(
            _rule("output", [_meta("oifname", "eth0"),
                             {"accept": None}])))
        fake = NetRunner(json.dumps(drifted))
        with self.assertRaises(network.NetworkError):
            network.install_policy(fake, "b" * 12, TABLE, PEER)
        self.assertEqual(fake.ops(), ["read"])

    def test_malformed_existing_never_applies(self):
        for raw in ("not json", json.dumps({"nftables": [{"other": {}}]}),
                    json.dumps({"nftables": [{"table": {"family": "ip",
                                                      "name": "x",
                                                      "handle": 1}}]})):
            fake = NetRunner(raw)
            with self.assertRaises(network.NetworkError, msg=raw[:20]):
                network.install_policy(fake, "b" * 12, TABLE, PEER)
            self.assertEqual(fake.ops(), ["read"], msg=raw[:20])

    def test_drift_detected(self):
        fake = NetRunner(json.dumps(ruleset_doc()))
        record = network.install_policy(
            fake, "b" * 12, TABLE, PEER, 2222, "workload")
        fake.read_ruleset = json.dumps(ruleset_doc(rule_edit=lambda e:
            e[10]["rule"]["expr"].__setitem__(
                1, _payload("tcp", "dport", 9999))))
        with self.assertRaises(network.NetworkError):
            network.verify_policy(fake, "b" * 12, record)

    def test_absent_policy_fails_verify(self):
        fake = NetRunner(EMPTY_RULESET, json.dumps(ruleset_doc()))
        record = network.install_policy(fake, "b" * 12, TABLE, PEER)
        fake.read_ruleset = EMPTY_RULESET
        with self.assertRaises(network.NetworkError):
            network.verify_policy(fake, "b" * 12, record)
        self.assertIsNone(network.read_policy(fake, "b" * 12, TABLE))

    def test_helper_failure(self):
        class Bad(NetRunner):
            def run(self, argv, **kw):
                return runner.CommandResult(
                    argv, 0, json.dumps({"ok": False, "error": "nope"}), "")
        with self.assertRaises(network.NetworkError):
            network.install_policy(Bad(""), "b" * 12, TABLE, PEER)

    def test_helper_oversized_output(self):
        class Big(NetRunner):
            def run(self, argv, **kw):
                return runner.CommandResult(
                    argv, 0, "x" * (network.MAX_HELPER_STDOUT_BYTES + 1), "")
        with self.assertRaises(network.NetworkError):
            network.install_policy(Big(""), "b" * 12, TABLE, PEER)


if __name__ == "__main__":
    unittest.main()
