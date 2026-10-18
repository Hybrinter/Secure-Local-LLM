"""nftables policy rendering, namespace install, and canonical readback."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from pathlib import Path

from .runner import RunnerError

TABLE_RE = re.compile(r"sllm_[0-9a-f]{8,16}")
NS_RE = re.compile(r"^(user|net):\[[0-9]+\]$")
_ROLES = ("workload", "git")
HELPER_PATH = Path(__file__).with_name("netns_helper.py")


class NetworkError(Exception):
    pass


class PolicyMismatch(NetworkError):
    pass


def table_name(instance_uuid):
    try:
        canonical = str(uuid.UUID(str(instance_uuid)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise NetworkError("instance UUID required") from exc
    if canonical != instance_uuid:
        raise NetworkError("instance UUID must be canonical")
    return "sllm_" + canonical.replace("-", "")[:12]


def _check_table(table):
    if not isinstance(table, str) or not TABLE_RE.fullmatch(table):
        raise NetworkError(f"invalid policy table name: {table!r}")
    return table


def _check_peer(value):
    if not isinstance(value, str):
        raise NetworkError("peer: IPv4 address string required")
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise NetworkError("peer: IPv4 address required") from exc
    if (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
        or not ip.is_private
    ):
        raise NetworkError("peer: private non-loopback IPv4 required")
    return str(ip)


def _check_port(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise NetworkError("peer_port: integer required")
    if not 1 <= value <= 65535:
        raise NetworkError("peer_port: outside [1, 65535]")
    return value


def _check_role(role):
    if role not in _ROLES:
        raise NetworkError(f"role must be one of {_ROLES}")
    return role


def render_policy(table, peer_ip, peer_port=2222, role="workload"):
    table = _check_table(table)
    ip = _check_peer(peer_ip)
    port = _check_port(peer_port)
    role = _check_role(role)
    input_rules = [
        'iifname "lo" accept',
        "ct state invalid drop",
        "ct state established,related accept",
    ]
    output_rules = [
        'oifname "lo" accept',
        "ct state invalid drop",
        "ct state established,related accept",
    ]
    if role == "workload":
        output_rules.append(
            f"ip daddr {ip} tcp dport {port} ct state new accept")
    else:
        input_rules.append(
            f"ip saddr {ip} tcp dport {port} ct state new accept")
    lines = [f"table inet {table} {{"]
    for hook, rules in (("input", input_rules), ("output", output_rules)):
        lines.append(f"    chain {hook} {{")
        lines.append(
            f"        type filter hook {hook} priority -10; policy drop;")
        lines.extend(f"        {rule}" for rule in rules)
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _norm_expr(expr):
    """Normalize only explicitly known-equivalent nft encodings.

    nft 1.0.9 emits ``right: ["a", "b"]`` for multi-value ``in`` matches;
    some builds wrap that list as ``{"set": [...]}``. Unwrap only that one
    shape; anything else is preserved verbatim for strict comparison.
    """
    if isinstance(expr, dict) and set(expr) == {"match"}:
        match = expr["match"]
        if (
            isinstance(match, dict)
            and set(match) == {"op", "left", "right"}
            and match.get("op") == "in"
            and isinstance(match.get("right"), dict)
            and set(match["right"]) == {"set"}
            and isinstance(match["right"]["set"], list)
        ):
            return {"match": {**match, "right": match["right"]["set"]}}
    return expr


def canonicalize_ruleset(raw):
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise NetworkError("nft ruleset output is not JSON") from exc
    entries = doc.get("nftables") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise NetworkError("nft ruleset output lacks nftables list")
    canonical = []
    for entry in entries:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise NetworkError("unexpected ruleset entry shape")
        if "metainfo" in entry:
            continue
        kind = next(iter(entry))
        if kind not in ("table", "chain", "rule"):
            raise NetworkError(f"unexpected ruleset entry kind: {kind!r}")
        body = entry[kind]
        if not isinstance(body, dict):
            raise NetworkError("unexpected ruleset entry body")
        body = {k: v for k, v in body.items() if k != "handle"}
        if kind == "rule" and isinstance(body.get("expr"), list):
            body["expr"] = [_norm_expr(e) for e in body["expr"]]
        canonical.append({kind: body})
    return canonical


def _lo_expr(direction, verdict="accept"):
    return [
        {"match": {"op": "==",
                   "left": {"meta": {"key": direction}},
                   "right": "lo"}},
        {verdict: None},
    ]


def _ct_expr(states, verdict):
    return [
        {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                   "right": states}},
        {verdict: None},
    ]


def _peer_expr(field, peer_ip, peer_port):
    return [
        {"match": {"op": "==",
                   "left": {"payload": {"protocol": "ip", "field": field}},
                   "right": peer_ip}},
        {"match": {"op": "==",
                   "left": {"payload": {"protocol": "tcp",
                                        "field": "dport"}},
                   "right": peer_port}},
        {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                   "right": "new"}},
        {"accept": None},
    ]


def _expected_exprs(role, peer_ip, peer_port):
    base_in = [
        _lo_expr("iifname"),
        _ct_expr("invalid", "drop"),
        _ct_expr(["established", "related"], "accept"),
    ]
    base_out = [
        _lo_expr("oifname"),
        _ct_expr("invalid", "drop"),
        _ct_expr(["established", "related"], "accept"),
    ]
    if role == "workload":
        base_out.append(_peer_expr("daddr", peer_ip, peer_port))
    else:
        base_in.append(_peer_expr("saddr", peer_ip, peer_port))
    return {"input": base_in, "output": base_out}


_CHAIN_KEYS = {"family", "table", "name", "type", "hook", "prio", "policy"}
_RULE_KEYS = {"family", "table", "chain", "expr"}
_TABLE_KEYS = {"family", "name"}


def verify_canonical(canonical, table, role, peer_ip=None, peer_port=None):
    _check_table(table)
    role = _check_role(role)
    if peer_ip is None:
        raise NetworkError("peer_ip required for strict verification")
    ip = _check_peer(peer_ip)
    port = _check_port(peer_port)
    tables = [e["table"] for e in canonical if "table" in e]
    if (
        len(tables) != 1
        or set(tables[0]) - _TABLE_KEYS
        or tables[0].get("name") != table
        or tables[0].get("family") != "inet"
    ):
        raise NetworkError(f"expected exactly table inet {table}")
    chains = [e["chain"] for e in canonical if "chain" in e]
    if (
        len(chains) != 2
        or {c.get("name") for c in chains} != {"input", "output"}
        or len({c.get("name") for c in chains}) != 2
    ):
        raise NetworkError("expected exactly input/output chains")
    for chain in chains:
        if (
            set(chain) - _CHAIN_KEYS
            or chain.get("family") != "inet"
            or chain.get("table") != table
            or chain.get("hook") != chain.get("name")
            or chain.get("type") != "filter"
            or chain.get("prio") != -10
            or chain.get("policy") != "drop"
        ):
            raise NetworkError(
                f"chain {chain.get('name')}: unexpected shape")
    expected = _expected_exprs(role, ip, port)
    rules = {"input": [], "output": []}
    for entry in canonical:
        if "rule" not in entry:
            continue
        rule = entry["rule"]
        chain = rule.get("chain")
        if (
            set(rule) - _RULE_KEYS
            or rule.get("family") != "inet"
            or rule.get("table") != table
            or chain not in rules
            or not isinstance(rule.get("expr"), list)
        ):
            raise NetworkError("unexpected rule shape in ruleset")
        rules[chain].append(rule["expr"])
    for hook in ("input", "output"):
        if rules[hook] != expected[hook]:
            raise PolicyMismatch(
                f"chain {hook}: rules do not match the pinned policy")
    return canonical


def canonical_hash(canonical):
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _check_container_id(container_id):
    if (
        not isinstance(container_id, str)
        or not re.fullmatch(r"[0-9a-f]{12,64}", container_id)
    ):
        raise NetworkError(f"invalid container id: {container_id!r}")
    return container_id


def inspect_namespaces(runner, container_id):
    _check_container_id(container_id)
    res = runner.podman(
        ["exec", container_id, "readlink",
         "/proc/self/ns/user", "/proc/self/ns/net"],
        timeout=30,
    )
    if res.returncode != 0 or res.timed_out:
        raise NetworkError(
            f"cannot read namespaces of {container_id[:12]}: "
            f"{res.stderr.strip()[-300:]}")
    found = {}
    for line in res.stdout.splitlines():
        match = NS_RE.fullmatch(line.strip())
        if not match:
            raise NetworkError("unexpected ns link output")
        found[match.group(1)] = line.strip()
    if set(found) != {"user", "net"}:
        raise NetworkError("missing namespace links")
    res = runner.podman(
        ["inspect", container_id, "--format", "{{.State.Pid}}"], timeout=30)
    if res.returncode != 0 or res.timed_out:
        raise NetworkError(f"cannot inspect pid of {container_id[:12]}")
    try:
        pid = int(res.stdout.strip())
    except ValueError as exc:
        raise NetworkError("container pid not an integer") from exc
    if pid <= 0:
        raise NetworkError("container not running")
    return {"pid": pid, "user": found["user"], "net": found["net"]}


MAX_HELPER_STDOUT_BYTES = 2 * 1024 * 1024


def _helper_call(runner, request):
    try:
        res = runner.run(
            ["podman", "--remote=false", "unshare",
             "python3", "-I", "-B", str(HELPER_PATH)],
            stdin_text=json.dumps(request),
            timeout=120,
        )
    except RunnerError as exc:
        raise NetworkError(f"helper spawn failed: {exc}") from exc
    if res.timed_out:
        raise NetworkError("helper timed out")
    if len(res.stdout.encode("utf-8", "replace")) > MAX_HELPER_STDOUT_BYTES:
        raise NetworkError("helper output exceeds bound")
    try:
        out = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise NetworkError(
            f"helper output malformed rc={res.returncode}: "
            f"{res.stderr.strip()[-300:]}") from exc
    if not isinstance(out, dict) or out.get("ok") is not True:
        detail = out.get("error") if isinstance(out, dict) else None
        raise NetworkError(f"helper failed: {detail or res.stderr.strip()[-300:]}")
    if not isinstance(out.get("ruleset"), str):
        raise NetworkError("helper returned no ruleset")
    return out["ruleset"]


def _policy_record(table, role, peer_ip, peer_port, canonical):
    return {
        "schema": "secure-local-llm/netpol@1",
        "table": table,
        "role": role,
        "peer_ip": str(ipaddress.IPv4Address(peer_ip)),
        "peer_port": peer_port,
        "canonical_sha256": canonical_hash(canonical),
    }


def _helper_request(runner, container_id, request):
    ns = inspect_namespaces(runner, container_id)
    return _helper_call(runner, {
        "pid": ns["pid"],
        "expect_user": ns["user"],
        "expect_net": ns["net"],
        **request,
    })


def install_policy(runner, container_id, table, peer_ip, peer_port=2222,
                   role="workload"):
    policy = render_policy(table, peer_ip, peer_port, role)
    existing = canonicalize_ruleset(
        _helper_request(runner, container_id, {"op": "read"}))
    if existing:
        canonical = verify_canonical(
            existing, table, role, peer_ip=peer_ip, peer_port=peer_port)
        return _policy_record(table, role, peer_ip, peer_port, canonical)
    ruleset = _helper_request(
        runner, container_id, {"op": "apply", "policy": policy})
    canonical = verify_canonical(
        canonicalize_ruleset(ruleset), table, role,
        peer_ip=peer_ip, peer_port=peer_port)
    return _policy_record(table, role, peer_ip, peer_port, canonical)


def read_policy(runner, container_id, table):
    _check_table(table)
    ruleset = _helper_request(runner, container_id, {"op": "read"})
    canonical = canonicalize_ruleset(ruleset)
    if not any(
        "table" in e and e["table"].get("name") == table for e in canonical
    ):
        return None
    return canonical


def verify_policy(runner, container_id, record):
    canonical = read_policy(runner, container_id, record["table"])
    if canonical is None:
        raise NetworkError(f"policy table {record['table']} absent")
    canonical = verify_canonical(
        canonical, record["table"], record["role"],
        peer_ip=record["peer_ip"], peer_port=record["peer_port"])
    if canonical_hash(canonical) != record["canonical_sha256"]:
        raise PolicyMismatch(
            f"policy table {record['table']} drifted; refusing to proceed")
    return canonical
