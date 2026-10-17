#!/usr/bin/env python3
"""Opt-in live network-policy gate for secure-local-llm.

Creates only new nonce-labelled podman resources, proves connectivity before
policy, applies the workload nftables policy inside the pod netns via
netns_helper, asserts allowed/denied flows, exercises drift detection and
re-apply after pod restart, then removes exactly the resources it created
and verifies they are gone.

Usage: python3 tests/integration/network_gate.py --run
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))

from local_agent import network, runner, state

TCP_LISTENER_SRC = (
    "import socket,sys\n"
    "af=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET\n"
    "s=socket.socket(af)\n"
    "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "s.bind((sys.argv[1],int(sys.argv[2])))\n"
    "s.listen(8)\n"
    "while True:\n"
    " c,_=s.accept()\n"
    " c.sendall(b'echo-'+c.recv(64))\n"
    " c.close()\n"
)
UDP_LISTENER_SRC = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    "s.bind((sys.argv[1],int(sys.argv[2])))\n"
    "while True:\n"
    " d,a=s.recvfrom(64)\n"
    " s.sendto(b'uecho-'+d,a)\n"
)
TCP_CONNECT_SRC = (
    "import socket,sys\n"
    "af=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET\n"
    "s=socket.socket(af)\n"
    "s.settimeout(5)\n"
    "s.connect((sys.argv[1],int(sys.argv[2])))\n"
    "s.sendall(sys.argv[3].encode())\n"
    "data=s.recv(128)\n"
    "assert data==b'echo-'+sys.argv[3].encode(),data\n"
    "print('echo-ok')\n"
)
UDP_CONNECT_SRC = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    "s.settimeout(5)\n"
    "s.sendto(sys.argv[3].encode(),(sys.argv[1],int(sys.argv[2])))\n"
    "data,_=s.recvfrom(128)\n"
    "assert data==b'uecho-'+sys.argv[3].encode(),data\n"
    "print('uecho-ok')\n"
)

LABEL = "org.secure-local-llm.test"


def write_exclusive(path, text):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


class Gate:
    def __init__(self, run):
        self.r = run
        self.nonce = secrets.token_hex(4)
        self.results = []
        self.log = []
        self.created = {"pods": [], "containers": [], "networks": []}
        self.residual = []
        self.procs = []
        self.network_meta = {}

    def note(self, msg):
        line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
        self.log.append(line)
        print(line, flush=True)

    def check(self, name, ok, detail=""):
        self.results.append({"name": name, "ok": bool(ok),
                             "detail": detail})
        self.note(f"{'PASS' if ok else 'FAIL'}: {name} {detail}")

    def pdm(self, args, timeout=60, stdin_text=None):
        res = self.r.podman(args, timeout=timeout, stdin_text=stdin_text)
        self.note(f"$ podman {' '.join(args)} -> rc={res.returncode}")
        return res

    def must(self, res, what):
        if res.returncode != 0 or res.timed_out:
            raise RuntimeError(
                f"{what} failed: {res.stderr.strip()[-300:]}")
        return res.stdout.strip()

    def used_networks(self):
        used = []
        res = self.must(
            self.pdm(["network", "ls", "--format", "{{.Name}}"]),
            "network ls")
        for name in res.split():
            info = self.must(self.pdm(
                ["network", "inspect", name, "--format",
                 "{{json .Subnets}}"]), f"inspect network {name}")
            try:
                for sub in json.loads(info):
                    used.append(ipaddress.ip_network(sub["subnet"]))
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise RuntimeError(
                    f"unparsable subnet data for network {name}") from exc
        for ver in ("-4", "-6"):
            res = self.r.run(["ip", ver, "-j", "route"], timeout=15)
            if res.returncode != 0 or res.timed_out:
                raise RuntimeError(f"ip {ver} route failed")
            try:
                routes = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"ip {ver} route output unparseable") \
                    from exc
            if not isinstance(routes, list):
                raise RuntimeError(f"ip {ver} route output not a list")
            for route in routes:
                dst = route.get("dst")
                if dst in (None, "default"):
                    continue
                try:
                    used.append(ipaddress.ip_network(dst, strict=False))
                except ValueError as exc:
                    raise RuntimeError(f"unparsable route dst {dst!r}") \
                        from exc
        return used

    def free_subnet4(self):
        used = self.used_networks()
        for _ in range(64):
            cand = ipaddress.ip_network(f"10.253.{secrets.randbelow(256)}.0/28")
            if not any(cand.overlaps(u) for u in used):
                return str(cand)
        raise RuntimeError("no free /28 candidate found")

    def free_subnet6(self):
        used = self.used_networks()
        for _ in range(64):
            cand = ipaddress.ip_network(
                f"fd00:5354:4c4d:{secrets.randbelow(65536):x}::/64")
            if not any(
                cand.version == u.version and cand.overlaps(u)
                for u in used
            ):
                return str(cand)
        raise RuntimeError("no free ULA /64 candidate found")

    def gateway_of(self, net):
        """Assign a controlled witness address on this test's bridge.

        --internal bridges carry no gateway address, so pick the last
        usable host address of this test's own /28 and add it to the
        bridge inside the rootless network namespace. The address dies
        with the disposable bridge on `network rm`.
        """
        res = self.must(self.pdm(
            ["network", "inspect", net, "--format",
             "{{json .Subnets}} {{json .NetworkInterface}}"]),
            f"inspect {net} subnets")
        parts = res.rsplit(" ", 1)
        try:
            subnets = json.loads(parts[0])
            iface = json.loads(parts[1])
            subnet = ipaddress.ip_network(subnets[0]["subnet"])
            addr = str(list(subnet.hosts())[-1])
        except (json.JSONDecodeError, KeyError, IndexError,
                TypeError, ValueError) as exc:
            raise RuntimeError(f"cannot read gateway of {net}") from exc
        self.must(self.pdm(
            ["unshare", "--rootless-netns", "ip", "addr", "add",
             f"{addr}/{subnet.prefixlen}", "dev", iface], timeout=20),
            f"assign witness addr on {iface}")
        res = self.pdm(
            ["unshare", "--rootless-netns", "ip", "-o", "-4", "addr",
             "show", iface], timeout=20)
        if res.returncode != 0 or f"inet {addr}/" not in res.stdout:
            raise RuntimeError(
                f"bridge {iface} lacks witness addr {addr}: "
                f"{res.stdout.strip() or res.stderr.strip()[-200:]}")
        return addr

    def ip_of(self, container, net):
        res = self.must(self.pdm(
            ["inspect", container, "--format",
             "{{json .NetworkSettings.Networks}}"]),
            f"inspect networks of {container}")
        nets = json.loads(res)
        if net not in nets:
            raise RuntimeError(f"{container} lacks network {net}")
        entry = nets[net]
        return entry.get("IPAddress"), entry.get("GlobalIPv6Address")

    def connect(self, cid, ip, port, token, udp=False):
        src = UDP_CONNECT_SRC if udp else TCP_CONNECT_SRC
        res = self.pdm(
            ["exec", cid, "python3", "-I", "-B", "-c", src, ip, str(port), token],
            timeout=15)
        ok = "echo-ok" if not udp else "uecho-ok"
        return res.returncode == 0 and ok in res.stdout

    def listener(self, cid, bind, port, udp=False):
        src = UDP_LISTENER_SRC if udp else TCP_LISTENER_SRC
        self.pdm(["exec", "-d", cid, "python3", "-I", "-B", "-c", src,
                  bind, str(port)])

    def wait_ready(self, cid, ip, port, token, tries=20, udp=False):
        for _ in range(tries):
            if self.connect(cid, ip, port, token, udp=udp):
                return True
            time.sleep(0.5)
        return False

    def start_gateway_listener(self, gw_ip, port):
        """Detached python listener bound to the bridge gateway address.

        Runs inside the rootless network namespace via
        `podman unshare --rootless-netns`; own process group so cleanup
        kills exactly this listener.
        """
        argv = [
            "podman", "--remote=false", "unshare", "--rootless-netns",
            "python3", "-I", "-B", "-c", TCP_LISTENER_SRC, gw_ip, str(port),
        ]
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=runner.base_env(),
            start_new_session=True)
        self.procs.append(proc)
        self.note(f"gateway listener pid={proc.pid} on {gw_ip}:{port}")
        return proc

    def cleanup(self):
        for pod in self.created["pods"]:
            self.pdm(["pod", "rm", "-f", "-t", "3", pod], timeout=30)
        for cid in self.created["containers"]:
            self.pdm(["rm", "-f", "-t", "3", cid], timeout=30)
        for net in self.created["networks"]:
            self.pdm(["network", "rm", net], timeout=30)
        for proc in self.procs:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=10)
                except (ProcessLookupError, PermissionError,
                        subprocess.TimeoutExpired):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
        self.verify_cleanup()

    def verify_cleanup(self):
        for cid in self.created["containers"]:
            if self.pdm(["inspect", cid], timeout=15).returncode == 0:
                self.residual.append(f"container {cid}")
        for pod in self.created["pods"]:
            if self.pdm(["pod", "inspect", pod],
                        timeout=15).returncode == 0:
                self.residual.append(f"pod {pod}")
        for net in self.created["networks"]:
            if self.pdm(["network", "inspect", net],
                        timeout=15).returncode == 0:
                self.residual.append(f"network {net}")
        for proc in self.procs:
            if proc.poll() is None:
                self.residual.append(f"process {proc.pid}")
        if self.residual:
            self.check("cleanup residue absent", False,
                       "; ".join(self.residual))
        else:
            self.check("cleanup residue absent", True)

    def make_pod(self, name, net, base_image):
        res = self.pdm([
            "pod", "create", "--name", name, "--network", net,
            "--share", "net", "--userns", "keep-id",
            "--label", f"{LABEL}={self.nonce}",
            "--infra-image", base_image,
            "--infra-command", "sleep infinity"])
        pod_id = self.must(res, f"pod create {name}")
        self.created["pods"].append(pod_id)
        return pod_id

    def run_container(self, name, net_or_pod, image, via_pod):
        args = ["run", "-d", "--pull=never", "--name", name,
                "--cap-drop", "ALL", "--read-only",
                "--security-opt", "no-new-privileges",
                "--memory", "256m", "--pids-limit", "64",
                "--label", f"{LABEL}={self.nonce}"]
        if via_pod:
            args += ["--pod", net_or_pod]
        else:
            args += ["--network", net_or_pod, "--userns", "keep-id"]
        cid = self.must(
            self.pdm(args + [image, "sleep", "infinity"], timeout=60),
            f"run {name}")
        self.created["containers"].append(cid)
        return cid

    def make_network(self, args, name):
        res = self.must(self.pdm(
            ["network", "create", *args,
             "--label", f"{LABEL}={self.nonce}", name]),
            f"network create {name}")
        info = self.must(self.pdm(
            ["network", "inspect", name]),
            f"inspect network {name}")
        try:
            net_id = json.loads(info)[0]["id"]
        except (json.JSONDecodeError, IndexError, KeyError,
                TypeError) as exc:
            raise RuntimeError(
                f"network id missing from inspect of {name}") from exc
        if not isinstance(net_id, str) or not re.fullmatch(
                r"[0-9a-f]{64}", net_id):
            raise RuntimeError(
                f"network {name} id is not a hex64 value: {net_id!r}")
        self.network_meta[net_id] = hashlib.sha256(
            info.encode()).hexdigest()
        self.created["networks"].append(net_id)
        return net_id

    def run_gate(self, harness_image, base_image):
        r = self.r
        subnet = self.free_subnet4()
        net = f"sllmgn-{self.nonce}"
        pod = f"sllmgp-{self.nonce}"
        wl = f"sllmgw-{self.nonce}"
        peers = [f"sllmga-{self.nonce}", f"sllmgb-{self.nonce}"]

        self.make_network(
            ["--internal", "--disable-dns", "--subnet", subnet], net)

        pod_id = self.make_pod(pod, net, base_image)
        wl_cid = self.run_container(wl, pod, harness_image, True)
        peer_ids = {
            p: self.run_container(p, net, harness_image, False)
            for p in peers
        }
        self.note(f"pod id={pod_id} wl id={wl_cid} peers={peer_ids}")
        gw_ip = self.gateway_of(net)

        infra = self.must(self.pdm(
            ["pod", "inspect", pod, "--format", "{{.InfraContainerID}}"]),
            "pod inspect")
        wl_ip, _ = self.ip_of(infra, net)
        if not wl_ip:
            raise RuntimeError("pod has no IPv4 address")
        peer_ips = {p: self.ip_of(p, net)[0] for p in peers}
        self.note(f"pod ip {wl_ip} gw {gw_ip} peers {peer_ips}")

        for p in peers:
            self.listener(p, "0.0.0.0", 2222)
        self.listener(peers[0], "0.0.0.0", 3333)
        self.listener(peers[0], "0.0.0.0", 5353, udp=True)
        self.listener(wl, "0.0.0.0", 2222)
        self.start_gateway_listener(gw_ip, 4444)
        token = secrets.token_hex(4)

        self.check("baseline wl->peer1:2222",
                   self.wait_ready(wl, peer_ips[peers[0]], 2222, token))
        self.check("baseline wl->peer1:3333",
                   self.wait_ready(wl, peer_ips[peers[0]], 3333, token))
        self.check("baseline wl->peer2:2222",
                   self.wait_ready(wl, peer_ips[peers[1]], 2222, token))
        self.check("baseline wl->peer1 UDP:5353",
                   self.wait_ready(wl, peer_ips[peers[0]], 5353, token,
                                   udp=True))
        self.check("baseline wl->gateway:4444",
                   self.wait_ready(wl, gw_ip, 4444, token))
        self.check("baseline peer1->workload:2222",
                   self.wait_ready(peers[0], wl_ip, 2222, token))
        if not all(r["ok"] for r in self.results):
            raise RuntimeError("baseline connectivity failed")

        table = "sllm_" + self.nonce + "00"
        wl_id = self.must(self.pdm(
            ["inspect", wl, "--format", "{{.Id}}"]), "wl id")
        record = network.install_policy(
            r, wl_id, table, peer_ips[peers[0]], 2222, "workload")
        self.note(f"policy installed sha256={record['canonical_sha256'][:16]}")

        self.check("policy wl->peer1:2222 allowed",
                   self.connect(wl, peer_ips[peers[0]], 2222, token))
        self.check("policy wl->peer1:3333 denied",
                   not self.connect(wl, peer_ips[peers[0]], 3333, token))
        self.check("policy wl->peer2:2222 denied",
                   not self.connect(wl, peer_ips[peers[1]], 2222, token))
        self.check("policy peer1->workload:2222 denied",
                   not self.connect(peers[0], wl_ip, 2222, token))
        self.check("policy wl->peer1 UDP:5353 denied (udp egress)",
                   not self.connect(wl, peer_ips[peers[0]], 5353, token,
                                    udp=True))
        self.check("policy wl->gateway:4444 denied",
                   not self.connect(wl, gw_ip, 4444, token))
        self.check("policy wl->203.0.113.1:443 denied (doc prefix)",
                   not self.connect(wl, "203.0.113.1", 443, token))

        sec = self.must(self.pdm(
            ["inspect", wl, "--format",
             '{{json .HostConfig.ReadonlyRootfs}}'
             ' {{json .HostConfig.SecurityOpt}}'
             ' {{json .HostConfig.Memory}} {{json .HostConfig.PidsLimit}}']),
            "inspect security")
        fields = sec.split()
        status = self.pdm(
            ["exec", wl, "grep", "-E",
             "Cap(Eff|Bnd)|Seccomp|NoNewPrivs", "/proc/self/status"])
        ro = fields[0] == "true"
        nnp = "no-new-privileges" in fields[1]
        mem = fields[2] == "268435456"
        pids = fields[3] == "64"
        st = status.stdout
        seccomp = "Seccomp:\t2" in st
        nnp_bit = "NoNewPrivs:\t1" in st
        cap_zero = ("CapEff:\t0000000000000000" in st
                    and "CapBnd:\t0000000000000000" in st)
        self.check("workload ro/nnp/seccomp/mem/pids/caps",
                   all([ro, nnp, nnp_bit, seccomp, mem, pids, cap_zero]),
                   f"ro={ro} nnp={nnp} nnp1={nnp_bit} seccomp={seccomp} "
                   f"mem={mem} pids={pids} caps0={cap_zero}")

        drifted = False
        ns = network.inspect_namespaces(r, wl_id)
        try:
            network._helper_call(r, {
                "op": "apply",
                "pid": ns["pid"],
                "expect_user": ns["user"],
                "expect_net": ns["net"],
                "policy": f"add rule inet {table} output accept\n",
            })
        except network.NetworkError as exc:
            self.note(f"drift inject failed: {exc}")
        try:
            network.verify_policy(r, wl_id, record)
        except network.NetworkError:
            drifted = True
        self.check("policy drift detected and refused", drifted)

        self.must(self.pdm(["pod", "stop", "-t", "3", pod], timeout=60),
                  "pod stop")
        self.must(self.pdm(["pod", "start", pod], timeout=60), "pod start")
        record2 = network.install_policy(
            r, wl_id, table, peer_ips[peers[0]], 2222, "workload")
        network.verify_policy(r, wl_id, record2)
        self.check("policy re-applied after pod restart",
                   self.connect(wl, peer_ips[peers[0]], 2222, token))
        self.check("restart wl->peer2:2222 denied",
                   not self.connect(wl, peer_ips[peers[1]], 2222, token))

        self.ipv6_gate(harness_image, base_image)

    def ipv6_gate(self, harness_image, base_image):
        net6 = f"sllmg6-{self.nonce}"
        pod6 = f"sllmgp6-{self.nonce}"
        wl6 = f"sllmgw6-{self.nonce}"
        peer6 = f"sllmgc-{self.nonce}"
        sub4 = self.free_subnet4()
        ula = self.free_subnet6()
        res = self.pdm([
            "network", "create", "--internal", "--disable-dns",
            "--ipv6", "--subnet", sub4, "--subnet", ula,
            "--label", f"{LABEL}={self.nonce}", net6])
        if res.returncode != 0:
            self.check("ipv6 gate", False,
                       f"blocked: v6 network create: {res.stderr.strip()[-200:]}")
            return
        info = self.must(self.pdm(["network", "inspect", net6]),
                         f"inspect network {net6}")
        try:
            net6_id = json.loads(info)[0]["id"]
        except (json.JSONDecodeError, IndexError, KeyError,
                TypeError) as exc:
            raise RuntimeError(
                f"network id missing from inspect of {net6}") from exc
        if not isinstance(net6_id, str) or not re.fullmatch(
                r"[0-9a-f]{64}", net6_id):
            raise RuntimeError(
                f"network {net6} id is not a hex64 value: {net6_id!r}")
        self.network_meta[net6_id] = hashlib.sha256(
            info.encode()).hexdigest()
        self.created["networks"].append(net6_id)
        self.make_pod(pod6, net6, base_image)
        wl6_cid = self.run_container(wl6, pod6, harness_image, True)
        peer6_cid = self.run_container(peer6, net6, harness_image, False)
        infra6 = self.must(self.pdm(
            ["pod", "inspect", pod6, "--format", "{{.InfraContainerID}}"]),
            "pod6 inspect")
        peer6_ip4, peer6_ip6 = self.ip_of(peer6, net6)
        if not peer6_ip6:
            self.check("ipv6 gate", False,
                       "blocked: peer has no IPv6 address")
            return
        self.listener(peer6, "::", 2222)
        token = secrets.token_hex(4)
        self.check("ipv6 baseline wl6->peer6:2222",
                   self.wait_ready(wl6, peer6_ip6, 2222, token))
        wl6_id = self.must(self.pdm(
            ["inspect", wl6, "--format", "{{.Id}}"]), "wl6 id")
        network.install_policy(
            self.r, wl6_id, "sllm_" + self.nonce + "66", peer6_ip4, 2222,
            "workload")
        self.check("ipv6 non-lo denied after policy",
                   not self.connect(wl6, peer6_ip6, 2222, token))
        self.check("ipv6 policy wl6->peer6 v4:2222 allowed",
                   self.connect(wl6, peer6_ip4, 2222, token))


def smoke(gate, harness_image):
    net = f"sllmsm-{gate.nonce}"
    ct = f"sllmsc-{gate.nonce}"
    gate.make_network(["--internal", "--disable-dns",
                       "--subnet", gate.free_subnet4()], net)
    gate.run_container(ct, net, harness_image, False)
    gate.note(f"smoke fixture created: {gate.created}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    if not (args.run or args.smoke):
        print("network gate is opt-in: pass --run or --smoke")
        return 0
    gate = Gate(runner.Runner())
    artifacts_dir = state._ensure_private_dir(state.state_root())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = artifacts_dir / f"network-gate-{stamp}-{gate.nonce}.json"
    out_log = artifacts_dir / f"network-gate-{stamp}-{gate.nonce}.log"
    status = "error"
    try:
        prepared = state.load_prepared(state.state_root(), "demo")
        if not prepared:
            raise RuntimeError("instance demo not prepared")
        harness = prepared["images"]["harness"]
        base = json.loads(Path(
            ".devin/artifacts.lock.json").read_text())["base_image"]
        gate.note(f"harness image {harness[:16]} nonce {gate.nonce}")
        if args.smoke:
            smoke(gate, harness)
        else:
            gate.run_gate(harness, base)
        status = "pass" if all(r["ok"] for r in gate.results) else "fail"
    except Exception as exc:
        gate.check("gate", False, f"{type(exc).__name__}: {exc}")
    finally:
        gate.cleanup()
        if gate.residual and status == "pass":
            status = "blocked"
        payload = {
            "schema": "secure-local-llm/netgate@1",
            "nonce": gate.nonce,
            "status": status,
            "results": gate.results,
            "residual": gate.residual,
            "created": gate.created,
            "network_meta": gate.network_meta,
        }
        write_exclusive(out_json, json.dumps(payload, indent=2,
                                             sort_keys=True))
        write_exclusive(out_log, "\n".join(gate.log) + "\n")
        print(f"artifacts: {out_json} {out_log}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
