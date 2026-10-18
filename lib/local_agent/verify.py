"""Shared effective verification: runs for `up` and the `verify` command."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import artifacts, network, podman, runtime_spec as spec
from . import verify_spec as vspec
from .config import fingerprint_file, load_profile
from .runtime_record import RuntimeFault, _read_control, _CONTROL_MODES
from .state import (
    load_git_prepared,
    load_manifest,
    load_prepared,
)

Result = vspec.Result
_check_container_spec = vspec._check_container_spec
_member_expect = vspec._member_expect


def _inspect(runner, cid):
    res = runner.podman(["inspect", cid], timeout=30)
    if res.returncode != 0 or res.timed_out:
        return None
    try:
        info = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    return info[0] if isinstance(info, list) and info else None


def _exec(runner, cid, argv, timeout=30):
    res = runner.podman(["exec", cid, *argv], timeout=timeout)
    if res.returncode != 0 or res.timed_out:
        return None
    return res.stdout


def _exec_py(runner, cid, script, timeout=30):
    return _exec(runner, cid, ["python3", "-I", "-B", "-c", script],
                 timeout=timeout)


def _running(info):
    return bool(info) and info.get("State", {}).get("Running") is True


_NS_PROBE = (";".join(
    f"readlink /proc/1/ns/{t}" for t in vspec.NS_TYPES))


def _ns_inventory(r, runner, role, cid):
    out = _exec(runner, cid,
                ["sh", "-c", _NS_PROBE], timeout=20)
    if out is None:
        r.expect(f"{role} namespace readlinks", False, "probe failed")
        return None
    vals = {}
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) != len(vspec.NS_TYPES):
        r.expect(f"{role} namespace readlinks", False,
                 f"got {len(lines)} lines")
        return None
    for t, val in zip(vspec.NS_TYPES, lines):
        if not val.startswith(t + ":["):
            r.expect(f"{role} ns {t}", False, val[:60])
            return None
        vals[t] = val
    return vals


def _proc_status_checks(r, runner, cid, role):
    out = _exec(runner, cid, ["cat", "/proc/1/status"])
    if out is None:
        r.expect(f"{role} /proc/1/status", False, "probe failed")
        return
    fields = {}
    for line in out.splitlines():
        key, _, val = line.partition(":")
        fields[key.strip()] = val.strip()
    uid_parts = fields.get("Uid", "").split()
    r.expect(f"{role} uid",
             len(uid_parts) == 4
             and all(p == "1000" for p in uid_parts),
             fields.get("Uid"))
    r.expect(f"{role} CapEff zero", fields.get("CapEff") in
             ("0000000000000000", "0"), fields.get("CapEff"))
    r.expect(f"{role} CapBnd zero", fields.get("CapBnd") in
             ("0000000000000000", "0"), fields.get("CapBnd"))
    r.expect(f"{role} NoNewPrivs", fields.get("NoNewPrivs") == "1",
             fields.get("NoNewPrivs"))
    r.expect(f"{role} Seccomp filter", fields.get("Seccomp") == "2",
             fields.get("Seccomp"))


def _infra_status_check(r, runner, cid):
    out = _exec(runner, cid, ["cat", "/proc/1/status"])
    if out is None:
        r.expect("infra /proc/1/status", False, "probe failed")
        return
    fields = {}
    for line in out.splitlines():
        key, _, val = line.partition(":")
        fields[key.strip()] = val.strip()
    r.expect("infra NoNewPrivs", fields.get("NoNewPrivs") == "1",
             fields.get("NoNewPrivs"))


def _cgroup_checks(r, runner, cid, role, expect):
    mem = _exec(runner, cid, ["cat", "/sys/fs/cgroup/memory.max"])
    if mem is None:
        r.expect(f"{role} cgroups", False, "memory.max read failed")
        return
    r.expect(f"{role} cgroup memory.max",
             mem.strip() == str(expect["memory"]),
             mem.strip()[:80])
    swap = _exec(
        runner, cid, ["cat", "/sys/fs/cgroup/memory.swap.max"])
    if swap is None:
        r.expect(f"{role} cgroup swap.max", False, "read failed")
    else:
        r.expect(f"{role} cgroup swap.max (no extra swap)",
                 swap.strip() == "0",
                 swap.strip()[:80])
    pids = _exec(runner, cid, ["cat", "/sys/fs/cgroup/pids.max"])
    if pids is None:
        r.expect(f"{role} cgroup pids.max", False, "read failed")
    else:
        r.expect(f"{role} cgroup pids.max",
                 pids.strip() == str(expect["pids"]),
                 pids.strip()[:80])
    cpu = _exec(runner, cid, ["cat", "/sys/fs/cgroup/cpu.max"])
    if cpu is None:
        r.expect(f"{role} cgroup cpu.max", False, "read failed")
    else:
        quota = expect["nanocpus"] // 10_000
        r.expect(f"{role} cgroup cpu.max",
                 cpu.strip() == f"{quota} 100000",
                 cpu.strip()[:80])


def _listener_check(r, runner, cid, role, expected_listeners):
    out = _exec_py(
        runner, cid,
        "seen = set()\n"
        "for line in open('/proc/net/tcp').read().splitlines()[1:]:\n"
        "    p = line.split()\n"
        "    if p[3] != '0A':\n"
        "        continue\n"
        "    addr, port = p[1].rsplit(':', 1)\n"
        "    seen.add((addr, int(port, 16)))\n"
        "try:\n"
        "    tcp6 = open('/proc/net/tcp6').read().splitlines()[1:]\n"
        "except FileNotFoundError:\n"
        "    tcp6 = []\n"
        "for line in tcp6:\n"
        "    p = line.split()\n"
        "    if p[3] == '0A':\n"
        "        seen.add(('v6:' + p[1].rsplit(':', 1)[0],\n"
        "                  int(p[1].rsplit(':', 1)[1], 16)))\n"
        "print(sorted(seen))\n")
    if out is None:
        r.expect(f"{role} listeners", False, "probe failed")
        return
    expected = sorted(expected_listeners)
    r.expect(f"{role} listeners", out.strip() == str(expected),
             out.strip()[:200])


def verify(root_dir, name, repo, runner):
    root_dir = Path(root_dir)
    repo = Path(repo)
    r = Result()
    manifest = load_manifest(root_dir, name)
    if manifest is None:
        r.expect("manifest", False, "not initialized")
        return r
    uuid = manifest["identity"]["uuid"]
    prepared = load_prepared(root_dir, name)
    git_prepared = load_git_prepared(root_dir, name)
    inst = root_dir / "instances" / name
    from .runtime_record import load_runtime as _load_rt
    record = _load_rt(inst, name)
    if prepared is None or git_prepared is None or record is None:
        r.expect("records", False,
                 f"prepared={bool(prepared)} git={bool(git_prepared)} "
                 f"runtime={bool(record)}")
        return r
    r.expect("records loaded", True)

    profile, profile_fp = load_profile(repo, manifest["profile"]["name"])
    r.expect("profile fingerprint",
             profile_fp["sha256"] == manifest["profile"]["sha256"])
    _, lock_fp = artifacts.load_lock(
        Path(manifest["artifacts_lock"]["path"]))
    r.expect("artifacts lock fingerprint",
             lock_fp["sha256"] == manifest["artifacts_lock"]["sha256"])
    fps = record["fingerprints"]
    r.expect("record profile fingerprint",
             fps["profile"] == manifest["profile"]["sha256"]
             == git_prepared["profile_sha256"])
    r.expect("record lock fingerprint",
             fps["artifacts_lock"] == manifest["artifacts_lock"]["sha256"]
             == git_prepared["artifacts_lock_sha256"])
    for role in ("harness", "inference"):
        cur = fingerprint_file(
            repo / "containers" / f"{role}.Containerfile")["sha256"]
        r.expect(f"{role} recipe fingerprint",
                 cur == prepared["fingerprints"][f"{role}_containerfile"])
    for rel, sha in git_prepared["files"].items():
        cur = fingerprint_file(repo / rel)["sha256"]
        r.expect(f"git recipe {Path(rel).name}", cur == sha)
    try:
        template = (
            repo / ".devin" / "opencode" / "opencode.json").read_bytes()
    except OSError as exc:
        r.expect("native config fingerprint", False, str(exc))
        return r
    r.expect(
        "native config fingerprint",
        hashlib.sha256(template).hexdigest()
        == record["fingerprints"]["source_config"])
    r.expect("record images match prepared",
             record["images"]["harness"] == prepared["images"]["harness"]
             and record["images"]["inference"]
             == prepared["images"]["inference"]
             and record["images"]["git"] == git_prepared["image_id"])

    mres = manifest["resources"]
    objs = record["objects"]
    r.expect("manifest pod id",
             mres.get("pod_id") == objs["pod"])
    r.expect("manifest containers",
             mres.get("container_ids") == objs["containers"])
    r.expect("manifest volumes",
             mres.get("volume_names") == objs["volumes"])
    r.expect("manifest network id",
             mres.get("network_id") == record["network"]["id"])

    n = spec.names(uuid)
    net = podman.object_exists(runner, "network", n["net"])
    if r.expect("network exists", net, n["net"]):
        info = json.loads(podman.must(
            runner, ["network", "inspect", n["net"]],
            "inspect net"))[0]
        r.expect("network id", info.get("id") == record["network"]["id"])
        r.expect("network internal", info.get("internal") is True)
        r.expect("network dns disabled", info.get("dns_enabled") is False)
        r.expect("network ipv6 disabled",
                 info.get("ipv6_enabled") is not True)
        subs = info.get("subnets") or []
        r.expect("network subnet",
                 len(subs) == 1 and subs[0].get("subnet")
                 == record["subnet"])
        labels = info.get("labels") or {}
        r.expect("network labels",
                 labels.get(spec.LABEL_INSTANCE) == uuid
                 and labels.get(spec.LABEL_ROLE) == "network")

    for role, vname in objs["volumes"].items():
        exists = podman.object_exists(runner, "volume", vname)
        if r.expect(f"volume {role} exists", exists, vname):
            labels = podman.object_labels(runner, "volume", vname) or {}
            r.expect(f"volume {role} labels",
                     labels.get(spec.LABEL_INSTANCE) == uuid
                     and labels.get(spec.LABEL_ROLE) == role)

    infra = objs["infra"]
    pod_ok = podman.object_exists(runner, "pod", objs["pod"])
    if r.expect("pod exists", pod_ok, objs["pod"][:12]):
        labels = podman.object_labels(runner, "pod", objs["pod"]) or {}
        r.expect("pod labels",
                 labels.get(spec.LABEL_INSTANCE) == uuid
                 and labels.get(spec.LABEL_ROLE) == "pod")
        live_infra = podman.must(
            runner,
            ["pod", "inspect", objs["pod"], "--format",
             "{{.InfraContainerID}}"], "infra id").strip()
        r.expect("pod infra id", live_infra == infra)
        cgroup_path = podman.must(
            runner,
            ["pod", "inspect", objs["pod"], "--format",
             "{{.CgroupPath}}"], "pod cgroup").strip()
        cbase = Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")
        try:
            pmem = (cbase / "memory.max").read_text().strip()
            pcpu = (cbase / "cpu.max").read_text().strip()
        except OSError as exc:
            r.expect("pod cgroup limits", False, str(exc))
        else:
            res = profile["resources"]
            r.expect("pod cgroup memory.max",
                     pmem == str(res["memory_mb"] << 20), pmem[:40])
            r.expect("pod cgroup cpu.max",
                     pcpu == f"{int(res['cpus'] * 100000)} 100000",
                     pcpu[:40])

    control = inst / "control"
    expects = _member_expect(
        objs["volumes"], control, profile, infra,
        record["network"]["name"])
    for role, cid in sorted(objs["containers"].items()):
        info = _inspect(runner, cid)
        if not r.expect(f"{role} container exists", info is not None):
            continue
        labels = info.get("Config", {}).get("Labels") or {}
        r.expect(f"{role} labels",
                 labels.get(spec.LABEL_INSTANCE) == uuid
                 and labels.get(spec.LABEL_ROLE) == role)
        r.expect(f"{role} image",
                 info.get("Image") == record["images"][role])
        if role != "git":
            r.expect(f"{role} pod membership",
                     info.get("Pod") == objs["pod"])
        _check_container_spec(r, role, info, expects[role])

    ctrl_fps = {}
    for fname in spec.CONTROL_FILES:
        try:
            ctrl_fps[fname] = hashlib.sha256(
                _read_control(control / fname, _CONTROL_MODES[fname],
                              fname)).hexdigest()
        except (OSError, RuntimeFault, FileNotFoundError):
            ctrl_fps[fname] = None
    r.expect("control fingerprints", ctrl_fps == record["control_sha256"],
             "drift" if ctrl_fps != record["control_sha256"] else "")

    running = {}
    infos = {}
    for role, cid in sorted(objs["containers"].items()):
        infos[role] = _inspect(runner, cid)
        running[role] = _running(infos[role])
        r.expect(f"{role} running", running[role],
                 "required member not running")
    infra_info = _inspect(runner, infra)
    infra_running = _running(infra_info)
    r.expect("infra running", infra_running,
             "required infra not running")

    if infra_running:
        try:
            network.verify_policy(
                runner, infra, record["policy"]["workload"])
            r.expect("workload policy canonical", True)
        except network.NetworkError as exc:
            r.expect("workload policy canonical", False, str(exc))
        _infra_status_check(r, runner, infra)
    if running.get("git"):
        try:
            network.verify_policy(
                runner, objs["containers"]["git"], record["policy"]["git"])
            r.expect("git policy canonical", True)
        except network.NetworkError as exc:
            r.expect("git policy canonical", False, str(exc))

    namespaces = {"infra": None, "git": None,
                  "inference": None, "harness": None}
    if infra_running:
        namespaces["infra"] = _ns_inventory(
            r, runner, "infra", infra)
    for role in ("inference", "harness", "git"):
        if running.get(role):
            namespaces[role] = _ns_inventory(
                r, runner, role, objs["containers"][role])
        else:
            r.expect(f"{role} namespace inventory", False,
                     "not running")
    if infra_running:
        vspec.check_namespaces(r, namespaces, infra)
    else:
        r.expect("namespace comparison", False, "infra not running")

    for role, cid in sorted(objs["containers"].items()):
        if running.get(role):
            _proc_status_checks(r, runner, cid, role)
            _cgroup_checks(r, runner, cid, role, expects[role])
        else:
            r.expect(f"{role} proc/cgroup checks", False, "not running")

    if running.get("harness") and running.get("inference"):
        hc = objs["containers"]["harness"]
        out = _exec_py(runner, hc, spec.PROBE_MODEL)
        r.expect("model api authenticated models list",
                 out is not None,
                 "probe failed" if out is None else "")
        out = _exec_py(
            runner, hc,
            "import urllib.request, urllib.error\n"
            "try:\n"
            "    urllib.request.urlopen("
            "'http://127.0.0.1:8080/v1/models', timeout=5)\n"
            "    print('unexpected')\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(e.code)\n")
        r.expect("model api unauthenticated rejected",
                 out is not None and out.strip() in ("401", "403"),
                 (out or "").strip()[:80])
        out = _exec_py(runner, hc, spec.PROBE_SERVICE)
        r.expect("opencode api authenticated", out is not None,
                 "probe failed" if out is None else "")
        out = _exec_py(
            runner, hc,
            "import urllib.request, urllib.error\n"
            "try:\n"
            "    urllib.request.urlopen("
            "'http://127.0.0.1:4096/api/config', timeout=5)\n"
            "    print('unexpected')\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(e.code)\n")
        r.expect("opencode api unauthenticated 401",
                 out is not None and out.strip() == "401",
                 (out or "").strip()[:80])
        out = _exec_py(
            runner, hc,
            "import os\n"
            "bad = [p for p in ('/repos', '/seed', '/proc/1/root/.ssh')"
            " if os.path.exists(p)]\n"
            "print('clear' if not bad else 'LEAK ' + ','.join(bad))\n")
        r.expect("harness path canaries absent",
                 out is not None and out.strip() == "clear",
                 (out or "").strip()[:80])
        out = _exec_py(
            runner, hc,
            "import os\n"
            "print(sorted(os.listdir('/run/local-agent')))\n")
        r.expect("harness control mounts present",
                 out is not None and "ssh_host_ed25519_key" not in out
                 and "authorized_keys" not in out,
                 (out or "").strip()[:200])
        _listener_check(r, runner, hc, "pod netns",
                        [("0100007F", 8080), ("0100007F", 4096)])
    else:
        r.expect("api/listener checks", False,
                 "harness/inference not running")
    if running.get("git"):
        _listener_check(r, runner, objs["containers"]["git"], "git",
                        [("00000000", spec.GIT_PORT)])
        out = _exec_py(
            runner, objs["containers"]["git"],
            "import subprocess\n"
            "print(subprocess.run(['git','-C','/repos/demo.git',\n"
            "  'rev-parse','refs/heads/main'],capture_output=True,\n"
            "  text=True).stdout.strip())\n")
        r.expect("seed main commit", out is not None
                 and out.strip() == record["seed_main"],
                 (out or "").strip()[:80])

    lsm = Path("/sys/kernel/security/apparmor/profiles")
    selinux = Path("/sys/fs/selinux/enforce")
    lsm_active = lsm.exists() or (selinux.exists()
                                and selinux.read_text().strip() == "1")
    r.add("lsm confinement", "degraded",
          "prototype exception: no active LSM confinement"
          if not lsm_active else "lsm present")
    r.add("storage quotas", "degraded",
          "prototype exception: writable storage quotas unverified")
    r.add("infra hardening", "degraded",
          "infra container runs default read-only/cap profile "
          "(podman 4.9 limitation); pod cgroup limits verified; "
          "policy enforced at pod netns")
    return r
