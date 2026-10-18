"""Pure expected-spec comparison for effective verification."""

from __future__ import annotations

from . import runtime_spec as spec

_FULL_CAPS = {
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
    "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
    "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
}

_DEFAULT_CAPS = {
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID",
    "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT",
}

_STATUSES = ("pass", "fail", "degraded")

EXPECTED_TMPFS = {
    "/run/local-agent": {"rw", "mode=755", "size=16m"},
    "/tmp": {"rw", "nosuid", "nodev", "noexec", "mode=1777", "size=64m"},
}


class Result:
    def __init__(self):
        self.checks = []

    def add(self, name, status, detail=""):
        if status is True:
            status = "pass"
        elif status is False:
            status = "fail"
        if status not in _STATUSES:
            raise ValueError(f"unknown check status: {status!r}")
        self.checks.append({"name": name, "status": status,
                            "detail": detail})
        return status == "pass"

    def expect(self, name, cond, detail=""):
        return self.add(name, bool(cond), detail)

    @property
    def ok(self):
        return bool(self.checks) and all(
            c["status"] != "fail" for c in self.checks)


def _expect_mounts(r, name, info, expected):
    actual = {}
    for m in info.get("Mounts") or []:
        actual[m.get("Destination")] = m
    missing = sorted(d for d in expected if d not in actual)
    if missing:
        return r.expect(name, False, f"missing mounts {missing}")
    extra = sorted(d for d in actual if d not in expected)
    if extra:
        return r.expect(name, False, f"unexpected mounts {extra}")
    for dest, req in expected.items():
        m = actual[dest]
        if m.get("RW") != req["rw"]:
            return r.expect(name, False, f"{dest} rw mismatch")
        if req.get("type") and m.get("Type") != req["type"]:
            return r.expect(name, False, f"{dest} type mismatch")
        if req.get("name") and m.get("Name") != req["name"]:
            return r.expect(name, False, f"{dest} volume mismatch")
        if req.get("source") and m.get("Source") != req["source"]:
            return r.expect(name, False, f"{dest} source mismatch")
        opts = set(m.get("Options") or [])
        if not req.get("opts", frozenset()) <= opts:
            return r.expect(
                name, False, f"{dest} missing opts {req['opts'] - opts}")
    return r.expect(name, True)


def _expected_mounts(role, control, vols):
    ro_bind = frozenset({"rbind", "nosuid", "nodev", "noexec"})
    if role == "inference":
        return {
            "/models": {"type": "volume", "name": vols["model"],
                        "rw": False,
                        "opts": frozenset({"nosuid", "nodev", "noexec"})},
            "/run/local-agent/model-api-key":
                {"type": "bind",
                 "source": str(control / "model-api-key"),
                 "rw": False, "opts": ro_bind},
        }
    if role == "harness":
        exp = {
            "/workspace": {"type": "volume", "name": vols["workspace"],
                           "rw": True,
                           "opts": frozenset({"nosuid", "nodev"})},
            "/state": {"type": "volume", "name": vols["state"],
                       "rw": True,
                       "opts": frozenset({"nosuid", "nodev"})},
        }
        for fname in (
            "opencode.json", "service.json", "model-api-key", "ssh_config",
            "client_key", "known_hosts", "gitconfig",
        ):
            sub = "opencode/" if fname in ("opencode.json", "service.json") \
                else ""
            exp[f"/run/local-agent/{sub}{fname}"] = {
                "type": "bind", "source": str(control / fname),
                "rw": False, "opts": ro_bind}
        return exp
    return {
        "/repos": {"type": "volume", "name": vols["repo"], "rw": True,
                   "opts": frozenset({"nosuid", "nodev"})},
        "/run/local-agent/ssh_host_ed25519_key":
            {"type": "bind",
             "source": str(control / "ssh_host_ed25519_key"),
             "rw": False, "opts": ro_bind},
        "/run/local-agent/authorized_keys":
            {"type": "bind", "source": str(control / "authorized_keys"),
             "rw": False, "opts": ro_bind},
    }


def _expect_tmpfs(r, name, info):
    tmpfs = (info.get("HostConfig") or {}).get("Tmpfs") or {}
    if set(tmpfs) != set(EXPECTED_TMPFS):
        return r.expect(
            name, False, f"tmpfs dests {sorted(tmpfs)}")
    for dest, required in EXPECTED_TMPFS.items():
        opts = set(str(tmpfs[dest]).replace(":", ",").split(","))
        if not required <= opts:
            return r.expect(
                name, False, f"{dest} missing opts {required - opts}")
    return r.expect(name, True)


def _check_container_spec(r, role, info, expect):
    host = info.get("HostConfig", {})
    cfg = info.get("Config", {})
    name = f"{role} spec"
    r.expect(f"{name}: command", cfg.get("Cmd") == expect["cmd"],
             str(cfg.get("Cmd"))[:120])
    r.expect(f"{name}: user", cfg.get("User") == "1000:1000",
             str(cfg.get("User")))
    r.expect(f"{name}: readonly rootfs",
             host.get("ReadonlyRootfs") is True)
    r.expect(f"{name}: memory",
             host.get("Memory") == expect["memory"],
             f"{host.get('Memory')} != {expect['memory']}")
    r.expect(f"{name}: memory-swap equals memory (no extra swap)",
             host.get("MemorySwap") == expect["memory"],
             f"{host.get('MemorySwap')}")
    r.expect(f"{name}: cpus", host.get("NanoCpus") == expect["nanocpus"],
             f"{host.get('NanoCpus')} != {expect['nanocpus']}")
    r.expect(f"{name}: pids", host.get("PidsLimit") == expect["pids"],
             f"{host.get('PidsLimit')}")
    r.expect(
        f"{name}: security opts exact",
        host.get("SecurityOpt") == ["no-new-privileges"],
        str(host.get("SecurityOpt")))
    r.expect(f"{name}: no added capabilities",
             not (host.get("CapAdd") or []))
    dropped = set(host.get("CapDrop") or [])
    r.expect(
        f"{name}: cap-drop covers full set",
        "ALL" in dropped or _FULL_CAPS <= dropped
        or _DEFAULT_CAPS <= dropped,
        f"{len(dropped)} caps dropped")
    for mode, want in (
        ("PidMode", "private"), ("IpcMode", "private"),
        ("UTSMode", "private"), ("CgroupMode", "private"),
    ):
        r.expect(f"{name}: {mode}", host.get(mode) == want,
                 str(host.get(mode)))
    userns = expect.get("userns")
    if userns == "keep-id":
        idm = host.get("IDMappings") or {}
        uidmap = set(idm.get("UidMap") or [])
        gidmap = set(idm.get("GidMap") or [])
        r.expect(f"{name}: userns keep-id",
                 "1000:0:1" in uidmap and "1000:0:1" in gidmap,
                 f"UidMap={sorted(uidmap)}")
    elif userns == "container":
        r.expect(f"{name}: userns exact infra",
                 host.get("UsernsMode") == expect["userns_id"],
                 str(host.get("UsernsMode")))
    if expect.get("pod_member"):
        r.expect(f"{name}: netns exact infra",
                 host.get("NetworkMode") == expect["netns_id"],
                 str(host.get("NetworkMode")))
    if expect.get("network_name"):
        nets = (info.get("NetworkSettings") or {}).get("Networks") or {}
        r.expect(f"{name}: network membership",
                 set(nets) == {expect["network_name"]},
                 str(sorted(nets)))
    log = host.get("LogConfig") or {}
    r.expect(f"{name}: log driver", log.get("Type") == "k8s-file",
             str(log.get("Type")))
    r.expect(f"{name}: log size",
             str(log.get("Size")).lower() == "4mb", str(log.get("Size")))
    r.expect(f"{name}: no privileged", host.get("Privileged") is not True)
    rp = host.get("RestartPolicy") or {}
    r.expect(f"{name}: no restart policy", rp.get("Name") in ("", "no"))
    r.expect(f"{name}: no published ports",
             not host.get("PortBindings")
             and host.get("PublishAllPorts") is not True)
    r.expect(f"{name}: no extra devices", not (host.get("Devices") or []))
    env = cfg.get("Env") or []
    envmap = dict(e.split("=", 1) for e in env if "=" in e)
    bad_env = [
        k for k in envmap
        if k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                 "https_proxy", "all_proxy", "SSH_AUTH_SOCK")
    ]
    r.expect(f"{name}: no proxy/agent env", not bad_env, str(bad_env))
    for key, value in _expected_env(role).items():
        if envmap.get(key) != value:
            r.expect(f"{name}: env {key}", False, envmap.get(key))
    _expect_mounts(r, f"{name}: mounts", info, expect["mounts"])
    _expect_tmpfs(r, f"{name}: tmpfs", info)


def _expected_env(role):
    if role == "harness":
        return dict(spec.HARNESS_ENV)
    return {}


def _member_expect(vols, control, profile, infra_id, net_name):
    res = profile["resources"]
    inf_mb = 3 * res["memory_mb"] // 4
    har_mb = res["memory_mb"] // 4
    member_pids = res["pids"] // 2
    return {
        "inference": {
            "cmd": spec.model_argv(profile),
            "memory": inf_mb << 20,
            "nanocpus": int(res["cpus"] * 1e9),
            "pids": member_pids,
            "userns": "container",
            "userns_id": f"container:{infra_id}",
            "pod_member": True,
            "netns_id": f"container:{infra_id}",
            "mounts": _expected_mounts("inference", control, vols),
        },
        "harness": {
            "cmd": ["opencode", "serve", "--service"],
            "memory": har_mb << 20,
            "nanocpus": int(res["cpus"] * 1e9),
            "pids": member_pids,
            "userns": "container",
            "userns_id": f"container:{infra_id}",
            "pod_member": True,
            "netns_id": f"container:{infra_id}",
            "mounts": _expected_mounts("harness", control, vols),
        },
        "git": {
            "cmd": ["/usr/sbin/sshd", "-D", "-e", "-f",
                    "/etc/ssh/sshd_config_fixture"],
            "memory": 512 << 20,
            "nanocpus": int(1e9),
            "pids": 64,
            "userns": "keep-id",
            "network_name": net_name,
            "mounts": _expected_mounts("git", control, vols),
        },
    }


NS_TYPES = ("net", "user", "pid", "ipc", "uts", "mnt", "cgroup")


def check_namespaces(r, namespaces, infra_id):
    """namespaces: {role: {ns: 'type:[inode]'}}; fail-closed compare."""
    have = {role: ns for role, ns in namespaces.items() if ns is not None}
    for role in ("infra", "inference", "harness", "git"):
        if role not in have or any(
            namespaces[role].get(t) is None for t in NS_TYPES
        ):
            return r.expect(
                "namespace inventory", False,
                f"missing namespace data for {role}")
    infra_ns = namespaces["infra"]
    pod_ns = namespaces
    for role in ("inference", "harness"):
        for t in ("net", "user"):
            r.expect(f"{role} ns {t} shared with infra",
                     pod_ns[role][t] == infra_ns[t],
                     f"{pod_ns[role][t]} != {infra_ns[t]}")
    for t in ("pid", "ipc", "uts", "mnt", "cgroup"):
        seen = {}
        dup = None
        for role in ("infra", "inference", "harness", "git"):
            val = pod_ns[role][t]
            if val in seen:
                dup = f"{t}: {seen[val]} == {role}"
            seen[val] = role
        r.expect(f"ns {t} pairwise private", dup is None, dup or "")
    r.expect("git ns net distinct from pod",
             namespaces["git"]["net"] != infra_ns["net"])
    r.expect("git ns user distinct from pod",
             namespaces["git"]["user"] != infra_ns["user"])
    return True
