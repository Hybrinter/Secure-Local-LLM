"""Shared pure fixtures for verification tests (no live imports)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import runtime_spec as spec  # noqa: E402
from local_agent import verify_spec as vspec  # noqa: E402

UUID = "01234567-89ab-4cde-8f01-23456789abcd"
CONTROL = Path("/ctl")
INFRA = "a" * 64

PROFILE = {
    "resources": {"memory_mb": 8192, "cpus": 4, "pids": 512},
    "model": {"context_tokens": 8192, "max_output_tokens": 1024,
              "threads": 4, "parallel": 1},
    "timeouts": {"startup_seconds": 300, "request_seconds": 120},
}
VOLS = {"workspace": "vw", "state": "vs", "model": "vm", "repo": "vr"}


class FakeRes:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = False


class FakeRunner:
    def __init__(self, routes=None):
        self.calls = []
        self.routes = routes or {}

    def podman(self, args, timeout=None, extra_env=None, stdin_text=None,
               pass_fds=()):
        self.calls.append(list(args))
        for prefix, res in self.routes.items():
            if " ".join(args).startswith(prefix):
                return res() if callable(res) else res
        return FakeRes(0, "")

    def run(self, argv, timeout=None, extra_env=None, stdin_text=None,
            pass_fds=()):
        self.calls.append(list(argv))
        return FakeRes(0, "")


def _expects():
    return vspec._member_expect(VOLS, CONTROL, PROFILE, INFRA, "net-x")


def _good_inspect(role):
    exp = _expects()[role]
    mounts = []
    for dest, req in exp["mounts"].items():
        m = {"Destination": dest, "RW": req["rw"],
             "Type": req.get("type", "volume"),
             "Options": list(req.get("opts", ()))}
        if req.get("name"):
            m["Name"] = req["name"]
            m["Source"] = "/var/vols/" + req["name"]
        else:
            m["Source"] = req.get("source", "")
        mounts.append(m)
    env = [f"{k}={v}" for k, v in
           (spec.HARNESS_ENV if role == "harness" else {}).items()]
    env.append("PATH=/usr/bin:/bin")
    return {
        "Config": {"Cmd": exp["cmd"], "User": "1000:1000", "Env": env,
                   "Labels": {spec.LABEL_INSTANCE: UUID,
                              spec.LABEL_ROLE: role}},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Memory": exp["memory"], "MemorySwap": exp["memory"],
            "NanoCpus": exp["nanocpus"], "PidsLimit": exp["pids"],
            "SecurityOpt": ["no-new-privileges"],
            "CapAdd": [], "CapDrop": list(vspec._DEFAULT_CAPS),
            "PidMode": "private", "IpcMode": "private",
            "UTSMode": "private", "CgroupMode": "private",
            "UsernsMode": ("private"
                           if role == "git" else exp["userns_id"]),
            "IDMappings": (
                {"UidMap": ["0:1:1000", "1000:0:1"],
                 "GidMap": ["0:1:1000", "1000:0:1"]}
                if role == "git" else None),
            "NetworkMode": ("bridge" if role == "git"
                            else exp["netns_id"]),
            "LogConfig": {"Type": "k8s-file", "Config": {},
                          "Size": "4MB"},
            "Privileged": False,
            "RestartPolicy": {"Name": "no"},
            "PortBindings": None, "PublishAllPorts": False,
            "Devices": [],
            "Tmpfs": {
                "/run/local-agent": "rw,mode=755,size=16m",
                "/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=64m",
            },
        },
        "Mounts": mounts,
        "NetworkSettings": (
            {"Networks": {"net-x": {}}} if role == "git" else {}),
    }


def _fail_names(r):
    return [c["name"] for c in r.checks if c["status"] == "fail"]
