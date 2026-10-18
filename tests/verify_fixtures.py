"""Shared pure fixtures for verification tests (no live imports)."""

import contextlib
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import runtime_spec as spec  # noqa: E402
from local_agent import state  # noqa: E402
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


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_REL = ".devin/opencode/opencode.json"
_REPO_COPIES = (
    ".devin/profiles/cpu.json",
    ".devin/artifacts.lock.json",
    "containers/harness.Containerfile",
    "containers/inference.Containerfile",
    *state.GIT_PREPARED_FILES,
)


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextlib.contextmanager
def verify_env():
    """Records-loaded verify() sandbox: real temp repo reads, mocked state."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        repo = tmp / "repo"
        for rel in (*_REPO_COPIES, TEMPLATE_REL):
            dst = repo / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((REPO_ROOT / rel).read_bytes())
        template_path = repo / TEMPLATE_REL
        profile_path = repo / ".devin" / "profiles" / "cpu.json"
        lock_path = repo / ".devin" / "artifacts.lock.json"
        profile_sha = _sha256(profile_path)
        lock_sha = _sha256(lock_path)
        names = spec.names(UUID)
        objects = {
            "pod": "0" * 64,
            "infra": INFRA,
            "containers": {
                "inference": "1" * 64,
                "harness": "2" * 64,
                "git": "3" * 64,
            },
            "volumes": dict(VOLS),
        }
        images = {
            "harness": "4" * 64,
            "inference": "5" * 64,
            "git": "6" * 64,
        }
        manifest = {
            "identity": {"uuid": UUID},
            "profile": {
                "name": "cpu", "sha256": profile_sha,
                "bytes": profile_path.stat().st_size,
                "path": str(profile_path),
            },
            "artifacts_lock": {
                "path": str(lock_path), "sha256": lock_sha,
                "bytes": lock_path.stat().st_size,
            },
            "resources": {
                "pod_id": objects["pod"],
                "container_ids": dict(objects["containers"]),
                "volume_names": dict(objects["volumes"]),
                "network_id": "7" * 64,
            },
        }
        prepared = {
            "fingerprints": {
                f"{role}_containerfile": _sha256(
                    repo / "containers" / f"{role}.Containerfile")
                for role in ("harness", "inference")
            },
            "images": {
                "harness": images["harness"],
                "inference": images["inference"],
            },
        }
        git_prepared = {
            "profile_sha256": profile_sha,
            "artifacts_lock_sha256": lock_sha,
            "files": {
                rel: _sha256(repo / rel)
                for rel in state.GIT_PREPARED_FILES
            },
            "image_id": images["git"],
        }
        record = {
            "instance_uuid": UUID,
            "subnet": "10.240.7.0/28",
            "pod_ip": "10.240.7.2",
            "git_ip": "10.240.7.3",
            "network": {
                "id": manifest["resources"]["network_id"],
                "name": names["net"],
            },
            "objects": objects,
            "images": images,
            "fingerprints": {
                "profile": profile_sha,
                "artifacts_lock": lock_sha,
                "source_config": _sha256(template_path),
            },
            "control_sha256": {
                fname: "8" * 64 for fname in spec.CONTROL_FILES
            },
            "policy": {"workload": {}, "git": {}},
            "seed_main": "9" * 40,
        }
        inspects = {objects["infra"]: {}}
        for role, cid in objects["containers"].items():
            info = _good_inspect(role)
            if role == "git":
                info["NetworkSettings"]["Networks"] = {names["net"]: {}}
            else:
                info["Pod"] = objects["pod"]
            inspects[cid] = info
        vol_roles = {v: k for k, v in objects["volumes"].items()}
        runner = FakeRunner()

        def podman(args, timeout=None, extra_env=None, stdin_text=None,
                   pass_fds=()):
            runner.calls.append(list(args))
            joined = " ".join(args)
            if args[:2] == ["network", "inspect"]:
                return FakeRes(0, json.dumps([{
                    "id": record["network"]["id"],
                    "internal": True,
                    "dns_enabled": False,
                    "ipv6_enabled": False,
                    "subnets": [{"subnet": record["subnet"]}],
                    "labels": {
                        spec.LABEL_INSTANCE: UUID,
                        spec.LABEL_ROLE: "network",
                    },
                }]))
            if args[:2] == ["volume", "inspect"]:
                if "--format" in args:
                    return FakeRes(0, json.dumps({
                        spec.LABEL_INSTANCE: UUID,
                        spec.LABEL_ROLE: vol_roles[args[2]],
                    }))
                return FakeRes(0, "[]")
            if args[:2] == ["pod", "inspect"]:
                if "InfraContainerID" in joined:
                    return FakeRes(0, objects["infra"] + "\n")
                if "CgroupPath" in joined:
                    return FakeRes(0, "sll-verify-env-absent\n")
                if "--format" in args:
                    return FakeRes(0, json.dumps({
                        spec.LABEL_INSTANCE: UUID,
                        spec.LABEL_ROLE: "pod",
                    }))
                return FakeRes(0, "[]")
            if args[:1] == ["inspect"]:
                info = inspects.get(args[1])
                if info is None:
                    return FakeRes(1, "", "no such object")
                return FakeRes(0, json.dumps([info]))
            return FakeRes(0, "")

        runner.podman = podman
        env = SimpleNamespace(
            root=tmp / "state", repo=repo, name="demo", runner=runner,
            manifest=manifest, prepared=prepared,
            git_prepared=git_prepared, record=record,
            template_path=template_path,
        )
        with mock.patch(
                "local_agent.verify.load_manifest",
                return_value=manifest), mock.patch(
                "local_agent.verify.load_prepared",
                return_value=prepared), mock.patch(
                "local_agent.verify.load_git_prepared",
                return_value=git_prepared), mock.patch(
                "local_agent.runtime_record.load_runtime",
                return_value=record):
            yield env
