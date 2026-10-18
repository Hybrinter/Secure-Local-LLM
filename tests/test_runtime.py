"""Unit tests for runtime lifecycle: ownership, stop, adoption refusal."""

import contextlib
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import artifacts, network, runtime  # noqa: E402
from local_agent import runtime_record, runtime_spec as spec  # noqa: E402
from local_agent import state, verify  # noqa: E402

UUID = "01234567-89ab-4cde-8f01-23456789abcd"
BASE_REF = (
    "docker.io/library/debian@sha256:"
    "7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587")


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


class CheckOwned(unittest.TestCase):
    def test_foreign_labels_rejected(self):
        runner = FakeRunner({
            "network inspect sll-x-net": FakeRes(
                0, '[{"labels":{"other":"x"}}]'),
        })
        with self.assertRaises(runtime.RuntimeFault):
            runtime._check_owned(
                runner, "network", "sll-x-net", UUID, "network")

    def test_foreign_role_rejected(self):
        runner = FakeRunner({
            "container inspect c": FakeRes(
                0, json.dumps([{"Config": {"Labels": {
                    spec.LABEL_INSTANCE: UUID,
                    spec.LABEL_ROLE: "git"}}}])),
        })
        with self.assertRaises(runtime.RuntimeFault):
            runtime._check_owned(
                runner, "container", "c", UUID, "harness")


class VerifiedMember(unittest.TestCase):
    def _runner(self, labels=None, pod="p" * 64, rc=0):
        info = {
            "Config": {"Labels": labels if labels is not None else {
                spec.LABEL_INSTANCE: UUID, spec.LABEL_ROLE: "harness"}},
            "Pod": pod,
        }
        return FakeRunner({
            "inspect": FakeRes(rc, json.dumps([info])),
        })

    def test_ok(self):
        runtime._verified_member(
            self._runner(), "c" * 64, "harness", UUID, "p" * 64)

    def test_foreign_role_refused(self):
        r = self._runner(labels={
            spec.LABEL_INSTANCE: UUID, spec.LABEL_ROLE: "git"})
        with self.assertRaises(runtime.RuntimeFault):
            runtime._verified_member(
                r, "c" * 64, "harness", UUID, "p" * 64)

    def test_foreign_instance_refused(self):
        r = self._runner(labels={
            spec.LABEL_INSTANCE: str(uuid.uuid4()),
            spec.LABEL_ROLE: "harness"})
        with self.assertRaises(runtime.RuntimeFault):
            runtime._verified_member(
                r, "c" * 64, "harness", UUID, "p" * 64)

    def test_wrong_pod_refused(self):
        r = self._runner(pod="e" * 64)
        with self.assertRaises(runtime.RuntimeFault):
            runtime._verified_member(
                r, "c" * 64, "harness", UUID, "p" * 64)

    def test_git_not_in_pod(self):
        r = self._runner(labels={
            spec.LABEL_INSTANCE: UUID, spec.LABEL_ROLE: "git"}, pod="")
        runtime._verified_member(
            r, "c" * 64, "git", UUID, "p" * 64)

    def test_inspect_failure_refused(self):
        with self.assertRaises(runtime.RuntimeFault):
            runtime._verified_member(
                self._runner(rc=1), "c" * 64, "harness", UUID, "p" * 64)


class StopPaths(unittest.TestCase):
    def _root(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        inst = root / "instances" / "demo"
        inst.mkdir(parents=True)
        for d in (root, root / "instances", inst):
            os.chmod(d, 0o700)
        manifest = {
            "schema": "secure-local-llm/instance@1",
            "identity": {"name": "demo", "uuid": UUID,
                         "created_utc": "2026-10-17T00:00:00+00:00"},
            "profile": {"name": "cpu", "sha256": "a" * 64},
            "artifacts_lock": {"sha256": "b" * 64, "path": "/l",
                               "bytes": 10},
            "exceptions": {"prototype_no_lsm_acknowledged": True},
            "resources": {
                "pod_id": "f" * 64,
                "container_ids": {"harness": "1" * 64,
                                  "inference": "2" * 64},
                "volume_names": {"workspace": "sll-01234567-ws"},
                "network_id": "c" * 64},
        }
        state.validate_manifest(manifest, expected_name="demo")
        (inst / "manifest.json").write_bytes(
            json.dumps(manifest).encode())
        os.chmod(inst / "manifest.json", 0o600)
        return td, root

    def _runner(self, stop_rc=None, pod_rc=0):
        infos = {
            "1" * 64: {"Config": {"Labels": {
                spec.LABEL_INSTANCE: UUID,
                spec.LABEL_ROLE: "harness"}}, "Pod": "f" * 64},
            "2" * 64: {"Config": {"Labels": {
                spec.LABEL_INSTANCE: UUID,
                spec.LABEL_ROLE: "inference"}}, "Pod": "f" * 64},
        }
        stop_rc = stop_rc or {}
        runner = FakeRunner()

        def podman_fn(args, **kw):
            runner.calls.append(list(args))
            joined = " ".join(args)
            if joined.startswith("inspect"):
                cid = args[1]
                if cid not in infos:
                    return FakeRes(1, "", "no such object")
                return FakeRes(0, json.dumps([infos[cid]]))
            if joined.startswith("pod inspect"):
                return FakeRes(0, json.dumps({
                    spec.LABEL_INSTANCE: UUID,
                    spec.LABEL_ROLE: "pod"}))
            if joined.startswith("stop"):
                cid = args[3]
                return FakeRes(stop_rc.get(cid, 0), "")
            if joined.startswith("pod stop"):
                return FakeRes(pod_rc, "")
            return FakeRes(0, "")

        runner.podman = podman_fn
        return runner

    def test_stop_all_verified(self):
        td, root = self._root()
        self.addCleanup(td.cleanup)
        out = runtime._stop(root, "demo", self._runner())
        self.assertEqual(
            sorted(out["stopped"]), ["harness", "inference", "pod"])

    def test_failed_member_stop_reports(self):
        td, root = self._root()
        self.addCleanup(td.cleanup)
        runner = self._runner(stop_rc={"1" * 64: 1})
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._stop(root, "demo", runner)
        self.assertIn("harness", str(ctx.exception))
        self.assertIn("stopped", str(ctx.exception))

    def test_foreign_member_never_stopped(self):
        td, root = self._root()
        self.addCleanup(td.cleanup)
        infos_runner = self._runner()
        orig = infos_runner.podman

        def hostile(args, **kw):
            if args[:1] == ["inspect"]:
                cid = args[1]
                bad = {"Config": {"Labels": {
                    spec.LABEL_INSTANCE: str(uuid.uuid4()),
                    spec.LABEL_ROLE: "harness"}}, "Pod": "f" * 64}
                return FakeRes(0, json.dumps([bad]))
            return orig(args, **kw)

        infos_runner.podman = hostile
        with self.assertRaises(runtime.RuntimeFault):
            runtime._stop(root, "demo", infos_runner)
        self.assertFalse(
            any(c[0] == "stop" for c in infos_runner.calls),
            "stop must not run against unverified members")

    def test_pod_drift_refused_before_stops(self):
        td, root = self._root()
        self.addCleanup(td.cleanup)
        runner = self._runner()
        orig = runner.podman

        def drift(args, **kw):
            if args[:2] == ["pod", "inspect"]:
                return FakeRes(0, json.dumps({
                    spec.LABEL_INSTANCE: str(uuid.uuid4()),
                    spec.LABEL_ROLE: "pod"}))
            return orig(args, **kw)

        runner.podman = drift
        with self.assertRaises(runtime.RuntimeFault):
            runtime._stop(root, "demo", runner)
        self.assertFalse(any(c[0] == "stop" for c in runner.calls))


class BoundBeforeCreate(unittest.TestCase):
    def test_recorded_member_missing_refuses_first(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        inst = root / "instances" / "demo"
        inst.mkdir(parents=True)
        for d in (root, root / "instances", inst):
            os.chmod(d, 0o700)
        n = spec.names(UUID)
        manifest = {
            "schema": "secure-local-llm/instance@1",
            "identity": {"name": "demo", "uuid": UUID,
                         "created_utc": "2026-10-17T00:00:00+00:00"},
            "profile": {"name": "cpu", "sha256": "a" * 64},
            "artifacts_lock": {"sha256": "b" * 64, "path": "/l",
                               "bytes": 10},
            "exceptions": {"prototype_no_lsm_acknowledged": True},
            "resources": {
                "pod_id": "f" * 64,
                "container_ids": {"inference": "1" * 64,
                                  "harness": "2" * 64,
                                  "git": "3" * 64},
                "volume_names": {
                    "workspace": n["vol_workspace"],
                    "state": n["vol_state"],
                    "model": n["vol_model"],
                    "repo": n["vol_repo"]},
                "network_id": "c" * 64},
        }
        state.validate_manifest(manifest, expected_name="demo")
        (inst / "manifest.json").write_bytes(json.dumps(manifest).encode())
        os.chmod(inst / "manifest.json", 0o600)

        runner = FakeRunner()

        vol_role = {
            name: role
            for role, name in manifest["resources"]["volume_names"].items()
        }

        def podman_fn(args, **kw):
            runner.calls.append(list(args))
            if args[0] == "volume" and args[1] == "inspect":
                if "--format" in args:
                    return FakeRes(0, json.dumps({
                        spec.LABEL_INSTANCE: UUID,
                        spec.LABEL_ROLE: vol_role.get(args[2], "")}))
                return FakeRes(0, "[]")
            if args[:2] == ["pod", "inspect"]:
                if "{{json .Labels}}" in args:
                    return FakeRes(0, json.dumps({
                        spec.LABEL_INSTANCE: UUID,
                        spec.LABEL_ROLE: "pod"}))
                if "{{.Name}}" in args:
                    return FakeRes(0, n["pod"])
                return FakeRes(0, "f" * 64)
            return FakeRes(1, "", "no such object")

        runner.podman = podman_fn
        profile = {"resources": {"memory_mb": 8192, "cpus": 4,
                                 "pids": 512}}
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._bring_up(
                root, "demo", inst, manifest, runner, n, UUID, None,
                {"inference": "i" * 64, "harness": "h" * 64,
                 "git": "g" * 64},
                profile, {}, Path("/ctl"), {},
                __import__("ipaddress").ip_network("10.240.0.0/28"),
                "10.240.0.2", "10.240.0.3", "c" * 64,
                "l" * 64, "p" * 64, "s" * 64, [], lambda *a: None,
                base_image="i" * 64, model_algorithm="sha256")
        self.assertIn("refusing", str(ctx.exception))
        self.assertFalse(
            any("create" in " ".join(c) for c in runner.calls),
            "no create must run while recorded bindings are unresolved")


def _helper_reply(request):
    if request.get("op") == "read":
        return {"ok": True, "ruleset": json.dumps({"nftables": []})}
    policy = request.get("policy") or ""
    table = re.search(r"table inet (\S+)", policy).group(1)
    match = re.search(r"ip (daddr|saddr) (\S+) tcp dport (\d+)", policy)
    peer, port = match.group(2), int(match.group(3))
    role = "workload" if match.group(1) == "daddr" else "git"
    entries = [{"metainfo": {}},
               {"table": {"family": "inet", "name": table}}]
    for hook in ("input", "output"):
        entries.append({"chain": {
            "family": "inet", "table": table, "name": hook,
            "type": "filter", "hook": hook, "prio": -10,
            "policy": "drop"}})
        for expr in network._expected_exprs(role, peer, port)[hook]:
            entries.append({"rule": {
                "family": "inet", "table": table, "chain": hook,
                "expr": expr}})
    return {"ok": True,
            "ruleset": json.dumps({"nftables": entries})}


class _UpFixture:
    def _repo(self):
        return Path(__file__).resolve().parents[1]

    def _fixture(self, root, base_ref=BASE_REF, model_algo="sha256",
                 prepared_model=None):
        repo = self._repo()
        inst = root / "instances" / "demo"
        inst.mkdir(parents=True)
        for d in (root, root / "instances", inst):
            os.chmod(d, 0o700)
        model_hex = "4" * (64 if model_algo == "sha256" else 128)
        lock = {
            "schema": artifacts.LOCK_SCHEMA,
            "platform": artifacts.LOCK_PLATFORM,
            "base_image": base_ref,
            "artifacts": {
                "opencode": {
                    "format": "binary-tar", "version": "0.0.0",
                    "url": "https://example.invalid/opencode.tar",
                    "hash": {"algorithm": "sha256", "hex": "1" * 64},
                    "max_bytes": 1024,
                    "member": "package/bin/opencode",
                    "max_unpacked_bytes": 4096},
                "model": {
                    "format": "file", "version": "0.0.0",
                    "url": "https://example.invalid/model.gguf",
                    "hash": {"algorithm": model_algo, "hex": model_hex},
                    "max_bytes": 1024},
                "inference_source": {
                    "format": "source-tar", "version": "0.0.0",
                    "url": "https://example.invalid/src.tar",
                    "hash": {"algorithm": "sha256", "hex": "3" * 64},
                    "max_bytes": 1024, "root": "src",
                    "max_unpacked_bytes": 4096},
            },
        }
        lock_path = root / "lock.json"
        lock_path.write_bytes(json.dumps(lock).encode())
        os.chmod(lock_path, 0o600)

        def sha(rel):
            return hashlib.sha256((repo / rel).read_bytes()).hexdigest()

        profile_sha = sha(".devin/profiles/cpu.json")
        lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        manifest = {
            "schema": state.MANIFEST_SCHEMA,
            "identity": {"name": "demo", "uuid": UUID,
                         "created_utc": "2026-10-17T00:00:00+00:00"},
            "profile": {"name": "cpu", "sha256": profile_sha},
            "artifacts_lock": {"path": str(lock_path), "sha256": lock_sha,
                               "bytes": lock_path.stat().st_size},
            "exceptions": {"prototype_no_lsm_acknowledged": True},
            "resources": {"pod_id": None, "container_ids": {},
                          "volume_names": {}, "network_id": None},
        }
        prepared = {
            "schema": state.PREPARED_SCHEMA,
            "instance": "demo",
            "created_utc": "2026-10-17T00:00:00+00:00",
            "fingerprints": {
                "artifacts_lock": lock_sha,
                "profile": profile_sha,
                "harness_containerfile":
                    sha("containers/harness.Containerfile"),
                "inference_containerfile":
                    sha("containers/inference.Containerfile")},
            "artifacts": {
                "model": prepared_model or {
                    "path": str(root / "model.gguf"),
                    model_algo: model_hex},
                "opencode": {"path": str(root / "opencode.tar"),
                             "sha256": "5" * 64},
                "inference_source": {"path": str(root / "src.tar"),
                                     "sha256": "6" * 64}},
            "images": {"harness": "7" * 64, "inference": "8" * 64},
            "packages": {"harness": ["pkg"], "inference": ["pkg"]},
        }
        git_prepared = {
            "schema": state.GIT_PREPARED_SCHEMA,
            "instance": "demo",
            "instance_uuid": UUID,
            "created_utc": "2026-10-17T00:00:00+00:00",
            "artifacts_lock_sha256": lock_sha,
            "profile_sha256": profile_sha,
            "files": {rel: sha(rel) for rel in state.GIT_PREPARED_FILES},
            "image_id": "9" * 64,
            "packages": ["git"],
        }
        for fname, rec in (("manifest.json", manifest),
                           ("prepared.json", prepared),
                           ("git-prepared.json", git_prepared)):
            target = inst / fname
            target.write_bytes(json.dumps(rec).encode())
            os.chmod(target, 0o600)
        return inst

    def _runner(self, member_infos=None, member_stop=None,
                pod_labels=None, pod_stop=None, base_image_out=None,
                pod_exists=False, infra_image=None):
        runner = FakeRunner()
        roles = {"7" * 64: "harness", "8" * 64: "inference",
                 "9" * 64: "git"}
        member_infos = member_infos or {}
        member_stop = member_stop or {}
        if pod_labels is None:
            pod_labels = {
                spec.LABEL_INSTANCE: UUID, spec.LABEL_ROLE: "pod"}
        if pod_stop is None:
            pod_stop = FakeRes(0)
        if base_image_out is None:
            base_image_out = FakeRes(0, "b" * 64)
        if infra_image is None:
            infra_image = "b" * 64
        n = spec.names(UUID)
        cids = {n["inference"]: "1" * 64, n["harness"]: "2" * 64,
                n["git"]: "3" * 64}
        cid_roles = {
            cids[n["inference"]]: "inference",
            cids[n["harness"]]: "harness",
            cids[n["git"]]: "git"}
        created = {"net": set(), "vol": set(), "pod": set(),
                   "ctr": set()}

        def podman_fn(args, **kw):
            runner.calls.append(list(args))
            fmt = (args[args.index("--format") + 1]
                   if "--format" in args else None)
            if args[:2] == ["image", "inspect"]:
                if fmt == "{{json .Config.Labels}}":
                    return FakeRes(0, json.dumps({
                        spec.LABEL_INSTANCE: UUID,
                        spec.LABEL_ROLE: roles.get(args[2], "")}))
                return (base_image_out()
                        if callable(base_image_out) else base_image_out)
            if args[:2] == ["run", "--rm"]:
                if "/opt/llama/llama-server" in args:
                    return FakeRes(
                        0, " ".join(spec.MODEL_REQUIRED_FLAGS))
                if any("local-agent.seeded" in a for a in args):
                    return FakeRes(0, "main=" + "d" * 40 + "\n")
                return FakeRes(0, "")
            if args[:2] == ["network", "ls"]:
                return FakeRes(0, "")
            if args[:2] == ["network", "create"]:
                created["net"].add(args[-1])
                return FakeRes(0, args[-1])
            if args[:2] == ["network", "inspect"]:
                if args[2] in created["net"]:
                    return FakeRes(0, json.dumps([{
                        "id": "c" * 64,
                        "labels": {spec.LABEL_INSTANCE: UUID,
                                   spec.LABEL_ROLE: "network"},
                        "subnets": [{"subnet": "10.240.0.0/28"}]}]))
                return FakeRes(1, "", "no such network")
            if args[:2] == ["volume", "create"]:
                created["vol"].add(args[-1])
                return FakeRes(0, args[-1])
            if args[:2] == ["volume", "inspect"]:
                if args[2] in created["vol"]:
                    return FakeRes(0, "[{}]")
                return FakeRes(1, "", "no such volume")
            if args[:2] == ["pod", "create"]:
                created["pod"].add(args[args.index("--name") + 1])
                return FakeRes(0, "f" * 64)
            if args[:2] == ["pod", "inspect"]:
                if fmt == "{{json .Labels}}":
                    return FakeRes(0, json.dumps(pod_labels))
                if fmt == "{{.Id}}":
                    return FakeRes(0, "f" * 64)
                if fmt == "{{.InfraContainerID}}":
                    return FakeRes(0, "0" * 64)
                if fmt == "{{.Name}}":
                    return FakeRes(0, n["pod"])
                if args[2] in created["pod"] or pod_exists:
                    return FakeRes(0, "")
                return FakeRes(1, "", "no such pod")
            if args[:2] == ["pod", "stop"]:
                return pod_stop() if callable(pod_stop) else pod_stop
            if args[0] == "create":
                cname = args[args.index("--name") + 1]
                cid = cids.get(cname, "9" * 64)
                created["ctr"].add(cid)
                return FakeRes(0, cid)
            if args[0] == "inspect":
                if fmt == "{{.Id}}":
                    return FakeRes(0, args[1])
                if fmt == "{{.State.Pid}}":
                    return FakeRes(0, "4321")
                if fmt == "{{.State.Status}}":
                    return FakeRes(0, "running")
                if fmt == "{{.Image}}":
                    return FakeRes(0, infra_image)
                info = member_infos.get(args[1])
                if info is not None:
                    return FakeRes(0, json.dumps([info]))
                if args[1] in created["ctr"]:
                    return FakeRes(0, json.dumps([{
                        "Config": {"Labels": {
                            spec.LABEL_INSTANCE: UUID,
                            spec.LABEL_ROLE:
                                cid_roles.get(args[1], "")}},
                        "Pod": "f" * 64}]))
                return FakeRes(1, "", "no such object")
            if args[0] == "start":
                return FakeRes(0, "")
            if args[0] == "stop":
                return member_stop.get(args[3], FakeRes(0))
            if args[0] == "exec":
                if "readlink" in args:
                    return FakeRes(
                        0, "user:[4026531837]\nnet:[4026531840]\n")
                return FakeRes(0, "")
            return FakeRes(0, "")

        def run_fn(argv, **kw):
            runner.calls.append(list(argv))
            if argv[0] == "ssh-keygen":
                target = Path(argv[argv.index("-f") + 1])
                target.write_bytes(b"PRIV-" + target.name.encode() + b"\n")
                os.chmod(target, 0o600)
                pub = Path(str(target) + ".pub")
                pub.write_bytes(
                    b"ssh-ed25519 AAAA" + target.name.encode() + b" x\n")
                os.chmod(pub, 0o644)
            elif argv[0] == "podman" and "unshare" in argv:
                request = json.loads(kw.get("stdin_text") or "{}")
                return FakeRes(0, json.dumps(_helper_reply(request)))
            return FakeRes(0, "")

        runner.podman = podman_fn
        runner.run = run_fn
        return runner

    @contextlib.contextmanager
    def _stub_verify(self, res):
        with mock.patch("local_agent.verify.verify", return_value=res):
            yield res

    def _passing_verify(self):
        res = verify.Result()
        res.add("stubbed verifier", "pass")
        return self._stub_verify(res)


class StaleControlRetry(_UpFixture, unittest.TestCase):
    def test_no_prior_stale_controls_refused_before_bring_up(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        inst = self._fixture(root)
        runner = self._runner()
        stale = b'{"stale": true}\n'
        runtime_record._ensure_control(inst, runner, stale, "10.240.0.3")

        bring_up_calls = []
        original = runtime._bring_up

        def _sentinel(*a, **kw):
            bring_up_calls.append(True)
            return original(*a, **kw)

        runtime._bring_up = _sentinel
        self.addCleanup(setattr, runtime, "_bring_up", original)
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._up(root, "demo", self._repo(), runner, lambda *a: None)
        self.assertIn("opencode.json", str(ctx.exception))
        self.assertFalse(bring_up_calls)
        self.assertFalse(
            any("create" in " ".join(c) for c in runner.calls),
            "no resource creation may run after stale controls fail")
        self.assertFalse((inst / "runtime.json").exists())
        self.assertEqual(
            (inst / "control" / "opencode.json").read_bytes(), stale)


class BringUpCleanup(_UpFixture, unittest.TestCase):
    POD = "f" * 64
    MEMBERS = {"harness": "1" * 64, "inference": "2" * 64}

    def _member_infos(self):
        return {
            cid: {"Config": {"Labels": {
                spec.LABEL_INSTANCE: UUID, spec.LABEL_ROLE: role}},
                  "Pod": self.POD}
            for role, cid in self.MEMBERS.items()}

    def _stage(self, member_stop=None, pod_stop=None, pod_labels=None,
               member_infos=None):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root)
        runner = self._runner(
            member_infos=(
                self._member_infos() if member_infos is None
                else member_infos),
            member_stop=member_stop,
            pod_labels=pod_labels,
            pod_stop=pod_stop)
        original = runtime._bring_up

        def _failing(*a, **kw):
            a[3]["resources"]["pod_id"] = self.POD
            a[-2].extend(self.MEMBERS.items())
            raise runtime.RuntimeFault("injected bring-up failure")

        runtime._bring_up = _failing
        self.addCleanup(setattr, runtime, "_bring_up", original)
        return root, runner

    def _drive(self, root, runner):
        return runtime._up(
            root, "demo", self._repo(), runner, lambda *a: None)

    def test_successful_cleanup_preserves_original(self):
        root, runner = self._stage()
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            self._drive(root, runner)
        self.assertEqual(str(ctx.exception), "injected bring-up failure")
        self.assertNotIn("cleanup stop failures", str(ctx.exception))
        stops = [
            c for c in runner.calls
            if c[0] == "stop" or c[:2] == ["pod", "stop"]]
        self.assertEqual(len(stops), 3)

    def test_nonzero_pod_stop_reported(self):
        root, runner = self._stage(pod_stop=FakeRes(3))
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            self._drive(root, runner)
        msg = str(ctx.exception)
        self.assertIn("injected bring-up failure", msg)
        self.assertIn("cleanup stop failures", msg)
        self.assertIn("pod:ffffffffffff", msg)
        self.assertIn("rc=3", msg)
        self.assertIsInstance(ctx.exception.__cause__, runtime.RuntimeFault)
        self.assertEqual(
            str(ctx.exception.__cause__), "injected bring-up failure")

    def test_timed_out_pod_stop_reported(self):
        res = FakeRes(0)
        res.timed_out = True
        root, runner = self._stage(pod_stop=res)
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            self._drive(root, runner)
        msg = str(ctx.exception)
        self.assertIn("cleanup stop failures", msg)
        self.assertIn("pod:ffffffffffff", msg)
        self.assertIn("rc=0", msg)
        self.assertIn("timeout=True", msg)

    def test_member_and_pod_failures_aggregate(self):
        root, runner = self._stage(
            member_stop={"1" * 64: FakeRes(1)}, pod_stop=FakeRes(2))
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            self._drive(root, runner)
        msg = str(ctx.exception)
        self.assertIn("cleanup stop failures", msg)
        self.assertIn("harness:111111111111 rc=1", msg)
        self.assertIn("pod:ffffffffffff", msg)
        self.assertIn("rc=2", msg)

    def test_foreign_pod_never_stopped(self):
        root, runner = self._stage(pod_labels={
            spec.LABEL_INSTANCE: str(uuid.uuid4()),
            spec.LABEL_ROLE: "pod"})
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            self._drive(root, runner)
        msg = str(ctx.exception)
        self.assertIn("cleanup stop failures", msg)
        self.assertIn("pod:ffffffffffff unverified", msg)
        self.assertFalse(
            any(c[:2] == ["pod", "stop"] for c in runner.calls),
            "pod stop must not run against unverified pods")
        self.assertTrue(any(c[0] == "stop" for c in runner.calls))


class SelectedBaseImage(_UpFixture, unittest.TestCase):
    CUSTOM_REF = "docker.io/library/alpine@sha256:" + "a" * 64

    def _pod_create(self, runner):
        creates = [
            c for c in runner.calls if c[:2] == ["pod", "create"]]
        self.assertEqual(len(creates), 1)
        return creates[0]

    def _infra_image(self, runner):
        args = self._pod_create(runner)
        return args[args.index("--infra-image") + 1]

    def _inspected_refs(self, runner):
        return [
            c[2] for c in runner.calls
            if c[:2] == ["image", "inspect"] and "{{.Id}}" in c]

    def test_custom_lock_selects_local_id(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root, base_ref=self.CUSTOM_REF)
        runner = self._runner(
            base_image_out=FakeRes(0, "sha256:" + "e" * 64))
        with self._passing_verify():
            record = runtime._up(
                root, "demo", self._repo(), runner, lambda *a: None)
        self.assertEqual(self._inspected_refs(runner), [self.CUSTOM_REF])
        self.assertEqual(self._infra_image(runner), "e" * 64)
        self.assertIsInstance(record, dict)

    def test_default_lock_selects_local_id(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root)
        runner = self._runner(base_image_out=FakeRes(0, "b" * 64))
        with self._passing_verify():
            runtime._up(
                root, "demo", self._repo(), runner, lambda *a: None)
        self.assertEqual(self._inspected_refs(runner), [BASE_REF])
        self.assertEqual(self._infra_image(runner), "b" * 64)

    def test_missing_selected_image_refuses_before_creates(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root, base_ref=self.CUSTOM_REF)
        runner = self._runner(
            base_image_out=FakeRes(1, "", "no such image"))
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._up(root, "demo", self._repo(), runner, lambda *a: None)
        self.assertIn("base image", str(ctx.exception))
        self.assertFalse(
            any("create" in " ".join(c) for c in runner.calls),
            "missing selected image must fail before any create")
        self.assertFalse(
            any(c[0] == "pull" for c in runner.calls),
            "missing selected image must never trigger a pull")

    def test_malformed_selected_image_id_refuses(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root, base_ref=self.CUSTOM_REF)
        runner = self._runner(
            base_image_out=FakeRes(0, "not-an-image-id"))
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._up(root, "demo", self._repo(), runner, lambda *a: None)
        self.assertIn("invalid image id", str(ctx.exception))
        self.assertFalse(
            any("create" in " ".join(c) for c in runner.calls))
        self.assertFalse(
            any(c[0] == "pull" for c in runner.calls))

    def test_timed_out_image_inspect_refuses(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root, base_ref=self.CUSTOM_REF)
        res = FakeRes(0)
        res.timed_out = True
        runner = self._runner(base_image_out=res)
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._up(root, "demo", self._repo(), runner, lambda *a: None)
        self.assertIn("timed out", str(ctx.exception))
        self.assertFalse(
            any("create" in " ".join(c) for c in runner.calls))
        self.assertFalse(
            any(c[0] == "pull" for c in runner.calls))

    def test_existing_infra_image_mismatch_refuses(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        inst = self._fixture(root)
        runner = self._runner(
            pod_exists=True, infra_image="d" * 64)
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._up(root, "demo", self._repo(), runner, lambda *a: None)
        self.assertIn("infra image", str(ctx.exception))
        self.assertFalse(any(c[0] == "create" for c in runner.calls))
        self.assertFalse(any(c[0] == "start" for c in runner.calls))
        self.assertFalse(
            any(c[:2] == ["pod", "stop"] for c in runner.calls),
            "refused foreign-baseline pod must not be stopped")
        self.assertFalse((inst / "runtime.json").exists())

    def test_adopted_matching_infra_image_continues(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root)
        runner = self._runner(
            pod_exists=True, infra_image="sha256:" + "b" * 64)
        with self._passing_verify():
            runtime._up(
                root, "demo", self._repo(), runner, lambda *a: None)
        self.assertFalse(
            any(c[:2] == ["pod", "create"] for c in runner.calls),
            "existing pod with matching infra image is adopted")
        self.assertTrue(any(c[0] == "start" for c in runner.calls))


class SelectedModelHash(_UpFixture, unittest.TestCase):

    def _populate_call(self, runner):
        calls = [c for c in runner.calls if any(
            a.startswith("EXPECTED_MODEL_SHA=") for a in c)]
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_sha256_selected_propagates(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root)
        runner = self._runner()
        with self._passing_verify():
            runtime._up(
                root, "demo", self._repo(), runner, lambda *a: None)
        args = self._populate_call(runner)
        self.assertIn("EXPECTED_MODEL_ALGORITHM=sha256", args)
        self.assertIn("EXPECTED_MODEL_SHA=" + "4" * 64, args)

    def test_sha512_selected_propagates(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        self.addCleanup(td.cleanup)
        self._fixture(root, model_algo="sha512")
        runner = self._runner()
        with self._passing_verify():
            runtime._up(
                root, "demo", self._repo(), runner, lambda *a: None)
        args = self._populate_call(runner)
        self.assertIn("EXPECTED_MODEL_ALGORITHM=sha512", args)
        self.assertIn("EXPECTED_MODEL_SHA=" + "4" * 128, args)

    def test_prepared_lock_disagreement_refuses(self):
        for model_algo, prepared_model in (
                ("sha256", {"path": "/x/model.gguf", "sha256": "9" * 64}),
                ("sha512", {"path": "/x/model.gguf", "sha256": "9" * 64})):
            with self.subTest(model_algo=model_algo,
                              prepared=sorted(prepared_model)):
                td = tempfile.TemporaryDirectory()
                self.addCleanup(td.cleanup)
                root = Path(td.name)
                self._fixture(root, model_algo=model_algo,
                              prepared_model=prepared_model)
                runner = self._runner()
                with self.assertRaises(runtime.RuntimeFault) as ctx:
                    runtime._up(
                        root, "demo", self._repo(), runner, lambda *a: None)
                self.assertIn("model", str(ctx.exception))
                self.assertFalse(
                    any("create" in " ".join(c) for c in runner.calls))
                self.assertFalse(
                    any(c[0] == "pull" for c in runner.calls))


class UpVerification(_UpFixture, unittest.TestCase):
    CIDS = {"1" * 64, "2" * 64, "3" * 64}

    def _stop_targets(self, runner):
        return {
            c[3] for c in runner.calls
            if c[:2] == ["stop", "-t"]}

    def test_real_verifier_failure_reaches_cleanup(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner()
        events = []
        with self.assertRaises(runtime.RuntimeFault) as ctx:
            runtime._up(
                root, "demo", self._repo(), runner,
                lambda *a: events.append(a))
        msg = str(ctx.exception)
        self.assertIn("effective verification failed", msg)
        for name in ("network internal", "inference running",
                     "namespace comparison"):
            self.assertIn(name, msg)
        self.assertEqual(self._stop_targets(runner), self.CIDS,
                         "verify failure must stop created members")
        self.assertTrue(
            any(c[:2] == ["pod", "stop"] for c in runner.calls))
        self.assertTrue(
            (inst / "runtime.json").exists(),
            "saved identity record must survive a failed up")
        self.assertNotIn(("verify", "verified"), events)

    def test_failed_names_only_in_fault(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner()
        res = verify.Result()
        res.add("good check", "pass")
        res.add("bad check A", "fail", "detail-A-secret")
        res.add("bad check B", "fail")
        res.add("degraded check", "degraded")
        events = []
        with self._stub_verify(res):
            with self.assertRaises(runtime.RuntimeFault) as ctx:
                runtime._up(
                    root, "demo", self._repo(), runner,
                    lambda *a: events.append(a))
        msg = str(ctx.exception)
        self.assertIn("bad check A", msg)
        self.assertIn("bad check B", msg)
        self.assertNotIn("good check", msg)
        self.assertNotIn("degraded check", msg)
        self.assertNotIn("detail-A-secret", msg)
        self.assertEqual(self._stop_targets(runner), self.CIDS)
        self.assertTrue((inst / "runtime.json").exists())
        self.assertNotIn(("verify", "verified"), events)
        self.assertIn(("health", "probes-passed"), events)

    def test_empty_verify_result_fails(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner()
        events = []
        with self._stub_verify(verify.Result()):
            with self.assertRaises(runtime.RuntimeFault) as ctx:
                runtime._up(
                    root, "demo", self._repo(), runner,
                    lambda *a: events.append(a))
        self.assertIn("effective verification failed",
                      str(ctx.exception))
        self.assertEqual(self._stop_targets(runner), self.CIDS)
        self.assertTrue((inst / "runtime.json").exists())
        self.assertNotIn(("verify", "verified"), events)

    def test_degraded_only_result_accepts(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        self._fixture(root)
        runner = self._runner()
        res = verify.Result()
        res.add("records loaded", "pass")
        res.add("lsm confinement", "degraded")
        res.add("storage quotas", "degraded")
        events = []
        with self._stub_verify(res):
            record = runtime._up(
                root, "demo", self._repo(), runner,
                lambda *a: events.append(a))
        self.assertIsInstance(record, dict)
        self.assertIn(("health", "probes-passed"), events)
        self.assertIn(("verify", "verified"), events)
        self.assertLess(
            events.index(("health", "probes-passed")),
            events.index(("verify", "verified")))

    def test_verify_called_once_with_record_persisted(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner()
        repo = self._repo()
        seen = {}
        events = []

        def gate(*args, **kw):
            seen["args"] = args
            events.append(("gate", "called"))
            seen["record"] = runtime_record.load_runtime(inst, "demo")
            res = verify.Result()
            res.add("stubbed verifier", "pass")
            return res

        with mock.patch("local_agent.verify.verify",
                        side_effect=gate):
            record = runtime._up(
                root, "demo", repo, runner,
                lambda *a: events.append(a))
        self.assertEqual(seen["args"], (root, "demo", repo, runner))
        self.assertIsNotNone(
            seen["record"], "runtime.json must persist before verify runs")
        self.assertEqual(seen["record"]["objects"]["pod"], "f" * 64)
        self.assertIsInstance(record, dict)
        self.assertLess(
            events.index(("gate", "called")),
            events.index(("verify", "verified")))
        self.assertEqual(self._stop_targets(runner), set())
        self.assertFalse(
            any(c[:2] == ["pod", "stop"] for c in runner.calls))

    def test_verifier_exception_triggers_cleanup(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner()
        boom = RuntimeError("verifier blew up")
        events = []
        with mock.patch("local_agent.verify.verify", side_effect=boom):
            with self.assertRaises(RuntimeError) as ctx:
                runtime._up(
                    root, "demo", self._repo(), runner,
                    lambda *a: events.append(a))
        self.assertIs(ctx.exception, boom)
        self.assertEqual(self._stop_targets(runner), self.CIDS)
        self.assertTrue(
            any(c[:2] == ["pod", "stop"] for c in runner.calls))
        self.assertNotIn(("verify", "verified"), events)
        self.assertTrue((inst / "runtime.json").exists())

    def test_verify_failure_and_pod_cleanup_aggregate(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner(pod_stop=FakeRes(3, "", "stop failed"))
        res = verify.Result()
        res.add("harness labels", "fail")
        with self._stub_verify(res):
            with self.assertRaises(runtime.RuntimeFault) as ctx:
                runtime._up(
                    root, "demo", self._repo(), runner,
                    lambda *a: None)
        outer = ctx.exception
        self.assertIn("harness labels", str(outer))
        self.assertIn("cleanup stop failures", str(outer))
        self.assertIn("pod:ffffffffffff rc=3", str(outer))
        cause = outer.__cause__
        self.assertIsInstance(cause, runtime.RuntimeFault)
        self.assertIn("effective verification failed", str(cause))
        self.assertIn("harness labels", str(cause))
        self.assertEqual(self._stop_targets(runner), self.CIDS)
        self.assertTrue((inst / "runtime.json").exists())

    def _seeded(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        inst = self._fixture(root)
        runner = self._runner()
        with self._passing_verify():
            runtime._up(root, "demo", self._repo(), runner,
                        lambda *a: None)
        return root, inst, runner

    def test_resume_prior_matches_and_gate_runs_once(self):
        root, inst, runner = self._seeded()
        repo = self._repo()
        persisted = runtime_record.load_runtime(inst, "demo")
        seen = {}

        def seam(*args, **kw):
            seen["prior"] = args[7]
            return runtime_record.load_runtime(args[2], args[1])

        res = verify.Result()
        res.add("stubbed verifier", "pass")
        events = []
        with mock.patch.object(
                runtime, "_bring_up", side_effect=seam) as bm, \
                mock.patch("local_agent.verify.verify",
                           return_value=res) as vm:
            record = runtime._up(
                root, "demo", repo, runner,
                lambda *a: events.append(a))
        self.assertEqual(bm.call_count, 1)
        self.assertEqual(seen["prior"], persisted)
        self.assertEqual(vm.call_count, 1)
        self.assertEqual(
            vm.call_args, mock.call(root, "demo", repo, runner))
        self.assertIsInstance(record, dict)
        self.assertEqual(record["objects"]["pod"], "f" * 64)
        self.assertIn(("verify", "verified"), events)
        self.assertEqual(self._stop_targets(runner), set())

    def test_resume_verify_failure_cleans_appended(self):
        root, inst, runner = self._seeded()

        def seam(*args, **kw):
            args[20].extend([
                ("inference", "1" * 64), ("harness", "2" * 64),
                ("git", "3" * 64)])
            return runtime_record.load_runtime(args[2], args[1])

        res = verify.Result()
        res.add("infra running", "fail")
        with mock.patch.object(runtime, "_bring_up", side_effect=seam), \
                self._stub_verify(res):
            with self.assertRaises(runtime.RuntimeFault) as ctx:
                runtime._up(
                    root, "demo", self._repo(), runner,
                    lambda *a: None)
        self.assertIn("effective verification failed",
                      str(ctx.exception))
        self.assertIn("infra running", str(ctx.exception))
        self.assertEqual(self._stop_targets(runner), self.CIDS)
        self.assertTrue(
            any(c[:2] == ["pod", "stop"] for c in runner.calls))
        self.assertTrue((inst / "runtime.json").exists())


if __name__ == "__main__":
    unittest.main()
