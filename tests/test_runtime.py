"""Unit tests for runtime lifecycle: ownership, stop, adoption refusal."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import artifacts, runtime, runtime_record  # noqa: E402
from local_agent import runtime_spec as spec, state  # noqa: E402

UUID = "01234567-89ab-4cde-8f01-23456789abcd"


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
                "l" * 64, "p" * 64, "s" * 64, [], lambda *a: None)
        self.assertIn("refusing", str(ctx.exception))
        self.assertFalse(
            any("create" in " ".join(c) for c in runner.calls),
            "no create must run while recorded bindings are unresolved")


class StaleControlRetry(unittest.TestCase):
    def _repo(self):
        return Path(__file__).resolve().parents[1]

    def _fixture(self, root):
        repo = self._repo()
        inst = root / "instances" / "demo"
        inst.mkdir(parents=True)
        for d in (root, root / "instances", inst):
            os.chmod(d, 0o700)
        lock = {
            "schema": artifacts.LOCK_SCHEMA,
            "platform": artifacts.LOCK_PLATFORM,
            "base_image": "docker.io/library/debian@sha256:" + "0" * 64,
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
                    "hash": {"algorithm": "sha256", "hex": "2" * 64},
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
                "model": {"path": str(root / "model.gguf"),
                          "sha256": "4" * 64},
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

    def _runner(self):
        runner = FakeRunner()
        roles = {"7" * 64: "harness", "8" * 64: "inference",
                 "9" * 64: "git"}

        def podman_fn(args, **kw):
            runner.calls.append(list(args))
            if args[:2] == ["image", "inspect"]:
                return FakeRes(0, json.dumps({
                    spec.LABEL_INSTANCE: UUID,
                    spec.LABEL_ROLE: roles.get(args[2], "")}))
            if args[:2] == ["run", "--rm"]:
                return FakeRes(0, " ".join(spec.MODEL_REQUIRED_FLAGS))
            if args[:2] == ["network", "ls"]:
                return FakeRes(0, "")
            if args[:2] == ["network", "inspect"]:
                return FakeRes(1, "", "no such network")
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
            return FakeRes(0, "")

        runner.podman = podman_fn
        runner.run = run_fn
        return runner

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


if __name__ == "__main__":
    unittest.main()
