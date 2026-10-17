"""Unit tests for runtime lifecycle: ownership, stop, adoption refusal."""

import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import runtime, runtime_spec as spec, state  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
