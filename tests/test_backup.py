"""Backup admission and lifecycle tests (faked podman)."""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from local_agent import backup
from local_agent import runtime_spec as spec
from local_agent.runner import CommandResult
from local_agent.runtime_record import RuntimeFault

UUID = "01234567-89ab-4cde-8f01-23456789abcd"


def _manifest():
    return {
        "identity": {"uuid": UUID},
        "profile": {"name": "cpu", "sha256": "a" * 64},
        "artifacts_lock": {"sha256": "b" * 64},
        "resources": {
            "pod_id": "p" * 64,
            "container_ids": {"harness": "h" * 64, "git": "g" * 64},
            "volume_names": {
                "workspace": "v-ws", "state": "v-st",
                "model": "v-mo", "repo": "v-re"},
            "network_id": "n" * 64,
        },
    }


def _record():
    return {
        "objects": {
            "pod": "p" * 64,
            "infra": "i" * 64,
            "containers": {"harness": "h" * 64, "git": "g" * 64},
            "volumes": {
                "workspace": "v-ws", "state": "v-st",
                "model": "v-mo", "repo": "v-re"},
        },
        "network": {"id": "n" * 64},
        "images": {"harness": "h" * 64, "inference": "i" * 64,
                   "git": "g" * 64},
        "fingerprints": {"artifacts_lock": "b" * 64,
                         "profile": "a" * 64},
        "seed_main": "c" * 40,
    }


class _Runner:
    def __init__(self, running=False, labels=True, images=True):
        self.running = running
        self.labels = labels
        self.images = images

    def podman(self, args, timeout=60):
        if args[0] == "inspect" and "--format" not in args:
            role = "harness" if args[1].startswith("h") else "git"
            lab = ({"org.secure-local-llm.instance": UUID,
                    "org.secure-local-llm.role": role}
                   if self.labels else {})
            return CommandResult(args, 0, json.dumps([{
                "Config": {"Labels": lab},
                "Pod": "p" * 64,
                "State": {"Running": self.running},
            }]), "", False)
        if args[0] in ("pod", "volume", "image") \
                and args[1] == "inspect":
            if args[0] == "image" and "--format" in args \
                    and "Id" in args[3]:
                return CommandResult(
                    args, 0, "sha256:" + "g" * 64 + "\n", "", False)
            role = "git" if args[0] == "image" else \
                ("pod" if args[0] == "pod" else "workspace")
            lab = ({spec.LABEL_INSTANCE: UUID,
                    spec.LABEL_ROLE: role} if self.labels else {})
            return CommandResult(
                args, 0, json.dumps(lab), "", False)
        return CommandResult(args, 1, "", "unexpected", False)


class MemberStopped(unittest.TestCase):
    def test_running_refused(self):
        with self.assertRaises(RuntimeFault) as ctx:
            backup._member_admitted(
                _Runner(running=True), "h" * 64, "harness", UUID,
                "p" * 64, True)
        self.assertIn("quiesced", str(ctx.exception))

    def test_garbage_running_refused(self):
        runner = _Runner()
        orig = runner.podman
        def weird(args, timeout=60):
            res = orig(args, timeout)
            if args[0] == "inspect" and "--format" not in args:
                data = json.loads(res.stdout)
                data[0]["State"]["Running"] = "garbage"
                res.stdout = json.dumps(data)
            return res
        runner.podman = weird
        with self.assertRaises(RuntimeFault):
            backup._member_admitted(
                runner, "h" * 64, "harness", UUID, "p" * 64, True)

    def test_foreign_labels_refused(self):
        with self.assertRaises(RuntimeFault):
            backup._member_admitted(
                _Runner(labels=False), "h" * 64, "harness", UUID,
                "p" * 64, True)

    def test_stopped_owned_ok(self):
        backup._member_admitted(
            _Runner(), "h" * 64, "harness", UUID, "p" * 64, True)


class AdmissionShape(unittest.TestCase):
    def test_match(self):
        backup._static_admission_shape(_manifest(), _record())

    def _drift(self, mutate):
        m = _manifest()
        mutate(m)
        with self.assertRaises(RuntimeFault):
            backup._static_admission_shape(m, _record())

    def test_container_drift(self):
        self._drift(
            lambda m: m["resources"]["container_ids"].update(
                harness="x" * 64))

    def test_pod_drift(self):
        self._drift(lambda m: m["resources"].update(pod_id="z" * 64))

    def test_volume_drift(self):
        self._drift(
            lambda m: m["resources"]["volume_names"].update(
                workspace="v-x"))

    def test_missing_role(self):
        self._drift(
            lambda m: m["resources"]["volume_names"].pop("model"))

    def test_network_drift(self):
        self._drift(
            lambda m: m["resources"].update(network_id="9" * 64))

    def test_fingerprint_drift(self):
        self._drift(
            lambda m: m["artifacts_lock"].update(sha256="f" * 64))


class CacheCopy(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        os.chmod(self.root, 0o700)
        self.src = self.root / "src"
        self.dst = self.root / "dst"
        for d in (self.src, self.dst):
            d.mkdir(mode=0o700)
            os.chmod(d, 0o700)

    def _lock(self, hexval="a" * 64):
        return {"artifacts": {
            "model": {"hash": {"algorithm": "sha256", "hex": hexval},
                      "max_bytes": 1 << 20, "url": "u"},
            "opencode": {"hash": {"algorithm": "sha256",
                                  "hex": hexval},
                         "max_bytes": 1 << 20, "url": "u"},
            "inference_source": {"hash": {"algorithm": "sha256",
                                          "hex": hexval},
                                 "max_bytes": 1 << 20, "url": "u"}}}

    def _stage(self, name, data, mode=0o600, hexval="a" * 64):
        p = self.src / f"{name}-{hexval[:16]}"
        p.write_bytes(data)
        os.chmod(p, mode)
        return p

    def _fds(self, name, hexval="a" * 64):
        entry = self._lock(hexval)["artifacts"][name]
        want = f"{name}-{hexval[:16]}"
        return {name: (
            backup._open_source_cache(self.src, want, entry),
            want, entry)}

    def test_copy_verified(self):
        import hashlib
        data = b"model-bytes"
        sha = hashlib.sha256(data).hexdigest()
        self._stage("model", data, hexval=sha)
        fds = self._fds("model", sha)
        copied = backup._copy_source_cache(
            fds, self.dst, self._lock(sha))
        for fd, _w, _e in fds.values():
            os.close(fd)
        self.assertEqual(copied, [f"model-{sha[:16]}"])
        got = (self.dst / f"model-{sha[:16]}").read_bytes()
        self.assertEqual(got, data)

    def test_tampered_hash_refused(self):
        self._stage("model", b"tampered")
        with self.assertRaises(RuntimeFault):
            self._fds("model")

    def test_644_source_refused(self):
        self._stage("model", b"x", mode=0o644)
        with self.assertRaises(RuntimeFault):
            self._fds("model")

    def test_hardlink_source_refused(self):
        p = self._stage("model", b"x")
        os.link(p, self.src / "other")
        with self.assertRaises(RuntimeFault):
            self._fds("model")

    def test_existing_invalid_target_fails(self):
        import hashlib
        data = b"good"
        sha = hashlib.sha256(data).hexdigest()
        self._stage("model", data, hexval=sha)
        bad = self.dst / f"model-{sha[:16]}"
        bad.write_bytes(b"EVIL")
        os.chmod(bad, 0o600)
        fds = self._fds("model", sha)
        try:
            with self.assertRaises(RuntimeFault):
                backup._copy_source_cache(
                    fds, self.dst, self._lock(sha))
        finally:
            for fd, _w, _e in fds.values():
                os.close(fd)
        self.assertEqual(bad.read_bytes(), b"EVIL")


if __name__ == "__main__":
    unittest.main()


import io
import tarfile
import tempfile


class RepoSeedCommitTests(unittest.TestCase):
    def _make_tar(self, path, ref_path="demo.git/refs/heads/main",
                  content=b"c" * 40):
        with tarfile.open(path, "w") as tf:
            info = tarfile.TarInfo(ref_path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))

    def test_valid_commit(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "repo.tar"
            self._make_tar(archive)
            self.assertEqual(
                backup._repo_seed_commit(archive), "c" * 40)

    def test_missing_ref_raises(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "repo.tar"
            with tarfile.open(archive, "w") as tf:
                info = tarfile.TarInfo("demo.git/HEAD")
                info.size = 4
                tf.addfile(info, io.BytesIO(b"ref\n"))
            with self.assertRaises(RuntimeFault):
                backup._repo_seed_commit(archive)

    def test_invalid_commit_raises(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "repo.tar"
            self._make_tar(archive, content=b"z" * 40)
            with self.assertRaises(RuntimeFault):
                backup._repo_seed_commit(archive)
