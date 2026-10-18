"""Unit tests for the dry-run commands renderer."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import artifacts, commands  # noqa: E402
from local_agent.runtime_record import RuntimeFault  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
UUID = "01234567-89ab-4cde-8f01-23456789abcd"
BASE_REF = "docker.io/library/debian@sha256:" + "a" * 64


def _lock(base_ref):
    return {
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


def _root(base_ref=BASE_REF):
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    inst = root / "instances" / "demo"
    inst.mkdir(parents=True)
    for d in (root, root / "instances", inst):
        os.chmod(d, 0o700)
    lock_path = root / "lock.json"
    lock_path.write_bytes(json.dumps(_lock(base_ref)).encode())
    os.chmod(lock_path, 0o600)
    manifest = {
        "schema": "secure-local-llm/instance@1",
        "identity": {"name": "demo", "uuid": UUID,
                     "created_utc": "2026-10-17T00:00:00+00:00"},
        "profile": {"name": "cpu", "sha256": "a" * 64},
        "artifacts_lock": {
            "sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            "path": str(lock_path),
            "bytes": lock_path.stat().st_size},
        "exceptions": {"prototype_no_lsm_acknowledged": True},
        "resources": {
            "pod_id": "f" * 64,
            "container_ids": {"inference": "1" * 64,
                              "harness": "2" * 64, "git": "3" * 64},
            "volume_names": {"workspace": "sll-01234567-ws",
                             "state": "sll-01234567-state",
                             "model": "sll-01234567-model",
                             "repo": "sll-01234567-repo"},
            "network_id": "c" * 64},
    }
    record = {
        "schema": "secure-local-llm/runtime@1",
        "instance": "demo",
        "instance_uuid": UUID,
        "created_utc": "2026-10-17T00:00:00+00:00",
        "subnet": "10.240.0.0/28",
        "pod_ip": "10.240.0.2",
        "git_ip": "10.240.0.3",
        "network": {"id": "c" * 64, "name": "sll-01234567-net"},
        "tables": {"workload": "sllm_0123456789ab00",
                   "git": "sllm_0123456789ab01"},
        "policy": {
            "workload": {
                "schema": "secure-local-llm/netpol@1",
                "table": "sllm_0123456789ab00", "role": "workload",
                "peer_ip": "10.240.0.3", "peer_port": 2222,
                "canonical_sha256": "d" * 64},
            "git": {
                "schema": "secure-local-llm/netpol@1",
                "table": "sllm_0123456789ab01", "role": "git",
                "peer_ip": "10.240.0.2", "peer_port": 2222,
                "canonical_sha256": "e" * 64},
        },
        "objects": {
            "pod": "f" * 64, "infra": "0" * 64,
            "containers": {"inference": "1" * 64, "harness": "2" * 64,
                           "git": "3" * 64},
            "volumes": {"workspace": "sll-01234567-ws",
                        "state": "sll-01234567-state",
                        "model": "sll-01234567-model",
                        "repo": "sll-01234567-repo"},
        },
        "images": {"harness": "3" * 64, "inference": "4" * 64,
                   "git": "5" * 64},
        "fingerprints": {"profile": "6" * 64, "artifacts_lock": "7" * 64,
                         "source_config": "8" * 64},
        "control_sha256": {
            k: "9" * 64 for k in (
                "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub",
                "client_key", "client_key.pub", "authorized_keys",
                "model-api-key", "service.json", "gitconfig",
                "ssh_config", "known_hosts", "opencode.json")},
        "seed_sha256": "a" * 64,
        "seed_main": "b" * 40,
    }
    (inst / "manifest.json").write_text(json.dumps(manifest))
    os.chmod(inst / "manifest.json", 0o600)
    (inst / "runtime.json").write_text(json.dumps(record))
    os.chmod(inst / "runtime.json", 0o600)
    return td, root


class Render(unittest.TestCase):
    def test_missing_instance_refused(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        with self.assertRaises(RuntimeFault):
            commands.render_commands(td.name, "demo", REPO)

    def test_rendered_shapes(self):
        td, root = _root()
        self.addCleanup(td.cleanup)
        lines = commands.render_commands(root, "demo", REPO)
        blob = "\n".join(lines)
        self.assertIn("network create --internal --disable-dns", blob)
        self.assertIn("pod create", blob)
        self.assertIn(f"--infra-image {BASE_REF}", blob)
        self.assertIn("create --pull=never", blob)
        self.assertIn("unshare python3 -I -B", blob)
        self.assertIn("--security-opt no-new-privileges", blob)
        self.assertIn("--cap-drop ALL", blob)
        self.assertIn("sll-01234567-net", blob)
        self.assertIn("10.240.0.2", blob)
        for line in lines:
            self.assertFalse(line.lstrip().startswith("eval"), line)

    def test_no_secret_values_rendered(self):
        td, root = _root()
        self.addCleanup(td.cleanup)
        (root / "instances" / "demo" / "control").mkdir()
        secret = "SUPERSECRETVALUE9"
        (root / "instances" / "demo" / "control" / "model-api-key"
         ).write_text(secret)
        lines = commands.render_commands(root, "demo", REPO)
        self.assertNotIn(secret, "\n".join(lines))
        self.assertIn("model-api-key", "\n".join(lines))

    def test_custom_lock_image_rendered(self):
        custom = "docker.io/library/alpine@sha256:" + "e" * 64
        td, root = _root(base_ref=custom)
        self.addCleanup(td.cleanup)
        lines = commands.render_commands(root, "demo", REPO)
        self.assertIn(f"--infra-image {custom}", "\n".join(lines))

    def test_drifted_lock_refused(self):
        td, root = _root()
        self.addCleanup(td.cleanup)
        lock_path = Path(json.loads(
            (root / "instances" / "demo" / "manifest.json").read_text()
        )["artifacts_lock"]["path"])
        lock_path.write_bytes(lock_path.read_bytes() + b" ")
        with self.assertRaises(RuntimeFault) as ctx:
            commands.render_commands(root, "demo", REPO)
        self.assertIn("artifacts lock drifted", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
