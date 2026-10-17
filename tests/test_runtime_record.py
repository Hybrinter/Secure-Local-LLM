"""Unit tests for frozen runtime record and private control files."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import runtime_record, runtime_spec as spec  # noqa: E402
from local_agent import state  # noqa: E402

UUID = "01234567-89ab-4cde-8f01-23456789abcd"
HEX64 = "a" * 64
TABLES = {"workload": "sllm_0123456789ab00", "git": "sllm_0123456789ab01"}


def _record():
    cid = "b" * 64
    return {
        "schema": runtime_record.RUNTIME_SCHEMA,
        "instance": "demo",
        "instance_uuid": UUID,
        "created_utc": "2026-10-17T00:00:00+00:00",
        "subnet": "10.240.0.0/28",
        "pod_ip": "10.240.0.2",
        "git_ip": "10.240.0.3",
        "network": {"id": "c" * 64, "name": "sll-01234567-net"},
        "tables": dict(TABLES),
        "policy": {
            "workload": {
                "schema": "secure-local-llm/netpol@1",
                "table": TABLES["workload"], "role": "workload",
                "peer_ip": "10.240.0.3", "peer_port": 2222,
                "canonical_sha256": "d" * 64},
            "git": {
                "schema": "secure-local-llm/netpol@1",
                "table": TABLES["git"], "role": "git",
                "peer_ip": "10.240.0.2", "peer_port": 2222,
                "canonical_sha256": "e" * 64},
        },
        "objects": {
            "pod": "f" * 64, "infra": "0" * 64,
            "containers": {"inference": cid, "harness": "1" * 64,
                           "git": "2" * 64},
            "volumes": {"workspace": "sll-01234567-ws",
                        "state": "sll-01234567-state",
                        "model": "sll-01234567-model",
                        "repo": "sll-01234567-repo"},
        },
        "images": {"harness": "3" * 64, "inference": "4" * 64,
                   "git": "5" * 64},
        "fingerprints": {"profile": "6" * 64, "artifacts_lock": "7" * 64,
                         "source_config": "8" * 64},
        "control_sha256": {k: "9" * 64 for k in spec.CONTROL_FILES},
        "seed_sha256": "a" * 64,
        "seed_main": "b" * 40,
    }


class ValidateRuntime(unittest.TestCase):
    def test_valid(self):
        runtime_record.validate_runtime(_record(), expected_name="demo")

    def test_rejects(self):
        def setkey(k, v):
            def m(r):
                r[k] = v
            return m

        cases = [
            setkey("extra", 1),
            lambda r: r.pop("seed_sha256"),
            setkey("schema", "other@2"),
            setkey("instance", "other"),
            setkey("instance_uuid", "not-a-uuid"),
            setkey("created_utc", "not-a-time"),
            setkey("subnet", "10.0.0.0/24"),
            setkey("subnet", "8.8.8.0/28"),
            setkey("pod_ip", "10.240.0.9"),
            setkey("git_ip", "10.240.0.2"),
            lambda r: r["network"].update(id="short"),
            lambda r: r["network"].update(name="other-net"),
            lambda r: r["tables"].update(extra="sllm_zzzz0000"),
            lambda r: r["tables"].update(workload="sllm_ffff0000ff"),
            lambda r: r["policy"]["workload"].pop("canonical_sha256"),
            lambda r: r["policy"].pop("git"),
            lambda r: r["policy"]["workload"].update(
                schema="secure-local-llm/netpolicy@1"),
            lambda r: r["policy"]["workload"].update(role="git"),
            lambda r: r["policy"]["workload"].update(peer_port=22),
            lambda r: r["policy"]["workload"].update(peer_ip="10.240.0.2"),
            lambda r: r["policy"]["git"].update(peer_ip="10.240.0.3"),
            lambda r: r["policy"]["workload"].update(table=TABLES["git"]),
            lambda r: r["objects"].pop("infra"),
            lambda r: r["objects"]["containers"].pop("git"),
            lambda r: r["objects"]["containers"].update(
                inference="short"),
            lambda r: r["objects"]["volumes"].update(workspace="foreign"),
            lambda r: r["objects"]["volumes"].pop("repo"),
            lambda r: r["images"].pop("git"),
            lambda r: r["images"].update(harness="zz"),
            lambda r: r["fingerprints"].pop("profile"),
            lambda r: r["control_sha256"].pop("known_hosts"),
            lambda r: r["control_sha256"].pop("client_key.pub"),
            setkey("seed_main", "nothex"),
            setkey("seed_sha256", "x" * 63),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                rec = _record()
                mutate(rec)
                with self.assertRaises(state.StateError):
                    runtime_record.validate_runtime(
                        rec, expected_name="demo")

    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inst = root / "instances" / "demo"
            inst.mkdir(parents=True)
            os.chmod(root, 0o700)
            os.chmod(root / "instances", 0o700)
            os.chmod(inst, 0o700)
            payload = json.dumps(_record())
            dup = payload.replace(
                '"instance": "demo"',
                '"instance": "demo", "instance": "evil"', 1)
            (inst / "runtime.json").write_bytes(dup.encode())
            os.chmod(inst / "runtime.json", 0o600)
            with self.assertRaises(state.StateError):
                runtime_record.load_runtime(inst, "demo")


class ReadControl(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _write(self, name, data=b"x", mode=0o600):
        p = self.dir / name
        p.write_bytes(data)
        os.chmod(p, mode)
        return p

    def test_ok(self):
        p = self._write("k", b"secret", 0o600)
        self.assertEqual(
            runtime_record._read_control(p, {0o600}, "k"), b"secret")

    def test_symlink_refused(self):
        target = self._write("real", b"data")
        link = self.dir / "link"
        link.symlink_to(target)
        with self.assertRaises(runtime_record.RuntimeFault):
            runtime_record._read_control(link, {0o600}, "link")

    def test_wrong_mode_refused(self):
        p = self._write("k", b"x", 0o644)
        with self.assertRaises(runtime_record.RuntimeFault):
            runtime_record._read_control(p, {0o600}, "k")

    def test_directory_refused(self):
        with self.assertRaises(runtime_record.RuntimeFault):
            runtime_record._read_control(self.dir, {0o700}, "dir")

    def test_hardlink_refused(self):
        p = self._write("k")
        os.link(p, self.dir / "k2")
        with self.assertRaises(runtime_record.RuntimeFault):
            runtime_record._read_control(p, {0o600}, "k")


if __name__ == "__main__":
    unittest.main()
