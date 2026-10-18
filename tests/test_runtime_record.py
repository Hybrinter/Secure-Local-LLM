"""Unit tests for frozen runtime record and private control files."""

import hashlib
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


class _Res:
    def __init__(self, rc=0, stdout=""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = ""
        self.timed_out = False


class _KeygenRunner:
    def __init__(self):
        self.calls = []
        self.count = 0

    def run(self, argv, timeout=None, extra_env=None, stdin_text=None,
            pass_fds=()):
        self.calls.append(list(argv))
        if argv[0] == "ssh-keygen":
            self.count += 1
            target = Path(argv[argv.index("-f") + 1])
            target.write_bytes(f"private-{self.count}\n".encode())
            os.chmod(target, 0o600)
            pub = Path(str(target) + ".pub")
            pub.write_bytes(
                f"ssh-ed25519 AAAA{self.count:04d} fake\n".encode())
            os.chmod(pub, 0o644)
        return _Res()


class EnsureControl(unittest.TestCase):
    RENDERED = b'{"rendered": "config-v1"}\n'
    GIT_IP = "10.240.0.3"

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.inst = Path(self.td.name) / "instances" / "demo"
        self.inst.mkdir(parents=True)
        os.chmod(self.inst.parent, 0o700)
        os.chmod(self.inst, 0o700)
        self.runner = _KeygenRunner()
        self.control = self.inst / "control"

    def tearDown(self):
        self.td.cleanup()

    def _ensure(self, rendered=None, git_ip=None):
        return runtime_record._ensure_control(
            self.inst, self.runner,
            self.RENDERED if rendered is None else rendered,
            self.GIT_IP if git_ip is None else git_ip)

    def _bytes(self, name):
        return (self.control / name).read_bytes()

    def _snapshot(self):
        return {n: self._bytes(n) for n in spec.CONTROL_FILES}

    def _keygen_calls(self):
        return [c for c in self.runner.calls if c[0] == "ssh-keygen"]

    def test_fresh_generation(self):
        control, fps = self._ensure()
        self.assertEqual(control, self.control)
        self.assertEqual(set(fps), set(spec.CONTROL_FILES))
        for name in spec.CONTROL_FILES:
            self.assertEqual(
                fps[name], hashlib.sha256(self._bytes(name)).hexdigest())
        self.assertEqual(self._bytes("gitconfig"), spec.GITCONFIG.encode())
        self.assertEqual(self._bytes("opencode.json"), self.RENDERED)
        self.assertEqual(
            self._bytes("ssh_config"),
            spec.SSH_CONFIG.format(git_ip=self.GIT_IP).encode())
        self.assertEqual(
            self._bytes("authorized_keys"), self._bytes("client_key.pub"))
        host_pub = self._bytes("ssh_host_ed25519_key.pub").decode().strip()
        self.assertEqual(
            self._bytes("known_hosts"),
            f"[{self.GIT_IP}]:{spec.GIT_PORT} {host_pub}\n".encode())
        self.assertEqual(len(self._keygen_calls()), 2)

    def test_identical_retry_preserves_bytes(self):
        _, first_fps = self._ensure()
        first = self._snapshot()
        _, fps = self._ensure()
        self.assertEqual(fps, first_fps)
        self.assertEqual(self._snapshot(), first)
        self.assertEqual(len(self._keygen_calls()), 2)

    def test_stale_rendered_config_refused(self):
        self._ensure()
        with self.assertRaises(runtime_record.RuntimeFault) as ctx:
            self._ensure(rendered=b'{"rendered": "config-v2"}\n')
        self.assertIn("opencode.json", str(ctx.exception))
        self.assertEqual(self._bytes("opencode.json"), self.RENDERED)

    def test_git_ip_change_refused(self):
        self._ensure()
        known_hosts = self._bytes("known_hosts")
        ssh_config = self._bytes("ssh_config")
        with self.assertRaises(runtime_record.RuntimeFault) as ctx:
            self._ensure(git_ip="10.240.0.19")
        self.assertTrue(
            "known_hosts" in str(ctx.exception)
            or "ssh_config" in str(ctx.exception))
        self.assertEqual(self._bytes("known_hosts"), known_hosts)
        self.assertEqual(self._bytes("ssh_config"), ssh_config)

    def test_altered_gitconfig_refused(self):
        self._ensure()
        target = self.control / "gitconfig"
        drifted = b"[core]\n\thooksPath = /tmp/hooks\n"
        os.chmod(target, 0o600)
        target.write_bytes(drifted)
        os.chmod(target, 0o400)
        with self.assertRaises(runtime_record.RuntimeFault) as ctx:
            self._ensure()
        self.assertIn("gitconfig", str(ctx.exception))
        self.assertEqual(self._bytes("gitconfig"), drifted)

    def test_regenerated_client_key_stale_authorized_keys(self):
        self._ensure()
        authorized = self._bytes("authorized_keys")
        (self.control / "client_key").unlink()
        (self.control / "client_key.pub").unlink()
        with self.assertRaises(runtime_record.RuntimeFault) as ctx:
            self._ensure()
        self.assertIn("authorized_keys", str(ctx.exception))
        self.assertEqual(self._bytes("authorized_keys"), authorized)
        self.assertNotEqual(self._bytes("client_key.pub"), authorized)

    def test_regenerated_host_key_stale_known_hosts(self):
        self._ensure()
        known_hosts = self._bytes("known_hosts")
        (self.control / "ssh_host_ed25519_key").unlink()
        (self.control / "ssh_host_ed25519_key.pub").unlink()
        with self.assertRaises(runtime_record.RuntimeFault) as ctx:
            self._ensure()
        self.assertIn("known_hosts", str(ctx.exception))
        self.assertEqual(self._bytes("known_hosts"), known_hosts)


if __name__ == "__main__":
    unittest.main()
