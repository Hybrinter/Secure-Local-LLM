"""Unit tests for pure runtime spec builders."""

import json
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import runtime_spec as spec  # noqa: E402

UUID = str(uuid.uuid4())
N = spec.names(UUID)
CONTROL = Path("/state/instances/demo/control")

PROFILE = {
    "resources": {"memory_mb": 8192, "cpus": 4, "pids": 512},
    "model": {"context_tokens": 8192, "max_output_tokens": 1024,
              "threads": 4, "parallel": 1},
    "timeouts": {"startup_seconds": 300, "request_seconds": 120},
}


class CheckProfile(unittest.TestCase):
    def test_ok(self):
        spec.check_profile(PROFILE)

    def test_memory_floor(self):
        bad = json.loads(json.dumps(PROFILE))
        bad["resources"]["memory_mb"] = 8191
        with self.assertRaises(ValueError):
            spec.check_profile(bad)

    def test_pids_floor(self):
        bad = json.loads(json.dumps(PROFILE))
        bad["resources"]["pids"] = 127
        with self.assertRaises(ValueError):
            spec.check_profile(bad)

    def test_cpus_not_fixed(self):
        prof = json.loads(json.dumps(PROFILE))
        prof["resources"]["cpus"] = 2
        spec.check_profile(prof)


class ModelArgv(unittest.TestCase):
    def test_profile_derived(self):
        argv = spec.model_argv(PROFILE)
        self.assertEqual(argv[0], "/opt/llama/llama-server")
        for flag, want in (
            ("--ctx-size", "8192"), ("--predict", "1024"),
            ("--threads", "4"), ("--threads-batch", "4"),
            ("--parallel", "1"), ("--port", "8080"),
            ("--alias", "granite-cpu"),
        ):
            self.assertEqual(argv[argv.index(flag) + 1], want)
        self.assertIn("--api-key-file", argv)
        self.assertIn("--no-webui", argv)
        self.assertIn("--no-slots", argv)
        self.assertNotIn("--api-key", argv)
        joined = " ".join(argv)
        self.assertNotIn("granite", joined.replace("--alias granite-cpu", ""))


class RenderConfig(unittest.TestCase):
    TEMPLATE = json.dumps({
        "providers": {"local": {
            "name": "local",
            "settings": {"baseURL": "http://127.0.0.1:8080/v1",
                         "timeout": 0},
            "models": {"granite-cpu": {
                "name": "granite-cpu",
                "limit": {"context": 0, "output": 0}}}}},
        "agents": {"build": {"request": {"body": {"max_tokens": 0}}}},
        "permissions": {"edit": "deny"},
    }).encode()

    def test_only_profile_fields_change(self):
        out = json.loads(spec.render_opencode_config(self.TEMPLATE,
                                                     PROFILE))
        model = out["providers"]["local"]["models"]["granite-cpu"]
        self.assertEqual(model["limit"]["context"], 8192)
        self.assertEqual(model["limit"]["output"], 1024)
        self.assertEqual(out["providers"]["local"]["settings"]["timeout"],
                         120000)
        self.assertEqual(
            out["agents"]["build"]["request"]["body"]["max_tokens"], 1024)
        self.assertEqual(
            out["providers"]["local"]["settings"]["baseURL"],
            "http://127.0.0.1:8080/v1")
        self.assertEqual(out["permissions"], {"edit": "deny"})
        src = json.loads(self.TEMPLATE)
        src["providers"]["local"]["models"]["granite-cpu"]["limit"] = {
            "context": 8192, "output": 1024}
        src["providers"]["local"]["settings"]["timeout"] = 120000
        src["agents"]["build"]["request"]["body"]["max_tokens"] = 1024
        self.assertEqual(out, src)


class CommonFlags(unittest.TestCase):
    def _assert_common(self, args):
        joined = " ".join(args)
        for flag in ("--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges",
                     "--pull=never", "--log-driver", "k8s-file",
                     "--log-opt", "max-size=4mb",
                     "--http-proxy=false",
                     "--image-volume", "ignore"):
            self.assertIn(flag, args)
        self.assertIn("--user", args)
        self.assertIn("1000:1000", args)
        self.assertIn("nofile=1024:1024", args)
        self.assertIn("core=0:0", args)
        self.assertNotIn("--restart", args)
        self.assertNotIn("--restart=always", joined)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("HTTP_PROXY", joined)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--publish", args)
        self.assertIn(f"{spec.LABEL_INSTANCE}={UUID}", args)

    def _vols(self):
        return {"workspace": "vw", "state": "vs", "model": "vm",
                "repo": "vr"}

    def test_pod_args(self):
        args = spec.pod_args(N, UUID, N["net"], "10.240.0.2", PROFILE)
        self.assertIn("8192m", args)
        mem_i = args.index("--memory")
        swap_i = args.index("--memory-swap")
        self.assertEqual(args[mem_i + 1], "8192m")
        self.assertEqual(args[swap_i + 1], "8192m")
        self.assertIn("4", args)
        self.assertIn("--cpus", args)
        self.assertEqual(args[args.index("--cpus") + 1], "4")
        self.assertIn("--share", args)
        self.assertIn("net", args)
        self.assertIn("keep-id:uid=1000,gid=1000", args)
        self.assertIn("--security-opt", args)
        self.assertIn("no-new-privileges", args)
        self.assertIn("--dns", args)
        self.assertIn("none", args)
        self.assertIn("--ip", args)
        self.assertIn("10.240.0.2", args)

    def test_inference_args(self):
        args = spec.inference_args(
            N, UUID, "img", "vol-model", CONTROL, PROFILE)
        self._assert_common(args)
        self.assertIn("--pod", args)
        self.assertEqual(args[args.index("--memory") + 1], "6144m")
        self.assertEqual(args[args.index("--memory-swap") + 1], "6144m")
        self.assertEqual(args[args.index("--cpus") + 1], "4")
        self.assertEqual(args[args.index("--pids-limit") + 1], "256")
        mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
        self.assertIn("vol-model:/models:ro,nosuid,nodev,noexec", mounts)
        self.assertTrue(any(
            m.endswith(
                ":/run/local-agent/model-api-key:ro,nosuid,nodev,noexec")
            for m in mounts))
        self.assertNotIn("/workspace", " ".join(mounts))
        self.assertNotIn("/repos", " ".join(mounts))
        self.assertFalse(any("ssh" in m for m in mounts))
        tail = args[args.index("img") + 1:]
        self.assertEqual(tail, spec.model_argv(PROFILE))
        self.assertNotIn("--userns", args)

    def test_harness_args(self):
        args = spec.harness_args(
            N, UUID, "img", self._vols(), CONTROL, PROFILE)
        self._assert_common(args)
        self.assertEqual(args[args.index("--memory") + 1], "2048m")
        self.assertEqual(args[args.index("--memory-swap") + 1], "2048m")
        self.assertEqual(args[args.index("--pids-limit") + 1], "256")
        mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
        self.assertIn("vw:/workspace:rw,nosuid,nodev", mounts)
        self.assertIn("vs:/state:rw,nosuid,nodev", mounts)
        ro = [m for m in mounts
              if m.endswith(":ro,nosuid,nodev,noexec")]
        self.assertEqual(len(ro), 7)
        self.assertTrue(any("service.json" in m for m in ro))
        self.assertTrue(any("client_key" in m for m in ro))
        self.assertTrue(any("known_hosts" in m for m in ro))
        self.assertFalse(any("authorized_keys" in m for m in mounts))
        self.assertFalse(any("ssh_host" in m for m in mounts))
        self.assertFalse(any("/repos" in m for m in mounts))
        env = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
        envmap = dict(e.split("=", 1) for e in env)
        self.assertEqual(
            envmap["OPENCODE_CONFIG_DIR"], "/run/local-agent/opencode")
        self.assertEqual(envmap["HOME"], "/state")
        self.assertEqual(
            envmap["GIT_SSH_COMMAND"], "ssh -F /run/local-agent/ssh_config")
        self.assertEqual(envmap["GIT_CONFIG_GLOBAL"],
                         "/run/local-agent/gitconfig")
        self.assertNotIn("password", " ".join(env))
        self.assertEqual(args[-3:], ["opencode", "serve", "--service"])

    def test_git_args(self):
        args = spec.git_args(
            N, UUID, "img", N["net"], "10.240.0.3", "repo-vol", CONTROL)
        self._assert_common(args)
        self.assertIn("--ip", args)
        self.assertIn("10.240.0.3", args)
        self.assertEqual(args[args.index("--memory") + 1], "512m")
        self.assertEqual(args[args.index("--memory-swap") + 1], "512m")
        self.assertEqual(args[args.index("--cpus") + 1], "1")
        self.assertEqual(args[args.index("--pids-limit") + 1], "64")
        self.assertIn("keep-id:uid=1000,gid=1000", args)
        self.assertIn("--dns", args)
        mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
        self.assertIn("repo-vol:/repos:rw,nosuid,nodev", mounts)
        self.assertTrue(any("ssh_host_ed25519_key" in m for m in mounts))
        self.assertTrue(any("authorized_keys" in m for m in mounts))
        self.assertFalse(any("client_key" in m for m in mounts))
        self.assertFalse(any("known_hosts" in m for m in mounts))
        self.assertFalse(any("service.json" in m for m in mounts))
        targets = [m.split(":")[1] for m in mounts]
        self.assertNotIn("/workspace", targets)
        self.assertNotIn("/state", targets)
        self.assertNotIn("/models", targets)
        self.assertEqual(args[-1], "/etc/ssh/sshd_config_fixture")

    def test_helper_args(self):
        for label, args in (
            ("bootstrap",
             spec.bootstrap_args(UUID, "img", self._vols(), CONTROL)),
            ("model",
             spec.model_populate_args(
                 UUID, "img", "vm", "/seed/model.gguf", "a" * 64)),
        ):
            with self.subTest(label=label):
                self.assertIn("--network", args)
                self.assertIn("none", args)
                self.assertIn("--cap-drop", args)
                self.assertIn("--read-only", args)
                self.assertIn("--rm", args)
                self.assertIn("--pull=never", args)
                self.assertIn("512m", args)
                self.assertIn("--pids-limit", args)
                self.assertIn("--user", args)
                self.assertIn("1000:1000", args)

    def test_bootstrap_refusal_branches(self):
        script = spec.BOOTSTRAP_SH
        self.assertIn("seed marker present but main missing", script)
        self.assertIn("seed marker present but worktree git dir missing",
                      script)
        self.assertIn("worktree remote identity drifted", script)
        self.assertIn("baseline test file missing", script)
        self.assertIn("baseline test file drifted", script)
        self.assertIn("bare repo initialized but seed marker absent", script)
        self.assertIn("existing worktree file", script)
        self.assertIn("existing git worktree without seed marker", script)
        self.assertIn("protocol.file.allow=always", script)
        self.assertIn("refs/heads/main", script)
        self.assertIn("ssh://git@git-fixture:2222/repos/demo.git", script)
        self.assertNotIn("__TEST_SHA256__", script)

    def test_model_populate_atomic(self):
        script = spec.MODEL_POPULATE_SH
        self.assertIn("mktemp", script)
        self.assertIn("sha256sum", script)
        self.assertIn("EXPECTED_MODEL_SHA", script)
        self.assertIn("[ -L \"$dst\" ]", script)
        self.assertIn("mv \"$tmp\" \"$dst\"", script)
        self.assertNotIn("/models/.model.gguf.tmp", script)

    def test_names_unique(self):
        self.assertEqual(len(set(N.values())), len(N))
        self.assertTrue(all(N[k].startswith("sll-") for k in N))

    def test_seed_sha256_stable(self):
        self.assertEqual(spec.seed_sha256(), spec.seed_sha256())
        self.assertEqual(len(spec.seed_sha256()), 64)


if __name__ == "__main__":
    unittest.main()
