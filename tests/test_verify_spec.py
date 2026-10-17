"""Pure unit tests for verification inspect/spec/namespace comparison."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_agent import runtime_spec as spec  # noqa: E402
from local_agent import verify_spec as vspec  # noqa: E402
from verify_fixtures import (  # noqa: E402
    INFRA, _expects, _fail_names, _good_inspect,
)


class SpecCompare(unittest.TestCase):
    def test_good_specs_pass(self):
        for role in ("inference", "harness", "git"):
            r = vspec.Result()
            exp = _expects()[role]
            vspec._check_container_spec(
                r, role, _good_inspect(role), exp)
            self.assertEqual(_fail_names(r), [],
                             f"{role}: {_fail_names(r)}")

    def _mutate(self, role, fn):
        info = _good_inspect(role)
        fn(info)
        r = vspec.Result()
        vspec._check_container_spec(r, role, info, _expects()[role])
        return _fail_names(r)

    def test_zero_cpu(self):
        fails = self._mutate(
            "harness", lambda i: i["HostConfig"].update(NanoCpus=0))
        self.assertIn("harness spec: cpus", fails)

    def test_extra_swap(self):
        fails = self._mutate(
            "inference",
            lambda i: i["HostConfig"].update(
                MemorySwap=i["HostConfig"]["Memory"] * 2))
        self.assertIn(
            "inference spec: memory-swap equals memory (no extra swap)",
            fails)

    def test_wrong_command(self):
        fails = self._mutate(
            "harness", lambda i: i["Config"].update(Cmd=["/bin/sh"]))
        self.assertIn("harness spec: command", fails)

    def test_wrong_user(self):
        fails = self._mutate(
            "git", lambda i: i["Config"].update(User="0:0"))
        self.assertIn("git spec: user", fails)

    def test_extra_mount(self):
        def add(i):
            i["Mounts"].append({
                "Destination": "/etc", "RW": True, "Type": "bind",
                "Source": "/etc", "Options": ["rbind"]})
        fails = self._mutate("harness", add)
        self.assertIn("harness spec: mounts", fails)

    def test_missing_mount(self):
        def drop(i):
            i["Mounts"] = [
                m for m in i["Mounts"]
                if m["Destination"] != "/workspace"]
        fails = self._mutate("harness", drop)
        self.assertIn("harness spec: mounts", fails)

    def test_rw_regression(self):
        def flip(i):
            for m in i["Mounts"]:
                if m["Destination"] == "/models":
                    m["RW"] = True
        fails = self._mutate("inference", flip)
        self.assertIn("inference spec: mounts", fails)

    def test_missing_mount_opts(self):
        def strip(i):
            for m in i["Mounts"]:
                if "model-api-key" in m["Destination"]:
                    m["Options"] = ["rbind", "ro"]
        fails = self._mutate("inference", strip)
        self.assertIn("inference spec: mounts", fails)

    def test_missing_nnp(self):
        fails = self._mutate(
            "git", lambda i: i["HostConfig"].update(SecurityOpt=[]))
        self.assertIn("git spec: security opts exact", fails)

    def test_seccomp_override_rejected(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(
                SecurityOpt=["no-new-privileges", "seccomp=unconfined"]))
        self.assertIn("harness spec: security opts exact", fails)

    def test_apparmor_override_rejected(self):
        fails = self._mutate(
            "git",
            lambda i: i["HostConfig"].update(
                SecurityOpt=["no-new-privileges",
                             "apparmor=unconfined"]))
        self.assertIn("git spec: security opts exact", fails)

    def test_cap_add(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(CapAdd=["SYS_ADMIN"]))
        self.assertIn("harness spec: no added capabilities", fails)

    def test_partial_capdrop(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(CapDrop=["CHOWN"]))
        self.assertIn("harness spec: cap-drop covers full set", fails)

    def test_host_pid(self):
        fails = self._mutate(
            "inference",
            lambda i: i["HostConfig"].update(PidMode="host"))
        self.assertIn("inference spec: PidMode", fails)

    def test_published_port(self):
        fails = self._mutate(
            "git",
            lambda i: i["HostConfig"].update(
                PortBindings={"2222/tcp": [{"HostPort": "2222"}]}))
        self.assertIn("git spec: no published ports", fails)

    def test_restart_policy(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(
                RestartPolicy={"Name": "always"}))
        self.assertIn("harness spec: no restart policy", fails)

    def test_privileged(self):
        fails = self._mutate(
            "harness", lambda i: i["HostConfig"].update(Privileged=True))
        self.assertIn("harness spec: no privileged", fails)

    def test_extra_device(self):
        fails = self._mutate(
            "git",
            lambda i: i["HostConfig"].update(
                Devices=[{"PathOnHost": "/dev/kvm"}]))
        self.assertIn("git spec: no extra devices", fails)

    def test_proxy_env(self):
        fails = self._mutate(
            "harness",
            lambda i: i["Config"]["Env"].append(
                "HTTP_PROXY=http://evil:3128"))
        self.assertIn("harness spec: no proxy/agent env", fails)

    def test_ssh_agent_env(self):
        fails = self._mutate(
            "harness",
            lambda i: i["Config"]["Env"].append("SSH_AUTH_SOCK=/tmp/x"))
        self.assertIn("harness spec: no proxy/agent env", fails)

    def test_missing_env(self):
        fails = self._mutate(
            "harness",
            lambda i: i["Config"].update(Env=["PATH=/bin"]))
        self.assertTrue(
            any(n.startswith("harness spec: env") for n in fails))

    def test_writable_rootfs(self):
        fails = self._mutate(
            "git",
            lambda i: i["HostConfig"].update(ReadonlyRootfs=False))
        self.assertIn("git spec: readonly rootfs", fails)

    def test_wrong_log_driver(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(
                LogConfig={"Type": "journald", "Size": "4MB"}))
        self.assertIn("harness spec: log driver", fails)

    def test_wrong_log_size(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(
                LogConfig={"Type": "k8s-file", "Size": "1gb"}))
        self.assertIn("harness spec: log size", fails)

    def test_userns_drift(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(UsernsMode="host"))
        self.assertIn("harness spec: userns exact infra", fails)

    def test_userns_wrong_container(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"].update(
                UsernsMode="container:" + "z" * 64))
        self.assertIn("harness spec: userns exact infra", fails)

    def test_netns_drift(self):
        fails = self._mutate(
            "inference",
            lambda i: i["HostConfig"].update(NetworkMode="host"))
        self.assertIn("inference spec: netns exact infra", fails)

    def test_tmpfs_extra(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"]["Tmpfs"].update(
                {"/scratch": "rw"}))
        self.assertIn("harness spec: tmpfs", fails)

    def test_tmpfs_unbounded(self):
        fails = self._mutate(
            "harness",
            lambda i: i["HostConfig"]["Tmpfs"].update(
                {"/tmp": "rw,nosuid,nodev,noexec,mode=1777"}))
        self.assertIn("harness spec: tmpfs", fails)

    def test_tmpfs_missing(self):
        fails = self._mutate(
            "git", lambda i: i["HostConfig"].update(Tmpfs={}))
        self.assertIn("git spec: tmpfs", fails)


class NamespaceChecks(unittest.TestCase):
    def _inventory(self):
        infra = {"net": "net:[111]", "user": "user:[222]",
                 "pid": "pid:[i1]", "ipc": "ipc:[i1]", "uts": "uts:[i1]",
                 "mnt": "mnt:[i1]", "cgroup": "cgroup:[i1]"}
        def member(k):
            return {
                "net": "net:[111]", "user": "user:[222]",
                "pid": f"pid:[{k}]", "ipc": f"ipc:[{k}]",
                "uts": f"uts:[{k}]", "mnt": f"mnt:[{k}]",
                "cgroup": f"cgroup:[{k}]"}
        git = {"net": "net:[333]", "user": "user:[444]",
               "pid": "pid:[g1]", "ipc": "ipc:[g1]", "uts": "uts:[g1]",
               "mnt": "mnt:[g1]", "cgroup": "cgroup:[g1]"}
        return {"infra": infra, "inference": member("n1"),
                "harness": member("n2"), "git": git}

    def test_good(self):
        r = vspec.Result()
        vspec.check_namespaces(r, self._inventory(), INFRA)
        self.assertEqual(_fail_names(r), [])

    def test_wrong_netns(self):
        ns = self._inventory()
        ns["harness"]["net"] = "net:[999]"
        r = vspec.Result()
        vspec.check_namespaces(r, ns, INFRA)
        self.assertIn("harness ns net shared with infra",
                      _fail_names(r))

    def test_equal_private_inode(self):
        ns = self._inventory()
        ns["harness"]["pid"] = ns["inference"]["pid"]
        r = vspec.Result()
        vspec.check_namespaces(r, ns, INFRA)
        self.assertIn("ns pid pairwise private", _fail_names(r))

    def test_git_same_net(self):
        ns = self._inventory()
        ns["git"]["net"] = ns["infra"]["net"]
        r = vspec.Result()
        vspec.check_namespaces(r, ns, INFRA)
        self.assertIn("git ns net distinct from pod", _fail_names(r))

    def test_missing_output(self):
        ns = self._inventory()
        ns["git"]["uts"] = None
        r = vspec.Result()
        vspec.check_namespaces(r, ns, INFRA)
        self.assertIn("namespace inventory", _fail_names(r))


class ResultObject(unittest.TestCase):
    def test_empty_not_ok(self):
        self.assertFalse(vspec.Result().ok)

    def test_unknown_status_rejected(self):
        with self.assertRaises(ValueError):
            vspec.Result().add("x", "mystery")

    def test_fail_makes_not_ok(self):
        r = vspec.Result()
        r.expect("a", True)
        r.expect("b", False)
        self.assertFalse(r.ok)

    def test_degraded_ok(self):
        r = vspec.Result()
        r.expect("a", True)
        r.add("b", "degraded")
        self.assertTrue(r.ok)


class ExpectResources(unittest.TestCase):
    def test_profile_split(self):
        exp = _expects()
        self.assertEqual(exp["inference"]["memory"], 6144 << 20)
        self.assertEqual(exp["harness"]["memory"], 2048 << 20)
        self.assertEqual(exp["git"]["memory"], 512 << 20)
        self.assertEqual(exp["inference"]["pids"], 256)
        self.assertEqual(exp["git"]["pids"], 64)
        self.assertEqual(exp["inference"]["nanocpus"], 4_000_000_000)
        self.assertEqual(exp["git"]["nanocpus"], 1_000_000_000)
        self.assertEqual(
            exp["inference"]["cmd"], spec.model_argv(
                {"resources": {"memory_mb": 8192, "cpus": 4,
                               "pids": 512},
                 "model": {"context_tokens": 8192,
                           "max_output_tokens": 1024, "threads": 4,
                           "parallel": 1},
                 "timeouts": {"startup_seconds": 300,
                              "request_seconds": 120}}))
        self.assertEqual(
            exp["harness"]["userns_id"], f"container:{INFRA}")


if __name__ == "__main__":
    unittest.main()
