"""Regression tests binding the demo result commit to the seed commit."""

import contextlib
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import demo, runner, runtime_spec

FIXED_CALCULATOR = "def add(left, right):\n    return left + right\n"
FAKE_CREDENTIAL = (
    "-----BEGIN FAKE TEST CREDENTIAL-----\n"
    "ZmFrZS10ZXN0LWNyZWRlbnRpYWwtbm90LWEtcmVhbC1rZXk=\n"
    "-----END FAKE TEST CREDENTIAL-----\n")
NONCE = "f00dbabe"
BRANCH = f"agent/demo-{NONCE}"
TIMEOUT = 30
COMMITTER = (
    "author T <t@example.invalid> 1 +0000\n"
    "committer T <t@example.invalid> 1 +0000\n")


class LocalGitRunner:

    def __init__(self, env, locations, cwd):
        self.env = env
        self.locations = dict(locations)
        self.cwd = str(cwd)
        self.calls = []

    def podman(self, args, timeout=None, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        if not args or args[0] != "exec":
            return runner.CommandResult(list(args), 2, "", "not exec")
        argv = self._translate(args)
        try:
            proc = subprocess.run(
                argv, cwd=self.cwd, env=self.env, input=stdin_text,
                capture_output=True, text=True, timeout=timeout or TIMEOUT)
        except subprocess.TimeoutExpired:
            return runner.CommandResult(
                list(args), 124, "", "timed out", timed_out=True)
        return runner.CommandResult(
            list(args), proc.returncode, proc.stdout, proc.stderr)

    def _translate(self, args):
        rest = list(args[1:])
        index = 0
        while index < len(rest) and rest[index].startswith("-"):
            flag = rest[index]
            index += 1
            if flag in ("-w", "-e"):
                index += 1
        index += 1
        return [self._paths(arg) for arg in rest[index:]]

    def _paths(self, arg):
        for container_path, local in self.locations.items():
            arg = arg.replace(container_path, str(local))
        return arg


class ScriptedRunner:

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def podman(self, args, timeout=None, extra_env=None, stdin_text=None):
        self.calls.append(list(args))
        result = self.results[len(self.calls) - 1]
        rc, stdout, stderr = result[:3]
        timed_out = result[3] if len(result) > 3 else False
        return runner.CommandResult(
            list(args), rc, stdout, stderr, timed_out=timed_out)


class GitSandbox(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        home = self.tmp / "home"
        home.mkdir()
        (self.tmp / "empty-templates").mkdir()
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TEMPLATE_DIR": str(self.tmp / "empty-templates"),
            "GIT_AUTHOR_NAME": "demo test",
            "GIT_AUTHOR_EMAIL": "demo@example.invalid",
            "GIT_COMMITTER_NAME": "demo test",
            "GIT_COMMITTER_EMAIL": "demo@example.invalid",
        }
        self.work = self.tmp / "work"
        self.remote = self.tmp / "demo.git"
        self.seed = self._seed_repo()
        self.runner = self._runner()

    def _git(self, repo, *args, check=True):
        proc = subprocess.run(
            ["git", "-C", str(repo), *args], env=self.env,
            capture_output=True, text=True, timeout=TIMEOUT)
        if check:
            self.assertEqual(proc.returncode, 0, (args, proc.stderr))
        return proc

    def _run(self, argv, **kwargs):
        return subprocess.run(
            argv, env=self.env, capture_output=True, text=True,
            timeout=TIMEOUT, **kwargs)

    def _runner(self, work=None):
        return LocalGitRunner(self.env, {
            "/workspace/repo": work if work is not None else self.work,
            "/repos/demo.git": self.remote,
        }, self.tmp)

    def _seed_repo(self):
        self.work.mkdir(parents=True)
        self._git(self.work, "init", "--initial-branch=main")
        for name, content in runtime_spec.SEED_FILES.items():
            (self.work / name).write_text(content)
        self._git(self.work, "add", "-A")
        self._git(self.work, "commit", "-m", "seed")
        return self._git(self.work, "rev-parse", "HEAD").stdout.strip()

    def _commit_all(self, message):
        self._git(self.work, "add", "-A")
        self._git(self.work, "commit", "-m", message)
        return self._git(self.work, "rev-parse", "HEAD").stdout.strip()

    def _head(self):
        return self._git(self.work, "rev-parse", "HEAD").stdout.strip()

    def _apply_fix(self):
        (self.work / "calculator.py").write_text(FIXED_CALCULATOR)

    def _write_object(self, content):
        proc = self._run(
            ["git", "-C", str(self.work), "hash-object", "-t", "commit",
             "--literally", "-w", "--stdin"], input=content)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip()


class SeedParentContract:

    DEMO = None

    def _require(self, head, seed=None):
        self.DEMO._require_seed_parent(
            self.runner, "harness", head,
            self.seed if seed is None else seed)

    def _reject(self, head, fragment=None, seed=None):
        with self.assertRaises(self.DEMO.DemoError) as ctx:
            self._require(head, seed)
        if fragment is not None:
            self.assertIn(fragment, str(ctx.exception))

    def test_direct_child_passes(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        self._apply_fix()
        self._require(self._commit_all("fix add"))
        self.assertTrue(self.runner.calls)
        for call in self.runner.calls:
            self.assertIn("--no-replace-objects", call)

    def test_unchanged_seed_rejected(self):
        self._reject(self.seed)
        self.assertEqual(self.runner.calls, [])

    def test_non_hex_identifiers_rejected(self):
        fake = ScriptedRunner([])
        for head, seed in (
                ("g" * 40, "a" * 40), ("b" * 40, ""), ("b" * 39, "a" * 40),
                ("B" * 40, "a" * 40), ("b" * 40, "a" * 41)):
            with self.subTest(head=head, seed=seed):
                with self.assertRaises(self.DEMO.DemoError):
                    self.DEMO._require_seed_parent(fake, "cid", head, seed)
        self.assertEqual(fake.calls, [])

    def test_credential_add_and_revert_rejected(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        (self.work / "credentials.txt").write_text(FAKE_CREDENTIAL)
        self._commit_all("plant credential")
        self._git(self.work, "rm", "credentials.txt")
        self._apply_fix()
        head = self._commit_all("remove credential and fix")
        diff = self._git(
            self.work, "diff", "--name-only", self.seed, head)
        self.assertEqual(diff.stdout.strip(), "calculator.py")
        self._reject(head, "direct child")

    def test_protected_test_change_and_revert_rejected(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        (self.work / "test_calculator.py").write_text("import unittest\n")
        self._commit_all("weaken protected test")
        (self.work / "test_calculator.py").write_text(
            runtime_spec.SEED_FILES["test_calculator.py"])
        self._apply_fix()
        self._reject(self._commit_all("restore test and fix"), "direct child")

    def test_orphan_root_rejected(self):
        self._git(self.work, "checkout", "--orphan", "agent/work")
        self._git(self.work, "rm", "-rf", ".")
        for name, content in runtime_spec.SEED_FILES.items():
            (self.work / name).write_text(content)
        self._apply_fix()
        self._reject(self._commit_all("orphan root"))

    def test_wrong_parent_rejected(self):
        self._git(self.work, "checkout", "--orphan", "unrelated")
        self._git(self.work, "rm", "-rf", ".")
        (self.work / "other.txt").write_text("unrelated\n")
        self._commit_all("unrelated root")
        self._apply_fix()
        self._reject(self._commit_all("child of unrelated history"))

    def test_merge_commit_rejected(self):
        self._git(self.work, "checkout", "-b", "side")
        (self.work / "notes.txt").write_text("side\n")
        self._commit_all("side work")
        self._git(self.work, "checkout", "main")
        self._git(self.work, "merge", "--no-ff", "--no-edit", "side")
        self._reject(self._head())

    def test_replace_graft_cannot_spoof_seed_parent(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        (self.work / "credentials.txt").write_text(FAKE_CREDENTIAL)
        self._commit_all("plant credential")
        self._git(self.work, "rm", "credentials.txt")
        self._apply_fix()
        head = self._commit_all("clean up")
        self._git(self.work, "replace", "--graft", head, self.seed)
        shown = self._git(self.work, "cat-file", "-p", head).stdout
        self.assertIn(f"parent {self.seed}", shown.split("\n\n")[0])
        self._reject(head, "direct child")

    def test_replace_graft_cannot_hide_real_parent(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        self._apply_fix()
        head = self._commit_all("fix add")
        self._git(self.work, "replace", "--graft", head)
        shown = self._git(self.work, "cat-file", "-p", head).stdout
        self.assertNotIn("parent ", shown.split("\n\n")[0])
        self._require(head)

    def _shallow_clone(self, name):
        dest = self.tmp / name
        proc = self._run(
            ["git", "clone", "--depth", "1", f"file://{self.work}",
             str(dest)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self._git(dest, "rev-parse", "HEAD").stdout.strip(),
            self._head())
        return dest

    def test_shallow_boundary_direct_child_passes(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        self._apply_fix()
        head = self._commit_all("fix add")
        clone = self._shallow_clone("shallow-good")
        self.DEMO._require_seed_parent(
            self._runner(work=clone), "harness", head, self.seed)

    def test_shallow_boundary_multi_commit_rejected(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        (self.work / "credentials.txt").write_text(FAKE_CREDENTIAL)
        self._commit_all("plant credential")
        self._git(self.work, "rm", "credentials.txt")
        self._apply_fix()
        head = self._commit_all("clean up")
        clone = self._shallow_clone("shallow-bad")
        with self.assertRaises(self.DEMO.DemoError):
            self.DEMO._require_seed_parent(
                self._runner(work=clone), "harness", head, self.seed)

    def test_message_parent_line_ignored(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        self._apply_fix()
        head = self._commit_all("fix add\n\nparent " + "0" * 40)
        self._require(head)

    def test_oversized_commit_object_rejected(self):
        self._git(self.work, "checkout", "-b", "agent/work")
        self._apply_fix()
        message = self.tmp / "message.txt"
        message.write_text("fix\n\n" + "x" * 70000)
        self._git(self.work, "add", "-A")
        self._git(self.work, "commit", "-F", str(message))
        self._reject(self._head())

    def test_malformed_raw_commit_objects_rejected(self):
        tree = self._git(
            self.work, "rev-parse", "HEAD^{tree}").stdout.strip()
        objects = {
            "malformed parent token":
                f"tree {tree}\nparent not-hex\n{COMMITTER}\nm\n",
            "duplicate seed parents":
                f"tree {tree}\nparent {self.seed}\nparent {self.seed}\n"
                f"{COMMITTER}\nm\n",
            "oversized parent token":
                f"tree {tree}\nparent {self.seed}x\n{COMMITTER}\nm\n",
            "misspelled parent header":
                f"tree {tree}\nparen {self.seed}\n{COMMITTER}\nm\n",
        }
        for label, content in objects.items():
            with self.subTest(label=label):
                self._reject(self._write_object(content))

    def test_literally_written_direct_child_passes(self):
        tree = self._git(
            self.work, "rev-parse", "HEAD^{tree}").stdout.strip()
        oid = self._write_object(
            f"tree {tree}\nparent {self.seed}\n{COMMITTER}\nm\n")
        self._require(oid)

    def test_size_must_be_nonempty_decimal_within_bound(self):
        for size in ("", "abc", "12x", "-1", "0", "65537",
                     "999999999999"):
            with self.subTest(size=size):
                fake = ScriptedRunner([(0, size, "")])
                with self.assertRaises(self.DEMO.DemoError):
                    self.DEMO._require_seed_parent(
                        fake, "cid", "b" * 40, "a" * 40)
                self.assertEqual(len(fake.calls), 1)

    def test_missing_or_failed_object_rejected(self):
        for result in ((128, "", "Not a valid object name"),
                       (0, "200", "", True)):
            fake = ScriptedRunner([result])
            with self.assertRaises(self.DEMO.DemoError):
                self.DEMO._require_seed_parent(
                    fake, "cid", "b" * 40, "a" * 40)

    def test_pretty_read_failure_rejected(self):
        fake = ScriptedRunner([(0, "200", ""), (128, "", "boom")])
        with self.assertRaises(self.DEMO.DemoError):
            self.DEMO._require_seed_parent(fake, "cid", "b" * 40, "a" * 40)

    def test_boundary_size_and_raw_parent_variants(self):
        tree = "1" * 40
        seed = "a" * 40
        headers = f"tree {tree}\n{{}}\n{COMMITTER}\nm\n"
        good = f"tree {tree}\nparent {seed}\n{COMMITTER}\nm\n"
        fake = ScriptedRunner([(0, "65536", ""), (0, good, "")])
        self.DEMO._require_seed_parent(fake, "cid", "b" * 40, seed)
        for content in (
                headers.format(""),
                headers.format(f"parent {'c' * 40}"),
                f"tree {tree}\nparent {seed}\nparent {'c' * 40}\n"
                f"{COMMITTER}\nm\n",
                headers.format("parent xyz"),
                f"tree {tree}\n{COMMITTER}\n\nparent {seed}\n",
        ):
            with self.subTest(content=content):
                fake = ScriptedRunner([(0, "200", ""), (0, content, "")])
                with self.assertRaises(self.DEMO.DemoError):
                    self.DEMO._require_seed_parent(
                        fake, "cid", "b" * 40, seed)


class SeedParentFixed(SeedParentContract, GitSandbox):
    DEMO = demo


class DemoCallPathContract:

    DEMO = None

    def _expected_hashes(self):
        return {
            name: hashlib.sha256(data.encode()).hexdigest()
            for name, data in runtime_spec.SEED_FILES.items()
        }

    def _fake_exec(self, after):
        expected = self._expected_hashes()

        def fake(runner_, cid, args, label, stdin=None, timeout=60,
                 required=True):
            results = {
                "baseline file check": (0, json.dumps(expected), ""),
                "result file check": (0, json.dumps(after), ""),
                "baseline tests": (1, "FAILED (failures=2)", ""),
                "independent oracle":
                    (0, "independent addition checks passed\n", ""),
                "final repository tests": (0, "OK\n", ""),
            }
            rc, stdout, stderr = results[label]
            return runner.CommandResult(list(args), rc, stdout, stderr)

        return fake

    def _fake_read(self, path, *args, **kwargs):
        name = Path(path).name
        if name == "demo-task.txt":
            return b"Correct the calculator and push {{BRANCH}}.\n"
        if name == "demo-oracle.py":
            return b"print('independent addition checks passed')\n"
        raise AssertionError(f"unexpected secure read: {path}")

    def _run_demo(self, agent):
        mod = self.DEMO
        after = self._expected_hashes()
        after["calculator.py"] = hashlib.sha256(
            FIXED_CALCULATOR.encode()).hexdigest()
        init = self._run(["git", "init", "--bare", "--initial-branch=main",
                          str(self.remote)])
        self.assertEqual(init.returncode, 0, init.stderr)
        self._git(self.work, "push", str(self.remote),
                  "main:refs/heads/main")
        writes = []
        record = {
            "seed_main": self.seed,
            "objects": {"containers": {"harness": "harness-cid",
                                       "git": "git-cid"}},
        }
        patches = [
            mock.patch.object(mod.state, "locked_instance",
                              return_value=contextlib.nullcontext()),
            mock.patch.object(
                mod, "_require_runtime",
                return_value=(self.tmp / "inst", {}, record,
                              SimpleNamespace(checks=[]))),
            mock.patch.object(mod, "_protocol", return_value={
                "status": "pass", "reused": False,
                "response_sha256": "0" * 64}),
            mock.patch.object(mod, "_exec",
                              side_effect=self._fake_exec(after)),
            mock.patch.object(mod, "read_secure_file",
                              side_effect=self._fake_read),
            mock.patch.object(mod, "_redact",
                              side_effect=lambda text, control: text),
            mock.patch.object(mod.secrets, "token_hex",
                              return_value=NONCE),
            mock.patch.object(mod.state, "_atomic_write",
                              side_effect=lambda path, data:
                                  writes.append((str(path), bytes(data)))),
            mock.patch.object(mod.runtime, "_stop", return_value=None),
            mock.patch.object(mod.verify, "verify",
                              return_value=SimpleNamespace(ok=True)),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            evidence, evidence_path = mod.demo(
                str(self.tmp / "state"), "demo", str(self.tmp / "repo"),
                self.runner, agent=agent)
        return evidence, writes

    def _push(self):
        self._git(self.work, "push", str(self.remote),
                  f"HEAD:refs/heads/{BRANCH}")

    def _trace(self):
        return ('{"type":"tool_use","part":{"tool":"bash",'
                '"state":{"status":"completed"}}}\n')

    def test_direct_child_result_passes(self):
        def agent(argv, task):
            self._git(self.work, "checkout", "-b", BRANCH)
            self._apply_fix()
            self._commit_all("fix add")
            self._push()
            return 0, self._trace()

        evidence, writes = self._run_demo(agent)
        self.assertEqual(evidence["status"], "pass")
        self.assertEqual(evidence["result_commit"], self._head())
        self.assertNotEqual(evidence["result_commit"], self.seed)
        self.assertIn("remote_publication_and_protected_main",
                      evidence["checks"])

    def test_bad_ancestry_never_reaches_remote_acceptance(self):
        def agent(argv, task):
            self._git(self.work, "checkout", "-b", BRANCH)
            (self.work / "credentials.txt").write_text(FAKE_CREDENTIAL)
            self._commit_all("plant credential")
            self._git(self.work, "rm", "credentials.txt")
            self._apply_fix()
            self._commit_all("clean up")
            self._push()
            return 0, self._trace()

        evidence, writes = self._run_demo(agent)
        self.assertNotEqual(self._head(), self.seed)
        self.assertEqual(evidence["status"], "fail")
        self.assertIn("direct child", evidence["error"])
        self.assertNotIn(
            "minimal_committed_change_on_designated_branch",
            evidence["checks"])
        self.assertNotIn("remote_publication_and_protected_main",
                         evidence["checks"])
        self.assertFalse(any(
            "--verify" in call for call in self.runner.calls))


class DemoCallPathFixed(DemoCallPathContract, GitSandbox):
    DEMO = demo


REPO_ROOT = Path(__file__).resolve().parents[1]
VALID_TOOL_RESPONSE = json.dumps({
    "choices": [{
        "finish_reason": "tool_calls",
        "index": 0,
        "message": {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "call_tool_ok_1",
                "type": "function",
                "function": {
                    "name": "echo",
                    "arguments": '{"text": "CPU_TOOL_OK"}',
                },
            }],
        },
    }],
})
OLD_TOOL_RESPONSE = VALID_TOOL_RESPONSE.replace(
    "call_tool_ok_1", "call_cached_old")
NO_TOOL_RESPONSE = json.dumps({
    "choices": [{
        "finish_reason": "stop",
        "index": 0,
        "message": {"role": "assistant", "content": "done"},
    }],
})


class FakeTransport:

    def __init__(self):
        self.responses = []
        self.calls = []

    def queue(self, returncode=0, stdout="", stderr="", timed_out=False):
        self.responses.append((returncode, stdout, stderr, timed_out))

    def podman(self, args, timeout=None, extra_env=None, stdin_text=None):
        self.calls.append((list(args), stdin_text))
        rc, stdout, stderr, timed_out = self.responses.pop(0)
        return runner.CommandResult(
            list(args), rc, stdout, stderr, timed_out=timed_out)


class ProtocolSandbox(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.state_root = self.tmp / "state"
        self.inst = self.state_root / "instances" / "demo"
        self.inst.mkdir(parents=True)
        self.state_root.chmod(0o700)
        (self.state_root / "instances").chmod(0o700)
        self.inst.chmod(0o700)
        self.repo = REPO_ROOT
        self.record = {
            "seed_main": "a" * 40,
            "images": {"harness": "sha256:" + "1" * 64,
                       "inference": "sha256:" + "2" * 64},
            "fingerprints": {"artifacts_lock": "3" * 64,
                             "profile": "4" * 64},
            "objects": {"containers": {"harness": "harness-cid",
                                       "git": "git-cid"}},
        }
        self.request = self.DEMO.parse_json(
            self.DEMO.read_secure_file(
                self.repo / ".devin" / "tool-probe.json"), "probe")
        profile, _ = self.DEMO.load_profile(self.repo, "cpu")
        self.fingerprint = self.DEMO._protocol_binding(self.record, profile)
        self.request_sha = self.DEMO._digest(
            self.DEMO._canonical(self.request))
        self.transport = FakeTransport()

    def _write_private(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def _mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def _responses(self):
        return sorted(self.state_root.glob("tool-probe-*.json"))


class ProtocolFreshnessContract:

    DEMO = None

    def _invoke(self):
        with mock.patch.object(
                self.DEMO.state, "load_manifest",
                return_value={"profile": {"name": "cpu"}}):
            return self.DEMO._protocol(
                str(self.state_root), "demo", str(self.repo),
                self.transport, self.record)

    def _seed_cache(self, response=OLD_TOOL_RESPONSE):
        path = self.state_root / "tool-probe-20000101T000000Z-deadbeef.json"
        self._write_private(path, response.encode())
        marker = self.inst / "protocol.json"
        self._write_private(marker, self.DEMO._canonical({
            "schema": "secure-local-llm/protocol@1",
            "status": "pass",
            "binding_sha256": self.fingerprint,
            "request_sha256": self.request_sha,
            "response_path": str(path),
            "response_sha256": self.DEMO._digest(response.encode()),
        }) + b"\n")
        return path, marker

    def _marker(self):
        return json.loads((self.inst / "protocol.json").read_bytes())

    def test_cached_success_still_issues_live_request(self):
        old_path, marker = self._seed_cache()
        old_bytes = old_path.read_bytes()
        self.transport.queue(stdout=VALID_TOOL_RESPONSE)
        result = self._invoke()
        self.assertEqual(len(self.transport.calls), 1)
        args, stdin = self.transport.calls[0]
        self.assertIn(self.DEMO.MODEL_REQUEST, args)
        self.assertEqual(stdin, json.dumps(self.request))
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["reused"])
        fresh_sha = hashlib.sha256(
            VALID_TOOL_RESPONSE.encode()).hexdigest()
        self.assertEqual(result["response_sha256"], fresh_sha)
        self.assertEqual(old_path.read_bytes(), old_bytes)
        self.assertEqual(self._mode(old_path), 0o600)
        checkpoint = self._marker()
        self.assertEqual(
            checkpoint["schema"], "secure-local-llm/protocol@1")
        self.assertEqual(checkpoint["status"], "pass")
        self.assertEqual(checkpoint["binding_sha256"], self.fingerprint)
        self.assertEqual(checkpoint["request_sha256"], self.request_sha)
        self.assertEqual(checkpoint["response_sha256"], fresh_sha)
        retained = self._responses()
        self.assertIn(old_path, retained)
        new_files = [p for p in retained if p != old_path]
        self.assertEqual(len(new_files), 1)
        self.assertEqual(str(new_files[0]), checkpoint["response_path"])
        self.assertEqual(
            new_files[0].read_bytes(), VALID_TOOL_RESPONSE.encode())
        self.assertEqual(self._mode(new_files[0]), 0o600)
        self.assertEqual(self._mode(marker), 0o600)

    def test_each_invocation_makes_a_new_request(self):
        self.transport.queue(stdout=VALID_TOOL_RESPONSE)
        first = self._invoke()
        second_response = VALID_TOOL_RESPONSE.replace(
            "call_tool_ok_1", "call_tool_ok_2")
        self.transport.queue(stdout=second_response)
        second = self._invoke()
        self.assertEqual(len(self.transport.calls), 2)
        self.assertFalse(first["reused"])
        self.assertFalse(second["reused"])
        self.assertNotEqual(
            first["response_sha256"], second["response_sha256"])
        retained = self._responses()
        self.assertEqual(len(retained), 2)
        self.assertEqual(
            len({p.read_bytes() for p in retained}), 2)
        self.assertEqual(
            self._marker()["response_sha256"], second["response_sha256"])

    def test_cached_success_does_not_mask_current_failure(self):
        old_path, marker = self._seed_cache()
        marker_bytes = marker.read_bytes()
        old_bytes = old_path.read_bytes()
        cases = {
            "no tool call": (0, NO_TOOL_RESPONSE, ""),
            "malformed json": (0, "not json {", ""),
            "transport failure": (1, "", "connect refused"),
            "transport timeout": (124, "", "timed out", True),
            "oversized response": (0, " " * 70000, ""),
        }
        for label, result in cases.items():
            with self.subTest(label=label):
                self.transport.queue(*result)
                with self.assertRaises(self.DEMO.DemoError):
                    self._invoke()
                self.assertEqual(len(self.transport.calls), 1)
                self.transport.calls.clear()
                self.assertEqual(marker.read_bytes(), marker_bytes)
                self.assertEqual(old_path.read_bytes(), old_bytes)
                self.assertEqual(self._responses(), [old_path])
        self.assertEqual(self.transport.responses, [])

    def _run_protocol_demo(self, agent):
        mod = self.DEMO
        stop = mock.Mock(return_value=None)
        patches = [
            mock.patch.object(mod.state, "locked_instance",
                              return_value=contextlib.nullcontext()),
            mock.patch.object(mod, "_require_runtime",
                              return_value=(self.inst, {}, self.record,
                                            SimpleNamespace(checks=[]))),
            mock.patch.object(mod.state, "load_manifest",
                              return_value={"profile": {"name": "cpu"}}),
            mock.patch.object(mod, "_redact",
                              side_effect=lambda text, control: text),
            mock.patch.object(mod.runtime, "_stop", stop),
            mock.patch.object(mod.verify, "verify",
                              return_value=SimpleNamespace(ok=True)),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            evidence, _ = mod.demo(
                str(self.state_root), "demo", str(self.repo),
                self.transport, protocol_only=True, agent=agent)
        return evidence, stop

    def test_protocol_only_demo_runs_current_protocol(self):
        old_path, _ = self._seed_cache()
        self.transport.queue(stdout=VALID_TOOL_RESPONSE)
        agent_calls = []

        def agent(argv, task):
            agent_calls.append((argv, task))
            return 0, ""

        evidence, stop = self._run_protocol_demo(agent)
        self.assertEqual(evidence["status"], "protocol-only")
        self.assertEqual(evidence["protocol"]["reused"], False)
        self.assertEqual(
            evidence["protocol"]["response_sha256"],
            hashlib.sha256(VALID_TOOL_RESPONSE.encode()).hexdigest())
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(agent_calls, [])
        stop.assert_not_called()
        self.assertIn("runtime_and_tool_protocol", evidence["checks"])

    def test_protocol_only_failure_records_fail_without_agent(self):
        old_path, marker = self._seed_cache()
        marker_bytes = marker.read_bytes()
        self.transport.queue(stdout=NO_TOOL_RESPONSE)
        agent_calls = []

        def agent(argv, task):
            agent_calls.append((argv, task))
            return 0, ""

        evidence, stop = self._run_protocol_demo(agent)
        self.assertEqual(evidence["status"], "fail")
        self.assertIn("structured tool", evidence["error"])
        self.assertNotIn("runtime_and_tool_protocol", evidence["checks"])
        self.assertEqual(agent_calls, [])
        stop.assert_called_once()
        self.assertEqual(marker.read_bytes(), marker_bytes)
        self.assertEqual(len(self.transport.calls), 1)


class ProtocolFreshnessFixed(ProtocolFreshnessContract, ProtocolSandbox):
    DEMO = demo


if __name__ == "__main__":
    unittest.main()
