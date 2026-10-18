"""Unit tests for the restricted git SSH fixture scripts."""

import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from local_agent import runtime_spec

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "git-fixture"
CONTAINERFILE = REPO / "containers" / "git-fixture.Containerfile"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, FIXTURE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


serve_git = _load("serve_git", "serve_git.py")
pre_receive = _load("pre_receive", "pre_receive.py")

ZERO = "0" * 40
A = "a" * 40
B = "b" * 40


def _container_instructions():
    instructions = []
    pending = ""
    for raw in CONTAINERFILE.read_text().splitlines():
        line = raw.strip()
        if not line or (not pending and line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        pending += line
        keyword, _, value = pending.partition(" ")
        instructions.append((keyword.upper(), value))
        pending = ""
    return instructions


class ServeGit(unittest.TestCase):
    def _run(self, command):
        with mock.patch.dict(
            os.environ, {"SSH_ORIGINAL_COMMAND": command}, clear=False
        ), mock.patch.object(serve_git.os, "execve") as execve:
            try:
                serve_git.main()
            except SystemExit as exc:
                return exc.code, None
            return None, execve.call_args

    def test_upload_pack_ok(self):
        code, call = self._run("git-upload-pack /repos/demo.git")
        self.assertIsNone(code)
        argv = call.args[1]
        env = call.args[2]
        self.assertEqual(call.args[0], "/usr/bin/git")
        self.assertEqual(
            argv,
            [
                "git",
                "-c", "core.hooksPath=/opt/local-agent/hooks",
                "-c", "receive.maxInputSize=33554432",
                "upload-pack", "/repos/demo.git",
            ],
        )
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertNotIn("SSH_ORIGINAL_COMMAND", env)
        self.assertNotIn("SSH_AUTH_SOCK", env)

    def test_receive_pack_ok(self):
        code, call = self._run("git-receive-pack '/repos/demo.git'")
        self.assertIsNone(code)
        self.assertIn("receive-pack", call.args[1])

    def test_rejects(self):
        for cmd in (
            "",
            "echo hi",
            "git-upload-pack /repos/other.git",
            "git-upload-pack /repos/demo.git extra",
            "git-upload-pack",
            "git-upload-pack --opt /repos/demo.git",
            "git-upload-archive /repos/demo.git",
            "git-upload-pack /repos/demo.git; rm -rf /",
            "git-upload-pack 'unterminated",
            "/usr/bin/git-upload-pack /repos/demo.git",
            "git-upload-pack /repos/../repos/demo.git",
            "git-upload-pack /repos/demo.git/.",
        ):
            with self.subTest(cmd=cmd):
                code, call = self._run(cmd)
                self.assertEqual(code, 1)
                self.assertIsNone(call)

    def test_no_command_env(self):
        with mock.patch.dict(
            os.environ, {}, clear=True
        ), mock.patch.object(serve_git.os, "execve"):
            with self.assertRaises(SystemExit) as ctx:
                serve_git.main()
            self.assertEqual(ctx.exception.code, 1)


class _Stdin(io.TextIOBase):
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


MAIN = "d" * 40
TEST_BLOB = "f" * 40
SHARED = "2" * 40


class _GitModel:
    def __init__(self):
        self.types = {}
        self.blobs = {}
        self.trees = {}
        self.refs = {}
        self.lists = {}
        self.ancestors = {}
        self.calls = []

    def blob(self, content):
        oid = hashlib.sha1(content.encode()).hexdigest()
        self.types[oid] = "blob"
        self.blobs[oid] = content
        return oid

    def commit(self, oid, calc, test=TEST_BLOB):
        self.types[oid] = "commit"
        self.trees[oid] = [
            ("100644", "blob", self.blob(calc), "calculator.py"),
            ("100644", "blob", test, "test_calculator.py"),
        ]
        return oid

    def seed(self):
        self.refs["refs/heads/main"] = MAIN
        self.types[MAIN] = "commit"
        self.types[TEST_BLOB] = "blob"
        self.trees[MAIN] = [
            ("100644", "blob", self.blob(pre_receive.CALC_MINUS),
             "calculator.py"),
            ("100644", "blob", TEST_BLOB, "test_calculator.py"),
        ]
        return self

    def tip(self, oid, calc=pre_receive.CALC_PLUS, commits=None,
            test=TEST_BLOB):
        self.commit(oid, calc, test=test)
        self.lists[oid] = list(commits) if commits is not None else [oid]
        return self

    def __call__(self, *args):
        self.calls.append(args)
        res = SimpleNamespace(returncode=0, stdout="", stderr="")
        op = args[0]
        if op == "check-ref-format":
            return res
        if op == "rev-parse":
            oid = self.refs.get(args[-1].split("^{")[0])
            if oid is None:
                res.returncode = 128
            else:
                res.stdout = oid + "\n"
            return res
        if op == "cat-file":
            kind, oid = args[1], args[2]
            if kind == "-t":
                if oid not in self.types:
                    res.returncode = 128
                else:
                    res.stdout = self.types[oid] + "\n"
            elif kind == "-s":
                if oid not in self.blobs:
                    res.returncode = 128
                else:
                    res.stdout = f"{len(self.blobs[oid].encode())}\n"
            elif kind in ("blob", "-p"):
                if oid not in self.blobs:
                    res.returncode = 128
                else:
                    res.stdout = self.blobs[oid]
            return res
        if op == "ls-tree":
            entries = self.trees.get(args[1])
            if entries is None:
                res.returncode = 128
            else:
                res.stdout = "".join(
                    f"{mode} {kind} {oid}\t{name}\n"
                    for mode, kind, oid, name in entries)
            return res
        if op == "merge-base":
            res.returncode = self.ancestors.get((args[2], args[3]), 0)
            return res
        if op == "rev-list":
            res.stdout = "".join(
                oid + "\n" for oid in self.lists.get(args[2], []))
            return res
        res.returncode = 1
        return res


class PreReceive(unittest.TestCase):
    def _run(self, data, git=None):
        hook = mock.Mock(side_effect=git or _GitModel().seed())
        with mock.patch.object(pre_receive, "_git", hook), \
                mock.patch.object(pre_receive.sys, "stdin", _Stdin(data)):
            try:
                pre_receive.main()
            except SystemExit as exc:
                return exc.code, hook
        return 0, hook

    def test_new_branch_ok(self):
        model = _GitModel().seed().tip(A)
        code, _ = self._run(
            f"{ZERO} {A} refs/heads/agent/work\n".encode(), model)
        self.assertEqual(code, 0)

    def test_ff_ok(self):
        model = _GitModel().seed().tip(B)
        code, hook = self._run(
            f"{A} {B} refs/heads/agent/x\n".encode(), model)
        self.assertEqual(code, 0)
        self.assertIn(("merge-base", "--is-ancestor", A, B),
                      [c.args for c in hook.call_args_list])

    def test_non_ff_rejected(self):
        model = _GitModel().seed().tip(B)
        model.ancestors[(A, B)] = 1
        code, _ = self._run(f"{A} {B} refs/heads/agent/x\n".encode(), model)
        self.assertEqual(code, 1)

    def test_missing_or_bad_seed_rejected(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        code, _ = self._run(update, _GitModel().tip(A))
        self.assertEqual(code, 1)
        model = _GitModel().seed()
        model.types[MAIN] = "blob"
        code, _ = self._run(update, model)
        self.assertEqual(code, 1)
        model = _GitModel().seed()
        model.trees[MAIN][0] = (
            "100644", "blob", model.blob("def add(a, b):\n    return a - b\n"),
            "calculator.py")
        code, _ = self._run(update, model)
        self.assertEqual(code, 1)
        model = _GitModel().seed()
        model.trees[MAIN] = model.trees[MAIN][:1]
        code, _ = self._run(update, model)
        self.assertEqual(code, 1)
        model = _GitModel().seed()
        model.refs["refs/heads/main"] = "xyz"
        code, _ = self._run(update, model)
        self.assertEqual(code, 1)
        model = _GitModel().seed()
        model.trees[MAIN][0] = (
            "120000", "blob", model.trees[MAIN][0][2], "calculator.py")
        code, _ = self._run(update, model)
        self.assertEqual(code, 1)

    def test_duplicate_root_entry_rejected(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        model = _GitModel().seed().tip(A)
        calc_oid = model.trees[A][0][2]
        dup = (
            f"100644 blob {B}\tcalculator.py\n"
            f"100644 blob {calc_oid}\tcalculator.py\n"
            f"100644 blob {TEST_BLOB}\ttest_calculator.py\n")

        def git(*args):
            res = model(*args)
            if args[:2] == ("ls-tree", A):
                res = SimpleNamespace(returncode=0, stdout=dup, stderr="")
            return res

        code, _ = self._run(update, git)
        self.assertEqual(code, 1)

    def test_git_call_failures_fail_closed(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        for key in (
                ("rev-parse", "--verify", "refs/heads/main"),
                ("cat-file", "-t", MAIN),
                ("ls-tree", MAIN),
                ("merge-base", "--is-ancestor"),
                ("rev-list", "--max-count=129"),
                ("ls-tree", A),
                ("cat-file", "-s"),
                ("cat-file", "blob")):
            with self.subTest(key=key):
                model = _GitModel().seed().tip(A)

                def git(*args):
                    res = model(*args)
                    if args[:len(key)] == key and res.returncode == 0:
                        res = SimpleNamespace(
                            returncode=1, stdout=res.stdout, stderr="")
                    return res

                code, _ = self._run(update, git)
                self.assertEqual(code, 1)

    def test_blob_size_bounds(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        for size in ("-1", "65537", "99999999999", "", "abc"):
            with self.subTest(size=size):
                model = _GitModel().seed().tip(A)
                calc_oid = model.trees[A][0][2]

                def git(*args):
                    res = model(*args)
                    if args[:3] == ("cat-file", "-s", calc_oid):
                        res = SimpleNamespace(
                            returncode=0, stdout=size, stderr="")
                    return res

                code, _ = self._run(update, git)
                self.assertEqual(code, 1)

    def test_content_policy_rejected(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        cases = []
        model = _GitModel().seed().tip(A)
        model.trees[A].append(
            ("100644", "blob", model.blob("secret\n"), "credentials.txt"))
        cases.append(("extra file", model))
        model = _GitModel().seed().tip(A)
        model.trees[A][0] = ("120000", "blob", model.blob("x"), "calculator.py")
        cases.append(("symlink mode", model))
        model = _GitModel().seed().tip(A)
        model.trees[A][1] = ("160000", "commit", B, "test_calculator.py")
        cases.append(("gitlink", model))
        model = _GitModel().seed().tip(A, test="9" * 40)
        cases.append(("changed test blob", model))
        model = _GitModel().seed().tip(A, calc="def add(a, b):\n    pass\n")
        cases.append(("rewritten calculator", model))
        model = _GitModel().seed().tip(A, calc=pre_receive.CALC_MINUS +
                                         "# fake credential marker\n")
        cases.append(("credential comment in calculator", model))
        model = _GitModel().seed().tip(A)
        model.ancestors[(MAIN, A)] = 1
        cases.append(("main not ancestor", model))
        model = _GitModel().seed().tip(A)
        model.lists[A] = ["not-a-commit-oid"]
        cases.append(("malformed rev-list output", model))
        model = _GitModel().seed().tip(A)
        model.commit(B, pre_receive.CALC_PLUS)
        model.trees[B].append(
            ("100644", "blob", model.blob("secret\n"), "credentials.txt"))
        model.lists[A] = [A, B]
        cases.append(("unsafe merge-side commit", model))
        for label, model in cases:
            with self.subTest(label=label):
                code, _ = self._run(update, model)
                self.assertEqual(code, 1)

    def test_content_policy_accepted(self):
        model = _GitModel().seed().tip(A, calc=pre_receive.CALC_MINUS)
        code, _ = self._run(
            f"{ZERO} {A} refs/heads/agent/x\n".encode(), model)
        self.assertEqual(code, 0)

    def test_history_bound(self):
        update = f"{ZERO} {B} refs/heads/agent/x\n".encode()
        commits = [f"{i:040x}" for i in range(1, 130)]
        model = _GitModel().seed()
        model.types[B] = "commit"
        for oid in commits[:128]:
            model.commit(oid, pre_receive.CALC_PLUS)
        model.lists[B] = commits[:128]
        code, _ = self._run(update, model)
        self.assertEqual(code, 0)
        model.commit(commits[128], pre_receive.CALC_PLUS)
        model.lists[B] = commits[:129]
        code, _ = self._run(update, model)
        self.assertEqual(code, 1)

    def test_shared_history_validated_once(self):
        model = _GitModel().seed()
        model.tip(A, commits=[A, SHARED]).tip(B, commits=[B, SHARED])
        model.commit(SHARED, pre_receive.CALC_PLUS)
        data = (
            f"{ZERO} {A} refs/heads/agent/a\n"
            f"{ZERO} {B} refs/heads/agent/b\n"
        ).encode()
        code, _ = self._run(data, model)
        self.assertEqual(code, 0)
        seen = [call for call in model.calls
                if call[:2] == ("ls-tree", SHARED)]
        self.assertEqual(len(seen), 1)

    def test_malformed_git_output_fails_closed(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        for key, stdout in (
                (("ls-tree",), "garbage without fields\n"),
                (("cat-file", "-s"), "not-a-size\n"),
                (("rev-list",), "z z z\n")):
            with self.subTest(key=key):
                model = _GitModel().seed().tip(A)

                def git(*args):
                    res = model(*args)
                    if args[:len(key)] == key and res.returncode == 0:
                        res = SimpleNamespace(
                            returncode=0, stdout=stdout, stderr="")
                    return res

                code, _ = self._run(update, git)
                self.assertEqual(code, 1)

    def test_git_timeout_and_failure_fail_closed(self):
        update = f"{ZERO} {A} refs/heads/agent/x\n".encode()
        for exc in (
                subprocess.TimeoutExpired("git", 10),
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "boom")):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch.object(
                        pre_receive.subprocess, "run",
                        side_effect=exc), mock.patch.object(
                        pre_receive.sys, "stdin", _Stdin(update)):
                    with self.assertRaises(SystemExit) as ctx:
                        pre_receive.main()
                    self.assertEqual(ctx.exception.code, 1)

    def test_rejects(self):
        lines = [
            f"{ZERO} {A} refs/heads/main",
            f"{ZERO} {A} refs/tags/v1",
            f"{ZERO} {A} refs/heads/agent",
            f"{ZERO} {A} agent/x",
            f"{ZERO} {A} refs/heads/agent/../main",
            f"{ZERO} {A} refs/heads/agent/x y",
            f"{ZERO} {ZERO} refs/heads/agent/x",
            f"{A} {ZERO} refs/heads/agent/x",
            f"{ZERO} {A[:-1]} refs/heads/agent/x",
            f"{ZERO} {'G' * 40} refs/heads/agent/x",
            f"{ZERO} {A} refs/heads/agent/x\tx",
            "",
        ]
        for line in lines:
            with self.subTest(line=line):
                code, _ = self._run((line + "\n").encode())
                self.assertEqual(code, 1)

    def test_non_commit_new_object_rejected(self):
        def git(*args):
            class R:
                returncode = 0
                stdout = "tree\n"
                stderr = ""
            return R()
        code, _ = self._run(f"{ZERO} {A} refs/heads/agent/x\n".encode(), git)
        self.assertEqual(code, 1)

    def test_too_many_updates(self):
        data = b"".join(
            f"{ZERO} {A} refs/heads/agent/x{i}\n".encode()
            for i in range(129)
        )
        code, hook = self._run(data)
        self.assertEqual(code, 1)
        hook.assert_not_called()

    def test_stdin_bound(self):
        line = f"{ZERO} {A} refs/heads/agent/x\n"
        data = line.encode() + b"x" * (64 * 1024)
        code, hook = self._run(data)
        self.assertEqual(code, 1)
        hook.assert_not_called()

    def test_multiple_valid_updates(self):
        model = _GitModel().seed().tip(A).tip(B)
        data = (
            f"{ZERO} {A} refs/heads/agent/a\n"
            f"{ZERO} {B} refs/heads/agent/b\n"
        ).encode()
        code, _ = self._run(data, model)
        self.assertEqual(code, 0)

    def test_all_validated_before_success(self):
        model = _GitModel().seed().tip(A)
        data = (
            f"{ZERO} {A} refs/heads/agent/a\n"
            f"{ZERO} {B} refs/heads/main\n"
        ).encode()
        code, _ = self._run(data, model)
        self.assertEqual(code, 1)

    def test_passthrough_env(self):
        env = {
            "GIT_DIR": "/repos/demo.git",
            "GIT_OBJECT_DIRECTORY": "/repos/demo.git/objects/quar",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/repos/demo.git/objects",
            "GIT_QUARANTINE_PATH": "/repos/demo.git/objects/quar",
            "HOME": "/evil",
            "PATH": "/evil",
        }
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(pre_receive.subprocess, "run") as run, \
                mock.patch.object(pre_receive.sys, "stdin",
                                  _Stdin(f"{ZERO} {A} refs/heads/agent/x\n".encode())):
            run.return_value = mock.Mock(
                returncode=0, stdout=b"commit\n", stderr=b"")
            try:
                pre_receive.main()
            except SystemExit:
                pass
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["git", "--no-replace-objects"])
        used_env = run.call_args.kwargs["env"]
        self.assertEqual(used_env["GIT_DIR"], "/repos/demo.git")
        self.assertEqual(
            used_env["GIT_OBJECT_DIRECTORY"], "/repos/demo.git/objects/quar")
        self.assertEqual(used_env["PATH"], "/usr/bin:/bin")
        self.assertNotIn("HOME", used_env)


class SshdConfig(unittest.TestCase):
    REQUIRED = {
        "port": "2222",
        "addressfamily": "inet",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "permitemptypasswords": "no",
        "permitrootlogin": "no",
        "authenticationmethods": "publickey",
        "pubkeyauthentication": "yes",
        "usepam": "no",
        "allowusers": "git",
        "permittty": "no",
        "permituserrc": "no",
        "permituserenvironment": "no",
        "allowagentforwarding": "no",
        "allowtcpforwarding": "no",
        "allowstreamlocalforwarding": "no",
        "x11forwarding": "no",
        "permittunnel": "no",
        "disableforwarding": "yes",
        "pidfile": "none",
        "hostkey": "/run/local-agent/ssh_host_ed25519_key",
        "authorizedkeysfile": "/run/local-agent/authorized_keys",
        "forcecommand":
            "/usr/bin/python3 -I -B /usr/local/lib/local-agent/serve_git.py",
    }

    def test_directives(self):
        seen = {}
        for line in (FIXTURE / "sshd_config").read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            seen[key.lower()] = value.strip()
        for key, want in self.REQUIRED.items():
            self.assertEqual(seen.get(key), want, key)
        self.assertNotIn("subsystem", seen)
        self.assertNotIn("listenaddress ::", seen)


class RepoInit(unittest.TestCase):
    EXPECTED_ARGV = [
        "git", "init", "--bare", "--object-format=sha1",
        "--initial-branch=main", serve_git.REPO,
    ]
    TIMEOUT = 10

    def _init(self):
        found = [
            (index, shlex.split(value))
            for index, (keyword, value) in enumerate(_container_instructions())
            if keyword == "RUN" and shlex.split(value)[:2] == ["git", "init"]
        ]
        self.assertEqual(len(found), 1)
        return found[0]

    def _env(self, home):
        template = Path(home) / "empty-templates"
        template.mkdir(exist_ok=True)
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TEMPLATE_DIR": str(template),
            "GIT_AUTHOR_NAME": "fixture test",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture test",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }

    def _run(self, argv, env, check=True, stdin=None):
        result = subprocess.run(
            argv, env=env, input=stdin, capture_output=True, text=True,
            timeout=self.TIMEOUT
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _git(self, cwd, env, *args, check=True):
        return self._run(["git", "-C", str(cwd), *args], env, check=check)

    def _relocated(self, argv, dest):
        return [str(dest) if arg == serve_git.REPO else arg for arg in argv]

    def test_init_instruction(self):
        instructions = _container_instructions()
        index, argv = self._init()
        self.assertEqual(argv, self.EXPECTED_ARGV)
        users = [
            value.strip()
            for i, (keyword, value) in enumerate(instructions)
            if keyword == "USER" and i < index
        ]
        self.assertTrue(users)
        self.assertEqual(users[-1], "1000:1000")
        for keyword, value in instructions[index + 1:]:
            if keyword == "USER":
                self.assertNotIn(
                    value.split(":", 1)[0].strip(), {"0", "root"})

    def test_relocated_init(self):
        _, argv = self._init()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = self._env(tmp)
            bare = tmp / "demo.git"
            self._run(self._relocated(argv, bare), env)
            self.assertEqual(
                self._git(bare, env, "rev-parse", "--is-bare-repository")
                .stdout.strip(), "true")
            self.assertEqual(
                self._git(bare, env, "rev-parse", "--show-object-format")
                .stdout.strip(), "sha1")
            self.assertEqual(
                self._git(bare, env, "symbolic-ref", "HEAD")
                .stdout.strip(), "refs/heads/main")
            self.assertEqual(
                self._git(bare, env, "for-each-ref").stdout, "")
            seeded = self._git(bare, env, "config", "--get",
                               "local-agent.seeded", check=False)
            self.assertNotEqual(seeded.returncode, 0)
            self.assertEqual(os.stat(bare).st_uid, os.getuid())

    def _git_in(self, cwd, env, stdin, *args, check=True):
        return self._run(
            ["git", "-C", str(cwd), *args], env, check=check, stdin=stdin)

    def _install_hook(self, bare):
        hooks = bare / "hooks"
        hooks.mkdir(exist_ok=True)
        hook = hooks / "pre-receive"
        shutil.copyfile(FIXTURE / "pre_receive.py", hook)
        os.chmod(hook, 0o755)
        return hook

    def _bootstrap(self, tmp, env, argv, bare):
        self._run(self._relocated(argv, bare), env)
        work = tmp / "work"
        clone = self._run(["git", "clone", str(bare), str(work)], env)
        self.assertIn("empty repository", clone.stderr)
        self._git(work, env, "fetch", "origin")
        for name, content in runtime_spec.SEED_FILES.items():
            (work / name).write_text(content)
        self._git(work, env, "add", "-A")
        self._git(work, env, "commit", "-m", "seed")
        self._git(work, env, "push", "origin", "HEAD:refs/heads/main")
        seed = self._git(work, env, "rev-parse", "HEAD").stdout.strip()
        self._install_hook(bare)
        return work, seed

    def _fix(self, work, env, calc=pre_receive.CALC_PLUS):
        (work / "calculator.py").write_text(calc)
        self._git(work, env, "commit", "-am", "fix")
        return self._git(work, env, "rev-parse", "HEAD").stdout.strip()

    def _push_denied(self, work, env, ref, *refspecs):
        specs = refspecs or (f"HEAD:refs/heads/{ref}",)
        denied = self._git(work, env, "push", "origin", *specs,
                           check=False)
        self.assertNotEqual(denied.returncode, 0, ref)
        self.assertIn("pre-receive", denied.stderr)
        return denied

    def _refs(self, bare, env):
        return {
            line.split()[2]: line.split()[0]
            for line in self._git(bare, env, "for-each-ref")
            .stdout.splitlines()
        }

    def test_local_receive_pack(self):
        _, argv = self._init()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = self._env(tmp)
            bare = tmp / "demo.git"
            work, seed = self._bootstrap(tmp, env, argv, bare)

            self._fix(work, env)
            self._git(work, env, "push", "origin",
                      "HEAD:refs/heads/agent/work")
            second = self._fix(work, env, pre_receive.CALC_MINUS)
            self._git(work, env, "push", "origin",
                      "HEAD:refs/heads/agent/work")

            for refspec in ("HEAD:refs/heads/main", "HEAD:refs/tags/v1",
                            ":refs/heads/agent/work"):
                denied = self._git(work, env, "push", "origin", refspec,
                                   check=False)
                self.assertNotEqual(denied.returncode, 0, refspec)
                self.assertIn("pre-receive", denied.stderr)

            self._git(work, env, "reset", "--hard", "HEAD~1")
            (work / "calculator.py").write_text(pre_receive.CALC_MINUS)
            self._git(work, env, "commit", "-am", "diverged")
            denied = self._git(work, env, "push", "--force", "origin",
                               "HEAD:refs/heads/agent/work", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("non-fast-forward", denied.stderr)

            self.assertEqual(self._refs(bare, env), {
                "refs/heads/main": seed,
                "refs/heads/agent/work": second,
            })

            self._run(self._relocated(argv, bare), env)
            self.assertEqual(
                self._git(bare, env, "rev-parse", "refs/heads/agent/work")
                .stdout.strip(), second)
            self.assertEqual(
                self._git(bare, env, "symbolic-ref", "HEAD")
                .stdout.strip(), "refs/heads/main")

    def test_receive_pack_content_policy(self):
        _, argv = self._init()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = self._env(tmp)
            bare = tmp / "demo.git"
            work, seed = self._bootstrap(tmp, env, argv, bare)
            marker = "FAKE-SECRET-TEST-CONTENT-NOT-REAL"

            def reset():
                self._git(work, env, "checkout", "-B", "policy", seed)

            def denied():
                return self._push_denied(
                    work, env, "agent/policy")

            reset()
            (work / "credentials.txt").write_text(marker + "\n")
            self._git(work, env, "add", "credentials.txt")
            secret_blob = self._git(
                work, env, "rev-parse", ":credentials.txt").stdout.strip()
            self._git(work, env, "commit", "-m", "extra file")
            denied()

            reset()
            (work / "calculator.py").write_text(
                pre_receive.CALC_MINUS + "# " + marker + "\n")
            self._git(work, env, "commit", "-am", "credential comment")
            denied()

            reset()
            (work / "test_calculator.py").write_text("import unittest\n")
            self._git(work, env, "commit", "-am", "weaken tests")
            denied()

            reset()
            (work / "sub").mkdir()
            (work / "sub" / "extra.py").write_text("x = 1\n")
            os.symlink("calculator.py", work / "link.py")
            self._git(work, env, "add", "-A")
            self._git(work, env, "commit", "-m", "subdir and symlink")
            denied()

            reset()
            os.chmod(work / "calculator.py", 0o755)
            self._git(work, env, "add", "-A")
            self._git(work, env, "commit", "-m", "exec bit")
            denied()

            reset()
            self._git(work, env, "update-index", "--add", "--cacheinfo",
                      f"160000,{seed},submod")
            self._git(work, env, "commit", "-m", "gitlink")
            denied()

            reset()
            (work / "calculator.py").write_bytes(
                pre_receive.CALC_PLUS.replace("\n", "\r\n").encode())
            self._git(work, env, "commit", "-am", "crlf")
            denied()

            reset()
            (work / "calculator.py").write_bytes(
                pre_receive.CALC_PLUS.replace("\n    ", "\r    ").encode())
            self._git(work, env, "commit", "-am", "raw cr")
            denied()

            reset()
            (work / "credentials.txt").write_text(marker + "\n")
            self._git(work, env, "add", "credentials.txt")
            self._git(work, env, "commit", "-m", "plant")
            self._git(work, env, "rm", "credentials.txt")
            self._fix(work, env)
            tip = self._git(work, env, "rev-parse", "HEAD").stdout.strip()
            entries = self._git(work, env, "ls-tree", tip).stdout.splitlines()
            self.assertEqual(
                sorted(line.split("\t")[1] for line in entries),
                ["calculator.py", "test_calculator.py"])
            denied()

            reset()
            (work / "test_calculator.py").write_text("import unittest\n")
            self._git(work, env, "commit", "-am", "weaken")
            (work / "test_calculator.py").write_text(
                runtime_spec.SEED_FILES["test_calculator.py"])
            self._fix(work, env)
            tip = self._git(work, env, "rev-parse", "HEAD").stdout.strip()
            self.assertEqual(
                self._git(work, env, "rev-parse",
                          f"{tip}:test_calculator.py").stdout.strip(),
                self._git(work, env, "rev-parse",
                          f"{seed}:test_calculator.py").stdout.strip())
            denied()

            reset()
            test_oid = self._git(
                work, env, "rev-parse",
                f"{seed}:test_calculator.py").stdout.strip()
            calc_oid = self._git_in(
                work, env, pre_receive.CALC_PLUS, "hash-object", "-w",
                "--stdin").stdout.strip()
            hidden_blob = self._git_in(
                work, env, marker + "\n", "hash-object", "-w",
                "--stdin").stdout.strip()
            dup_tree = self._git_in(
                work, env,
                f"100644 blob {hidden_blob}\tcalculator.py\n"
                f"100644 blob {calc_oid}\tcalculator.py\n"
                f"100644 blob {test_oid}\ttest_calculator.py\n",
                "mktree").stdout.strip()
            tip = self._git(
                work, env, "commit-tree", dup_tree, "-p", seed,
                "-m", "duplicate entry").stdout.strip()
            denied_push = self._git(
                work, env, "push", "origin",
                f"{tip}:refs/heads/agent/dup", check=False)
            self.assertNotEqual(denied_push.returncode, 0)
            self.assertIn("pre-receive", denied_push.stderr)
            hidden = self._git(bare, env, "cat-file", "-e", hidden_blob,
                               check=False)
            self.assertNotEqual(hidden.returncode, 0)

            reset()
            self._git(work, env, "checkout", "--orphan", "orphan")
            self._git(work, env, "rm", "-rf", ".")
            for name, content in runtime_spec.SEED_FILES.items():
                (work / name).write_text(content)
            (work / "calculator.py").write_text(pre_receive.CALC_PLUS)
            self._git(work, env, "add", "-A")
            self._git(work, env, "commit", "-m", "orphan")
            denied()

            self._git(work, env, "checkout", "-B", "side", seed)
            (work / "credentials.txt").write_text(marker + "\n")
            self._git(work, env, "add", "credentials.txt")
            self._git(work, env, "commit", "-m", "plant")
            self._git(work, env, "checkout", "-B", "policy", seed)
            self._git(work, env, "merge", "-s", "ours", "--no-ff",
                      "--no-edit", "side")
            tip = self._git(work, env, "rev-parse", "HEAD").stdout.strip()
            raw = self._git(work, env, "cat-file", "-p", tip).stdout
            parents = [line for line in raw.partition("\n\n")[0].splitlines()
                       if line.startswith("parent ")]
            self.assertEqual(len(parents), 2)
            entries = self._git(work, env, "ls-tree", tip).stdout.splitlines()
            self.assertEqual(
                sorted(line.split("\t")[1] for line in entries),
                ["calculator.py", "test_calculator.py"])
            denied()

            remote_only = self._refs(bare, env)
            self.assertEqual(remote_only, {"refs/heads/main": seed})
            missing = self._git(bare, env, "cat-file", "-e", secret_blob,
                                check=False)
            self.assertNotEqual(missing.returncode, 0)

    def test_receive_pack_atomic_and_history_bound(self):
        _, argv = self._init()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = self._env(tmp)
            bare = tmp / "demo.git"
            work, seed = self._bootstrap(tmp, env, argv, bare)
            marker = "FAKE-SECRET-TEST-CONTENT-NOT-REAL"

            self._git(work, env, "checkout", "-B", "ok", seed)
            good = self._fix(work, env)
            self._git(work, env, "push", "origin",
                      f"{good}:refs/heads/agent/existing")
            self._git(work, env, "checkout", "-B", "bad", good)
            (work / "credentials.txt").write_text(marker + "\n")
            self._git(work, env, "add", "credentials.txt")
            self._git(work, env, "commit", "-m", "plant")
            bad = self._git(work, env, "rev-parse", "HEAD").stdout.strip()
            secret_blob = self._git(
                work, env, "rev-parse", ":credentials.txt").stdout.strip()
            denied = self._git(
                work, env, "push", "--atomic", "origin",
                f"{good}:refs/heads/agent/ok",
                f"{bad}:refs/heads/agent/existing",
                f"{bad}:refs/heads/agent/nope", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("pre-receive", denied.stderr)
            refs = self._refs(bare, env)
            self.assertEqual(refs["refs/heads/agent/existing"], good)
            self.assertNotIn("refs/heads/agent/ok", refs)
            self.assertNotIn("refs/heads/agent/nope", refs)
            leaked = self._git(bare, env, "cat-file", "-e", secret_blob,
                               check=False)
            self.assertNotEqual(leaked.returncode, 0)

            test_oid = self._git(
                work, env, "rev-parse",
                f"{seed}:test_calculator.py").stdout.strip()
            calc_oid = self._git_in(
                work, env, pre_receive.CALC_PLUS, "hash-object", "-w",
                "--stdin").stdout.strip()
            tree = self._git_in(
                work, env,
                f"100644 blob {calc_oid}\tcalculator.py\n"
                f"100644 blob {test_oid}\ttest_calculator.py\n",
                "mktree").stdout.strip()
            tips = []
            parent = seed
            for index in range(129):
                parent = self._git(
                    work, env, "commit-tree", tree, "-p", parent,
                    "-m", f"c{index}").stdout.strip()
                tips.append(parent)
            self._git(work, env, "push", "origin",
                      f"{tips[127]}:refs/heads/agent/many128")
            denied = self._git(
                work, env, "push", "origin",
                f"{tips[128]}:refs/heads/agent/many129", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("pre-receive", denied.stderr)
            refs = self._refs(bare, env)
            self.assertEqual(refs["refs/heads/agent/many128"], tips[127])
            self.assertNotIn("refs/heads/agent/many129", refs)

    def test_receive_pack_missing_seed(self):
        _, argv = self._init()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = self._env(tmp)
            bare = tmp / "demo.git"
            self._run(self._relocated(argv, bare), env)
            self._install_hook(bare)
            work = tmp / "work"
            self._git(tmp, env, "init", "--initial-branch=main", "work")
            for name, content in runtime_spec.SEED_FILES.items():
                (work / name).write_text(content)
            self._git(work, env, "add", "-A")
            self._git(work, env, "commit", "-m", "seed")
            denied = self._git(
                work, env, "push", str(bare),
                "HEAD:refs/heads/agent/x", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("pre-receive", denied.stderr)
            self.assertEqual(
                self._git(bare, env, "for-each-ref").stdout, "")


class PolicyConstants(unittest.TestCase):
    def test_seed_and_permitted_fix(self):
        self.assertEqual(
            pre_receive.CALC_MINUS,
            runtime_spec.SEED_FILES["calculator.py"])
        self.assertEqual(
            pre_receive.CALC_PLUS,
            "def add(left, right):\n    return left + right\n")
        self.assertNotEqual(pre_receive.CALC_MINUS, pre_receive.CALC_PLUS)
        self.assertEqual(
            set(pre_receive.SEED_FILES), set(runtime_spec.SEED_FILES))


class DefaultCommand(unittest.TestCase):
    EXPECTED_CMD = [
        "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config_fixture",
    ]

    def _cmd(self):
        found = [
            (index, value)
            for index, (keyword, value) in enumerate(_container_instructions())
            if keyword == "CMD"
        ]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_exec_form_argv(self):
        _, value = self._cmd()
        self.assertEqual(json.loads(value), self.EXPECTED_CMD)

    def test_after_init_with_nonroot_final_user(self):
        instructions = _container_instructions()
        cmd_index, _ = self._cmd()
        init_indexes = [
            index
            for index, (keyword, value) in enumerate(instructions)
            if keyword == "RUN"
            and shlex.split(value)[:2] == ["git", "init"]
        ]
        self.assertEqual(len(init_indexes), 1)
        self.assertLess(init_indexes[0], cmd_index)
        users = [
            value.strip()
            for keyword, value in instructions[:cmd_index]
            if keyword == "USER"
        ]
        self.assertTrue(users)
        self.assertEqual(users[-1], "1000:1000")
        for keyword, value in instructions[cmd_index + 1:]:
            if keyword == "USER":
                self.assertNotIn(
                    value.split(":", 1)[0].strip(), {"0", "root"})

    def test_config_copy_destination(self):
        _, value = self._cmd()
        argv = json.loads(value)
        config = argv[argv.index("-f") + 1]
        copies = [
            [arg for arg in shlex.split(v) if not arg.startswith("--")]
            for keyword, v in _container_instructions()
            if keyword == "COPY"
        ]
        matches = [copy for copy in copies if "sshd_config" in copy[:-1]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][-1], "/etc/ssh/sshd_config_fixture")
        self.assertEqual(matches[0][-1], config)

    def test_no_entrypoint(self):
        self.assertNotIn(
            "ENTRYPOINT",
            {keyword for keyword, _ in _container_instructions()})


if __name__ == "__main__":
    unittest.main()
