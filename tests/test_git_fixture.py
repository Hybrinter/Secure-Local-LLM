"""Unit tests for the restricted git SSH fixture scripts."""

import importlib.util
import io
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class PreReceive(unittest.TestCase):
    def _git_ok(self, *args):
        class R:
            returncode = 0
            stdout = "commit\n"
            stderr = ""
        if args[0] == "merge-base":
            R.returncode = 0
        return R()

    def _run(self, data, git=None):
        hook = mock.Mock(side_effect=git or self._git_ok)
        with mock.patch.object(pre_receive, "_git", hook), \
                mock.patch.object(pre_receive.sys, "stdin", _Stdin(data)):
            try:
                pre_receive.main()
            except SystemExit as exc:
                return exc.code, hook
        return 0, hook

    def test_new_branch_ok(self):
        code, _ = self._run(f"{ZERO} {A} refs/heads/agent/work\n".encode())
        self.assertEqual(code, 0)

    def test_ff_ok(self):
        def git(*args):
            class R:
                returncode = 0
                stdout = "commit\n"
                stderr = ""
            return R()
        code, hook = self._run(f"{A} {B} refs/heads/agent/x\n".encode(), git)
        self.assertEqual(code, 0)
        self.assertIn(("merge-base", "--is-ancestor", A, B),
                      [c.args for c in hook.call_args_list])

    def test_non_ff_rejected(self):
        def git(*args):
            class R:
                returncode = 0
                stdout = "commit\n"
                stderr = ""
            if args[0] == "merge-base":
                R.returncode = 1
            return R()
        code, _ = self._run(f"{A} {B} refs/heads/agent/x\n".encode(), git)
        self.assertEqual(code, 1)

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
        data = (
            f"{ZERO} {A} refs/heads/agent/a\n"
            f"{ZERO} {B} refs/heads/agent/b\n"
        ).encode()
        code, _ = self._run(data)
        self.assertEqual(code, 0)

    def test_all_validated_before_success(self):
        data = (
            f"{ZERO} {A} refs/heads/agent/a\n"
            f"{ZERO} {B} refs/heads/main\n"
        ).encode()
        code, _ = self._run(data)
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
            run.return_value = mock.Mock(returncode=0, stdout="commit\n", stderr="")
            pre_receive.main()
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

    def _instructions(self):
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

    def _init(self):
        found = [
            (index, shlex.split(value))
            for index, (keyword, value) in enumerate(self._instructions())
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

    def _run(self, argv, env, check=True):
        result = subprocess.run(
            argv, env=env, capture_output=True, text=True, timeout=self.TIMEOUT
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _git(self, cwd, env, *args, check=True):
        return self._run(["git", "-C", str(cwd), *args], env, check=check)

    def _relocated(self, argv, dest):
        return [str(dest) if arg == serve_git.REPO else arg for arg in argv]

    def test_init_instruction(self):
        instructions = self._instructions()
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

    def test_local_receive_pack(self):
        _, argv = self._init()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = self._env(tmp)
            bare = tmp / "demo.git"
            self._run(self._relocated(argv, bare), env)
            hooks = bare / "hooks"
            hooks.mkdir(exist_ok=True)
            hook = hooks / "pre-receive"
            shutil.copyfile(FIXTURE / "pre_receive.py", hook)
            os.chmod(hook, 0o755)

            work = tmp / "work"
            clone = self._run(["git", "clone", str(bare), str(work)], env)
            self.assertIn("empty repository", clone.stderr)
            self._git(work, env, "fetch", "origin")

            (work / "data.txt").write_text("one\n")
            self._git(work, env, "add", "data.txt")
            self._git(work, env, "commit", "-m", "one")
            self._git(work, env, "push", "origin",
                      "HEAD:refs/heads/agent/work")
            (work / "data.txt").write_text("two\n")
            self._git(work, env, "commit", "-am", "two")
            second = self._git(work, env, "rev-parse",
                               "HEAD").stdout.strip()
            self._git(work, env, "push", "origin",
                      "HEAD:refs/heads/agent/work")

            for refspec in ("HEAD:refs/heads/main", "HEAD:refs/tags/v1",
                            ":refs/heads/agent/work"):
                denied = self._git(work, env, "push", "origin", refspec,
                                   check=False)
                self.assertNotEqual(denied.returncode, 0, refspec)
                self.assertIn("pre-receive", denied.stderr)

            self._git(work, env, "reset", "--hard", "HEAD~1")
            (work / "data.txt").write_text("three\n")
            self._git(work, env, "commit", "-am", "three")
            denied = self._git(work, env, "push", "--force", "origin",
                               "HEAD:refs/heads/agent/work", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("non-fast-forward", denied.stderr)

            refs = {
                line.split()[2]: line.split()[0]
                for line in self._git(bare, env, "for-each-ref")
                .stdout.splitlines()
            }
            self.assertEqual(refs, {"refs/heads/agent/work": second})

            self._run(self._relocated(argv, bare), env)
            self.assertEqual(
                self._git(bare, env, "rev-parse", "refs/heads/agent/work")
                .stdout.strip(), second)
            self.assertEqual(
                self._git(bare, env, "symbolic-ref", "HEAD")
                .stdout.strip(), "refs/heads/main")


if __name__ == "__main__":
    unittest.main()
