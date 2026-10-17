import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import netns_helper


class HelperParsing(unittest.TestCase):
    def _fail_code(self, raw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                netns_helper._parse_request(raw)
        self.assertFalse(json.loads(buf.getvalue())["ok"])

    def test_request_validation(self):
        good = {"op": "read", "pid": 1, "expect_user": "user:[1]",
                "expect_net": "net:[2]"}
        self.assertEqual(netns_helper._parse_request(json.dumps(good)),
                         good)
        for bad in (
            "{}", "[1]", "not json",
            json.dumps({**good, "op": "exec"}),
            json.dumps({**good, "pid": True}),
            json.dumps({**good, "pid": "x"}),
            json.dumps({**good, "pid": 0}),
            json.dumps({**good, "pid": -3}),
            json.dumps({**good, "extra": 1}),
            json.dumps({**good, "op": "apply"}),
            json.dumps({**good, "op": "apply", "policy": "x", "extra": 1}),
            json.dumps({**good, "op": "apply", "policy": 5}),
            json.dumps({**good, "op": "apply",
                        "policy": "x" * (netns_helper.MAX_POLICY_BYTES + 1)}),
        ):
            self._fail_code(bad)

    def test_expect_inode_validation(self):
        self.assertEqual(
            netns_helper._expect_inode("user:[123]", "user"), 123)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                netns_helper._expect_inode("net:[1]", "user")
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                netns_helper._expect_inode(5, "user")

    def test_ns_fd_mismatch_and_owner(self):
        own = os.readlink("/proc/self/ns/user")
        inode = netns_helper._expect_inode(own, "user")
        fd = netns_helper._open_ns(os.getpid(), "user", inode)
        os.close(fd)
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                netns_helper._open_ns(os.getpid(), "user", inode + 1)
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit):
                netns_helper._open_ns(os.getpid(), "net", inode)
        nfd = netns_helper._open_ns(
            os.getpid(), "net",
            int(os.readlink("/proc/self/ns/net").split("[")[1].rstrip("]")))
        try:
            netns_helper._check_net_owner(nfd, inode)
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    netns_helper._check_net_owner(nfd, inode + 1)
        finally:
            os.close(nfd)


class NftArgv(unittest.TestCase):
    def setUp(self):
        self.user_fd = os.open("/proc/self/ns/user",
                               os.O_RDONLY | os.O_CLOEXEC)
        self.net_fd = os.open("/proc/self/ns/net",
                              os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.user_fd)
        self.addCleanup(os.close, self.net_fd)

    @staticmethod
    def _identity(dev, ino):
        return os.stat_result((0o40755, ino, dev, 1, 0, 0, 0, 0, 0, 0))

    def _fake_identity(self, fd_stat, self_stat):
        real_fstat = os.fstat
        real_stat = os.stat

        def fake_fstat(fd):
            if fd == self.user_fd:
                return fd_stat
            return real_fstat(fd)

        def fake_stat(path):
            if path == "/proc/self/ns/user":
                return self_stat
            return real_stat(path)

        stack = ExitStack()
        stack.enter_context(
            mock.patch.object(netns_helper.os, "fstat", fake_fstat))
        stack.enter_context(
            mock.patch.object(netns_helper.os, "stat", fake_stat))
        return stack

    def _assert_call(self, call, argv, text):
        self.assertEqual(call.args[0], argv)
        self.assertEqual(call.kwargs, {
            "input": text,
            "capture_output": True,
            "text": True,
            "timeout": netns_helper.NFT_TIMEOUT_SECONDS,
            "pass_fds": (self.user_fd, self.net_fd),
            "env": netns_helper._CLEAN_ENV,
        })

    def test_same_userns_omits_user(self):
        done = subprocess.CompletedProcess([], 0, "ruleset", "")
        with mock.patch.object(netns_helper.subprocess, "run",
                               return_value=done) as run:
            self.assertIs(netns_helper._nft(self.user_fd, self.net_fd,
                                            ["-f", "-"], "policy text"),
                          done)
            self.assertIs(netns_helper._nft(self.user_fd, self.net_fd,
                                            ["-j", "list", "ruleset"], ""),
                          done)
        self.assertEqual(run.call_count, 2)
        base = ["nsenter", f"--net=/proc/self/fd/{self.net_fd}",
                "--setuid", "0", "--setgid", "0", "nft"]
        self._assert_call(run.call_args_list[0],
                          base + ["-f", "-"], "policy text")
        self._assert_call(run.call_args_list[1],
                          base + ["-j", "list", "ruleset"], "")

    def test_different_userns_keeps_user(self):
        for fd_stat, self_stat in (
            (self._identity(1, 100), self._identity(1, 200)),
            (self._identity(1, 100), self._identity(2, 100)),
        ):
            for argv_tail, text in (
                (["-f", "-"], "policy text"),
                (["-j", "list", "ruleset"], ""),
            ):
                with self.subTest(target=(fd_stat.st_dev, fd_stat.st_ino),
                                  current=(self_stat.st_dev,
                                           self_stat.st_ino),
                                  argv=argv_tail):
                    done = subprocess.CompletedProcess([], 0, "", "")
                    with self._fake_identity(fd_stat, self_stat), \
                            mock.patch.object(netns_helper.subprocess, "run",
                                              return_value=done) as run:
                        netns_helper._nft(self.user_fd, self.net_fd,
                                          argv_tail, text)
                    run.assert_called_once()
                    self._assert_call(run.call_args_list[0], [
                        "nsenter",
                        f"--user=/proc/self/fd/{self.user_fd}",
                        f"--net=/proc/self/fd/{self.net_fd}",
                        "--setuid", "0", "--setgid", "0",
                        "nft", *argv_tail,
                    ], text)

    def test_identity_inspection_failure(self):
        for attr in ("fstat", "stat"):
            with self.subTest(attr=attr):
                with mock.patch.object(netns_helper.os, attr,
                                       side_effect=OSError(2, "boom")), \
                        mock.patch.object(netns_helper.subprocess,
                                          "run") as run:
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        with self.assertRaises(SystemExit):
                            netns_helper._nft(self.user_fd, self.net_fd,
                                              ["-j", "list", "ruleset"], "")
                run.assert_not_called()
                out = json.loads(buf.getvalue())
                self.assertFalse(out["ok"])
                self.assertIn("boom", out["error"])

    def test_nft_failures_are_structured(self):
        for exc in (subprocess.TimeoutExpired("nsenter", 30),
                    OSError(2, "no nsenter")):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch.object(netns_helper.subprocess, "run",
                                       side_effect=exc):
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        with self.assertRaises(SystemExit):
                            netns_helper._nft(self.user_fd, self.net_fd,
                                              ["-j", "list", "ruleset"], "")
                self.assertFalse(json.loads(buf.getvalue())["ok"])


class MainFlow(unittest.TestCase):
    def _request(self, op, **extra):
        return {"op": op, "pid": os.getpid(),
                "expect_user": "user:[1]", "expect_net": "net:[2]",
                **extra}

    @staticmethod
    def _close_quietly(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def _assert_closed(self, fd):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def _run_main(self, request, nft):
        user_fd = os.open("/dev/null", os.O_RDONLY)
        net_fd = os.open("/dev/null", os.O_RDONLY)
        self.addCleanup(self._close_quietly, user_fd)
        self.addCleanup(self._close_quietly, net_fd)

        def fake_open_ns(pid, kind, inode):
            return {"user": user_fd, "net": net_fd}[kind]

        stdin = mock.Mock()
        stdin.buffer.read.return_value = json.dumps(request).encode()
        buf = io.StringIO()
        with mock.patch.object(netns_helper.sys, "stdin", stdin), \
                mock.patch.object(netns_helper, "_open_ns", fake_open_ns), \
                mock.patch.object(netns_helper, "_check_net_owner"), \
                mock.patch.object(netns_helper, "_nft", nft), \
                redirect_stdout(buf):
            netns_helper.main()
        return buf, user_fd, net_fd

    def _recording_nft(self, calls):
        def fake_nft(user_fd, net_fd, args, text):
            calls.append((list(args), text))
            return subprocess.CompletedProcess([], 0, "ruleset\n", "")
        return fake_nft

    def test_main_read(self):
        calls = []
        buf, user_fd, net_fd = self._run_main(
            self._request("read"), self._recording_nft(calls))
        out = json.loads(buf.getvalue())
        self.assertTrue(out["ok"])
        self.assertEqual(out["ruleset"], "ruleset\n")
        self.assertEqual(calls, [(["-j", "list", "ruleset"], "")])
        self._assert_closed(user_fd)
        self._assert_closed(net_fd)

    def test_main_apply(self):
        calls = []
        buf, user_fd, net_fd = self._run_main(
            self._request("apply", policy="table inet t {}\n"),
            self._recording_nft(calls))
        out = json.loads(buf.getvalue())
        self.assertTrue(out["ok"])
        self.assertEqual(out["ruleset"], "ruleset\n")
        self.assertEqual(calls, [
            (["-f", "-"], "table inet t {}\n"),
            (["-j", "list", "ruleset"], ""),
        ])
        self._assert_closed(user_fd)
        self._assert_closed(net_fd)

    def test_main_rejection_never_invokes_nft(self):
        for reject_at in ("open_net", "check_owner"):
            with self.subTest(reject_at=reject_at):
                user_fd = os.open("/dev/null", os.O_RDONLY)
                net_fd = os.open("/dev/null", os.O_RDONLY)
                self.addCleanup(self._close_quietly, user_fd)
                self.addCleanup(self._close_quietly, net_fd)

                def fake_open_ns(pid, kind, inode):
                    if kind == "net" and reject_at == "open_net":
                        raise SystemExit(0)
                    return {"user": user_fd, "net": net_fd}[kind]

                owner = mock.Mock()
                if reject_at == "check_owner":
                    owner.side_effect = SystemExit(0)
                stdin = mock.Mock()
                stdin.buffer.read.return_value = json.dumps(
                    self._request("read")).encode()
                with mock.patch.object(netns_helper.sys, "stdin", stdin), \
                        mock.patch.object(netns_helper, "_open_ns",
                                          fake_open_ns), \
                        mock.patch.object(netns_helper, "_check_net_owner",
                                          owner), \
                        mock.patch.object(netns_helper, "_nft") as nft, \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        netns_helper.main()
                nft.assert_not_called()
                self._assert_closed(user_fd)
                if reject_at == "check_owner":
                    self._assert_closed(net_fd)
                else:
                    os.fstat(net_fd)


if __name__ == "__main__":
    unittest.main()
