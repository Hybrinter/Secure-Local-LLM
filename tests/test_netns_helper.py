import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
