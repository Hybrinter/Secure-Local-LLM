"""Bounded helper process I/O tests (plain argv, no podman)."""

import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from local_agent import backup_format as fmt
from local_agent import backup_helper as helper
from local_agent.runtime_record import RuntimeFault


class RunHelper(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        os.chmod(self.root, 0o700)
        self.out = self.root / "out.bin"
        self.err = self.root / "err.log"

    def test_success_streams_to_0600_files(self):
        argv = ["python3", "-c",
                "import sys;sys.stdout.buffer.write(b'x'*100);"
                "sys.stderr.write('note')"]
        helper.run_helper(argv, self.out, self.err, 1000)
        self.assertEqual(self.out.read_bytes(), b"x" * 100)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.err.stat().st_mode), 0o600)
        self.assertIn(b"note", self.err.read_bytes())

    def test_output_cap_removes_partials(self):
        argv = ["python3", "-c",
                "import sys;sys.stdout.buffer.write(b'x'*100)"]
        with self.assertRaises(RuntimeFault):
            helper.run_helper(argv, self.out, self.err, 10)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.err.exists())

    def test_rc_failure_removes_partials(self):
        argv = ["python3", "-c",
                "import sys;sys.stderr.write('boom');sys.exit(3)"]
        with self.assertRaises(RuntimeFault) as ctx:
            helper.run_helper(argv, self.out, self.err, 1000)
        self.assertIn("boom", str(ctx.exception))
        self.assertFalse(self.out.exists())

    def test_oversized_stderr_bounded(self):
        argv = ["python3", "-c",
                "import sys;sys.stderr.buffer.write(b'e'*"
                + str(helper.MAX_LOG_BYTES + 4096) + ")"]
        helper.run_helper(argv, self.out, self.err, 1000)
        self.assertLessEqual(
            self.err.stat().st_size, helper.MAX_LOG_BYTES)

    def test_existing_output_refused(self):
        self.out.write_bytes(b"old")
        argv = ["python3", "-c", "print(1)"]
        with self.assertRaises(OSError):
            helper.run_helper(argv, self.out, self.err, 1000)
        self.assertEqual(self.out.read_bytes(), b"old")

    def test_existing_err_preserved(self):
        self.err.write_bytes(b"FOREIGN")
        argv = ["python3", "-c", "print(1)"]
        with self.assertRaises(OSError):
            helper.run_helper(argv, self.out, self.err, 1000)
        self.assertEqual(self.err.read_bytes(), b"FOREIGN")
        self.assertFalse(self.out.exists())

    def test_silent_child_times_out(self):
        argv = ["python3", "-c", "import time;time.sleep(0.6)"]
        with self.assertRaises(RuntimeFault) as ctx:
            helper.run_helper(argv, self.out, self.err, 1000, timeout=0.15)
        self.assertIn("timed out", str(ctx.exception))
        self.assertFalse(self.out.exists())
        self.assertFalse(self.err.exists())

    def test_slow_stream_times_out(self):
        argv = ["python3", "-c",
                "import sys,time\n"
                "for i in range(10):\n"
                " sys.stdout.write('x'*10);sys.stdout.flush();"
                "time.sleep(0.15)"]
        with self.assertRaises(RuntimeFault) as ctx:
            helper.run_helper(argv, self.out, self.err, 1000, timeout=0.3)
        self.assertIn("timed out", str(ctx.exception))
        self.assertFalse(self.out.exists())

    def test_spawn_failure_removes_out_only(self):
        argv = ["./definitely-not-a-real-binary-xyz123"]
        with self.assertRaises(RuntimeFault):
            helper.run_helper(argv, self.out, self.err, 1000)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.err.exists())

    def test_helper_argv_shape(self):
        argv = helper.helper_argv(
            "sha256:" + "1" * 64, "vol", "ro", helper.EXPORT_PY)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--read-only", argv)
        i = argv.index("-v")
        self.assertEqual(argv[i + 1], "vol:/data:ro")
        self.assertNotIn("--privileged", argv)
        self.assertIn("-I", argv)

    def test_import_argv_member(self):
        argv = helper.helper_argv(
            "img", "vol", "rw", helper.IMPORT_PY,
            extra_args=("d" * 64, "repo.tar"),
            extra_vol="/stg:/archive:ro")
        self.assertIn("/stg:/archive:ro", argv)
        self.assertIn("vol:/data:rw", argv)


class ExportTree(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        os.chmod(self.root, 0o700)
        self.n = 0

    def _export_src(self, tree):
        src = helper.EXPORT_PY
        needle = 'ROOT = "/data"'
        self.assertEqual(src.count(needle), 1)
        src = src.replace(needle, f"ROOT = {str(tree)!r}")
        needle = "fst.st_uid != 1000"
        self.assertEqual(src.count(needle), 1)
        return src.replace(needle, "fst.st_uid != os.geteuid()")

    def _export(self, tree):
        self.n += 1
        out = self.root / f"out{self.n}.tar"
        err = self.root / f"err{self.n}.log"
        argv = ["python3", "-I", "-B", "-c", self._export_src(tree)]
        helper.run_helper(argv, out, err, 1 << 20, timeout=30)
        return out

    def _scan_out(self, out):
        fd = os.open(str(out), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return fmt.scan_ustar_fd(fd, 20000, 1 << 30, "t")[0]
        finally:
            os.close(fd)

    def _mk_tree(self, name, entries):
        tree = self.root / name
        tree.mkdir()
        for rel, kind, payload in entries:
            p = tree / rel
            if kind == "dir":
                p.mkdir(parents=True, exist_ok=True)
            elif kind == "file":
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(payload)
            elif kind == "symlink":
                p.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(payload, p)
            elif kind == "hardlink":
                p.parent.mkdir(parents=True, exist_ok=True)
                os.link(tree / payload, p)
            else:
                raise AssertionError(kind)
        return tree

    def _check_members(self, out, names, payloads):
        members = self._scan_out(out)
        self.assertEqual([m["name"] for m in members], names)
        info = fmt.validate_inner_inventory(members, "t")
        self.assertEqual(info["members"], len(names))
        with tarfile.open(out) as tf:
            self.assertEqual(
                tf.getnames(), [n.rstrip("/") for n in names])
            for name, want in payloads.items():
                self.assertEqual(tf.extractfile(name).read(), want)

    def test_long_boundary_names(self):
        names = ["d" * 155 + "/", "d" * 155 + "/" + "f" * 100]
        tree = self._mk_tree("t1", [
            ("d" * 155, "dir", None),
            ("d" * 155 + "/" + "f" * 100, "file", b"D"),
        ])
        self._check_members(
            self._export(tree), names, {names[1]: b"D"})

    def test_earlier_split_tree(self):
        names = [
            "a" * 100 + "/",
            "a" * 100 + "/" + "b" * 55 + "/",
            "a" * 100 + "/" + "b" * 55 + "/x",
        ]
        tree = self._mk_tree("t2", [
            ("a" * 100, "dir", None),
            ("a" * 100 + "/" + "b" * 55, "dir", None),
            ("a" * 100 + "/" + "b" * 55 + "/x", "file", b"X"),
        ])
        self._check_members(
            self._export(tree), names, {names[2]: b"X"})

    def test_utf8_names(self):
        names = [
            "ünïcode.py",
            "ü" * 77 + "/",
            "ü" * 77 + "/" + "n" * 100,
        ]
        tree = self._mk_tree("t3", [
            ("ünïcode.py", "file", b"U"),
            ("ü" * 77, "dir", None),
            ("ü" * 77 + "/" + "n" * 100, "file", b"N"),
        ])
        self._check_members(
            self._export(tree), names,
            {names[0]: b"U", names[2]: b"N"})

    def test_unencodable_bare_refused(self):
        tree = self._mk_tree("t4", [("f" * 101, "file", b"x")])
        with self.assertRaises(RuntimeFault) as ctx:
            self._export(tree)
        self.assertIn("USTAR limit", str(ctx.exception))

    def test_over_limit_nested_refused(self):
        tree = self._mk_tree("t5", [
            ("d" * 120, "dir", None),
            ("d" * 120 + "/" + "n" * 140, "file", b"x"),
        ])
        with self.assertRaises(RuntimeFault) as ctx:
            self._export(tree)
        self.assertIn("USTAR limit", str(ctx.exception))

    def test_unsafe_and_link_members_refused(self):
        cases = [
            ([("a\\b", "file", b"x")], "unsafe name"),
            ([("real", "file", b"x"), ("ln", "symlink", "real")],
             "symlink refused"),
            ([("orig", "file", b"x"), ("dup", "hardlink", "orig")],
             "hardlink refused"),
        ]
        for i, (entries, want) in enumerate(cases):
            with self.subTest(i=i):
                tree = self._mk_tree(f"bad{i}", entries)
                with self.assertRaises(RuntimeFault) as ctx:
                    self._export(tree)
                self.assertIn(want, str(ctx.exception))


class HelperSources(unittest.TestCase):
    def test_export_ustar_and_fd_verify(self):
        src = helper.EXPORT_PY
        self.assertIn("USTAR_FORMAT", src)
        self.assertIn("O_NOFOLLOW", src)
        self.assertIn("O_NONBLOCK", src)
        self.assertIn("st_nlink != 1", src)
        self.assertIn("fstat", src)

    def test_import_dirfd_no_follow(self):
        src = helper.IMPORT_PY
        self.assertIn("dir_fd", src)
        self.assertIn("O_NOFOLLOW", src)
        self.assertIn("O_EXCL", src)
        self.assertIn("duplicate member", src)


if __name__ == "__main__":
    unittest.main()
