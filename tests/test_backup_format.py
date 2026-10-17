"""Pure USTAR format and manifest schema tests."""

import io
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

from local_agent import backup_format as fmt
from local_agent.runtime_record import RuntimeFault


def _mk_tar(path, entries, format=tarfile.USTAR_FORMAT):
    with tarfile.open(path, "w", format=format) as tf:
        for name, kind, payload in entries:
            ti = tarfile.TarInfo(name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "file":
                data = payload if isinstance(payload, bytes) \
                    else b"x" * payload
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload or "target"
                tf.addfile(ti)
            elif kind == "hardlink":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload or "target"
                tf.addfile(ti)
            elif kind == "fifo":
                ti.type = tarfile.FIFOTYPE
                tf.addfile(ti)
            else:
                raise AssertionError(kind)


def _good_manifest():
    return {
        "schema": fmt.BACKUP_SCHEMA,
        "created_utc": "2026-01-01T00:00:00Z",
        "profile_name": "cpu",
        "profile_sha256": "a" * 64,
        "artifacts_lock_sha256": "b" * 64,
        "seed_main": "c" * 40,
        "volumes": {
            r: {"member": f"{r}.tar", "sha256": "d" * 64, "bytes": 10}
            for r in fmt.DATA_ROLES
        },
    }


def _scan(path, members=20000, total=fmt.MAX_ROLE_TAR_BYTES):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return fmt.scan_ustar_fd(fd, members, total, "t")[0]
    finally:
        os.close(fd)


class Names(unittest.TestCase):
    def test_safe(self):
        for ok in ("a.py", "d/e/f.txt", ".hidden", "x_y-z",
                   "a b", "ünïcode.py"):
            self.assertEqual(fmt.safe_member_name(ok), ok)
        for bad in ("", "/abs", "a/../b", "..", "a//b", "a/./b",
                    "a\\b", "a\x01b", "a\nd", "a\td"):
            self.assertIsNone(fmt.safe_member_name(bad), bad)
        self.assertIsNone(fmt.safe_member_name(123))

    def test_ustar_encodable(self):
        self.assertTrue(fmt.ustar_encodable("a" * 100))
        self.assertFalse(fmt.ustar_encodable("a" * 101))
        self.assertTrue(fmt.ustar_encodable("p" * 154 + "/" + "n" * 100))
        self.assertFalse(fmt.ustar_encodable("p" * 156 + "/n"))
        self.assertFalse(fmt.ustar_encodable("p" * 155 + "/" + "n" * 100))
        self.assertFalse(fmt.ustar_encodable("a" * 256))
        self.assertFalse(fmt.ustar_encodable("x\ud800"))


class ManifestSchema(unittest.TestCase):
    def test_good(self):
        import json
        raw = fmt.parse_manifest_bytes(
            json.dumps(_good_manifest()).encode())
        self.assertEqual(raw["schema"], fmt.BACKUP_SCHEMA)

    def _reject(self, mutate):
        import json
        raw = _good_manifest()
        mutate(raw)
        with self.assertRaises(RuntimeFault):
            fmt.parse_manifest_bytes(json.dumps(raw).encode())

    def test_unknown_key(self):
        self._reject(lambda r: r.update(extra=1))

    def test_missing_key(self):
        self._reject(lambda r: r.pop("seed_main"))

    def test_bad_schema(self):
        self._reject(lambda r: r.update(schema="x@9"))

    def test_bad_created(self):
        self._reject(lambda r: r.update(created_utc="yesterday"))
        self._reject(lambda r: r.update(created_utc=123))

    def test_bad_profile(self):
        self._reject(lambda r: r.update(profile_name="Bad Name"))

    def test_bad_volumes(self):
        self._reject(
            lambda r: r["volumes"].update(
                extra={"member": "e.tar", "sha256": "d" * 64,
                       "bytes": 1}))
        self._reject(lambda r: r["volumes"].pop("repo"))
        self._reject(
            lambda r: r["volumes"]["workspace"].update(
                member="ws.tar"))
        self._reject(
            lambda r: r["volumes"]["repo"].update(host_path="/t"))
        self._reject(
            lambda r: r["volumes"]["repo"].update(bytes=True))
        self._reject(
            lambda r: r["volumes"]["repo"].update(bytes=-1))
        self._reject(
            lambda r: r["volumes"]["state"].update(sha256="xyz"))

    def test_bad_seed(self):
        self._reject(lambda r: r.update(seed_main="z" * 40))

    def test_duplicate_json_key(self):
        import json
        raw = json.dumps(_good_manifest()).replace(
            '"schema"', '"x": 1, "x": 2, "schema"', 1)
        with self.assertRaises(RuntimeFault):
            fmt.parse_manifest_bytes(raw.encode())


class UstarScan(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def test_good(self):
        p = self.root / "g.tar"
        _mk_tar(p, [("d", "dir", None), ("d/f.py", "file", b"data"),
                    ("top.sh", "file", b"x")])
        members = _scan(p)
        self.assertEqual(len(members), 3)
        info = fmt.validate_inner_inventory(members, "t")
        self.assertEqual(info["members"], 3)

    def test_pax_rejected(self):
        p = self.root / "p.tar"
        _mk_tar(p, [("a" * 120, "file", b"x")],
                format=tarfile.PAX_FORMAT)
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_gnu_longname_rejected(self):
        p = self.root / "gn.tar"
        _mk_tar(p, [("a" * 120, "file", b"x")],
                format=tarfile.GNU_FORMAT)
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_symlink_rejected(self):
        p = self.root / "s.tar"
        _mk_tar(p, [("a", "file", b"x"), ("l", "symlink", "a")])
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_hardlink_rejected(self):
        p = self.root / "h.tar"
        _mk_tar(p, [("a", "file", b"x"), ("l", "hardlink", "a")])
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_fifo_rejected(self):
        p = self.root / "f.tar"
        _mk_tar(p, [("pipe", "fifo", None)])
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_traversal_rejected(self):
        p = self.root / "t.tar"
        _mk_tar(p, [("a", "file", b"x")])
        raw = bytearray(p.read_bytes())
        raw[0:10] = b"../escape\0"
        cksum = sum(raw[:148]) + 8 * 32 + sum(raw[156:512])
        raw[148:156] = f"{cksum:06o}\0 ".encode()
        p.write_bytes(bytes(raw))
        members = _scan(p)
        with self.assertRaises(RuntimeFault):
            fmt.validate_inner_inventory(members, "t")

    def test_truncated_rejected(self):
        p = self.root / "tr.tar"
        _mk_tar(p, [("a", "file", b"x" * 5000)])
        data = p.read_bytes()[:600]
        p.write_bytes(data)
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_member_bound(self):
        p = self.root / "b.tar"
        _mk_tar(p, [("a", "file", b"x"), ("b", "file", b"x")])
        with self.assertRaises(RuntimeFault):
            _scan(p, members=1)

    def test_dir_payload_rejected(self):
        p = self.root / "dp.tar"
        _mk_tar(p, [("d", "dir", None)])
        raw = bytearray(p.read_bytes())
        raw[124:136] = f"{10:011o} ".encode()
        cksum = sum(raw[:148]) + 8 * 32 + sum(raw[156:512])
        raw[148:156] = f"{cksum:06o}\0 ".encode()
        p.write_bytes(bytes(raw))
        with self.assertRaises(RuntimeFault):
            _scan(p)

    def test_duplicate_inventory(self):
        p = self.root / "d.tar"
        _mk_tar(p, [("a", "file", b"x"), ("a", "file", b"y")])
        members = _scan(p)
        with self.assertRaises(RuntimeFault):
            fmt.validate_inner_inventory(members, "t")

    def test_space_and_unicode_names_ok(self):
        p = self.root / "u.tar"
        _mk_tar(p, [("a b.txt", "file", b"x"),
                    ("ünïcode.py", "file", b"y")])
        members = _scan(p)
        info = fmt.validate_inner_inventory(members, "t")
        self.assertEqual(info["members"], 2)

    def test_file_size_bound(self):
        p = self.root / "big.tar"
        _mk_tar(p, [("a", "file", fmt.MAX_FILE_BYTES + 1)])
        members = _scan(p)
        with self.assertRaises(RuntimeFault):
            fmt.validate_inner_inventory(members, "t")

    def test_file_parent_collision_file_first(self):
        p = self.root / "pc1.tar"
        _mk_tar(p, [("a", "file", b"x"), ("a/b", "file", b"y")])
        members = _scan(p)
        with self.assertRaises(RuntimeFault):
            fmt.validate_inner_inventory(members, "t")

    def test_file_parent_collision_child_first(self):
        p = self.root / "pc2.tar"
        _mk_tar(p, [("a/b", "file", b"x"), ("a", "file", b"y")])
        members = _scan(p)
        with self.assertRaises(RuntimeFault):
            fmt.validate_inner_inventory(members, "t")

    def test_file_dir_collision(self):
        p = self.root / "dc.tar"
        _mk_tar(p, [("d", "dir", None), ("d", "file", b"x")])
        members = _scan(p)
        with self.assertRaises(RuntimeFault):
            fmt.validate_inner_inventory(members, "t")

    def test_junk_after_far_padding(self):
        p = self.root / "j.tar"
        _mk_tar(p, [("a", "file", b"x")])
        data = p.read_bytes() + b"\0" * (1 << 20) + b"JUNK"
        p.write_bytes(data)
        with self.assertRaises(RuntimeFault):
            _scan(p, total=fmt.MAX_OUTER_BYTES)

    def test_zero_padding_over_bound(self):
        p = self.root / "z.tar"
        _mk_tar(p, [("a", "file", b"x")])
        data = p.read_bytes() + b"\0" * (fmt.MAX_OUTER_BYTES + 1)
        with open(p, "wb") as fh:
            fh.write(data[:fmt.MAX_ROLE_TAR_BYTES + 4096])
        with self.assertRaises(RuntimeFault):
            _scan(p, total=fmt.MAX_ROLE_TAR_BYTES)


class OpenArchive(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def _file(self, name, mode=0o600):
        p = self.root / name
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT, mode)
        os.write(fd, b"x")
        os.close(fd)
        return p

    def test_good(self):
        fd = fmt.open_archive(self._file("a.tar"))
        self.assertGreater(fd, 0)
        os.close(fd)

    def test_mode_644_rejected(self):
        with self.assertRaises(RuntimeFault):
            fmt.open_archive(self._file("b.tar", 0o644))

    def test_symlink_rejected(self):
        p = self._file("real.tar")
        link = self.root / "link.tar"
        os.symlink(p.name, link)
        with self.assertRaises(OSError):
            fmt.open_archive(link)

    def test_hardlink_rejected(self):
        p = self._file("orig.tar")
        os.link(p, self.root / "hard.tar")
        with self.assertRaises(RuntimeFault):
            fmt.open_archive(self.root / "hard.tar")

    def test_fifo_rejected_no_hang(self):
        fifo = self.root / "f.tar"
        os.mkfifo(fifo)
        with self.assertRaises(RuntimeFault):
            fmt.open_archive(fifo)

    def test_fd_pins_inode_after_replace(self):
        p = self._file("r.tar")
        fd = fmt.open_archive(p)
        tmp = self._file("tmp.tar")
        tmp.write_bytes(b"REPLACED-CONTENT-LONGER")
        os.replace(tmp, p)
        got = os.pread(fd, 1, 0)
        os.close(fd)
        self.assertEqual(got, b"x")


class DirectoryParents(unittest.TestCase):
    def test_regular_parent_of_directory_refused_in_both_orders(self):
        entries = [
            {"name": "a", "type": "reg", "size": 1},
            {"name": "a/b", "type": "dir", "size": 0},
        ]
        for members in (entries, list(reversed(entries))):
            with self.assertRaises(RuntimeFault):
                fmt.validate_inner_inventory(members, "directory collision")


if __name__ == "__main__":
    unittest.main()
