import copy
import io
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import artifacts

REPO = Path(__file__).resolve().parents[1]
LOCK = REPO / ".devin" / "artifacts.lock.json"


def lock_dict():
    return {
        "schema": artifacts.LOCK_SCHEMA,
        "platform": artifacts.LOCK_PLATFORM,
        "base_image": "docker.io/library/debian@sha256:" + "a" * 64,
        "artifacts": {
            "opencode": {
                "version": "2.0.26",
                "url": "https://registry.npmjs.org/x.tgz",
                "hash": {"algorithm": "sha512", "hex": "b" * 128},
                "max_bytes": 1024,
                "format": "binary-tar",
                "member": "package/bin/opencode",
                "max_unpacked_bytes": 4096,
            },
            "model": {
                "version": "v1",
                "url": "https://example.com/m.gguf",
                "hash": {"algorithm": "sha256", "hex": "c" * 64},
                "max_bytes": 1024,
                "format": "file",
            },
            "inference_source": {
                "version": "v1",
                "url": "https://example.com/src.tgz",
                "hash": {"algorithm": "sha256", "hex": "d" * 64},
                "max_bytes": 1024,
                "format": "source-tar",
                "root": "proj-abc",
                "max_unpacked_bytes": 4096,
            },
        },
    }


class LockSchema(unittest.TestCase):
    def test_repo_lock_loads(self):
        lock, fp = artifacts.load_lock(LOCK)
        self.assertEqual(lock["schema"], "secure-local-llm/artifacts@1")
        self.assertEqual(set(lock["artifacts"]), set(artifacts.ARTIFACT_NAMES))
        self.assertTrue(lock["base_image"].startswith("docker.io/library/debian@sha256:"))
        self.assertEqual(len(fp["sha256"]), 64)

    def test_strict_rejections(self):
        cases = [
            lambda l: l.update(schema="other@9"),
            lambda l: l.update(platform="linux/arm64"),
            lambda l: l.update(base_image="debian:latest"),
            lambda l: l.update(base_image="docker.io/library/debian@sha256:" + "g" * 64),
            lambda l: l["artifacts"].update(extra={}),
            lambda l: l["artifacts"].pop("model"),
            lambda l: l["artifacts"].__setitem__("model", "not-a-dict"),
            lambda l: l["artifacts"].__setitem__("model", []),
            lambda l: l["artifacts"]["model"].update(format="binary-tar",
                                                     member="package/bin/opencode",
                                                     max_unpacked_bytes=8),
            lambda l: l["artifacts"]["opencode"].update(format="file"),
            lambda l: l["artifacts"]["inference_source"].update(format="file"),
            lambda l: l["artifacts"]["model"].update(url="http://insecure/x"),
            lambda l: l["artifacts"]["model"].update(url="https://u:p@h/x"),
            lambda l: l["artifacts"]["model"].update(url="https://h:443/x"),
            lambda l: l["artifacts"]["model"].update(url="https://h:bad/x"),
            lambda l: l["artifacts"]["model"].update(url="https://h/x\ty"),
            lambda l: l["artifacts"]["model"].update(url="https://h/x\x00y"),
            lambda l: l["artifacts"]["model"]["hash"].update(algorithm="md5"),
            lambda l: l["artifacts"]["model"]["hash"].update(hex="z" * 64),
            lambda l: l["artifacts"]["model"]["hash"].update(hex="c" * 63),
            lambda l: l["artifacts"]["model"].update(max_bytes=0),
            lambda l: l["artifacts"]["model"].update(max_bytes=True),
            lambda l: l["artifacts"]["model"].update(max_bytes=(3 << 30) + 1),
            lambda l: l["artifacts"]["model"].update(extra_key=1),
            lambda l: l["artifacts"]["model"].update(member="x"),
            lambda l: l["artifacts"]["opencode"].update(member="package/evil"),
            lambda l: l["artifacts"]["inference_source"].update(root="../up"),
            lambda l: l["artifacts"]["inference_source"].update(root="a/b"),
            lambda l: l["artifacts"]["inference_source"].update(root=""),
            lambda l: l["artifacts"]["inference_source"].update(root="a\tb"),
            lambda l: l["artifacts"]["inference_source"].pop("max_unpacked_bytes"),
        ]
        for i, mutate in enumerate(cases):
            raw = lock_dict()
            mutate(raw)
            with self.assertRaises(artifacts.ArtifactError, msg=f"case {i}"):
                artifacts.parse_lock(raw)


def make_tar(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, kind, data in members:
            if kind == "dir":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind == "file":
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "symlink":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = data.decode() if isinstance(data, bytes) else data
                tf.addfile(ti)
            elif kind == "hardlink":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.LNKTYPE
                ti.linkname = data
                tf.addfile(ti)
            elif kind == "fifo":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.FIFOTYPE
                tf.addfile(ti)


class Extract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.tar = self.dir / "a.tgz"
        self.out = self.dir / "out"
        self.out.mkdir(mode=0o700)
        self.spec = lock_dict()["artifacts"]

    def tearDown(self):
        self.tmp.cleanup()

    def extract(self, fmt):
        spec = {
            "binary-tar": self.spec["opencode"],
            "source-tar": self.spec["inference_source"],
        }[fmt]
        return artifacts.extract_tar(self.tar, self.out, spec, fmt)

    def test_binary_tar_ok(self):
        make_tar(self.tar, [
            ("package/", "dir", None),
            ("package/package.json", "file", b"{}"),
            ("package/bin/", "dir", None),
            ("package/bin/opencode", "file", b"\x7fELF"),
        ])
        res = self.extract("binary-tar")
        self.assertEqual(res["members"], 4)
        self.assertEqual(
            stat.S_IMODE((self.out / "package/bin/opencode").stat().st_mode),
            0o755)
        self.assertEqual(
            stat.S_IMODE((self.out / "package/package.json").stat().st_mode),
            0o600)

    def test_binary_tar_unexpected_member(self):
        for bad in ["package/README.md", "other/x", "package/bin/evil"]:
            make_tar(self.tar, [(bad, "file", b"x")])
            with self.assertRaises(artifacts.ArtifactError, msg=bad):
                self.extract("binary-tar")

    def test_binary_tar_link_member(self):
        make_tar(self.tar, [("package/bin/opencode", "symlink", "evil")])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("binary-tar")

    def test_binary_tar_missing_executable(self):
        make_tar(self.tar, [
            ("package/", "dir", None),
            ("package/package.json", "file", b"{}"),
        ])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("binary-tar")

    def test_binary_tar_duplicate_dir(self):
        make_tar(self.tar, [
            ("package/", "dir", None),
            ("package/", "dir", None),
        ])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("binary-tar")

    def test_source_root_must_be_dir(self):
        make_tar(self.tar, [("proj-abc", "file", b"x")])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("source-tar")

    def test_parent_component_is_file(self):
        make_tar(self.tar, [
            ("proj-abc/a", "file", b"x"),
            ("proj-abc/a/b", "file", b"y"),
        ])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("source-tar")

    def test_source_tar_ok(self):
        make_tar(self.tar, [
            ("proj-abc/", "dir", None),
            ("proj-abc/CMakeLists.txt", "file", b"cmake"),
            ("proj-abc/src/", "dir", None),
            ("proj-abc/src/main.cpp", "file", b"int main(){}"),
        ])
        res = self.extract("source-tar")
        self.assertTrue((self.out / "CMakeLists.txt").is_file())
        self.assertTrue((self.out / "src/main.cpp").is_file())
        self.assertEqual(
            stat.S_IMODE((self.out / "CMakeLists.txt").stat().st_mode), 0o600)
        self.assertFalse((self.out / "proj-abc").exists())

    def test_source_tar_outside_root(self):
        make_tar(self.tar, [("other/file", "file", b"x")])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("source-tar")

    def test_hostile_members(self):
        hostile = [
            [("../escape", "file", b"x")],
            [("/abs", "file", b"x")],
            [("proj-abc/../escape", "file", b"x")],
            [("proj-abc/./x", "file", b"x")],
            [("proj-abc/a//b", "file", b"x")],
            [("proj-abc/a\\b", "file", b"x")],
            [("proj-abc/a\tb", "file", b"x")],
            [("proj-abc/a\x01b", "file", b"x")],
            [("proj-abc/link", "symlink", "/etc/passwd")],
            [("proj-abc/hard", "hardlink", "proj-abc/x")],
            [("proj-abc/fifo", "fifo", None)],
            [("proj-abc/d/", "dir", None), ("proj-abc/d/", "dir", None)],
        ]
        for i, members in enumerate(hostile):
            self.tar = self.dir / f"h{i}.tgz"
            make_tar(self.tar, members)
            with self.assertRaises(artifacts.ArtifactError, msg=f"case {i}"):
                self.extract("source-tar")

    def test_duplicate_member(self):
        make_tar(self.tar, [
            ("proj-abc/f", "file", b"1"),
            ("proj-abc/f", "file", b"2"),
        ])
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("source-tar")

    def test_unpacked_bound(self):
        spec = dict(self.spec["inference_source"])
        spec["max_unpacked_bytes"] = 4
        make_tar(self.tar, [("proj-abc/f", "file", b"12345")])
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.extract_tar(self.tar, self.out, spec, "source-tar")

    def test_member_bound(self):
        make_tar(
            self.tar,
            [(f"proj-abc/f{i}", "file", b"x")
             for i in range(artifacts.MAX_TAR_MEMBERS + 1)],
        )
        with self.assertRaises(artifacts.ArtifactError):
            self.extract("source-tar")


if __name__ == "__main__":
    unittest.main()
