import copy
import fcntl
import json
import os
import stat
import tempfile
import unittest
import unittest.mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import state

PROFILE = {"name": "cpu"}
PROFILE_FP = {"sha256": "a" * 64}
LOCK_FP = {"path": "/tmp/lock.json", "sha256": "b" * 64, "bytes": 10}


class StateRoots(unittest.TestCase):
    def test_xdg_overrides(self):
        env = {"XDG_STATE_HOME": "/tmp/st", "XDG_CACHE_HOME": "/tmp/ca"}
        self.assertEqual(str(state.state_root(env)), "/tmp/st/secure-local-llm")
        self.assertEqual(str(state.cache_root(env)), "/tmp/ca/secure-local-llm")

    def test_relative_xdg_rejected(self):
        with self.assertRaises(state.StateError):
            state.state_root({"XDG_STATE_HOME": "rel/state"})
        with self.assertRaises(state.StateError):
            state.cache_root({"XDG_CACHE_HOME": "rel/cache"})


class Init(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "sll"

    def tearDown(self):
        self.tmp.cleanup()

    def init(self, name="demo", ack=True, root=None):
        return state.init_instance(
            root or self.root, name, PROFILE, PROFILE_FP, LOCK_FP, ack)

    def test_permissions_and_manifest(self):
        m = self.init()
        for d in (self.root, self.root / "instances",
                  self.root / "instances" / "demo"):
            self.assertEqual(stat.S_IMODE(d.lstat().st_mode), 0o700)
        for f in ("manifest.json", ".lock"):
            p = self.root / "instances" / "demo" / f
            self.assertEqual(stat.S_IMODE(p.lstat().st_mode), 0o600)
        self.assertEqual(m["schema"], state.MANIFEST_SCHEMA)
        self.assertTrue(m["exceptions"]["prototype_no_lsm_acknowledged"])
        self.assertIsNone(m["resources"]["pod_id"])
        self.assertEqual(len(m["identity"]["uuid"]), 36)
        self.assertEqual(state.load_manifest(self.root, "demo"), m)

    def test_missing_ancestors_created_0700(self):
        deep = Path(self.tmp.name) / "a" / "b" / "sll"
        self.init(root=deep)
        for d in (deep.parent, deep.parent.parent, deep):
            self.assertTrue(d.is_dir())
            self.assertEqual(stat.S_IMODE(d.lstat().st_mode), 0o700)
        self.assertIsNotNone(state.load_manifest(deep, "demo"))

    def test_missing_ancestors_existing_symlink_refused(self):
        real = Path(self.tmp.name) / "real"
        real.mkdir()
        link = Path(self.tmp.name) / "link"
        os.symlink(real, link)
        with self.assertRaises(state.StateError):
            self.init(root=link / "sll")

    def test_collision_refused(self):
        self.init()
        with self.assertRaises(state.StateError):
            self.init()

    def test_ack_must_be_exactly_true(self):
        for bad in (False, None, 1, "true", "yes"):
            with self.assertRaises(state.StateError, msg=repr(bad)):
                self.init(ack=bad)
        self.assertFalse((self.root / "instances").exists())

    def test_relative_root_and_bad_names_rejected(self):
        with self.assertRaises(state.StateError):
            state.init_instance(Path("rel"), "demo", PROFILE, PROFILE_FP,
                                LOCK_FP, True)
        for bad in ("../x", "Bad", "a" * 33):
            with self.assertRaises(state.StateError, msg=bad):
                self.init(name=bad)

    def test_insecure_existing_dir_refused_not_fixed(self):
        inst = self.root / "instances" / "demo"
        inst.mkdir(parents=True, mode=0o755)
        with self.assertRaises(state.StateError):
            self.init()
        self.assertEqual(stat.S_IMODE(inst.lstat().st_mode), 0o755)

    def test_insecure_parents_rejected_on_load(self):
        self.init()
        os.chmod(self.root / "instances", 0o755)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        os.chmod(self.root / "instances", 0o700)
        os.chmod(self.root, 0o750)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        self.assertEqual(stat.S_IMODE(self.root.lstat().st_mode), 0o750)

    def test_symlink_instance_dir_and_parent_refused(self):
        state._ensure_private_dir(self.root)
        inst = state._ensure_private_dir(self.root / "instances") / "demo"
        os.symlink(Path(self.tmp.name), inst)
        with self.assertRaises(state.StateError):
            self.init()
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        inst.unlink()
        inst.parent.rmdir()
        os.symlink(Path(self.tmp.name), inst.parent)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")

    def test_unowned_dir_refused(self):
        self.init()
        with unittest.mock.patch("os.geteuid", return_value=1):
            with self.assertRaises(state.StateError):
                state.load_manifest(self.root, "demo")

    def test_missing_is_readonly(self):
        self.assertIsNone(state.load_manifest(self.root, "demo"))
        self.assertFalse(self.root.exists())
        state._ensure_private_dir(self.root)
        state._ensure_private_dir(self.root / "instances")
        self.assertIsNone(state.load_manifest(self.root, "absent"))

    def test_lock_contention_times_out(self):
        self.init()
        lock = self.root / "instances" / "demo" / ".lock"
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with unittest.mock.patch.object(state, "LOCK_TIMEOUT_SECONDS", 0.3):
                with self.assertRaises(state.StateError):
                    self.init()
        finally:
            os.close(fd)

    def test_fifo_lock_refused(self):
        self.init()
        lock = self.root / "instances" / "demo" / ".lock"
        lock.unlink()
        os.mkfifo(lock)
        with self.assertRaises(state.StateError):
            self.init()


class ManifestValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "sll"
        state.init_instance(self.root, "demo", PROFILE, PROFILE_FP, LOCK_FP, True)
        self.mp = state.manifest_path(self.root, "demo")
        self.pristine = json.loads(self.mp.read_text())

    def tearDown(self):
        self.tmp.cleanup()

    def rewrite(self, raw):
        self.mp.write_text(json.dumps(raw))
        os.chmod(self.mp, 0o600)

    def expect_rejected(self, mutate):
        m = copy.deepcopy(self.pristine)
        mutate(m)
        self.rewrite(m)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        self.rewrite(self.pristine)

    def test_corrupt_json_and_dup_keys(self):
        self.mp.write_bytes(b"{not json")
        os.chmod(self.mp, 0o600)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        self.mp.write_bytes(b'{"schema": 1, "schema": 2}')
        os.chmod(self.mp, 0o600)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")

    def test_strict_field_rejections(self):
        cases = [
            lambda m: m.update(extra=1),
            lambda m: m["identity"].update(uuid="not-a-uuid"),
            lambda m: m["identity"].update(name="other"),
            lambda m: m["identity"].update(created_utc="not a date"),
            lambda m: m["profile"].update(sha256="xyz"),
            lambda m: m["artifacts_lock"].update(path="relative"),
            lambda m: m["artifacts_lock"].update(bytes=-1),
            lambda m: m["artifacts_lock"].update(bytes=True),
            lambda m: m["exceptions"].update(prototype_no_lsm_acknowledged=1),
            lambda m: m["exceptions"].update(prototype_no_lsm_acknowledged=False),
            lambda m: m["resources"].update(pod_id="z" * 64),
            lambda m: m["resources"].update(container_ids=[]),
            lambda m: m["resources"].update(container_ids={"role": "nothex"}),
            lambda m: m["resources"].update(volume_names={"v": 1}),
            lambda m: m["resources"].update(network_id=123),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                self.expect_rejected(mutate)

    def test_unsafe_manifest_file_kinds(self):
        victim = Path(self.tmp.name) / "victim"
        victim.write_text("keep")
        self.mp.unlink()
        os.symlink(victim, self.mp)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        self.mp.unlink()
        os.mkfifo(self.mp)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        self.mp.unlink()
        self.mp.write_bytes(b"x" * (state.MAX_MANIFEST_BYTES + 1))
        os.chmod(self.mp, 0o600)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")
        self.mp.write_bytes(b"{}")
        os.chmod(self.mp, 0o600)
        os.link(self.mp, Path(self.tmp.name) / "linked")
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")

    def test_insecure_manifest_mode(self):
        os.chmod(self.mp, 0o644)
        with self.assertRaises(state.StateError):
            state.load_manifest(self.root, "demo")


if __name__ == "__main__":
    unittest.main()
