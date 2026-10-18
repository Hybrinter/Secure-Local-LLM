import copy
import errno
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


class _SyscallRecorder:
    def __init__(self):
        self.events = []
        self.fd_info = {}
        self.fsync_hook = None
        self.replaced = False
        self._reals = {
            name: getattr(os, name)
            for name in ("open", "close", "fsync", "mkdir", "chmod",
                         "replace", "link", "unlink")
        }
        self._patchers = [
            unittest.mock.patch("os." + name, getattr(self, "_" + name))
            for name in self._reals
        ]

    def __enter__(self):
        for patcher in self._patchers:
            patcher.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        for patcher in reversed(self._patchers):
            patcher.stop()
        return False

    def index(self, pred, desc, start=0):
        for i, event in enumerate(self.events):
            if i >= start and pred(event):
                return i
        raise AssertionError(f"missing recorded event: {desc}")

    def _open(self, path, flags=0, mode=0o777, *args, **kwargs):
        fd = self._reals["open"](path, flags, mode, *args, **kwargs)
        self.fd_info[fd] = (str(path), flags)
        self.events.append(("open", str(path), flags, fd))
        return fd

    def _close(self, fd):
        info = self.fd_info.pop(fd, None)
        self.events.append(("close", info[0] if info else None, fd))
        return self._reals["close"](fd)

    def _fsync(self, fd):
        path, flags = self.fd_info.get(fd, (None, 0))
        is_dir = bool(flags & os.O_DIRECTORY)
        self.events.append(
            ("fsync", path, is_dir, os.fstat(fd).st_ino, fd))
        if self.fsync_hook is not None:
            self.fsync_hook(path, is_dir, fd)
        return self._reals["fsync"](fd)

    def _mkdir(self, path, *args, **kwargs):
        self.events.append(("mkdir", str(path)))
        return self._reals["mkdir"](path, *args, **kwargs)

    def _chmod(self, path, *args, **kwargs):
        self.events.append(("chmod", str(path)))
        return self._reals["chmod"](path, *args, **kwargs)

    def _replace(self, src, dst, *args, **kwargs):
        self.replaced = True
        self.events.append(("replace", str(src), str(dst)))
        return self._reals["replace"](src, dst, *args, **kwargs)

    def _link(self, src, dst, *args, **kwargs):
        self.events.append(("link", str(src), str(dst)))
        return self._reals["link"](src, dst, *args, **kwargs)

    def _unlink(self, path, *args, **kwargs):
        self.events.append(("unlink", str(path)))
        return self._reals["unlink"](path, *args, **kwargs)


class FsyncDirectory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "dir"
        self.dir.mkdir(mode=0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def test_open_flags_fsync_then_close(self):
        with _SyscallRecorder() as rec:
            state._fsync_directory(self.dir)
        open_i = rec.index(lambda e: e[0] == "open", "directory open")
        _, opened, flags, fd = rec.events[open_i]
        self.assertEqual(opened, str(self.dir))
        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
        self.assertTrue(flags & os.O_DIRECTORY)
        self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertTrue(flags & os.O_CLOEXEC)
        fsync_i = rec.index(
            lambda e: e[0] == "fsync" and e[4] == fd, "directory fsync",
            start=open_i)
        self.assertEqual(rec.events[fsync_i][3], self.dir.stat().st_ino)
        rec.index(
            lambda e: e[0] == "close" and e[2] == fd, "directory close",
            start=fsync_i)
        self.assertNotIn(fd, rec.fd_info)

    def test_fsync_failure_still_closes_fd(self):
        rec = _SyscallRecorder()

        def fail(path, is_dir, fd):
            raise OSError("injected fsync failure")

        rec.fsync_hook = fail
        with rec:
            with self.assertRaises(OSError):
                state._fsync_directory(self.dir)
        opens = [e for e in rec.events if e[0] == "open"]
        self.assertEqual(len(opens), 1)
        fd = opens[0][3]
        rec.index(
            lambda e: e[0] == "close" and e[2] == fd, "directory close")
        self.assertNotIn(fd, rec.fd_info)

    def test_non_directory_and_symlink_refused(self):
        f = Path(self.tmp.name) / "file"
        f.write_text("x")
        link = Path(self.tmp.name) / "link"
        os.symlink(self.dir, link)
        with _SyscallRecorder() as rec:
            with self.assertRaises(OSError) as cm:
                state._fsync_directory(f)
            self.assertEqual(cm.exception.errno, errno.ENOTDIR)
            with self.assertRaises(OSError) as cm:
                state._fsync_directory(link)
            self.assertIn(cm.exception.errno, (errno.ELOOP, errno.ENOTDIR))
        self.assertEqual([e for e in rec.events if e[0] == "fsync"], [])


class AtomicWriteDurability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name) / "private"
        self.parent.mkdir(mode=0o700)
        os.chmod(self.parent, 0o700)
        self.target = self.parent / "manifest.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _assert_write_order(self, payload, mode):
        with _SyscallRecorder() as rec:
            state._atomic_write(self.target, payload, mode=mode)
        file_fsync = rec.index(
            lambda e: e[0] == "fsync" and not e[2], "file fsync")
        replace = rec.index(lambda e: e[0] == "replace", "replace")
        dir_fsync = rec.index(
            lambda e: e[0] == "fsync" and e[2] and e[1] == str(self.parent),
            f"parent directory fsync for {self.parent}", start=replace)
        self.assertLess(file_fsync, replace)
        self.assertLess(replace, dir_fsync)
        self.assertEqual(rec.events[dir_fsync][3], self.parent.stat().st_ino)
        dir_fsyncs = [e for e in rec.events if e[0] == "fsync" and e[2]]
        self.assertEqual([e[1] for e in dir_fsyncs], [str(self.parent)])
        self.assertEqual(self.target.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(self.target.lstat().st_mode), mode)

    def test_new_file_write_order_and_modes(self):
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                self.target.unlink(missing_ok=True)
                self._assert_write_order(b'{"fresh": true}\n', mode)

    def test_existing_file_write_order_and_modes(self):
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                self.target.unlink(missing_ok=True)
                state._atomic_write(self.target, b"old", mode=0o600)
                self._assert_write_order(b'{"updated": true}\n', mode)

    def test_file_fsync_failure_preserves_target(self):
        state._atomic_write(self.target, b"original", mode=0o600)
        rec = _SyscallRecorder()

        def fail_file_fsync(path, is_dir, fd):
            if not is_dir:
                raise OSError("injected file fsync failure")

        rec.fsync_hook = fail_file_fsync
        with rec:
            with self.assertRaises(OSError):
                state._atomic_write(self.target, b"replacement", mode=0o600)
        self.assertEqual(self.target.read_bytes(), b"original")
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])

    def test_file_fsync_failure_leaves_no_target_or_temp(self):
        rec = _SyscallRecorder()

        def fail_file_fsync(path, is_dir, fd):
            if not is_dir:
                raise OSError("injected file fsync failure")

        rec.fsync_hook = fail_file_fsync
        with rec:
            with self.assertRaises(OSError):
                state._atomic_write(self.target, b"payload", mode=0o600)
        self.assertFalse(self.target.exists() or self.target.is_symlink())
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])

    def test_replace_failure_preserves_target_and_cleans_temp(self):
        state._atomic_write(self.target, b"original", mode=0o600)
        with _SyscallRecorder() as rec:
            with unittest.mock.patch(
                    "os.replace",
                    side_effect=OSError("injected replace failure")):
                with self.assertRaises(OSError):
                    state._atomic_write(
                        self.target, b"replacement", mode=0o600)
        self.assertEqual(self.target.read_bytes(), b"original")
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])
        dir_fsyncs = [e for e in rec.events if e[0] == "fsync" and e[2]]
        self.assertEqual(dir_fsyncs, [])

    def test_parent_fsync_failure_after_replace(self):
        rec = _SyscallRecorder()

        def fail_parent(path, is_dir, fd):
            if is_dir and rec.replaced:
                raise OSError("injected parent fsync failure")

        rec.fsync_hook = fail_parent
        with rec:
            with self.assertRaises(OSError):
                state._atomic_write(self.target, b"visible", mode=0o600)
        self.assertEqual(self.target.read_bytes(), b"visible")
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])
        dir_fd = next(e[4] for e in rec.events if e[0] == "fsync" and e[2])
        rec.index(
            lambda e: e[0] == "close" and e[2] == dir_fd,
            "post-replace directory close")


class AtomicWriteNoReplace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name) / "private"
        self.parent.mkdir(mode=0o700)
        os.chmod(self.parent, 0o700)
        self.target = self.parent / "evidence.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_publish_order_bytes_mode_nlink(self):
        with _SyscallRecorder() as rec:
            state._atomic_write(self.target, b"payload", mode=0o400,
                                replace=False)
        file_fsync = rec.index(
            lambda e: e[0] == "fsync" and not e[2], "file fsync")
        link = rec.index(lambda e: e[0] == "link", "link publish",
                         start=file_fsync)
        tmp_path, dst = rec.events[link][1], rec.events[link][2]
        self.assertEqual(dst, str(self.target))
        self.assertTrue(Path(tmp_path).name.startswith(".tmp-"))
        rec.index(
            lambda e: e[0] == "unlink" and e[1] == tmp_path,
            "temporary unlink", start=link)
        dir_fsync = rec.index(
            lambda e: e[0] == "fsync" and e[2] and e[1] == str(self.parent),
            "parent fsync", start=link)
        self.assertEqual(
            rec.events[dir_fsync][3], self.parent.stat().st_ino)
        self.assertEqual(self.target.read_bytes(), b"payload")
        self.assertEqual(stat.S_IMODE(self.target.lstat().st_mode), 0o400)
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])

    def test_collision_entry_types_preserved(self):
        victim = self.parent / "victim"
        victim.write_bytes(b"victim")
        os.chmod(victim, 0o600)
        kinds = (
            ("regular",
             lambda d: (d.write_bytes(b"original"),
                        os.chmod(d, 0o600))),
            ("symlink", lambda d: d.symlink_to(victim)),
            ("dangling", lambda d: d.symlink_to(self.parent / "absent")),
            ("directory", lambda d: d.mkdir(0o700)),
            ("fifo", lambda d: os.mkfifo(d)),
            ("hardlink", lambda d: os.link(victim, d)),
        )
        for label, make in kinds:
            with self.subTest(kind=label):
                dest = self.parent / f"dest-{label}"
                make(dest)
                before = dest.lstat()
                with self.assertRaises(state.StateError):
                    state._atomic_write(
                        dest, b"payload", mode=0o600, replace=False)
                after = dest.lstat()
                self.assertEqual(after.st_ino, before.st_ino)
                self.assertEqual(after.st_mode, before.st_mode)
                if stat.S_ISREG(after.st_mode):
                    self.assertEqual(
                        dest.read_bytes(),
                        b"victim" if label == "hardlink" else b"original")
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])

    def test_link_failure_cleans_temp_and_preserves_dest(self):
        self.target.write_bytes(b"original")
        os.chmod(self.target, 0o600)
        with unittest.mock.patch(
                "os.link",
                side_effect=OSError("injected link failure")):
            with self.assertRaises(OSError):
                state._atomic_write(
                    self.target, b"payload", mode=0o600, replace=False)
        self.assertEqual(self.target.read_bytes(), b"original")
        self.assertEqual(list(self.parent.glob(".tmp-*")), [])

    def test_default_replaces_regular_target(self):
        self.target.write_bytes(b"old")
        os.chmod(self.target, 0o600)
        state._atomic_write(self.target, b"new", mode=0o600)
        self.assertEqual(self.target.read_bytes(), b"new")


class InitDurability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def init(self, root, name="demo"):
        return state.init_instance(
            root, name, PROFILE, PROFILE_FP, LOCK_FP, True)

    def test_deep_init_dir_barriers_in_creation_order(self):
        root = Path(self.tmp.name) / "a" / "b" / "state"
        inst = root / "instances" / "demo"
        created = [
            Path(self.tmp.name) / "a",
            Path(self.tmp.name) / "a" / "b",
            root,
            root / "instances",
            inst,
        ]
        with _SyscallRecorder() as rec:
            self.init(root)
        mkdirs = [e[1] for e in rec.events if e[0] == "mkdir"]
        self.assertEqual(mkdirs, [str(d) for d in created])
        replace_i = rec.index(
            lambda e: e[0] == "replace", "manifest publication")
        for i, d in enumerate(created):
            mkdir_i = rec.index(
                lambda e, d=d: e[0] == "mkdir" and e[1] == str(d),
                f"mkdir {d}")
            chmod_i = rec.index(
                lambda e, d=d: e[0] == "chmod" and e[1] == str(d),
                f"chmod {d}", start=mkdir_i)
            dir_i = rec.index(
                lambda e, d=d: (
                    e[0] == "fsync" and e[2] and e[1] == str(d)),
                f"directory barrier for {d}", start=chmod_i)
            parent_i = rec.index(
                lambda e, d=d: (
                    e[0] == "fsync" and e[2] and e[1] == str(d.parent)),
                f"parent barrier {d.parent} after {d}", start=dir_i)
            self.assertLess(mkdir_i, chmod_i)
            self.assertLess(chmod_i, dir_i)
            self.assertLess(dir_i, parent_i)
            if i + 1 < len(created):
                next_mkdir_i = rec.index(
                    lambda e, n=created[i + 1]: (
                        e[0] == "mkdir" and e[1] == str(n)),
                    f"mkdir {created[i + 1]}")
                self.assertLess(parent_i, next_mkdir_i)
            else:
                self.assertLess(parent_i, replace_i)
            self.assertEqual(rec.events[dir_i][3], d.stat().st_ino)
        final_i = rec.index(
            lambda e: e[0] == "fsync" and e[2] and e[1] == str(inst),
            "post-replace manifest parent barrier", start=replace_i)
        trailing = rec.events[final_i + 1:]
        self.assertFalse(
            [e for e in trailing if e[0] in ("mkdir", "replace", "fsync")])
        self.assertIsNotNone(state.load_manifest(root, "demo"))

    def test_ancestor_parent_barrier_failure_aborts_init(self):
        root = Path(self.tmp.name) / "a" / "b" / "state"
        a = Path(self.tmp.name) / "a"
        b = a / "b"
        rec = _SyscallRecorder()
        a_fsyncs = []

        def fail_parent_of_b(path, is_dir, fd):
            if is_dir and path == str(a):
                a_fsyncs.append(path)
                if len(a_fsyncs) == 2:
                    raise OSError("injected ancestor parent barrier failure")

        rec.fsync_hook = fail_parent_of_b
        with rec:
            with self.assertRaises(OSError):
                self.init(root)
        self.assertTrue(b.is_dir())
        self.assertFalse(root.exists())
        self.assertFalse(
            (root / "instances" / "demo" / "manifest.json").exists())

    def test_existing_private_dirs_still_get_barriers(self):
        root = Path(self.tmp.name) / "state"
        instances = root / "instances"
        root.mkdir(mode=0o700)
        instances.mkdir(mode=0o700)
        for d in (root, instances):
            os.chmod(d, 0o700)
        with _SyscallRecorder() as rec:
            self.init(root)
        for d in (Path(self.tmp.name), root, instances,
                  instances / "demo"):
            rec.index(
                lambda e, d=d: e[0] == "fsync" and e[2] and e[1] == str(d),
                f"directory barrier for {d}")

    def test_final_barrier_failure_preserves_manifest_and_retry(self):
        root = Path(self.tmp.name) / "state"
        rec = _SyscallRecorder()

        def fail_after_replace(path, is_dir, fd):
            if is_dir and rec.replaced:
                raise OSError("injected final barrier failure")

        rec.fsync_hook = fail_after_replace
        with rec:
            with self.assertRaises(OSError):
                self.init(root)
        loaded = state.load_manifest(root, "demo")
        self.assertIsNotNone(loaded)
        first_uuid = loaded["identity"]["uuid"]
        with self.assertRaises(state.StateError):
            self.init(root)
        self.assertEqual(
            state.load_manifest(root, "demo")["identity"]["uuid"],
            first_uuid)


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


def valid_record(name="demo"):
    return {
        "schema": state.PREPARED_SCHEMA,
        "instance": name,
        "created_utc": "2026-10-17T00:00:00+00:00",
        "fingerprints": {
            "artifacts_lock": "a" * 64,
            "profile": "b" * 64,
            "harness_containerfile": "c" * 64,
            "inference_containerfile": "d" * 64,
        },
        "artifacts": {
            "model": {"sha256": "e" * 64, "path": "/cache/model"},
            "opencode": {"sha512": "f" * 128, "path": "/cache/oc"},
            "inference_source": {"sha256": "1" * 64, "path": "/cache/src"},
        },
        "images": {"harness": "2" * 64, "inference": "3" * 64},
        "packages": {"harness": ["pkg 1.0"], "inference": []},
    }


class PreparedValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "sll"
        state.init_instance(self.root, "demo", PROFILE, PROFILE_FP, LOCK_FP,
                            True)
        self.pp = self.root / "instances" / "demo" / "prepared.json"
        self.pristine = valid_record()

    def tearDown(self):
        self.tmp.cleanup()

    def rewrite(self, raw):
        self.pp.write_text(json.dumps(raw))
        os.chmod(self.pp, 0o600)

    def test_roundtrip(self):
        state.save_prepared(self.root, "demo", self.pristine)
        self.assertEqual(state.load_prepared(self.root, "demo"),
                         self.pristine)

    def test_missing_is_readonly(self):
        self.assertIsNone(state.load_prepared(self.root, "demo"))

    def test_corrupt_json_rejected(self):
        self.pp.write_bytes(b"{bad")
        os.chmod(self.pp, 0o600)
        with self.assertRaises(state.StateError):
            state.load_prepared(self.root, "demo")

    def test_strict_field_rejections(self):
        cases = [
            lambda r: r.update(extra=1),
            lambda r: r.update(schema="other@2"),
            lambda r: r.update(instance="other"),
            lambda r: r.update(instance="BAD"),
            lambda r: r.update(created_utc="not a date"),
            lambda r: r["fingerprints"].pop("profile"),
            lambda r: r["fingerprints"].update(extra="e" * 64),
            lambda r: r["fingerprints"].update(profile="xyz"),
            lambda r: r["artifacts"].pop("model"),
            lambda r: r["artifacts"].update(model="x"),
            lambda r: r["artifacts"]["model"].update(path="relative"),
            lambda r: r["artifacts"]["model"].update(path=None),
            lambda r: r["artifacts"]["model"].update(path={}),
            lambda r: r["artifacts"]["model"].update(path=[]),
            lambda r: r["artifacts"]["model"].update(sha256="nothex"),
            lambda r: r["artifacts"]["model"].update(extra="e" * 64),
            lambda r: r["artifacts"]["model"].pop("sha256"),
            lambda r: r["artifacts"]["opencode"].pop("sha512"),
            lambda r: r["images"].pop("inference"),
            lambda r: r["images"].update(harness="nothex"),
            lambda r: r["packages"].update(harness="pkg"),
            lambda r: r["packages"].update(harness=["ok", ""]),
            lambda r: r["packages"].update(harness=[1]),
            lambda r: r["packages"].pop("inference"),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                record = copy.deepcopy(self.pristine)
                mutate(record)
                self.rewrite(record)
                with self.assertRaises(state.StateError):
                    state.load_prepared(self.root, "demo")
                self.pp.unlink()

    def test_save_rejects_invalid_record(self):
        record = copy.deepcopy(self.pristine)
        record["images"]["harness"] = "nothex"
        with self.assertRaises(state.StateError):
            state.save_prepared(self.root, "demo", record)
        self.assertFalse(self.pp.exists())

    def test_insecure_parents_rejected_on_load(self):
        state.save_prepared(self.root, "demo", self.pristine)
        os.chmod(self.root / "instances", 0o755)
        with self.assertRaises(state.StateError):
            state.load_prepared(self.root, "demo")
        os.chmod(self.root / "instances", 0o700)
        self.assertIsNotNone(state.load_prepared(self.root, "demo"))


def valid_git_record(name="demo"):
    return {
        "schema": state.GIT_PREPARED_SCHEMA,
        "instance": name,
        "instance_uuid": "01234567-89ab-4cde-8f01-23456789abcd",
        "created_utc": "2026-10-17T00:00:00+00:00",
        "artifacts_lock_sha256": "a" * 64,
        "profile_sha256": "b" * 64,
        "files": {
            "containers/git-fixture.Containerfile": "c" * 64,
            "git-fixture/pre_receive.py": "d" * 64,
            "git-fixture/serve_git.py": "e" * 64,
            "git-fixture/sshd_config": "f" * 64,
        },
        "image_id": "1" * 64,
        "packages": ["openssh-server 1:9.2", "git 1:2.39"],
    }


class GitPreparedValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "sll"
        state.init_instance(self.root, "demo", PROFILE, PROFILE_FP, LOCK_FP,
                            True)
        self.gp = self.root / "instances" / "demo" / "git-prepared.json"
        self.pristine = valid_git_record()

    def tearDown(self):
        self.tmp.cleanup()

    def rewrite(self, raw):
        self.gp.write_text(json.dumps(raw))
        os.chmod(self.gp, 0o600)

    def test_roundtrip(self):
        state.save_git_prepared(self.root, "demo", self.pristine)
        self.assertEqual(state.load_git_prepared(self.root, "demo"),
                         self.pristine)
        st = os.stat(self.gp)
        self.assertEqual(st.st_mode & 0o777, 0o600)

    def test_missing_is_readonly(self):
        self.assertIsNone(state.load_git_prepared(self.root, "demo"))

    def test_corrupt_json_rejected(self):
        self.gp.write_bytes(b"{bad")
        os.chmod(self.gp, 0o600)
        with self.assertRaises(state.StateError):
            state.load_git_prepared(self.root, "demo")

    def test_strict_field_rejections(self):
        cases = [
            lambda r: r.update(extra=1),
            lambda r: r.pop("instance_uuid"),
            lambda r: r.update(schema="other@2"),
            lambda r: r.update(instance="other"),
            lambda r: r.update(instance_uuid="not-uuid"),
            lambda r: r.update(
                instance_uuid="46840CC1-3375-4710-BF83-8BF47C7175B9"),
            lambda r: r.update(created_utc="not a date"),
            lambda r: r.update(artifacts_lock_sha256="xyz"),
            lambda r: r.update(profile_sha256="G" * 64),
            lambda r: r.update(image_id="nothex"),
            lambda r: r["files"].pop("git-fixture/sshd_config"),
            lambda r: r["files"].update(extra="e" * 64),
            lambda r: r["files"].update(
                **{"containers/git-fixture.Containerfile": "x"}),
            lambda r: r.update(files=["not", "dict"]),
            lambda r: r.update(packages="openssh"),
            lambda r: r.update(packages=["ok", ""]),
            lambda r: r.update(packages=[1]),
            lambda r: r.update(packages=[{"pkg": 1}]),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(case=i):
                record = copy.deepcopy(self.pristine)
                mutate(record)
                self.rewrite(record)
                with self.assertRaises(state.StateError):
                    state.load_git_prepared(self.root, "demo")
                self.gp.unlink()

    def test_save_rejects_invalid_record(self):
        record = copy.deepcopy(self.pristine)
        record["image_id"] = "nothex"
        with self.assertRaises(state.StateError):
            state.save_git_prepared(self.root, "demo", record)
        self.assertFalse(self.gp.exists())

    def test_insecure_parents_rejected_on_load(self):
        state.save_git_prepared(self.root, "demo", self.pristine)
        os.chmod(self.root / "instances", 0o755)
        with self.assertRaises(state.StateError):
            state.load_git_prepared(self.root, "demo")
        os.chmod(self.root / "instances", 0o700)
        self.assertIsNotNone(state.load_git_prepared(self.root, "demo"))


if __name__ == "__main__":
    unittest.main()
