import hashlib
import io
import json
import os
import tarfile
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import artifacts, config, prepare, runner, state

REPO = Path(__file__).resolve().parents[1]
LOCK = REPO / ".devin" / "artifacts.lock.json"


def write_private(path, data, mode=0o600):
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


def write_tar(path, members):
    with tarfile.open(path, "w:gz") as tf:
        for name, kind, data in members:
            ti = tarfile.TarInfo(name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))


def make_lock(dir_):
    model = write_private(dir_ / "m.bin", b"model-bytes")
    oc = dir_ / "oc.tgz"
    write_tar(oc, [
        ("package/", "dir", None),
        ("package/bin/", "dir", None),
        ("package/package.json", "file", b"{}"),
        ("package/bin/opencode", "file", b"\x7fELF\x01"),
    ])
    src = dir_ / "src.tgz"
    write_tar(src, [
        ("root-x/", "dir", None),
        ("root-x/main.c", "file", b"int main(){}"),
    ])

    def entry(url, path, fmt, **kw):
        data = path.read_bytes()
        return {
            "version": "t",
            "url": url,
            "hash": {
                "algorithm": "sha256",
                "hex": hashlib.sha256(data).hexdigest(),
            },
            "max_bytes": len(data) + 1,
            "format": fmt,
            **kw,
        }

    lock = {
        "schema": artifacts.LOCK_SCHEMA,
        "platform": artifacts.LOCK_PLATFORM,
        "base_image": "docker.io/library/debian@sha256:" + "a" * 64,
        "artifacts": {
            "opencode": entry(
                "https://example.test/oc.tgz", oc, "binary-tar",
                member="package/bin/opencode", max_unpacked_bytes=4096),
            "model": entry("https://example.test/m.bin", model, "file"),
            "inference_source": entry(
                "https://example.test/src.tgz", src, "source-tar",
                root="root-x", max_unpacked_bytes=4096),
        },
    }
    path = write_private(dir_ / "lock.json", json.dumps(lock).encode())
    payloads = {
        "https://example.test/m.bin": model.read_bytes(),
        "https://example.test/oc.tgz": oc.read_bytes(),
        "https://example.test/src.tgz": src.read_bytes(),
    }
    return path, payloads


class FakeRunner(runner.Runner):
    def __init__(self):
        self.calls = []
        self.images = {}

    def run(self, argv, timeout=runner.DEFAULT_TIMEOUT_SECONDS,
            extra_env=None):
        self.calls.append(list(argv))
        if "image" in argv and "inspect" in argv:
            ref, fmt = argv[argv.index("inspect") + 1], argv[-1]
            ent = self.images.get(ref)
            if ent is None:
                return runner.CommandResult(argv, 1, "", "no image")
            if "Labels" in fmt:
                return runner.CommandResult(argv, 0, json.dumps(ent["labels"]), "")
            return runner.CommandResult(argv, 0, ent["id"], "")
        if "dpkg-query" in argv:
            return runner.CommandResult(argv, 0, "pkg 1.0\n", "")
        return runner.CommandResult(argv, 0, "", "")

    def register(self, image_id, instance_uuid, role):
        self.images[image_id] = {
            "id": image_id,
            "labels": {prepare.IMAGE_LABEL: instance_uuid,
                       prepare.IMAGE_ROLE_LABEL: role},
        }


def fake_builder(fake_runner, salt=""):
    def build(argv):
        tag = argv[argv.index("-t") + 1]
        labels = {}
        for i, a in enumerate(argv):
            if a == "--label":
                key, value = argv[i + 1].split("=", 1)
                labels[key] = value
        image_id = hashlib.sha256((salt + tag).encode()).hexdigest()
        fake_runner.images[tag] = {"id": image_id, "labels": labels}
        fake_runner.images[image_id] = fake_runner.images[tag]
        return ""
    return build


class Guard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = unittest.mock.patch.dict(os.environ, {
            "XDG_STATE_HOME": str(Path(self.tmp.name) / "xs"),
            "XDG_CACHE_HOME": str(Path(self.tmp.name) / "xc"),
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_requires_allow_network_before_any_action(self):
        fake = FakeRunner()
        with self.assertRaises(prepare.PrepareError):
            prepare.prepare(Path(self.tmp.name) / "state", "demo", REPO,
                            fake, False, fetcher=lambda *a: None)
        self.assertEqual(fake.calls, [])
        self.assertFalse((Path(self.tmp.name) / "xc").exists())

    def test_missing_instance_refused(self):
        with self.assertRaises(prepare.PrepareError):
            prepare.prepare(Path(self.tmp.name) / "state", "demo", REPO,
                            FakeRunner(), True, fetcher=lambda *a: None)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.env = unittest.mock.patch.dict(os.environ, {
            "XDG_STATE_HOME": str(self.dir / "xs"),
            "XDG_CACHE_HOME": str(self.dir / "xc"),
        })
        self.env.start()
        self.lock_path, self.payloads = make_lock(self.dir)
        self.lock_fp = artifacts.load_lock(self.lock_path)[1]
        self.profile, self.profile_fp = config.load_profile(REPO, "cpu")
        self.root = self.dir / "state"
        state.init_instance(self.root, "demo", self.profile, self.profile_fp,
                            self.lock_fp, True)
        self.manifest = state.load_manifest(self.root, "demo")
        self.uuid = self.manifest["identity"]["uuid"]
        self.uuid8 = self.uuid.replace("-", "")[:8]

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def fetcher(self):
        payloads = self.payloads

        def fetch(url, dest, max_bytes):
            if url not in payloads:
                raise prepare.PrepareError(f"unexpected url {url}")
            write_private(Path(dest), payloads[url])
            return dest
        return fetch

    def tag(self, role):
        fp = config.fingerprint_file(
            REPO / "containers" / f"{role}.Containerfile")["sha256"]
        return f"localhost/sll-{self.uuid8}-{role}:{fp[:12]}", fp

    def test_prepare_custom_lock_end_to_end(self):
        fake = FakeRunner()
        record = prepare.prepare(
            self.root, "demo", REPO, fake, True,
            fetcher=self.fetcher(), builder=fake_builder(fake))
        self.assertEqual(set(record["images"]), {"harness", "inference"})
        self.assertEqual(
            record["fingerprints"]["artifacts_lock"], self.lock_fp["sha256"])
        for role in ("harness", "inference"):
            tag, _fp = self.tag(role)
            self.assertIn(tag, fake.images)
            self.assertEqual(record["images"][role],
                             fake.images[tag]["id"])
            self.assertEqual(
                fake.images[tag]["labels"][prepare.IMAGE_LABEL], self.uuid)
            self.assertEqual(
                fake.images[tag]["labels"][prepare.IMAGE_ROLE_LABEL], role)
        self.assertTrue(
            any("pull" in " ".join(c) for c in fake.calls))

    def test_recorded_images_reused_without_rebuild(self):
        fake = FakeRunner()
        record = prepare.prepare(
            self.root, "demo", REPO, fake, True,
            fetcher=self.fetcher(), builder=fake_builder(fake))
        built = dict(fake.images)
        fake2 = FakeRunner()
        fake2.images = built
        builder2 = unittest.mock.Mock()
        statuses = []
        record2 = prepare.prepare(
            self.root, "demo", REPO, fake2, True,
            fetcher=self.fetcher(), builder=builder2,
            status=lambda s, p: statuses.append((s, p)))
        builder2.assert_not_called()
        self.assertEqual(record2["images"], record["images"])
        self.assertFalse(any("pull" in " ".join(c) for c in fake2.calls))
        self.assertIn(("image-harness", "present"), statuses)
        self.assertIn(("image-inference", "present"), statuses)

    def test_recorded_image_label_mismatch_rebuilds(self):
        fake = FakeRunner()
        prepare.prepare(
            self.root, "demo", REPO, fake, True,
            fetcher=self.fetcher(), builder=fake_builder(fake))
        old = state.load_prepared(self.root, "demo")
        stale = dict(fake.images)
        for role in ("harness", "inference"):
            stale[old["images"][role]] = {
                "id": old["images"][role],
                "labels": {prepare.IMAGE_LABEL: "short",  # legacy label policy
                           prepare.IMAGE_ROLE_LABEL: role},
            }
            tag, _ = self.tag(role)
            del stale[tag]
        fake2 = FakeRunner()
        fake2.images = stale
        called = []
        record2 = prepare.prepare(
            self.root, "demo", REPO, fake2, True,
            fetcher=self.fetcher(),
            builder=lambda argv: (called.append(argv),
                                  fake_builder(fake2, salt="v2")(argv))[1])
        self.assertEqual(len(called), 2)
        for role in ("harness", "inference"):
            self.assertNotEqual(record2["images"][role], old["images"][role])

    def test_foreign_tag_collision_refused(self):
        tag, _fp = self.tag("harness")
        fake = FakeRunner()
        fake.images[tag] = {
            "id": "f" * 64,
            "labels": {prepare.IMAGE_LABEL: "someone-else",
                       prepare.IMAGE_ROLE_LABEL: "harness"},
        }
        with self.assertRaises(prepare.PrepareError) as cm:
            prepare.prepare(self.root, "demo", REPO, fake, True,
                            fetcher=self.fetcher(),
                            builder=fake_builder(fake))
        self.assertIn("tag collision", str(cm.exception))

    def test_foreign_tag_refused_when_recipe_changed(self):
        tag, _fp = self.tag("harness")
        fake = FakeRunner()
        fake.images[tag] = {"id": "e" * 64, "labels": {}}
        with self.assertRaises(prepare.PrepareError):
            prepare._ensure_image(
                fake, "harness", tag, self.uuid, "f" * 64, False,
                lambda: self.dir, lambda: None,
                fake_builder(fake), None)

    def test_stored_id_role_mismatch_rebuilds(self):
        recorded = "a" * 64
        fake = FakeRunner()
        fake.register(recorded, self.uuid, "inference")
        called = []
        tag, _fp = self.tag("harness")

        def builder(argv):
            called.append(argv)
            return fake_builder(fake)(argv)

        image_id = prepare._ensure_image(
            fake, "harness", tag, self.uuid, recorded, True,
            lambda: self.dir, lambda: None, builder, None)
        self.assertEqual(len(called), 1)
        self.assertNotEqual(image_id, recorded)

    def test_workload_bindings_refused(self):
        manifest = state.load_manifest(self.root, "demo")
        manifest["resources"]["pod_id"] = "f" * 64
        mp = self.root / "instances" / "demo" / "manifest.json"
        write_private(mp, json.dumps(manifest).encode())
        with self.assertRaises(prepare.PrepareError):
            prepare.prepare(self.root, "demo", REPO, FakeRunner(), True,
                            fetcher=self.fetcher(),
                            builder=lambda argv: "")

    def test_corrupt_lock_refused(self):
        write_private(self.lock_path, b'{"schema": "bogus"}')
        with self.assertRaises(
                (artifacts.ArtifactError, prepare.PrepareError)):
            prepare.prepare(self.root, "demo", REPO, FakeRunner(), True,
                            fetcher=self.fetcher())

    def test_lock_drift_refused(self):
        fake = FakeRunner()
        lock, lock_fp = artifacts.load_lock(self.lock_path)
        bad = dict(lock_fp)
        bad["sha256"] = "0" * 64
        with unittest.mock.patch.object(
                prepare.artifacts, "load_lock",
                return_value=(lock, bad)):
            with self.assertRaises(prepare.PrepareError):
                prepare.prepare(self.root, "demo", REPO, fake, True,
                                fetcher=self.fetcher())
        self.assertFalse(any("pull" in " ".join(c) for c in fake.calls))

    def test_concurrent_prepare_fails_bounded(self):
        inst = self.root / "instances" / "demo"
        with state._locked(inst / ".lock"):
            with unittest.mock.patch.object(
                    state, "LOCK_TIMEOUT_SECONDS", 0.3):
                started = time.monotonic()
                with self.assertRaises(prepare.PrepareError):
                    prepare.prepare(self.root, "demo", REPO, FakeRunner(),
                                    True, fetcher=self.fetcher())
                self.assertLess(time.monotonic() - started, 10)

    def test_existing_context_dirs_untouched(self):
        cache = state._ensure_private_dir(
            Path(os.environ["XDG_CACHE_HOME"]) / "secure-local-llm"
            / "staging" / "demo")
        foreign = cache / "ctx-harness-AAAAAAAA"
        foreign.mkdir(mode=0o700)
        marker = foreign / "keep.txt"
        marker.write_text("keep")
        fake = FakeRunner()
        prepare.prepare(self.root, "demo", REPO, fake, True,
                        fetcher=self.fetcher(), builder=fake_builder(fake))
        self.assertEqual(marker.read_text(), "keep")


class RunBuild(unittest.TestCase):
    def test_bounded_log_tail(self):
        tail = prepare._run_build(
            ["python3", "-c", "print('x' * 100000)"], timeout=30)
        self.assertLessEqual(len(tail), prepare.BUILD_LOG_TAIL)
        self.assertIn("x" * 100, tail)

    def test_timeout_kills_process_group(self):
        started = time.monotonic()
        with self.assertRaises(prepare.PrepareError) as cm:
            prepare._run_build(
                ["python3", "-c",
                 "import subprocess,time;"
                 "subprocess.Popen(['sleep','60']);time.sleep(60)"],
                timeout=0.5)
        self.assertIn("timed out", str(cm.exception))
        self.assertLess(time.monotonic() - started, 15)

    def test_failure_rc_reported(self):
        with self.assertRaises(prepare.PrepareError) as cm:
            prepare._run_build(
                ["python3", "-c", "import sys;sys.exit(3)"], timeout=30)
        self.assertIn("rc=3", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
