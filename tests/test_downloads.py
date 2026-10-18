import hashlib
import io
import os
import stat
import tarfile
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import downloads


def write_private(path, data, mode=0o600):
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


def spec_for(path, fmt, **kw):
    data = Path(path).read_bytes()
    spec = {
        "version": "t",
        "url": "https://example.test/artifact",
        "hash": {"algorithm": "sha256",
                 "hex": hashlib.sha256(data).hexdigest()},
        "max_bytes": len(data) + 1,
        "format": fmt,
    }
    spec.update(kw)
    return spec


class VerifyFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.real = write_private(self.dir / "real", b"content")
        self.spec = spec_for(self.real, "file")

    def tearDown(self):
        self.tmp.cleanup()

    def test_symlink_rejected(self):
        link = self.dir / "link"
        link.symlink_to(self.real)
        with self.assertRaises(downloads.DownloadError):
            downloads._verify_file(link, self.spec, "model")

    def test_fifo_rejected(self):
        fifo = self.dir / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(downloads.DownloadError):
            downloads._verify_file(fifo, self.spec, "model")

    def test_hardlink_rejected(self):
        hard = self.dir / "hard"
        os.link(self.real, hard)
        with self.assertRaises(downloads.DownloadError):
            downloads._verify_file(hard, self.spec, "model")

    def test_insecure_mode_rejected(self):
        world = write_private(self.dir / "world", b"content", 0o644)
        with self.assertRaises(downloads.DownloadError):
            downloads._verify_file(world, self.spec, "model")

    def test_digest_mismatch_rejected(self):
        other = write_private(self.dir / "other", b"different")
        with self.assertRaises(downloads.DownloadError):
            downloads._verify_file(other, self.spec, "model")

    def test_oversize_rejected(self):
        spec = dict(self.spec)
        spec["max_bytes"] = 2
        with self.assertRaises(downloads.DownloadError):
            downloads._verify_file(self.real, spec, "model")


class StageFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cache = self.dir / "cache"
        self.cache.mkdir(mode=0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def fetcher_for(self, content):
        calls = []

        def fetch(url, dest, max_bytes):
            calls.append(url)
            write_private(Path(dest), content)
            return dest
        fetch.calls = calls
        return fetch

    def test_download_then_reuse_verified_cache(self):
        content = b"model-bytes"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        fetch = self.fetcher_for(content)
        events = []

        def status(name, phase):
            events.append((name, phase))
        staged = downloads._stage_file(
            self.cache, "model", spec, fetch, status=status)
        self.assertEqual(staged.read_bytes(), content)
        self.assertEqual(fetch.calls, [spec["url"]])
        self.assertEqual(
            stat.S_IMODE(staged.lstat().st_mode), 0o600)
        self.assertEqual(
            events, [("model", "downloading"), ("model", "verified")])
        self.assertEqual(
            [p.name for p in self.cache.iterdir()], [staged.name])
        again = downloads._stage_file(
            self.cache, "model", spec, fetch, status=status)
        self.assertEqual(again, staged)
        self.assertEqual(len(fetch.calls), 1)
        self.assertEqual(
            events,
            [("model", "downloading"), ("model", "verified"),
             ("model", "verified")])
        self.assertEqual(
            [p.name for p in self.cache.iterdir()], [staged.name])

    def test_failed_verification_retries_leave_no_staging(self):
        target = write_private(self.dir / "content", b"model-bytes")
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        sentinel = write_private(self.cache / "sentinel", b"keep")
        fetch = self.fetcher_for(b"bad")
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                with self.assertRaises(downloads.DownloadError):
                    downloads._stage_file(
                        self.cache, "model", spec, fetch)
                self.assertEqual(len(fetch.calls), attempt + 1)
                self.assertFalse(os.path.lexists(dest))
                self.assertEqual(
                    [p for p in self.cache.iterdir()
                     if p.name.startswith(".tmp-")], [])
                self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_oversized_fetch_removes_staging(self):
        target = write_private(self.dir / "content", b"x")
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        with self.assertRaises(downloads.DownloadError):
            downloads._stage_file(
                self.cache, "model", spec,
                self.fetcher_for(b"larger-than-bound"))
        self.assertFalse(os.path.lexists(dest))
        self.assertEqual([p.name for p in self.cache.iterdir()], [])

    def test_insecure_fetch_mode_removes_staging(self):
        content = b"model-bytes"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"

        def fetch(url, tmp, max_bytes):
            write_private(Path(tmp), content, 0o644)
            return tmp
        with self.assertRaises(downloads.DownloadError):
            downloads._stage_file(self.cache, "model", spec, fetch)
        self.assertFalse(os.path.lexists(dest))
        self.assertEqual([p.name for p in self.cache.iterdir()], [])

    def test_fetcher_error_removes_staging(self):
        target = write_private(self.dir / "content", b"model-bytes")
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        for exc in (RuntimeError("boom"), KeyboardInterrupt()):
            with self.subTest(exc=exc):
                def fetch(url, tmp, max_bytes):
                    write_private(Path(tmp), b"partial")
                    raise exc
                with self.assertRaises(type(exc)) as cm:
                    downloads._stage_file(
                        self.cache, "model", spec, fetch)
                self.assertIs(cm.exception, exc)
                self.assertFalse(os.path.lexists(dest))
                self.assertEqual(
                    [p.name for p in self.cache.iterdir()], [])

    def test_promotion_failure_removes_staging(self):
        content = b"model-bytes"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        sentinel = write_private(self.cache / "sentinel", b"keep")
        err = OSError("replace denied")
        with unittest.mock.patch.object(
                downloads.os, "replace", side_effect=err):
            with self.assertRaises(OSError) as cm:
                downloads._stage_file(
                    self.cache, "model", spec,
                    self.fetcher_for(content))
        self.assertIs(cm.exception, err)
        self.assertFalse(os.path.lexists(dest))
        self.assertEqual(
            [p.name for p in self.cache.iterdir()], ["sentinel"])
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_downloading_status_failure_leaves_no_staging(self):
        content = b"model-bytes"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        err = RuntimeError("status failed")

        def status(name, phase):
            raise err
        with self.assertRaises(RuntimeError) as cm:
            downloads._stage_file(
                self.cache, "model", spec,
                self.fetcher_for(content), status=status)
        self.assertIs(cm.exception, err)
        self.assertEqual([p.name for p in self.cache.iterdir()], [])

    def test_verified_status_failure_keeps_staged_file(self):
        content = b"model-bytes"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        err = RuntimeError("status failed")

        def status(name, phase):
            if phase == "verified":
                raise err
        with self.assertRaises(RuntimeError) as cm:
            downloads._stage_file(
                self.cache, "model", spec,
                self.fetcher_for(content), status=status)
        self.assertIs(cm.exception, err)
        self.assertEqual(dest.read_bytes(), content)
        self.assertEqual(
            [p.name for p in self.cache.iterdir()], [dest.name])

    def test_tampered_dest_refused(self):
        content = b"real"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        write_private(dest, b"tampered")
        with self.assertRaises(downloads.DownloadError):
            downloads._stage_file(self.cache, "model", spec,
                                  self.fetcher_for(content))

    def test_symlink_dest_refused(self):
        content = b"real"
        target = write_private(self.dir / "content", content)
        spec = spec_for(target, "file")
        dest = self.cache / f"model-{spec['hash']['hex'][:16]}"
        dest.symlink_to(target)
        with self.assertRaises(downloads.DownloadError):
            downloads._stage_file(self.cache, "model", spec,
                                  self.fetcher_for(content))

    def test_insecure_cache_dir_refused(self):
        loose = self.dir / "loose"
        loose.mkdir(mode=0o755)
        target = write_private(self.dir / "content", b"x")
        spec = spec_for(target, "file")
        with self.assertRaises(downloads.DownloadError):
            downloads._stage_file(loose, "model", spec,
                                  self.fetcher_for(b"x"))


class FetchTarget(unittest.TestCase):
    def test_rejects_unsafe_targets(self):
        for bad in (
            "http://h/f", "https://u:p@h/f", "https://h:99/f",
            "https://h:bad/f", "https://h/a\tb", "ftp://h/f", "",
        ):
            with self.assertRaises(downloads.DownloadError, msg=bad):
                downloads._check_fetch_target(bad)
        downloads._check_fetch_target("https://h/f?q=1")

    def test_redirect_handler_validates_newurl(self):
        handler = downloads._HttpsOnlyRedirect()
        with self.assertRaises(downloads.DownloadError):
            handler.redirect_request(
                None, None, 302, "", {}, "http://insecure/x")
        with self.assertRaises(downloads.DownloadError):
            handler.redirect_request(
                None, None, 302, "", {}, "https://u:p@h/x")


class FetchDeadline(unittest.TestCase):
    def test_total_deadline(self):
        class _SlowResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                time.sleep(0.2)
                return b"x"

        class _Opener:
            def open(self, req, timeout=None):
                return _SlowResp()

        tmp = tempfile.TemporaryDirectory()
        dest = Path(tmp.name) / "f"
        with unittest.mock.patch(
                "urllib.request.build_opener", lambda *a: _Opener()):
            with self.assertRaises(downloads.DownloadError) as cm:
                downloads.fetch_url("https://h/f", dest, 10, timeout=0.4)
        self.assertIn("timed out", str(cm.exception))
        self.assertFalse(dest.exists())
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
