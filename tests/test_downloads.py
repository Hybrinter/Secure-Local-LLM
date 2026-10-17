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
        staged = downloads._stage_file(self.cache, "model", spec, fetch)
        self.assertEqual(staged.read_bytes(), content)
        self.assertEqual(fetch.calls, [spec["url"]])
        self.assertEqual(
            stat.S_IMODE(staged.lstat().st_mode), 0o600)
        again = downloads._stage_file(self.cache, "model", spec, fetch)
        self.assertEqual(again, staged)
        self.assertEqual(len(fetch.calls), 1)

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
