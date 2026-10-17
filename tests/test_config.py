import json
import os
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from local_agent import config

REPO = Path(__file__).resolve().parents[1]


def valid_profile():
    return {
        "schema": config.PROFILE_SCHEMA,
        "name": "cpu",
        "model": {"context_tokens": 8192, "max_output_tokens": 1024,
                  "parallel": 1, "threads": 4},
        "resources": {"memory_mb": 8192, "cpus": 4, "pids": 512},
        "timeouts": {"startup_seconds": 120, "request_seconds": 300},
    }


class InstanceNames(unittest.TestCase):
    def test_valid(self):
        for name in ("demo", "a", "a-1", "x" * 32, "agent-01"):
            self.assertEqual(config.validate_instance_name(name), name)

    def test_invalid(self):
        for name in ("", "Demo", "0abc", "-a", "a_b", "a" * 33, "..", "../x",
                     None, 7):
            with self.assertRaises(config.ConfigError, msg=repr(name)):
                config.validate_instance_name(name)


class Profiles(unittest.TestCase):
    def test_repo_profile_loads(self):
        profile, fp = config.load_profile(REPO, "cpu")
        self.assertEqual(profile["schema"], "secure-local-llm/profile@1")
        self.assertEqual(profile["model"]["context_tokens"], 8192)
        self.assertEqual(profile["model"]["max_output_tokens"], 1024)
        self.assertEqual(profile["model"]["parallel"], 1)
        self.assertEqual(len(fp["sha256"]), 64)
        self.assertEqual(fp["bytes"], (REPO / ".devin/profiles/cpu.json").stat().st_size)

    def test_strict_rejections(self):
        cases = []
        raw = valid_profile(); raw["extra"] = 1; cases.append(raw)
        raw = valid_profile(); raw["model"]["temperature"] = 1; cases.append(raw)
        raw = valid_profile(); raw["model"]["parallel"] = True; cases.append(raw)
        raw = valid_profile(); raw["model"]["parallel"] = "1"; cases.append(raw)
        raw = valid_profile(); raw["model"]["parallel"] = 2; cases.append(raw)
        raw = valid_profile(); raw["resources"]["memory_mb"] = 1; cases.append(raw)
        raw = valid_profile(); raw["schema"] = "other/profile@0"; cases.append(raw)
        raw = valid_profile(); del raw["timeouts"]; cases.append(raw)
        raw = valid_profile(); raw["model"].pop("threads"); cases.append(raw)
        raw = valid_profile()
        raw["model"]["max_output_tokens"] = raw["model"]["context_tokens"] + 1
        cases.append(raw)
        for i, bad in enumerate(cases):
            with self.assertRaises(config.ConfigError, msg=f"case {i}"):
                config.parse_profile(bad)

    def test_name_mismatch_rejected(self):
        with self.assertRaises(config.ConfigError):
            config.parse_profile(valid_profile(), expected_name="other")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(config.ConfigError):
            config.parse_json(b'{"a": 1, "a": 2}', "test")

    def test_load_profile_dup_keys_and_bad_json(self):
        with tempfile.TemporaryDirectory() as td:
            prof = Path(td) / ".devin" / "profiles"
            prof.mkdir(parents=True)
            (prof / "cpu.json").write_text(
                '{"schema": "x", "schema": "y"}')
            with self.assertRaises(config.ConfigError):
                config.load_profile(td, "cpu")
            (prof / "cpu.json").write_text("{not json")
            with self.assertRaises(config.ConfigError):
                config.load_profile(td, "cpu")


class SecureReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_regular_file_fingerprint(self):
        f = self.dir / "f.json"
        f.write_bytes(b"data")
        fp = config.fingerprint_file(f)
        self.assertEqual(fp["bytes"], 4)
        self.assertEqual(len(fp["sha256"]), 64)

    def test_relative_path_rejected(self):
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file("relative/path.json")

    def test_symlink_rejected(self):
        target = self.dir / "real"
        target.write_bytes(b"x")
        link = self.dir / "link"
        os.symlink(target, link)
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(link)
        os.symlink(self.dir / "missing", self.dir / "dangling")
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(self.dir / "dangling")

    def test_fifo_and_dir_rejected(self):
        os.mkfifo(self.dir / "fifo")
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(self.dir / "fifo")
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(self.dir)

    def test_hardlink_rejected(self):
        f = self.dir / "f.json"
        f.write_bytes(b"data")
        os.link(f, self.dir / "f2.json")
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(f)

    def test_oversize_rejected(self):
        f = self.dir / "big"
        f.write_bytes(b"x" * (config.MAX_FILE_BYTES + 1))
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(f)

    def test_missing_rejected(self):
        with self.assertRaises(config.ConfigError):
            config.fingerprint_file(self.dir / "missing")


if __name__ == "__main__":
    unittest.main()
