"""Records-loaded verify() call-path tests with fakes; no real instance."""

import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_agent import verify  # noqa: E402
from verify_fixtures import (  # noqa: E402
    REPO_ROOT, TEMPLATE_REL, _fail_names, verify_env,
)

TEMPLATE_SHA256 = (
    "388aa0b920c56e45f01839baa2501d6aa14081e58b3c9263c04bd5e05bc97754"
)
NATIVE_FP = "native config fingerprint"


def _named(result, name):
    return [c for c in result.checks if c["name"] == name]


class SourceTemplateFile(unittest.TestCase):
    def test_checked_in_bytes_pinned(self):
        data = (REPO_ROOT / TEMPLATE_REL).read_bytes()
        self.assertEqual(
            hashlib.sha256(data).hexdigest(), TEMPLATE_SHA256)


class SourceConfigCallPath(unittest.TestCase):
    def test_matching_source_sha_passes(self):
        with verify_env() as env:
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        checks = _named(res, NATIVE_FP)
        self.assertEqual(_named(res, "records loaded")[0]["status"],
                         "pass")
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "pass")

    def test_drifted_source_bytes_fail(self):
        with verify_env() as env:
            env.template_path.write_bytes(b"{}")
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        checks = _named(res, NATIVE_FP)
        self.assertEqual(_named(res, "records loaded")[0]["status"],
                         "pass")
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "fail")
        self.assertFalse(res.ok)
        self.assertEqual(
            _named(res, "record images match prepared")[0]["status"],
            "pass")

    def test_missing_source_returns_failed_result(self):
        with verify_env() as env:
            env.template_path.unlink()
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        checks = _named(res, NATIVE_FP)
        self.assertEqual(_named(res, "records loaded")[0]["status"],
                         "pass")
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "fail")
        self.assertEqual(res.checks[-1]["name"], NATIVE_FP)
        self.assertFalse(res.ok)

    def test_source_read_denied_returns_failed_result(self):
        with verify_env() as env:
            with mock.patch.object(
                    Path, "read_bytes",
                    side_effect=PermissionError("read denied")):
                res = verify.verify(
                    env.root, env.name, env.repo, env.runner)
        checks = _named(res, NATIVE_FP)
        self.assertEqual(_named(res, "records loaded")[0]["status"],
                         "pass")
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "fail")
        self.assertEqual(res.checks[-1]["name"], NATIVE_FP)
        self.assertFalse(res.ok)


class EndpointAddressCallPath(unittest.TestCase):
    EP = ("git endpoint network membership", "git endpoint ipv4",
          "infra endpoint network membership", "infra endpoint ipv4")

    def _mutate_inspect(self, env, cid, addr):
        env.inspects[cid]["NetworkSettings"]["Networks"][
            env.net_name]["IPAddress"] = addr

    def test_endpoint_addresses_baseline_pass(self):
        with verify_env() as env:
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        for name in self.EP:
            self.assertEqual(
                _named(res, name)[0]["status"], "pass", name)

    def test_git_inspect_drift_fails_only_git(self):
        with verify_env() as env:
            base = verify.verify(env.root, env.name, env.repo, env.runner)
            self._mutate_inspect(
                env, env.record["objects"]["containers"]["git"],
                "10.240.7.9")
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        self.assertEqual(
            set(_fail_names(res)) - set(_fail_names(base)),
            {"git endpoint ipv4"})
        self.assertEqual(
            _named(res, "infra endpoint ipv4")[0]["status"], "pass")
        self.assertFalse(res.ok)

    def test_infra_inspect_drift_fails_only_infra(self):
        with verify_env() as env:
            base = verify.verify(env.root, env.name, env.repo, env.runner)
            self._mutate_inspect(
                env, env.record["objects"]["infra"], "10.240.7.9")
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        self.assertEqual(
            set(_fail_names(res)) - set(_fail_names(base)),
            {"infra endpoint ipv4"})
        self.assertEqual(
            _named(res, "git endpoint ipv4")[0]["status"], "pass")
        self.assertFalse(res.ok)

    def test_git_expected_ip_comes_from_record(self):
        with verify_env() as env:
            base = verify.verify(env.root, env.name, env.repo, env.runner)
            env.record["git_ip"] = "10.240.7.9"
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        self.assertEqual(
            set(_fail_names(res)) - set(_fail_names(base)),
            {"git endpoint ipv4"})
        self.assertEqual(
            _named(res, "infra endpoint ipv4")[0]["status"], "pass")
        self.assertFalse(res.ok)

    def test_infra_expected_ip_comes_from_record(self):
        with verify_env() as env:
            base = verify.verify(env.root, env.name, env.repo, env.runner)
            env.record["pod_ip"] = "10.240.7.9"
            res = verify.verify(env.root, env.name, env.repo, env.runner)
        self.assertEqual(
            set(_fail_names(res)) - set(_fail_names(base)),
            {"infra endpoint ipv4"})
        self.assertEqual(
            _named(res, "git endpoint ipv4")[0]["status"], "pass")
        self.assertFalse(res.ok)


if __name__ == "__main__":
    unittest.main()
