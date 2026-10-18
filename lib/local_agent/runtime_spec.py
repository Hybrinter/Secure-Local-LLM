"""Pure runtime spec builders: argv, mounts, resources, rendered config."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

LABEL_INSTANCE = "org.secure-local-llm.instance"
LABEL_ROLE = "org.secure-local-llm.role"
GIT_PORT = 2222
POD_OFFSET, GIT_OFFSET = 2, 3
MIN_MEMORY_MB = 8192
MIN_PIDS = 128

MODEL_REQUIRED_FLAGS = (
    "--model", "--alias", "--host", "--port", "--ctx-size", "--parallel",
    "--n-gpu-layers", "--threads", "--threads-batch", "--jinja",
    "--api-key-file", "--no-webui", "--no-slots", "--predict",
)

CONTROL_FILES = (
    "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub",
    "client_key", "client_key.pub", "authorized_keys",
    "model-api-key", "service.json", "gitconfig", "ssh_config",
    "known_hosts", "opencode.json",
)

SEED_FILES = {
    "calculator.py":
        "def add(left, right):\n    return left - right\n",
    "test_calculator.py":
        "import unittest\n"
        "from calculator import add\n"
        "\n"
        "class Addition(unittest.TestCase):\n"
        "    def test_positive(self):\n"
        "        self.assertEqual(add(2, 3), 5)\n"
        "    def test_negative(self):\n"
        "        self.assertEqual(add(-2, 3), 1)\n"
        "    def test_zero(self):\n"
        "        self.assertEqual(add(0, 0), 0)\n"
        "\n"
        "if __name__ == \"__main__\":\n"
        "    unittest.main()\n",
}

GITCONFIG = (
    "[core]\n\thooksPath = /dev/null\n"
    "[protocol]\n\tversion = 2\n"
    "[protocol \"file\"]\n\tallow = never\n"
    "[protocol \"ext\"]\n\tallow = never\n"
)

SSH_CONFIG = """Host git-fixture
  HostName {git_ip}
  Port 2222
  User git
  IdentityFile /run/local-agent/client_key
  UserKnownHostsFile /run/local-agent/known_hosts
  BatchMode yes
  IdentitiesOnly yes
  StrictHostKeyChecking yes
  IdentityAgent none
  ForwardAgent no
  ForwardX11 no
  ClearAllForwardings yes
"""

BOOTSTRAP_SH = """set -eu
seeded="$(git -C /repos/demo.git config --get local-agent.seeded 2>/dev/null || true)"
main="$(git -C /repos/demo.git rev-parse --verify -q refs/heads/main 2>/dev/null || true)"
if [ "$seeded" = "1" ]; then
  if [ -z "$main" ]; then
    echo "seed marker present but main missing; refusing" >&2
    exit 1
  fi
  if [ ! -d /workspace/repo/.git ]; then
    echo "seed marker present but worktree git dir missing; refusing" >&2
    exit 1
  fi
  origin="$(git -C /workspace/repo remote get-url origin 2>/dev/null || true)"
  if [ "$origin" != "ssh://git@git-fixture:2222/repos/demo.git" ]; then
    echo "worktree remote identity drifted; refusing" >&2
    exit 1
  fi
  if [ ! -f /workspace/repo/test_calculator.py ]; then
    echo "baseline test file missing; refusing" >&2
    exit 1
  fi
  test_sha="$(sha256sum /workspace/repo/test_calculator.py | cut -d' ' -f1)"
  if [ "$test_sha" != "__TEST_SHA256__" ]; then
    echo "baseline test file drifted; refusing" >&2
    exit 1
  fi
  echo "main=$main"
  exit 0
fi
if [ -n "$main" ]; then
  echo "bare repo initialized but seed marker absent; refusing" >&2
  exit 1
fi
for f in calculator.py test_calculator.py; do
  if [ -e "/workspace/repo/$f" ]; then
    echo "existing worktree file $f without seed marker; refusing" >&2
    exit 1
  fi
done
if [ -d /workspace/repo/.git ]; then
  echo "existing git worktree without seed marker; refusing" >&2
  exit 1
fi
mkdir -p /workspace/repo
git init -q -b main /workspace/repo
cp /seed/calculator.py /seed/test_calculator.py /workspace/repo/
git -C /workspace/repo config user.name "Local Agent Demo"
git -C /workspace/repo config user.email "agent@example.invalid"
git -C /workspace/repo add calculator.py test_calculator.py
git -C /workspace/repo commit -qm "seed demo fixture"
git init -q --bare --object-format=sha1 -b main /repos/demo.git
git -C /workspace/repo -c protocol.file.allow=always \
  push -q /repos/demo.git HEAD:refs/heads/main
git -C /workspace/repo remote add origin ssh://git@git-fixture:2222/repos/demo.git
main="$(git -C /repos/demo.git rev-parse refs/heads/main)"
git -C /repos/demo.git config local-agent.seeded 1
echo "main=$main"
"""
BOOTSTRAP_SH = BOOTSTRAP_SH.replace(
    "__TEST_SHA256__",
    hashlib.sha256(SEED_FILES["test_calculator.py"].encode()).hexdigest(),
)

MODEL_POPULATE_SH = """set -eu
dst=/models/model.gguf
if [ -L "$dst" ]; then
  echo "model destination is a symlink; refusing" >&2
  exit 1
fi
if [ -e "$dst" ]; then
  [ -f "$dst" ] || { echo "model destination not regular; refusing" >&2; exit 1; }
  actual="$(sha256sum "$dst" | cut -d' ' -f1)"
  [ "$actual" = "$EXPECTED_MODEL_SHA" ] || {
    echo "model volume drifted; refusing" >&2; exit 1; }
  exit 0
fi
tmp="$(mktemp /models/.model.XXXXXX)"
cp /seed-model/model.gguf "$tmp"
actual="$(sha256sum "$tmp" | cut -d' ' -f1)"
if [ "$actual" != "$EXPECTED_MODEL_SHA" ]; then
  rm -f "$tmp"
  exit 1
fi
mv "$tmp" "$dst"
"""

PROBE_MODEL = """
import json, urllib.request
key = open('/run/local-agent/model-api-key').read().strip()
req = urllib.request.Request(
    'http://127.0.0.1:8080/v1/models',
    headers={'Authorization': 'Bearer ' + key})
with urllib.request.urlopen(req, timeout=5) as r:
    data = json.loads(r.read())
ids = [m.get('id') for m in data.get('data', [])]
assert ids == ['granite-cpu'], ids
"""

PROBE_SERVICE = """
import base64, json, urllib.request
svc = json.loads(open('/run/local-agent/opencode/service.json').read())
tok = base64.b64encode(('opencode:' + svc['password']).encode()).decode()
req = urllib.request.Request(
    'http://127.0.0.1:%d/api/config' % svc['port'],
    headers={'Authorization': 'Basic ' + tok})
with urllib.request.urlopen(req, timeout=5) as r:
    assert r.status == 200
"""

HARNESS_ENV = {
    "OPENCODE_CONFIG_DIR": "/run/local-agent/opencode",
    "OPENCODE_CONFIG_PROJECT_DISABLE": "true",
    "OPENCODE_DISABLE_MODELS_FETCH": "true",
    "HOME": "/state",
    "XDG_DATA_HOME": "/state/.local/share",
    "XDG_STATE_HOME": "/state/.local/state",
    "XDG_CACHE_HOME": "/state/.cache",
    "GIT_SSH_COMMAND": "ssh -F /run/local-agent/ssh_config",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/run/local-agent/gitconfig",
}


def names(uuid):
    short = uuid.replace("-", "")[:8]
    return {
        "net": f"sll-{short}-net",
        "pod": f"sll-{short}-pod",
        "inference": f"sll-{short}-inference",
        "harness": f"sll-{short}-harness",
        "git": f"sll-{short}-git",
        "vol_workspace": f"sll-{short}-ws",
        "vol_state": f"sll-{short}-state",
        "vol_model": f"sll-{short}-model",
        "vol_repo": f"sll-{short}-repo",
    }


def check_profile(profile):
    res = profile["resources"]
    if res["memory_mb"] < MIN_MEMORY_MB:
        raise ValueError(
            f"profile memory_mb {res['memory_mb']} < {MIN_MEMORY_MB}")
    if res["pids"] < MIN_PIDS:
        raise ValueError(f"profile pids {res['pids']} < {MIN_PIDS}")


def model_argv(profile):
    m = profile["model"]
    return [
        "/opt/llama/llama-server",
        "--model", "/models/model.gguf",
        "--alias", "granite-cpu",
        "--host", "127.0.0.1",
        "--port", "8080",
        "--ctx-size", str(m["context_tokens"]),
        "--parallel", str(m["parallel"]),
        "--n-gpu-layers", "0",
        "--threads", str(m["threads"]),
        "--threads-batch", str(m["threads"]),
        "--jinja",
        "--api-key-file", "/run/local-agent/model-api-key",
        "--no-webui",
        "--no-slots",
        "--predict", str(m["max_output_tokens"]),
    ]


def render_opencode_config(template_bytes, profile):
    cfg = json.loads(template_bytes)
    model = cfg["providers"]["local"]["models"]["granite-cpu"]
    model["limit"]["context"] = profile["model"]["context_tokens"]
    model["limit"]["output"] = profile["model"]["max_output_tokens"]
    cfg["providers"]["local"]["settings"]["timeout"] = (
        profile["timeouts"]["request_seconds"] * 1000)
    cfg["agents"]["build"]["request"]["body"]["max_tokens"] = (
        profile["model"]["max_output_tokens"])
    return json.dumps(cfg, indent=2, sort_keys=True).encode() + b"\n"


def config_sha256(data):
    return hashlib.sha256(data).hexdigest()


def seed_sha256():
    parts = [
        hashlib.sha256(SEED_FILES[k].encode()).hexdigest()
        for k in sorted(SEED_FILES)
    ]
    return hashlib.sha256("".join(parts).encode()).hexdigest()


def _labels(uuid, role):
    return [
        "--label", f"{LABEL_INSTANCE}={uuid}",
        "--label", f"{LABEL_ROLE}={role}",
    ]


def pod_args(n, uuid, net, pod_ip, profile, *, base_image):
    res = profile["resources"]
    return [
        "pod", "create", "--name", n["pod"],
        "--network", net, "--ip", pod_ip,
        "--share", "net",
        "--userns", "keep-id:uid=1000,gid=1000",
        "--infra-image", base_image,
        "--infra-command", "sleep infinity",
        "--memory", f"{res['memory_mb']}m",
        "--memory-swap", f"{res['memory_mb']}m",
        "--cpus", str(res["cpus"]),
        "--security-opt", "no-new-privileges",
        "--dns", "none",
        *_labels(uuid, "pod"),
    ]


def _member_base(uuid, role):
    return [
        "create", "--pull=never",
        *_labels(uuid, role),
        "--user", "1000:1000",
        "--read-only", "--read-only-tmpfs=false",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--ulimit", "nofile=1024:1024",
        "--ulimit", "core=0:0",
        "--cgroupns", "private",
        "--pid", "private",
        "--ipc", "private",
        "--uts", "private",
        "--log-driver", "k8s-file",
        "--log-opt", "max-size=4mb",
        "--http-proxy=false",
        "--image-volume", "ignore",
        "--tmpfs", "/run/local-agent:rw,mode=755,size=16m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m",
    ]


def _member_pids(profile):
    return profile["resources"]["pids"] // 2


def inference_args(n, uuid, image, model_vol, control, profile):
    res = profile["resources"]
    mb = 3 * res["memory_mb"] // 4
    return [str(a) for a in [
        *_member_base(uuid, "inference"),
        "--name", n["inference"],
        "--pod", n["pod"],
        "--memory", f"{mb}m",
        "--memory-swap", f"{mb}m",
        "--cpus", str(res["cpus"]),
        "--pids-limit", str(_member_pids(profile)),
        "-v", f"{model_vol}:/models:ro,nosuid,nodev,noexec",
        "-v", f"{control}/model-api-key"
              ":/run/local-agent/model-api-key:ro,nosuid,nodev,noexec",
        image,
        *model_argv(profile),
    ]]


def harness_args(n, uuid, image, vols, control, profile):
    res = profile["resources"]
    mb = res["memory_mb"] // 4
    args = [
        *_member_base(uuid, "harness"),
        "--name", n["harness"],
        "--pod", n["pod"],
        "--memory", f"{mb}m",
        "--memory-swap", f"{mb}m",
        "--cpus", str(res["cpus"]),
        "--pids-limit", str(_member_pids(profile)),
        "-v", f"{vols['workspace']}:/workspace:rw,nosuid,nodev",
        "-v", f"{vols['state']}:/state:rw,nosuid,nodev",
        "-v", f"{control}/opencode.json"
              ":/run/local-agent/opencode/opencode.json:ro"
              ",nosuid,nodev,noexec",
        "-v", f"{control}/service.json"
              ":/run/local-agent/opencode/service.json:ro"
              ",nosuid,nodev,noexec",
        "-v", f"{control}/model-api-key:/run/local-agent/model-api-key"
              ":ro,nosuid,nodev,noexec",
        "-v", f"{control}/ssh_config:/run/local-agent/ssh_config"
              ":ro,nosuid,nodev,noexec",
        "-v", f"{control}/client_key:/run/local-agent/client_key"
              ":ro,nosuid,nodev,noexec",
        "-v", f"{control}/known_hosts:/run/local-agent/known_hosts"
              ":ro,nosuid,nodev,noexec",
        "-v", f"{control}/gitconfig:/run/local-agent/gitconfig"
              ":ro,nosuid,nodev,noexec",
    ]
    for key, value in sorted(HARNESS_ENV.items()):
        args += ["-e", f"{key}={value}"]
    return [str(a) for a in args] + [image, "opencode", "serve", "--service"]


def git_args(n, uuid, image, net, git_ip, repo_vol, control):
    return [str(a) for a in [
        *_member_base(uuid, "git"),
        "--name", n["git"],
        "--network", net,
        "--ip", git_ip,
        "--userns", "keep-id:uid=1000,gid=1000",
        "--dns", "none",
        "--memory", "512m",
        "--memory-swap", "512m",
        "--cpus", "1",
        "--pids-limit", "64",
        "-v", f"{repo_vol}:/repos:rw,nosuid,nodev",
        "-v", f"{control}/ssh_host_ed25519_key"
              ":/run/local-agent/ssh_host_ed25519_key:ro"
              ",nosuid,nodev,noexec",
        "-v", f"{control}/authorized_keys:/run/local-agent/authorized_keys"
              ":ro,nosuid,nodev,noexec",
        image,
        "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config_fixture",
    ]]


def bootstrap_args(uuid, image, vols, control):
    return [str(a) for a in [
        "run", "--rm", "--pull=never", "--network", "none",
        "--userns", "keep-id:uid=1000,gid=1000",
        "--user", "1000:1000",
        "--cap-drop", "ALL", "--read-only",
        "--security-opt", "no-new-privileges",
        "--memory", "512m", "--memory-swap", "512m",
        "--pids-limit", "64",
        *_labels(uuid, "bootstrap"),
        "-v", f"{vols['workspace']}:/workspace:rw",
        "-v", f"{vols['repo']}:/repos:rw",
        "-v", f"{control}/seed:/seed:ro",
        image, "sh", "-c", BOOTSTRAP_SH,
    ]]


def model_populate_args(uuid, image, model_vol, model_path, model_sha):
    return [str(a) for a in [
        "run", "--rm", "--pull=never", "--network", "none",
        "--userns", "keep-id:uid=1000,gid=1000",
        "--user", "1000:1000",
        "--cap-drop", "ALL", "--read-only",
        "--security-opt", "no-new-privileges",
        "--memory", "512m", "--memory-swap", "512m",
        "--pids-limit", "64",
        *_labels(uuid, "bootstrap"),
        "-v", f"{model_vol}:/models:rw",
        "-v", f"{model_path}:/seed-model/model.gguf:ro",
        "-e", f"EXPECTED_MODEL_SHA={model_sha}",
        image, "sh", "-c", MODEL_POPULATE_SH,
    ]]
