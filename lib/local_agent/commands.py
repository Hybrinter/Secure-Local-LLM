"""Dry-run rendering of the managed lifecycle for operator reference.

Prints the exact argv arrays the controller would execute for the
recorded instance, rendered with ``shlex.join``. Secrets are never
rendered (bind-mounted file paths only). This is a reference view: the
managed lifecycle (``up``/``stop``/``verify``) is authoritative; do not
paste these commands over existing objects.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from . import artifacts, runtime_spec as spec
from .config import load_profile
from .network import HELPER_PATH, render_policy
from .runtime_record import RuntimeFault, load_runtime
from .state import _instance_dir, load_manifest


def _render(root_dir, name, repo):
    root_dir = Path(root_dir)
    repo = Path(repo)
    manifest = load_manifest(root_dir, name)
    if manifest is None:
        raise RuntimeFault(f'instance "{name}": not initialized')
    inst = _instance_dir(root_dir, name)
    record = load_runtime(inst, name)
    if record is None:
        raise RuntimeFault(f'instance "{name}": no runtime record')
    lock, lock_fp = artifacts.load_lock(
        Path(manifest["artifacts_lock"]["path"]))
    if lock_fp["sha256"] != manifest["artifacts_lock"]["sha256"]:
        raise RuntimeFault("artifacts lock drifted since init")
    uuid = manifest["identity"]["uuid"]
    profile, _ = load_profile(repo, manifest["profile"]["name"])
    n = spec.names(uuid)
    control = inst / "control"
    vols = record["objects"]["volumes"]
    images = record["images"]
    pod_ip = record["pod_ip"]
    git_ip = record["git_ip"]

    lines = []
    lines.append(
        "# dry-run reference only; `up`/`stop`/`verify` are the managed "
        "lifecycle")
    lines.append(
        "# argv arrays for the recorded instance; secrets are file paths "
        "only")

    lines += ["", "# internal network (exists; do not recreate)"]
    lines.append(shlex.join([
        "podman", "--remote=false", "network", "create", "--internal",
        "--disable-dns", "--subnet", record["subnet"],
        "--label", f"{spec.LABEL_INSTANCE}={uuid}",
        "--label", f"{spec.LABEL_ROLE}=network",
        record["network"]["name"]]))

    lines += ["", "# workload pod"]
    lines.append(shlex.join(
        ["podman", "--remote=false"]
        + spec.pod_args(n, uuid, record["network"]["name"], pod_ip,
                        profile, base_image=lock["base_image"])))

    lines += ["", "# members"]
    for label, argv in (
        ("inference", spec.inference_args(
            n, uuid, images["inference"], vols["model"], control,
            profile)),
        ("harness", spec.harness_args(
            n, uuid, images["harness"], vols, control, profile)),
        ("git", spec.git_args(
            n, uuid, images["git"], record["network"]["name"], git_ip,
            vols["repo"], control)),
    ):
        lines.append(f"# {label}")
        lines.append(shlex.join(["podman", "--remote=false"] + argv))

    lines += ["", "# namespace policy helper (stdin JSON; handles read "
              "from the target at runtime)"]
    request = {
        "pid": "<target network-namespace pid>",
        "expect_user": "<target user-namespace inode>",
        "expect_net": "<target network-namespace inode>",
        "op": "apply",
        "policy": render_policy(
            record["tables"]["workload"], git_ip, spec.GIT_PORT,
            "workload"),
    }
    lines.append(shlex.join([
        "podman", "--remote=false", "unshare",
        "python3", "-I", "-B", str(HELPER_PATH)])
        + "  # stdin: " + json.dumps(request, sort_keys=True))
    lines.append("")
    return lines


def render_commands(root_dir, name, repo):
    return _render(root_dir, name, repo)
