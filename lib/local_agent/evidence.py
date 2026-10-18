"""Sanitized operator evidence report projected from shared verification.

Only allowlisted fields are emitted: schema, runtime status, controller
version, upstream pins/digests, image IDs and fingerprint hashes,
per-check name/status pairs, exception names and boundary notes, and a
validated projection of the latest operator workflow record if present.
No raw inspect/environment data, paths, namespace inodes, prompts, logs,
or credentials are written. ``status`` describes runtime controls only;
the captured workflow outcome is exposed separately under ``workflow``.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .artifacts import ArtifactError, load_lock
from .config import ConfigError, parse_json
from .runtime_record import (
    RuntimeFault, _read_control, load_runtime)
from .state import (
    StateError, _atomic_write, _require_private_dir, load_manifest,
    locked_instance, manifest_path)
from .verify import verify

EVIDENCE_SCHEMA = "secure-local-llm/evidence@1"
DEMO_SCHEMA = "secure-local-llm/demo@1"
_DEMO_NAME_RE = re.compile(r"demo-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.json")
_INSTANCE_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_DEMO_STATUSES = ("pass", "fail", "protocol-only")
_KNOWN_EXCEPTIONS = (
    "lsm confinement", "storage quotas", "infra hardening")
_DEMO_PHASES = (
    "runtime_and_tool_protocol",
    "pristine_seed_and_new_branch",
    "expected_baseline_test_failure",
    "actual_agent_tool_execution",
    "baseline_tests_unchanged",
    "independent_source_and_addition_oracle",
    "repository_tests",
    "minimal_committed_change_on_designated_branch",
    "remote_publication_and_protected_main",
    "independent_remote_tree_and_content",
    "post_task_runtime_verification",
)
_COMMIT_KEYS = ("seed_commit", "result_commit", "remote_commit")
_BRANCH_RE = re.compile(r"agent/demo-[0-9a-f]{8}")


def _status(result):
    degraded = [c for c in result.checks if c["status"] == "degraded"]
    failed = [c for c in result.checks if c["status"] == "fail"]
    if failed or not result.ok:
        return "fail"
    return "pass-with-exceptions" if degraded else "pass"


def _workflow_projection(inst, expected_name):
    files = [
        p for p in inst.glob("demo-*.json")
        if _DEMO_NAME_RE.fullmatch(p.name)
    ]
    if not files:
        return None
    latest = sorted(files, key=lambda p: p.name)[-1]
    try:
        data = _read_control(latest, {0o600}, "demo record")
        raw = parse_json(data, latest.name)
    except (RuntimeFault, StateError, ConfigError, OSError,
            ValueError):
        return {"file": latest.name, "readable": False}
    if not isinstance(raw, dict) or raw.get("schema") != DEMO_SCHEMA:
        return {"file": latest.name, "readable": False}
    instance = raw.get("instance")
    if (
        raw.get("status") not in _DEMO_STATUSES
        or not isinstance(instance, str)
        or not _INSTANCE_RE.fullmatch(instance)
        or instance != expected_name
    ):
        return {"file": latest.name, "readable": False}
    exceptions = raw.get("exceptions")
    if not isinstance(exceptions, list) or not all(
            isinstance(e, str) and e in _KNOWN_EXCEPTIONS
            for e in exceptions):
        return {"file": latest.name, "readable": False}

    out = {
        "file": latest.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "status": raw["status"],
        "instance": raw["instance"],
        "exceptions": sorted(exceptions),
    }
    phases = raw.get("checks")
    if isinstance(phases, list):
        out["checks"] = [
            {"name": p, "status": "pass"}
            for p in phases if p in _DEMO_PHASES
        ]
    protocol = raw.get("protocol")
    if isinstance(protocol, dict):
        entry = {}
        if protocol.get("status") in ("pass", "fail"):
            entry["status"] = protocol["status"]
        if isinstance(protocol.get("reused"), bool):
            entry["reused"] = protocol["reused"]
        digest = protocol.get("response_sha256")
        if isinstance(digest, str) and len(digest) == 64 \
                and set(digest) <= set("0123456789abcdef"):
            entry["response_sha256"] = digest
        if entry:
            out["protocol"] = entry
    for key in _COMMIT_KEYS:
        value = raw.get(key)
        if isinstance(value, str) and len(value) == 40 \
                and set(value) <= set("0123456789abcdef"):
            out[key] = value
    branch = raw.get("branch")
    if isinstance(branch, str) and _BRANCH_RE.fullmatch(branch):
        out["branch"] = branch
    return out


def _markdown(report):
    lines = [
        "# Evidence report",
        f"schema: {report['schema']}",
        f"generated: {report['generated_utc']}",
        f"controller: {report['controller_version']}",
        f"instance: {report['instance']}",
        f"status: {report['status']} (runtime controls only)",
        "",
        "## Exceptions",
    ]
    for exc in report["exceptions"]:
        lines.append(f"- {exc}")
    lines.append("")
    lines.append("## Checks")
    for c in report["checks"]:
        lines.append(f"- {c['status']}: {c['name']}")
    if report.get("workflow"):
        lines += [
            "", "## Captured workflow record",
            f"- file: {report['workflow']['file']}",
            f"- status: {report['workflow'].get('status')}"]
    lines.append("")
    return "\n".join(lines)


def evidence(root_dir, name, repo, runner, verify_fn=None):
    root_dir = Path(root_dir)
    repo = Path(repo)
    try:
        _require_private_dir(manifest_path(root_dir, name).parent)
    except FileNotFoundError as exc:
        raise StateError(f'instance "{name}": not initialized') from exc
    with locked_instance(root_dir, name) as inst:
        manifest = load_manifest(root_dir, name)
        if manifest is None:
            raise StateError(f'instance "{name}": not initialized')
        return _evidence_locked(
            root_dir, name, repo, runner, manifest, inst, verify_fn)


def _evidence_locked(root_dir, name, repo, runner, manifest, inst,
                     verify_fn):
    record = load_runtime(inst, name)
    if verify_fn is None:
        verify_fn = verify
    result = verify_fn(root_dir, name, repo, runner)

    upstream = {"artifacts_lock_sha256":
                manifest["artifacts_lock"]["sha256"]}
    try:
        lock, fp = load_lock(Path(manifest["artifacts_lock"]["path"]))
        if fp["sha256"] != manifest["artifacts_lock"]["sha256"]:
            upstream["error"] = (
                "artifacts lock fingerprint mismatch: pins withheld")
        else:
            upstream["base_image"] = lock["base_image"]
            upstream["platform"] = lock["platform"]
            upstream["artifacts"] = {
                n: {"version": s["version"],
                    "algorithm": s["hash"]["algorithm"],
                    "digest": s["hash"]["hex"]}
                for n, s in lock["artifacts"].items()
            }
    except Exception as exc:
        upstream["error"] = (
            f"artifacts lock pins unavailable: {type(exc).__name__}")

    checks = [{"name": c["name"], "status": c["status"]}
              for c in result.checks]
    report = {
        "schema": EVIDENCE_SCHEMA,
        "generated_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "controller_version": __version__,
        "instance": manifest["identity"]["name"],
        "status": _status(result),
        "status_scope": "runtime controls only; captured workflow "
                        "outcome is reported separately",
        "upstream": upstream,
        "runtime": {
            "profile_sha256": manifest["profile"]["sha256"],
            "images": dict(record["images"]) if record else {},
            "fingerprints": dict(record["fingerprints"]) if record else {},
            "control_files": sorted(record["control_sha256"])
            if record else [],
        },
        "checks": checks,
        "exceptions": [
            c["name"] for c in result.checks if c["status"] == "degraded"],
        "boundary_notes": [
            "workload confinement is namespace, cgroup, seccomp, and "
            "capability controls only; mandatory access control status "
            "is reported, not assumed",
            "writable storage quotas are reported, not assumed",
            "security-oriented proof of concept; not an authorized "
            "system",
        ],
    }
    workflow = _workflow_projection(inst, name)
    if workflow is not None:
        report["workflow"] = workflow

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    nonce = secrets.token_hex(4)
    out_json = inst / f"evidence-{stamp}-{nonce}.json"
    out_md = inst / f"evidence-{stamp}-{nonce}.md"
    for dest in (out_json, out_md):
        try:
            dest.lstat()
        except FileNotFoundError:
            continue
        raise StateError(f"evidence output already exists: {dest}")
    _atomic_write(
        out_json, json.dumps(report, indent=2, sort_keys=True).encode()
        + b"\n", 0o600, replace=False)
    _atomic_write(out_md, _markdown(report).encode(), 0o600,
                  replace=False)
    return report, out_json, out_md
