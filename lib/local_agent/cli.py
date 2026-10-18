"""Operator CLI: doctor/status/init implemented; lifecycle commands fail closed."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path

from .artifacts import ArtifactError, load_lock
from .config import ConfigError, fingerprint_file, load_profile, validate_instance_name
from .prepare import PrepareError, prepare as _prepare_run
from .podman import PodmanError
from .runner import Runner, RunnerError
from .runtime import (
    RuntimeFault,
    status as _rt_status,
    stop as _rt_stop,
    up as _rt_up,
)
from .verify import verify as _verify_run
from .state import (
    StateError,
    init_instance,
    load_git_prepared,
    load_manifest,
    state_root,
)

EXIT_OK, EXIT_ERROR, EXIT_UNAVAILABLE = 0, 1, 3
UNAVAILABLE_COMMANDS = ()
REQUIRED_TOOLS = ("nft", "nsenter", "ssh", "ssh-keygen")
REQUIRED_CGROUPS = ("cpu", "memory", "pids")
TESTED_PODMAN_VERSION = (4, 9, 3)
MIN_PODMAN_VERSION = (4, 9)


class _Unavailable(Exception):
    pass


def repo_root():
    return Path(__file__).resolve().parents[2]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="local-agent",
        description="Restricted local coding-agent prototype controller",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check host prerequisites (read-only)")
    for cmd in ("up", "stop", "status", "verify", "chat", "evidence",
                "commands", *UNAVAILABLE_COMMANDS):
        sp = sub.add_parser(cmd)
        sp.add_argument("--instance", default="demo", metavar="NAME")
    demo = sub.add_parser(
        "demo", help="operator-controlled synthetic model workflow")
    demo.add_argument("--instance", default="demo", metavar="NAME")
    demo.add_argument("--protocol-only", action="store_true",
                      help="verify runtime and tool protocol only; the "
                      "agent task is NOT attempted")
    init = sub.add_parser("init", help="initialize instance state")
    init.add_argument("--instance", default="demo", metavar="NAME")
    init.add_argument("--profile", default="cpu", metavar="NAME")
    init.add_argument("--acknowledge-prototype-no-lsm", action="store_true")
    init.add_argument("--artifacts-lock", default=None, metavar="PATH")
    prep = sub.add_parser("prepare", help="stage artifacts and build images")
    prep.add_argument("--instance", default="demo", metavar="NAME")
    prep.add_argument("--allow-network", action="store_true")
    bak = sub.add_parser(
        "backup", help="export quiesced data volumes to a private archive")
    bak.add_argument("--instance", default="demo", metavar="NAME")
    bak.add_argument("--output", default=None,
                     metavar="DIR", help="absolute private directory")
    res = sub.add_parser(
        "restore", help="restore data volumes into a fresh instance")
    res.add_argument("--instance", default="demo", metavar="SOURCE")
    res.add_argument("--archive", required=True, metavar="PATH")
    res.add_argument("--new-instance", required=True, metavar="NAME")
    return parser


class _Report:
    def __init__(self):
        self.failures = []

    def check(self, cond, msg):
        print(("ok" if cond else "fail") + f": {msg}")
        if not cond:
            self.failures.append(msg)

    def fail(self, msg):
        self.check(False, msg)

    def warn(self, msg):
        print(f"warn: {msg}")


def _podman_info(run, report):
    try:
        res = run.podman(["info", "--format", "json"], timeout=30)
    except RunnerError as exc:
        report.fail(f"podman unavailable: {exc}")
        return None
    if res.timed_out:
        report.fail("podman info timed out")
        return None
    if res.returncode != 0:
        report.fail(f"podman info rc={res.returncode}: {res.stderr.strip()}")
        return None
    try:
        info = json.loads(res.stdout)
    except json.JSONDecodeError:
        report.fail("podman info returned invalid JSON")
        return None
    if not isinstance(info, dict) or not isinstance(info.get("host"), dict):
        report.fail("podman info returned unexpected structure")
        return None
    return info


def _podman_version(info):
    ver = info.get("version")
    if not isinstance(ver, dict):
        return None, ver
    raw = ver.get("Version")
    if not isinstance(raw, str):
        return None, raw
    parts = raw.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None, raw
    return tuple(int(p) for p in parts), raw


def _cmd_doctor(run):
    r = _Report()
    r.check(sys.version_info >= (3, 11), f"python {platform.python_version()} >= 3.11")
    r.check(
        platform.system() == "Linux" and platform.machine() == "x86_64",
        "platform linux/x86_64",
    )
    for tool in REQUIRED_TOOLS:
        r.check(bool(shutil.which(tool)), f"tool present: {tool}")
    info = _podman_info(run, r)
    if info is not None:
        version, raw_ver = _podman_version(info)
        if version is None or version < MIN_PODMAN_VERSION:
            r.fail(
                f"podman version unsupported/malformed: {raw_ver!r} "
                f"(requires >= {'.'.join(map(str, MIN_PODMAN_VERSION))})"
            )
        elif version == TESTED_PODMAN_VERSION:
            r.check(True, f"podman {raw_ver} (tested version)")
        else:
            r.warn(
                f"podman {raw_ver} untested; prototype verified on "
                f"{'.'.join(map(str, TESTED_PODMAN_VERSION))}"
            )
        host = info["host"]
        sec = host.get("security")
        if not isinstance(sec, dict):
            r.fail("podman info: host.security is not an object")
        else:
            r.check(sec.get("rootless") is True, "podman rootless")
            r.check(sec.get("seccompEnabled") is True, "seccomp enabled")
            if (
                sec.get("selinuxEnabled") is not True
                and sec.get("apparmorEnabled") is not True
            ):
                r.warn(
                    "no LSM confinement active (AppArmor/SELinux); prototype-only "
                    "exception, init requires --acknowledge-prototype-no-lsm"
                )
        r.check(host.get("cgroupVersion") == "v2", "cgroups v2")
        controllers = host.get("cgroupControllers")
        if not isinstance(controllers, list) or not all(
            isinstance(c, str) for c in controllers
        ):
            r.fail("podman info: cgroupControllers is not a string list")
        else:
            for ctrl in REQUIRED_CGROUPS:
                r.check(ctrl in controllers, f"cgroup controller: {ctrl}")
        r.warn("writable storage quotas are not verified (not established)")
    return EXIT_ERROR if r.failures else EXIT_OK


def _cmd_status(args, runner=None):
    manifest = load_manifest(state_root(), args.instance)
    if manifest is None:
        print(f'instance "{args.instance}": not initialized')
        return EXIT_OK
    resources = manifest.get("resources", {})
    print(f'instance "{args.instance}": initialized')
    print(f'  uuid: {manifest.get("identity", {}).get("uuid")}')
    print(f'  profile: {manifest.get("profile", {}).get("name")}')
    print(f'  pod: {resources.get("pod_id") or "none"}')
    try:
        rt = _rt_status(state_root(), args.instance, runner or Runner())
    except RuntimeFault as exc:
        print(f'  runtime: unavailable ({exc})')
        return EXIT_OK
    print(f'  pod_state: {rt.get("pod_state", "none")}')
    for role, st in sorted(rt.get("containers", {}).items()):
        print(f'  container-{role}: {st}')
    return EXIT_OK


def _cmd_init(args):
    if not args.acknowledge_prototype_no_lsm:
        raise StateError(
            "init requires --acknowledge-prototype-no-lsm (prototype-only exception)"
        )
    root = repo_root()
    profile, profile_fp = load_profile(root, args.profile)
    lock_path = args.artifacts_lock or str(root / ".devin" / "artifacts.lock.json")
    _lock, lock_fp = load_lock(lock_path)
    manifest = init_instance(
        state_root(), args.instance, profile, profile_fp, lock_fp,
        args.acknowledge_prototype_no_lsm,
    )
    print(f'instance "{args.instance}": initialized')
    print(f'  uuid: {manifest["identity"]["uuid"]}')
    print(f'  profile: {profile["name"]} ({profile_fp["sha256"][:16]}...)')
    print(f'  artifacts lock: {lock_fp["sha256"][:16]}...')
    return EXIT_OK


def _cmd_up(args, runner):
    def status(subject, phase):
        print(f"{subject}: {phase}")

    record = _rt_up(
        state_root(), args.instance, repo_root(), runner, status=status)
    result = _verify_run(
        state_root(), args.instance, repo_root(), runner)
    failed = [c for c in result.checks if c["status"] == "fail"]
    for c in failed:
        print(f"verify-fail: {c['name']}: {c['detail']}", file=sys.stderr)
    if failed:
        try:
            _rt_stop(state_root(), args.instance, runner)
        except RuntimeFault as exc:
            print(f"error: cleanup stop failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"up: ready ({record['pod_ip']} pod, {record['git_ip']} git)")
    return EXIT_OK


def _cmd_verify(args, runner):
    result = _verify_run(
        state_root(), args.instance, repo_root(), runner)
    for c in result.checks:
        line = f"{c['status']}: {c['name']}"
        if c["detail"]:
            line += f" ({c['detail']})"
        print(line)
    if not result.ok:
        try:
            _rt_stop(state_root(), args.instance, runner)
            print("failed verify: stopped affected owned members")
        except RuntimeFault as exc:
            print(f"error: cleanup stop failed: {exc}", file=sys.stderr)
    return EXIT_OK if result.ok else EXIT_ERROR


def _cmd_stop(args, runner):
    result = _rt_stop(state_root(), args.instance, runner)
    print(f"stopped: {', '.join(result['stopped']) or 'nothing'}")
    return EXIT_OK


def _cmd_chat(args, runner):
    from .session import chat
    chat(state_root(), args.instance, repo_root(), runner)
    return EXIT_OK


def _cmd_demo(args, runner):
    from .demo import DemoError, demo
    try:
        result, path = demo(
            state_root(), args.instance, repo_root(), runner,
            protocol_only=args.protocol_only)
    except DemoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"demo status: {result['status']}")
    print(f"evidence: {path}")
    if args.protocol_only:
        print("protocol-only: agent task NOT attempted")
        return EXIT_OK if result["status"] == "protocol-only" \
            else EXIT_ERROR
    return EXIT_OK if result.get("status") == "pass" else EXIT_ERROR


def _cmd_evidence(args, runner):
    from .evidence import evidence
    report, out_json, out_md = evidence(
        state_root(), args.instance, repo_root(), runner)
    print(f"evidence status: {report['status']}")
    print(f"json: {out_json}")
    print(f"markdown: {out_md}")
    return EXIT_OK if report["status"] != "fail" else EXIT_ERROR


def _cmd_commands(args):
    from .commands import render_commands
    for line in render_commands(state_root(), args.instance, repo_root()):
        print(line)
    return EXIT_OK


def _cmd_backup(args, runner):
    from . import backup
    result = backup.backup(state_root(), args.instance, runner,
                           output_dir=args.output, repo=repo_root())
    print(f"backup: {result['archive']}")
    for role, entry in sorted(result["volumes"].items()):
        print(f"  {role}: {entry['bytes']} bytes "
              f"sha256:{entry['sha256'][:16]}")
    return EXIT_OK


def _cmd_restore(args, runner):
    from . import backup
    validate_instance_name(args.new_instance)
    result = backup.restore(state_root(), args.instance, args.archive,
                            args.new_instance, repo_root(), runner)
    print(f"restore: {result['instance']} from {result['source']}")
    print(f"archive sha256: {result['archive_sha256']}")
    print("data volumes restored into a fresh instance; runtime "
          "bindings and controls are new")
    for step in result["next"]:
        print(f"next: {step}")
    return EXIT_OK


def _cmd_prepare(args, runner):
    def status(subject, phase):
        print(f"{subject}: {phase}")

    record = _prepare_run(
        state_root(), args.instance, repo_root(), runner,
        args.allow_network, status=status,
    )
    for role, image_id in sorted(record["images"].items()):
        print(f"image-{role}: {image_id}")
    git_record = load_git_prepared(state_root(), args.instance)
    if git_record is not None:
        print(f"image-git: {git_record['image_id']}")
    print("prepared: ok")
    return EXIT_OK


def main(argv=None, runner=None):
    args = build_parser().parse_args(argv)
    try:
        if hasattr(args, "instance"):
            validate_instance_name(args.instance)
        if args.command in UNAVAILABLE_COMMANDS:
            raise _Unavailable(args.command)
        if args.command == "doctor":
            return _cmd_doctor(runner or Runner())
        if args.command == "status":
            return _cmd_status(args, runner or Runner())
        if args.command == "init":
            return _cmd_init(args)
        if args.command == "prepare":
            return _cmd_prepare(args, runner or Runner())
        if args.command == "up":
            if _cmd_doctor(runner or Runner()) != EXIT_OK:
                return EXIT_ERROR
            return _cmd_up(args, runner or Runner())
        if args.command == "stop":
            return _cmd_stop(args, runner or Runner())
        if args.command == "verify":
            return _cmd_verify(args, runner or Runner())
        if args.command == "chat":
            return _cmd_chat(args, runner or Runner())
        if args.command == "demo":
            return _cmd_demo(args, runner or Runner())
        if args.command == "evidence":
            return _cmd_evidence(args, runner or Runner())
        if args.command == "commands":
            return _cmd_commands(args)
        if args.command == "backup":
            return _cmd_backup(args, runner or Runner())
        if args.command == "restore":
            return _cmd_restore(args, runner or Runner())
    except _Unavailable as exc:
        print(
            f"error: {exc} is not implemented in this increment "
            "(failing closed; no action taken)",
            file=sys.stderr,
        )
        return EXIT_UNAVAILABLE
    except (ConfigError, StateError, RunnerError, ArtifactError,
            PrepareError, RuntimeFault, PodmanError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
