"""Operator CLI: doctor/status/init implemented; lifecycle commands fail closed."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path

from .config import ConfigError, fingerprint_file, load_profile, validate_instance_name
from .runner import Runner, RunnerError
from .state import StateError, init_instance, load_manifest, state_root

EXIT_OK, EXIT_ERROR, EXIT_UNAVAILABLE = 0, 1, 3
UNAVAILABLE_COMMANDS = (
    "up", "stop", "prepare", "verify", "chat", "demo",
    "backup", "restore", "evidence",
)
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
    for cmd in ("status", *UNAVAILABLE_COMMANDS):
        sp = sub.add_parser(cmd)
        sp.add_argument("--instance", default="demo", metavar="NAME")
    init = sub.add_parser("init", help="initialize instance state")
    init.add_argument("--instance", default="demo", metavar="NAME")
    init.add_argument("--profile", default="cpu", metavar="NAME")
    init.add_argument("--acknowledge-prototype-no-lsm", action="store_true")
    init.add_argument("--artifacts-lock", default=None, metavar="PATH")
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


def _cmd_status(args):
    manifest = load_manifest(state_root(), args.instance)
    if manifest is None:
        print(f'instance "{args.instance}": not initialized')
        return EXIT_OK
    resources = manifest.get("resources", {})
    print(f'instance "{args.instance}": initialized')
    print(f'  uuid: {manifest.get("identity", {}).get("uuid")}')
    print(f'  profile: {manifest.get("profile", {}).get("name")}')
    print(f'  pod: {resources.get("pod_id") or "none"}')
    return EXIT_OK


def _cmd_init(args):
    if not args.acknowledge_prototype_no_lsm:
        raise StateError(
            "init requires --acknowledge-prototype-no-lsm (prototype-only exception)"
        )
    root = repo_root()
    profile, profile_fp = load_profile(root, args.profile)
    lock_path = args.artifacts_lock or str(root / ".devin" / "artifacts.lock.json")
    lock_fp = fingerprint_file(lock_path)
    manifest = init_instance(
        state_root(), args.instance, profile, profile_fp, lock_fp,
        args.acknowledge_prototype_no_lsm,
    )
    print(f'instance "{args.instance}": initialized')
    print(f'  uuid: {manifest["identity"]["uuid"]}')
    print(f'  profile: {profile["name"]} ({profile_fp["sha256"][:16]}...)')
    print(f'  artifacts lock: {lock_fp["sha256"][:16]}...')
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
            return _cmd_status(args)
        if args.command == "init":
            return _cmd_init(args)
    except _Unavailable as exc:
        print(
            f"error: {exc} is not implemented in this increment "
            "(failing closed; no action taken)",
            file=sys.stderr,
        )
        return EXIT_UNAVAILABLE
    except (ConfigError, StateError, RunnerError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
