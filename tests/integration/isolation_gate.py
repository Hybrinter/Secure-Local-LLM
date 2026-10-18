#!/usr/bin/env python3
"""Opt-in host/other-workspace canary isolation gate.

Proves, on a running instance, that workload members cannot reach host
paths, other containers' volumes, engine sockets, or the model volume,
while each expected positive path still works. All fixtures created here
are nonce-named and labelled `org.secure-local-llm.test`; cleanup removes
only resources this invocation created, after label re-verification.
Host paths appear only inside the private 0600 report.

Usage: python3 tests/integration/isolation_gate.py --run [--instance NAME]
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))

from local_agent import runner as runner_mod
from local_agent import state
from local_agent.runtime_record import load_runtime

TEST_LABEL = "org.secure-local-llm.test"
EXPECTED_HARNESS_DESTS = frozenset({
    "/workspace",
    "/state",
    "/run/local-agent/client_key",
    "/run/local-agent/gitconfig",
    "/run/local-agent/known_hosts",
    "/run/local-agent/model-api-key",
    "/run/local-agent/ssh_config",
    "/run/local-agent/opencode/opencode.json",
    "/run/local-agent/opencode/service.json",
})
SOCKET_PATHS = (
    "/run/podman/podman.sock",
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
)
ENGINE_ENV = ("DOCKER_HOST", "PODMAN_HOST", "CONTAINER_HOST")

H_PROBE = (
    "import json,os,socket,stat,sys\n"
    "out={}\n"
    "for p in sys.argv[1:]:\n"
    "    try:\n"
    "        if os.path.lexists(p):\n"
    "            if stat.S_ISSOCK(os.lstat(p).st_mode):\n"
    "                s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
    "                s.settimeout(1)\n"
    "                s.connect(p); s.close()\n"
    "                out[p]='ACCESSIBLE'\n"
    "            else:\n"
    "                fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n"
    "                os.close(fd); out[p]='ACCESSIBLE'\n"
    "        else:\n"
    "            out[p]='DENIED:2'\n"
    "    except OSError as e:\n"
    "        out[p]='DENIED:'+str(e.errno)\n"
    "for v in ('DOCKER_HOST','PODMAN_HOST','CONTAINER_HOST'):\n"
    "    out['env:'+v]=('SET' if os.environ.get(v) else 'unset')\n"
    "out['/models exists']=os.path.lexists('/models')\n"
    "print(json.dumps(out))\n"
)
MODEL_WRITE_PROBE = (
    "use Fcntl qw(O_WRONLY O_NOFOLLOW);"
    "unless (-e '/models/model.gguf' && -r '/models/model.gguf') {"
    " print 'MISSING'; exit 0 }"
    "sysopen(my $f, '/models/model.gguf', O_WRONLY|O_NOFOLLOW)"
    " or do { print 'DENIED:'.$!; exit 0 };"
    " close($f); print 'WRITABLE';"
)
SENTINEL_WRITE = (
    "import sys\n"
    "open('/other-workspace/sentinel-PLACEHOLDER','w').write('ok')\n"
    "print(open('/other-workspace/sentinel-PLACEHOLDER').read())\n"
)


def _fresh_report_path(inst, nonce):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return inst / f"isolation-{stamp}-{nonce}.json"


class Gate:
    def __init__(self, runner):
        self.runner = runner
        self.results = []

    def check(self, name, ok, detail):
        self.results.append(
            {"check": name, "status": "pass" if ok else "fail",
             "detail": detail})
        print(("pass" if ok else "fail") + f": {name} ({detail})")

    def podman(self, args, timeout=60):
        res = self.runner.podman(list(args), timeout=timeout)
        return res.returncode == 0 and not res.timed_out, res

    def exec_probe(self, cid, argv, timeout=30):
        ok, res = self.podman(["exec", cid, *argv], timeout=timeout)
        if not ok:
            return None
        return res.stdout.strip()


def _volume_mountpoint(runner, name):
    res = runner.podman(
        ["volume", "inspect", name, "--format", "{{.Mountpoint}}"],
        timeout=30)
    if res.returncode != 0 or res.timed_out:
        return None
    out = res.stdout.strip()
    return out if out.startswith("/") else None


def _inspect(runner, cid):
    res = runner.podman(["inspect", cid], timeout=30)
    if res.returncode != 0 or res.timed_out:
        return None
    try:
        return json.loads(res.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError):
        return None


def _container_labels(runner, cid):
    info = _inspect(runner, cid)
    if not isinstance(info, dict):
        return {}
    return info.get("Config", {}).get("Labels") or {}


def _labels_ok(labels, nonce):
    return (
        isinstance(labels, dict)
        and labels.get(TEST_LABEL) == "isolation-gate"
        and labels.get(f"{TEST_LABEL}.nonce") == nonce
    )


def gate(root_dir, name, runner, repo=None, verify_fn=None):
    root_dir = Path(root_dir)
    manifest = state.load_manifest(root_dir, name)
    if manifest is None:
        raise SystemExit(f'instance "{name}": not initialized')
    inst = state._instance_dir(root_dir, name)
    record = load_runtime(inst, name)
    if record is None:
        raise SystemExit(f'instance "{name}": no runtime record')
    harness = record["objects"]["containers"].get("harness")
    inference = record["objects"]["containers"].get("inference")
    image = record["images"]["harness"]
    if not harness or not inference or not image:
        raise SystemExit("runtime record incomplete")

    g = Gate(runner)
    from local_agent.verify import verify as _verify
    verify_fn = verify_fn or _verify
    repo = repo or Path(__file__).resolve().parents[2]
    result = verify_fn(root_dir, name, repo, runner)
    g.check("shared verification admits instance",
            result.ok,
            f"{sum(1 for c in result.checks if c['status'] == 'pass')}"
            " pass")
    if not result.ok:
        _write_report(inst, name, secrets.token_hex(4), "", g, [])
        return 1
    nonce = secrets.token_hex(4)
    created = []
    canary_dir = state._ensure_private_dir(
        root_dir / "instances" / name / "canaries")
    canary = canary_dir / f"canary-{nonce}.txt"
    payload = f"isolation-canary-{nonce}\n"
    vol = f"sll-iso-{nonce}"
    cname = f"sll-iso-{nonce}"
    report_path = _fresh_report_path(inst, nonce)
    cleanup_log = []

    try:
        fd = os.open(str(canary),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        created.append(("host-file", str(canary)))
        got = canary.read_text()
        g.check("host canary written and readable",
                got == payload, "private 0600 file under instance state")
        created.append(("volume", vol))
        ok, _ = g.podman([
            "volume", "create",
            "--label", f"{TEST_LABEL}=isolation-gate",
            "--label", f"{TEST_LABEL}.nonce={nonce}",
            vol])
        if not ok:
            g.check("fixture volume created", False,
                    f"cannot create fixture volume {vol}")
            raise SystemExit(f"cannot create fixture volume {vol}")
        mountpoint = _volume_mountpoint(runner, vol)
        if mountpoint is None:
            g.check("fixture volume inspectable", False,
                    "fixture volume uninspectable")
            raise SystemExit("fixture volume uninspectable")

        ok, res = g.podman([
            "run", "-d", "--pull=never",
            "--name", cname,
            "--network", "none",
            "--userns", "keep-id:uid=1000,gid=1000",
            "--user", "1000:1000",
            "--cap-drop", "ALL",
            "--read-only",
            "--security-opt", "no-new-privileges",
            "--memory", "256m", "--memory-swap", "256m",
            "--cpus", "1", "--pids-limit", "32",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--label", f"{TEST_LABEL}=isolation-gate",
            "--label", f"{TEST_LABEL}.nonce={nonce}",
            "-v", f"{vol}:/other-workspace:rw,nosuid,nodev",
            image, "sleep", "300"], timeout=90)
        created.append(("container", cname))
        if not ok:
            g.check("fixture container started", False,
                    f"cannot start fixture: {res.stderr.strip()}")
            raise SystemExit(f"cannot start fixture: {res.stderr.strip()}")
        fixture_id = res.stdout.strip() or cname
        write_src = SENTINEL_WRITE.replace("PLACEHOLDER", nonce)
        out = g.exec_probe(
            fixture_id, ["python3", "-I", "-B", "-c", write_src])
        g.check("fixture writes and reads own sentinel",
                out == "ok", f"fixture {fixture_id[:12]} on {vol}")
        out = g.exec_probe(
            harness, ["python3", "-I", "-B", "-c",
                      "print(open('/workspace/repo/calculator.py')"
                      ".read()[:20])"])
        g.check("harness reads own workspace",
                bool(out), "positive control")
        probe = g.exec_probe(harness, [
            "python3", "-I", "-B", "-c", H_PROBE,
            str(canary), f"{mountpoint}/",
            f"/other-workspace/sentinel-{nonce}",
            *SOCKET_PATHS])
        try:
            verdict = json.loads(probe) if probe else {}
        except json.JSONDecodeError:
            verdict = {}
        for label, key, want in (
            ("harness cannot open host canary", str(canary), "DENIED"),
            ("harness cannot open fixture host mountpoint",
             f"{mountpoint}/", "DENIED"),
            ("harness cannot open other-workspace sentinel",
             f"/other-workspace/sentinel-{nonce}", "DENIED"),
        ):
            got = verdict.get(key, "")
            g.check(label, got.startswith(want), got or "no output")
        for p in SOCKET_PATHS:
            got = verdict.get(p, "")
            g.check(f"harness socket absent {p}",
                    got.startswith("DENIED"), got or "no output")
        for var in ENGINE_ENV:
            got = verdict.get(f"env:{var}", "")
            g.check(f"harness engine env absent {var}",
                    got == "unset", got or "no output")
        g.check("harness has no /models mount",
                verdict.get("/models exists") is False,
                repr(verdict.get("/models exists")))
        info = _inspect(runner, harness)
        mounts = info.get("Mounts", []) if isinstance(info, dict) else []
        dests = {m.get("Destination") for m in mounts
                 if isinstance(m, dict)}
        sources = {str(m.get("Source")) for m in mounts
                   if isinstance(m, dict)}
        g.check("harness mount surface exact",
                dests == EXPECTED_HARNESS_DESTS,
                f"{sorted(dests)}")
        g.check("harness mounts exclude fixture volume",
                vol not in sources
                and not any(vol in s for s in sources),
                "no fixture source present")
        out = g.exec_probe(
            inference, ["perl", "-e", MODEL_WRITE_PROBE])
        model_ok = isinstance(out, str) and (
            out.startswith("DENIED") or out == "MISSING")
        if out == "MISSING":
            model_ok = False
        g.check("inference model exists before write probe",
                out != "MISSING",
                out or "no output")
        g.check("inference O_WRONLY|O_NOFOLLOW on model denied",
                isinstance(out, str) and out.startswith("DENIED"),
                out or "no output")
    finally:
        for kind, ident in reversed(created):
            if kind == "host-file":
                try:
                    os.unlink(ident)
                    cleanup_log.append(f"removed host-file {ident}")
                    gone = not os.path.lexists(ident)
                except OSError as exc:
                    cleanup_log.append(f"host-file {ident}: {exc}")
                    gone = False
                g.check("cleanup: host canary absent", gone, "<redacted>")
            elif kind == "container":
                labels = _container_labels(runner, ident)
                if _labels_ok(labels, nonce):
                    ok, r = g.podman(["rm", "-f", ident])
                    cleanup_log.append(
                        f"container {ident[:12]} removed" if ok
                        else f"container rm failed: {r.stderr.strip()}")
                    absent, _ = g.podman(
                        ["inspect", ident, "--format", "{{.Id}}"])
                    g.check(
                        "cleanup: fixture container absent",
                        ok and not absent, ident[:12])
                else:
                    cleanup_log.append(
                        f"container {ident[:12]} labels drifted; "
                        "left in place")
                    g.check(
                        "cleanup: fixture container labels verified",
                        False, "unverified fixture left in place")
            elif kind == "volume":
                res = runner.podman(
                    ["volume", "inspect", ident, "--format",
                     "{{json .Labels}}"], timeout=30)
                try:
                    labels = json.loads(res.stdout)
                except json.JSONDecodeError:
                    labels = {}
                if res.returncode == 0 and _labels_ok(labels, nonce):
                    ok, r = g.podman(["volume", "rm", ident])
                    cleanup_log.append(
                        f"volume {ident} removed" if ok
                        else f"volume rm failed: {r.stderr.strip()}")
                    absent, _ = g.podman(
                        ["volume", "inspect", ident, "--format",
                         "{{.Name}}"])
                    g.check(
                        "cleanup: fixture volume absent",
                        ok and not absent, ident)
                else:
                    cleanup_log.append(
                        f"volume {ident} labels drifted; left in place")
                    g.check(
                        "cleanup: fixture volume labels verified",
                        False, "unverified volume left in place")
        _write_report(inst, name, nonce, vol, g, cleanup_log,
                      report_path)

    failed = [r for r in g.results if r["status"] != "pass"]
    print(f"{len(g.results) - len(failed)} pass, "
          f"{len(failed)} fail")
    return 0 if not failed else 1


def _write_report(inst, name, nonce, vol, g, cleanup_log,
                  report_path=None):
    report_path = report_path or _fresh_report_path(inst, nonce)
    report = {
        "schema": "secure-local-llm/isolation@1",
        "instance": name,
        "nonce": nonce,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "fixture_volume": vol,
        "results": g.results,
        "cleanup": cleanup_log,
    }
    state._atomic_write(
        report_path,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode(),
        replace=False)
    print(f"report: {report_path}")


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", action="store_true",
                   help="execute the live isolation gate")
    p.add_argument("--instance", default="demo", metavar="NAME")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.run:
        build_parser().print_help()
        return 2
    return gate(state.state_root(), args.instance,
                runner_mod.Runner())


if __name__ == "__main__":
    sys.exit(main())
