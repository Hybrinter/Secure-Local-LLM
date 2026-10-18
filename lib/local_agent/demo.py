"""Synthetic workflow with independently checked Git and Python artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import runtime, runtime_record, runtime_spec, state, verify
from .config import load_profile, parse_json, read_secure_file
from .runner import base_env

AGENT_TIMEOUT_SECONDS = 1800
MAX_AGENT_BYTES = 16 << 20
FILE_HASHES = """
import hashlib,json,os,stat
out={}
for name in ('calculator.py','test_calculator.py'):
    fd=os.open('/workspace/repo/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:
            raise SystemExit('unsafe demo file')
        data=f.read(65537)
    if len(data)>65536: raise SystemExit('oversized demo file')
    out[name]=hashlib.sha256(data).hexdigest()
print(json.dumps(out))
"""
MODEL_REQUEST = """
import sys,urllib.request
payload=sys.stdin.buffer.read(65537)
if len(payload)>65536: raise SystemExit('oversized probe request')
key=open('/run/local-agent/model-api-key').read().strip()
req=urllib.request.Request(
    'http://127.0.0.1:8080/v1/chat/completions',data=payload,
    headers={'Content-Type':'application/json','Authorization':'Bearer '+key})
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(req,timeout=300) as response: body=response.read(1048577)
if len(body)>1048576 or key.encode() in body:
    raise SystemExit('unsafe probe response')
sys.stdout.buffer.write(body)
"""
REMOTE_HASHES = """
import hashlib,json,subprocess,sys
out={}
for name in ('calculator.py','test_calculator.py'):
    result=subprocess.run(
        ['git','-C','/repos/demo.git','show',sys.argv[1]+':'+name],
        capture_output=True,timeout=10)
    if result.returncode or len(result.stdout)>65536:
        raise SystemExit('remote file check failed')
    out[name]=hashlib.sha256(result.stdout).hexdigest()
print(json.dumps(out))
"""


class DemoError(Exception):
    pass


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _exec(runner, cid, args, label, stdin=None, timeout=60, required=True):
    result = runner.podman(
        ["exec", "-i", "-w", "/workspace/repo", cid, *args],
        stdin_text=stdin, timeout=timeout)
    if required and (result.returncode != 0 or result.timed_out):
        raise DemoError(f"{label} failed; inspect the private evidence")
    return result


def _git(runner, cid, args, label, directory="/workspace/repo"):
    result = runner.podman([
        "exec", cid, "git", "--no-replace-objects",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
        "-C", directory, *args], timeout=60)
    if result.returncode != 0 or result.timed_out:
        raise DemoError(f"{label} failed")
    return result.stdout.strip()


def _require_seed_parent(runner, cid, head, seed_main):
    if not re.fullmatch(r"[0-9a-f]{40}", head) \
            or not re.fullmatch(r"[0-9a-f]{40}", seed_main):
        raise DemoError("invalid result or seed commit identifier")
    if head == seed_main:
        raise DemoError("the result commit is unchanged from the seed")
    size = _git(runner, cid, ["cat-file", "-s", head], "result commit size")
    if not re.fullmatch(r"[0-9]+", size) or not 0 < int(size) <= 65536:
        raise DemoError("the result commit object is malformed or oversized")
    raw = _git(runner, cid, ["cat-file", "-p", head], "result commit object")
    parents = [
        line[len("parent "):]
        for line in raw.partition("\n\n")[0].splitlines()
        if line.startswith("parent ")
    ]
    if parents != [seed_main]:
        raise DemoError("the result commit is not a direct child of the seed")


def _require_runtime(root, name, repo, runner):
    checked = verify.verify(root, name, repo, runner)
    if not checked.ok:
        try:
            runtime._stop(Path(root), name, runner)
        except Exception as exc:
            raise DemoError("runtime verification and safe stop failed") from exc
        raise DemoError("runtime verification failed; no agent task admitted")
    manifest = state.load_manifest(root, name)
    inst = Path(root) / "instances" / name
    record = runtime_record.load_runtime(inst, name)
    return inst, manifest, record, checked


def _validate_probe(repo, data):
    if len(data.encode()) > state.MAX_MANIFEST_BYTES:
        raise DemoError("tool response exceeds the controller input limit")
    result = subprocess.run(
        [sys.executable, "-I", "-B",
         str(Path(repo) / ".devin" / "check-tool-probe.py")],
        input=data, text=True, capture_output=True, timeout=10, env=base_env())
    if result.returncode or result.stdout.strip() != "structured tool call verified":
        raise DemoError("structured tool protocol failed independent validation")


def _protocol_binding(record, profile):
    binding = {
        "images": {role: record["images"][role]
                   for role in ("harness", "inference")},
        "artifacts_lock": record["fingerprints"]["artifacts_lock"],
        "profile": record["fingerprints"]["profile"],
        "model_argv": runtime_spec.model_argv(profile),
    }
    return _digest(_canonical(binding))


def _protocol(root, name, repo, runner, record):
    repo = Path(repo)
    request = parse_json(read_secure_file(repo / ".devin/tool-probe.json"), "probe")
    profile_name = state.load_manifest(root, name)["profile"]["name"]
    profile, _ = load_profile(repo, profile_name)
    fingerprint = _protocol_binding(record, profile)
    request_sha = _digest(_canonical(request))
    inst = Path(root) / "instances" / name
    marker = inst / "protocol.json"
    if marker.exists():
        cached = parse_json(state._read_private_file(marker, 65536), "protocol")
        if cached.get("binding_sha256") == fingerprint \
                and cached.get("request_sha256") == request_sha:
            path = Path(cached["response_path"])
            if path.parent != Path(root) or not re.fullmatch(
                    r"tool-probe-[A-Za-z0-9-]+\.json", path.name):
                raise DemoError("unsafe cached protocol evidence path")
            response = state._read_private_file(path, 1048576).decode()
            if _digest(response.encode()) != cached["response_sha256"]:
                raise DemoError("cached protocol response drifted")
            _validate_probe(repo, response)
            return {"status": "pass", "reused": True,
                    "response_sha256": cached["response_sha256"]}
    cid = record["objects"]["containers"]["harness"]
    response = _exec(
        runner, cid, ["python3", "-I", "-B", "-c", MODEL_REQUEST],
        "structured tool request", stdin=json.dumps(request), timeout=330).stdout
    _validate_probe(repo, response)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(root) / f"tool-probe-{stamp}-{secrets.token_hex(4)}.json"
    state._atomic_write(path, response.encode())
    checkpoint = {
        "schema": "secure-local-llm/protocol@1", "status": "pass",
        "binding_sha256": fingerprint, "request_sha256": request_sha,
        "response_path": str(path), "response_sha256": _digest(response.encode()),
    }
    state._atomic_write(marker, _canonical(checkpoint) + b"\n")
    return {"status": "pass", "reused": False,
            "response_sha256": checkpoint["response_sha256"]}


def _hashes(data):
    value = parse_json(data, "demo file hashes")
    if not isinstance(value, dict) or set(value) != set(runtime_spec.SEED_FILES) \
            or any(not isinstance(v, str) or not re.fullmatch(
                r"[0-9a-f]{64}", v) for v in value.values()):
        raise DemoError("invalid file-hash probe")
    return value


def _agent(argv, prompt, timeout=AGENT_TIMEOUT_SECONDS):
    process = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=base_env(), start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process.stdin.write(prompt.encode())
        process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise DemoError("agent task exceeded its workflow deadline")
            for key, _ in selector.select(timeout=1):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > MAX_AGENT_BYTES:
                    raise DemoError("agent output exceeded its bounded capture")
        return process.wait(timeout=10), output.decode("utf-8", "replace")
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        process.stdout.close()


def _redact(text, control):
    protected = []
    for name in ("client_key", "ssh_host_ed25519_key", "model-api-key"):
        data = runtime_record._read_control(
            control / name, runtime_record._CONTROL_MODES[name], name).decode()
        protected.extend([data, data.strip(), json.dumps(data.strip())[1:-1]])
        protected.extend(line for line in data.splitlines() if len(line) > 16)
    service = parse_json(runtime_record._read_control(
        control / "service.json", {0o600}, "service.json"), "service.json")
    protected.append(service["password"])
    for value in sorted(set(protected), key=len, reverse=True):
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def _tool_events(text):
    completed = set()
    errors = False
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        errors |= event.get("type") == "error"
        if event.get("type") != "tool_use":
            continue
        part = event.get("part") or {}
        tool = part.get("tool")
        if (part.get("state") or {}).get("status") == "completed" \
                and isinstance(tool, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tool):
            completed.add(tool)
    return sorted(completed), errors


def demo(root, name, repo, runner, protocol_only=False, agent=_agent):
    with state.locked_instance(root, name):
        inst, manifest, record, initial = _require_runtime(root, name, repo, runner)
        evidence = {
            "schema": "secure-local-llm/demo@1", "status": "fail",
            "instance": name, "checks": [],
            "exceptions": [c["name"] for c in initial.checks
                           if c["status"] == "degraded"],
        }
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        nonce = secrets.token_hex(4)
        path = inst / f"demo-{stamp}-{nonce}.json"
        try:
            evidence["protocol"] = _protocol(root, name, repo, runner, record)
            evidence["checks"].append("runtime_and_tool_protocol")
            if protocol_only:
                evidence["status"] = "protocol-only"
                state._atomic_write(path, _canonical(evidence) + b"\n")
                return evidence, path
            cid = record["objects"]["containers"]["harness"]
            git_cid = record["objects"]["containers"]["git"]
            branch = f"agent/demo-{nonce}"
            expected = {k: _digest(v.encode())
                        for k, v in runtime_spec.SEED_FILES.items()}
            before = _hashes(_exec(
                runner, cid, ["python3", "-I", "-B", "-c", FILE_HASHES],
                "baseline file check").stdout)
            if before != expected or _git(
                    runner, cid, ["status", "--porcelain=v1", "--untracked-files=all"],
                    "clean worktree") or _git(
                    runner, cid, ["rev-parse", "HEAD"], "baseline head") != record["seed_main"]:
                raise DemoError("demo requires the pristine synthetic seed; no reset performed")
            if _git(runner, git_cid, ["for-each-ref", "--format=%(refname)",
                    f"refs/heads/{branch}"], "fresh remote branch", "/repos/demo.git"):
                raise DemoError("the generated demo branch already exists")
            evidence["checks"].append("pristine_seed_and_new_branch")
            baseline = _exec(
                runner, cid, ["python3", "-B", "-m", "unittest", "-v", "test_calculator.py"],
                "baseline tests", required=False)
            if baseline.returncode != 1 or "FAILED (failures=2)" not in (
                    baseline.stdout + baseline.stderr):
                raise DemoError("baseline tests did not exhibit the expected two failures")
            evidence["checks"].append("expected_baseline_test_failure")
            task = read_secure_file(Path(repo) / ".devin/demo-task.txt").decode()
            if task.count("{{BRANCH}}") != 1:
                raise DemoError("demo task must contain exactly one branch placeholder")
            task = task.replace("{{BRANCH}}", branch)
            code, trace = agent([
                "podman", "--remote=false", "exec", "-i", "-w", "/workspace/repo",
                "-e", "PWD=/workspace/repo",
                cid, "opencode", "run", "--format", "json",
                "--model", "local/granite-cpu", "--agent", "build",
                "--title", "Synthetic CPU smoke"], task)
            trace = _redact(trace, inst / "control")
            state._atomic_write(inst / f"agent-{stamp}-{nonce}.log", trace.encode())
            tools, errors = _tool_events(trace)
            evidence.update(branch=branch, tools_observed=tools,
                            task_sha256=_digest(task.encode()), agent_exit=code)
            if code != 0 or errors or not tools:
                raise DemoError("agent did not complete a successful tool-bearing run")
            evidence["checks"].append("actual_agent_tool_execution")
            after = _hashes(_exec(
                runner, cid, ["python3", "-I", "-B", "-c", FILE_HASHES],
                "result file check").stdout)
            if after["test_calculator.py"] != expected["test_calculator.py"]:
                raise DemoError("the agent changed the protected baseline tests")
            evidence["checks"].append("baseline_tests_unchanged")
            oracle = read_secure_file(Path(repo) / ".devin/demo-oracle.py").decode()
            checked = _exec(
                runner, cid, ["python3", "-I", "-B", "-"], "independent oracle",
                stdin=oracle)
            if checked.stdout.strip() != "independent addition checks passed":
                raise DemoError("independent oracle did not confirm the permitted fix")
            evidence["checks"].append("independent_source_and_addition_oracle")
            tests = _exec(
                runner, cid, ["python3", "-B", "-m", "unittest", "-v", "test_calculator.py"],
                "final repository tests")
            if "OK" not in tests.stdout + tests.stderr:
                raise DemoError("repository test runner did not report success")
            evidence["checks"].append("repository_tests")
            head = _git(runner, cid, ["rev-parse", "HEAD"], "result commit")
            if not re.fullmatch(r"[0-9a-f]{40}", head) or head == record["seed_main"]:
                raise DemoError("the agent did not create a new commit")
            _require_seed_parent(runner, cid, head, record["seed_main"])
            if _git(runner, cid, ["branch", "--show-current"], "result branch") != branch:
                raise DemoError("the agent did not finish on its designated branch")
            if _git(runner, cid, ["diff", "--no-ext-diff", "--name-only",
                                record["seed_main"], head], "changed files") != "calculator.py":
                raise DemoError("the commit changed files outside the allowed fix")
            if _git(runner, cid, ["status", "--porcelain=v1", "--untracked-files=all"],
                    "final clean worktree"):
                raise DemoError("the agent left uncommitted or untracked changes")
            evidence["checks"].append("minimal_committed_change_on_designated_branch")
            remote = _git(runner, git_cid, ["rev-parse", "--verify",
                          f"refs/heads/{branch}"], "remote branch", "/repos/demo.git")
            main = _git(runner, git_cid, ["rev-parse", "refs/heads/main"],
                        "protected main", "/repos/demo.git")
            if remote != head or main != record["seed_main"]:
                raise DemoError("remote publication or protected main check failed")
            evidence["checks"].append("remote_publication_and_protected_main")
            tree = _git(runner, git_cid, ["ls-tree", "-r", "--name-only", head],
                        "remote tree", "/repos/demo.git").splitlines()
            if sorted(tree) != sorted(expected):
                raise DemoError("the remote tree contains unexpected files")
            content = runner.podman([
                "exec", git_cid, "python3", "-I", "-B", "-c",
                REMOTE_HASHES, head], timeout=30)
            if content.returncode or content.timed_out \
                    or _hashes(content.stdout) != after:
                raise DemoError("remote file content differs from the checked worktree")
            evidence["checks"].append("independent_remote_tree_and_content")
            if not verify.verify(root, name, repo, runner).ok:
                raise DemoError("post-task runtime verification failed")
            evidence["checks"].append("post_task_runtime_verification")
            evidence.update(status="pass", seed_commit=record["seed_main"],
                            result_commit=head, remote_commit=remote,
                            test_sha256=after["test_calculator.py"],
                            oracle="pass", repository_tests="pass")
        except Exception as exc:
            evidence["error"] = _redact(str(exc), inst / "control")
            try:
                runtime._stop(Path(root), name, runner)
            except Exception:
                evidence["stop"] = "failed; inspect instance status"
            else:
                evidence["stop"] = "owned members stopped; volumes preserved"
        state._atomic_write(path, _canonical(evidence) + b"\n")
        return evidence, path
