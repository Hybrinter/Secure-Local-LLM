"""Runtime lifecycle: up/stop/status for the restricted agent prototype."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from . import artifacts, network, podman, runtime_spec as spec
from .config import fingerprint_file, load_profile
from .runner import RunnerError
from .runtime_record import (
    RUNTIME_SCHEMA,
    RuntimeFault,
    _ensure_control,
    _ensure_seed_dir,
    _is_hex40,
    load_runtime,
    save_runtime,
)
from .state import (
    StateError,
    locked_instance,
    load_git_prepared,
    load_manifest,
    load_prepared,
    save_manifest_locked,
)

def _save_resources(root_dir, name, manifest):
    save_manifest_locked(root_dir, name, manifest)


def _must(runner, args, label, timeout=60):
    return podman.must(runner, args, label, timeout=timeout).strip()


def _check_owned(runner, kind, ident, uuid, role):
    labels = podman.object_labels(runner, kind, ident)
    if not isinstance(labels, dict) \
            or labels.get(spec.LABEL_INSTANCE) != uuid \
            or labels.get(spec.LABEL_ROLE) != role:
        raise RuntimeFault(f"foreign {kind} collision: {ident}")
    return labels


def up(root_dir, name, repo, runner, status=None):
    report = status or (lambda *a: None)
    try:
        return _up(Path(root_dir), name, Path(repo), runner, report)
    except (StateError, RunnerError, podman.PodmanError,
            network.NetworkError, artifacts.ArtifactError, ValueError) as exc:
        raise RuntimeFault(str(exc)) from exc


def _up(root_dir, name, repo, runner, report):
    with locked_instance(root_dir, name) as inst:
        manifest = load_manifest(root_dir, name)
        if manifest is None:
            raise RuntimeFault(f'instance "{name}": not initialized')
        prepared = load_prepared(root_dir, name)
        git_prepared = load_git_prepared(root_dir, name)
        if prepared is None or git_prepared is None:
            raise RuntimeFault("instance not prepared; run prepare first")
        uuid = manifest["identity"]["uuid"]
        if git_prepared["instance_uuid"] != uuid:
            raise RuntimeFault("git-prepared instance_uuid mismatch")
        profile, profile_fp = load_profile(repo, manifest["profile"]["name"])
        if profile_fp["sha256"] != manifest["profile"]["sha256"]:
            raise RuntimeFault("profile drifted since init")
        try:
            spec.check_profile(profile)
        except ValueError as exc:
            raise RuntimeFault(str(exc)) from exc
        lock_path = Path(manifest["artifacts_lock"]["path"])
        _, lock_fp = artifacts.load_lock(lock_path)
        if lock_fp["sha256"] != manifest["artifacts_lock"]["sha256"]:
            raise RuntimeFault("artifacts lock drifted since init")
        _check_recipe_fingerprints(repo, prepared, git_prepared)
        images = {
            "harness": prepared["images"]["harness"],
            "inference": prepared["images"]["inference"],
            "git": git_prepared["image_id"],
        }
        template = (repo / ".devin" / "opencode" / "opencode.json").read_bytes()
        source_config_sha = hashlib.sha256(template).hexdigest()
        rendered = spec.render_opencode_config(template, profile)
        config_sha = spec.config_sha256(rendered)

        prior = load_runtime(inst, name)
        if prior is not None:
            if (
                prior["images"] != images
                or prior["instance_uuid"] != uuid
                or prior["seed_sha256"] != spec.seed_sha256()
                or prior["fingerprints"]["source_config"]
                != source_config_sha
                or prior["fingerprints"]["profile"] != profile_fp["sha256"]
                or prior["fingerprints"]["artifacts_lock"]
                != lock_fp["sha256"]
                or prior["fingerprints"]["profile"]
                != git_prepared["profile_sha256"]
                or prior["fingerprints"]["artifacts_lock"]
                != git_prepared["artifacts_lock_sha256"]
            ):
                raise RuntimeFault("runtime record drifted; refusing resume")

        for role, image_id in images.items():
            if not _image_labels_ok(runner, image_id, uuid, role):
                raise RuntimeFault(
                    f"{role} image {image_id[:12]} not owned by instance")
        _check_model_flags(runner, images["inference"])

        n = spec.names(uuid)
        if podman.object_exists(runner, "network", n["net"]):
            _check_owned(runner, "network", n["net"], uuid, "network")
            subnet = podman.network_subnet(runner, n["net"])
            net_id = podman.network_id(runner, n["net"])
        elif prior is not None:
            raise RuntimeFault(
                "recorded network missing; refusing to recreate")
        else:
            subnet = podman.free_subnet4(runner)
            net_id = None
        pod_ip = str(subnet[spec.POD_OFFSET])
        git_ip = str(subnet[spec.GIT_OFFSET])
        if prior is not None and (
            prior["pod_ip"] != pod_ip or prior["git_ip"] != git_ip
            or ipaddress.ip_network(prior["subnet"]) != subnet
            or prior["network"]["id"] != net_id
        ):
            raise RuntimeFault(
                "network addresses drifted from runtime record")

        control, control_fps = _ensure_control(
            inst, runner, rendered, git_ip)
        if prior is not None and prior["control_sha256"] != control_fps:
            drift = sorted(
                k for k in spec.CONTROL_FILES
                if prior["control_sha256"].get(k) != control_fps.get(k))
            raise RuntimeFault(f"control files drifted: {drift}")
        _ensure_seed_dir(control)
        created_ids = []
        try:
            record = _bring_up(
                root_dir, name, inst, manifest, runner, n, uuid, prior,
                images, profile, prepared, control, control_fps,
                subnet, pod_ip, git_ip, net_id, lock_fp, profile_fp,
                source_config_sha, created_ids, report)
        except BaseException as exc:
            failures = []
            res = manifest.get("resources", {})
            pod_id = res.get("pod_id")
            for role, cid in created_ids:
                try:
                    _verified_member(runner, cid, role, uuid, pod_id)
                except RuntimeFault:
                    failures.append(f"{role}:{cid[:12]} unverified")
                    continue
                out = runner.podman(["stop", "-t", "5", cid], timeout=30)
                if out.returncode != 0 or out.timed_out:
                    failures.append(f"{role}:{cid[:12]} rc={out.returncode}")
            if pod_id:
                try:
                    _verified_pod(runner, pod_id, uuid)
                    out = runner.podman(
                        ["pod", "stop", "-t", "5", pod_id], timeout=30)
                    if out.returncode != 0 or out.timed_out:
                        failures.append(
                            f"pod:{pod_id[:12]} rc={out.returncode} "
                            f"timeout={out.timed_out}")
                except RuntimeFault:
                    failures.append(f"pod:{pod_id[:12]} unverified")
            if failures:
                raise RuntimeFault(
                    f"{exc}; cleanup stop failures: {failures}") from exc
            raise
        return record


def _check_recipe_fingerprints(repo, prepared, git_prepared):
    fps = prepared["fingerprints"]
    cf_dir = repo / "containers"
    for role in ("harness", "inference"):
        cur = fingerprint_file(cf_dir / f"{role}.Containerfile")["sha256"]
        if cur != fps[f"{role}_containerfile"]:
            raise RuntimeFault(f"{role}.Containerfile drifted since prepare")
    for rel, sha in git_prepared["files"].items():
        if fingerprint_file(repo / rel)["sha256"] != sha:
            raise RuntimeFault(f"git fixture file drifted: {rel}")


def _image_labels_ok(runner, image_id, uuid, role):
    labels = podman.object_labels(runner, "image", image_id)
    if not isinstance(labels, dict):
        return False
    return (
        labels.get(spec.LABEL_INSTANCE) == uuid
        and labels.get(spec.LABEL_ROLE) == role
    )


def _check_model_flags(runner, image):
    out = podman.must(
        runner,
        ["run", "--rm", "--pull=never", "--network", "none",
         "--cap-drop", "ALL", "--read-only",
         "--security-opt", "no-new-privileges",
         image, "/opt/llama/llama-server", "--help"],
        "llama-server --help", timeout=60)
    missing = [f for f in spec.MODEL_REQUIRED_FLAGS if f not in out]
    if missing:
        raise RuntimeFault(
            f"llama-server --help lacks required flags: {missing}")


def _bring_up(root_dir, name, inst, manifest, runner, n, uuid, prior,
              images, profile, prepared, control, control_fps,
              subnet, pod_ip, git_ip, net_id, lock_fp, profile_fp,
              source_config_sha, created_ids, report):
    res = manifest["resources"]

    if net_id is None:
        podman.must(runner, [
            "network", "create", "--internal", "--disable-dns",
            "--subnet", str(subnet),
            "--label", f"{spec.LABEL_INSTANCE}={uuid}",
            "--label", f"{spec.LABEL_ROLE}=network",
            n["net"]], f"create network {n['net']}")
        net_id = podman.network_id(runner, n["net"])
        report("network", "created")
    else:
        report("network", "present")

    for key, role in (
        ("vol_workspace", "workspace"), ("vol_state", "state"),
        ("vol_model", "model"), ("vol_repo", "repo"),
    ):
        if podman.object_exists(runner, "volume", n[key]):
            _check_owned(runner, "volume", n[key], uuid, role)
        else:
            if res["volume_names"].get(role):
                raise RuntimeFault(
                    f"recorded volume {res['volume_names'][role]} "
                    "missing; refusing recreation")
            podman.must(runner, [
                "volume", "create",
                "--label", f"{spec.LABEL_INSTANCE}={uuid}",
                "--label", f"{spec.LABEL_ROLE}={role}",
                n[key]], f"create volume {n[key]}")
        if res["volume_names"].get(role) \
                and res["volume_names"][role] != n[key]:
            raise RuntimeFault(
                f"recorded volume name drifted for {role}")
        res["volume_names"][role] = n[key]
        report(f"volume-{role}", "ready")
    _save_resources(root_dir, name, manifest)

    if res["pod_id"]:
        if not podman.object_exists(runner, "pod", res["pod_id"]):
            raise RuntimeFault(
                "recorded pod missing; refusing recreation")
        bound_name = _must(
            runner, ["pod", "inspect", res["pod_id"], "--format",
                     "{{.Name}}"], "pod name")
        if bound_name != n["pod"]:
            raise RuntimeFault("recorded pod name drifted")
        if not podman.object_exists(runner, "pod", n["pod"]):
            raise RuntimeFault(
                "recorded pod id exists under a different name; refusing")
    for role in ("inference", "harness", "git"):
        recorded = res["container_ids"].get(role)
        if recorded:
            info = runner.podman(["inspect", recorded], timeout=30)
            if info.returncode != 0 or info.timed_out:
                raise RuntimeFault(
                    f"recorded {role} container {recorded[:12]} missing;"
                    " refusing recreation")
            try:
                cname = json.loads(info.stdout)[0].get(
                    "Name", "").lstrip("/")
            except (json.JSONDecodeError, IndexError):
                raise RuntimeFault(
                    f"recorded {role} container unparsable; refusing")
            if cname != n[role]:
                raise RuntimeFault(
                    f"recorded {role} container name drifted")

    if podman.object_exists(runner, "pod", n["pod"]):
        _check_owned(runner, "pod", n["pod"], uuid, "pod")
        pod_id = _must(
            runner, ["pod", "inspect", n["pod"], "--format", "{{.Id}}"],
            "pod id")
    else:
        pod_id = _must(
            runner, spec.pod_args(n, uuid, n["net"], pod_ip, profile),
            f"create pod {n['pod']}", timeout=120)
    if res["pod_id"] and res["pod_id"] != pod_id:
        raise RuntimeFault(
            f"recorded pod {res['pod_id'][:12]} does not match {pod_id[:12]}"
            "; refusing to adopt a different pod")
    res["pod_id"] = pod_id
    if res["network_id"] and res["network_id"] != net_id:
        raise RuntimeFault(
            "recorded network id drifted; refusing to rebind")
    res["network_id"] = net_id
    _save_resources(root_dir, name, manifest)
    report("pod", pod_id[:12])

    containers = {
        "inference": spec.inference_args(
            n, uuid, images["inference"], res["volume_names"]["model"],
            control, profile),
        "harness": spec.harness_args(
            n, uuid, images["harness"], res["volume_names"], control,
            profile),
        "git": spec.git_args(
            n, uuid, images["git"], n["net"], git_ip,
            res["volume_names"]["repo"], control),
    }
    for role, args in containers.items():
        if podman.object_exists(runner, "container", n[role]):
            _check_owned(runner, "container", n[role], uuid, role)
            cid = _must(
                runner, ["inspect", n[role], "--format", "{{.Id}}"],
                f"inspect {role}")
            info = json.loads(_must(
                runner, ["inspect", cid], f"inspect {role}"))[0]
            if info.get("Image") != images[role]:
                raise RuntimeFault(
                    f"{role} container image drifted: "
                    f"{str(info.get('Image'))[:12]}")
            recorded = res["container_ids"].get(role)
            if recorded and recorded != cid:
                raise RuntimeFault(
                    f"recorded {role} container {recorded[:12]} does not "
                    f"match {cid[:12]}; refusing to adopt")
            from . import verify_spec as _vs
            infra_id = _must(
                runner, ["pod", "inspect", n["pod"], "--format",
                         "{{.InfraContainerID}}"], "infra id")
            vres = _vs.Result()
            expects = _vs._member_expect(
                res["volume_names"], control, profile, infra_id, n["net"])
            _vs._check_container_spec(vres, role, info, expects[role])
            bad = [c for c in vres.checks if c["status"] == "fail"]
            if bad:
                raise RuntimeFault(
                    f"{role} immutable spec drift: "
                    + "; ".join(c["name"] for c in bad))
            if role != "git" and info.get("Pod") != pod_id:
                raise RuntimeFault(
                    f"{role} container pod membership drifted")
        else:
            if res["container_ids"].get(role):
                raise RuntimeFault(
                    f"recorded {role} container missing; refusing to "
                    "create a replacement binding")
            cid = _must(runner, args, f"create {n[role]}", timeout=120)
        res["container_ids"][role] = cid
        created_ids.append((role, cid))
        _save_resources(root_dir, name, manifest)
        report(role, cid[:12])

    short = uuid.replace("-", "")[:12]
    wl_table = "sllm_" + short + "00"
    git_table = "sllm_" + short + "01"

    _must(runner, ["start", res["container_ids"]["git"]],
          "start git fixture", timeout=60)
    git_policy = network.install_policy(
        runner, res["container_ids"]["git"], git_table, pod_ip,
        spec.GIT_PORT, "git")
    report("git-policy", git_policy["canonical_sha256"][:16])

    infra = _must(
        runner, ["pod", "inspect", n["pod"], "--format",
                 "{{.InfraContainerID}}"], "infra id")
    infra_state = _must(
        runner, ["inspect", infra, "--format", "{{.State.Status}}"],
        "infra state")
    if infra_state != "running":
        _must(runner, ["start", infra], "start infra", timeout=60)
    wl_policy = network.install_policy(
        runner, infra, wl_table, git_ip, spec.GIT_PORT, "workload")
    report("workload-policy", wl_policy["canonical_sha256"][:16])

    helper_out = podman.must(
        runner,
        spec.bootstrap_args(
            uuid, images["git"],
            {r: res["volume_names"][r] for r in ("workspace", "repo")},
            control),
        "git bootstrap", timeout=180)
    seed_main = ""
    for line in helper_out.splitlines():
        if line.startswith("main="):
            seed_main = line.split("=", 1)[1].strip()
    if not _is_hex40(seed_main):
        raise RuntimeFault("bootstrap did not report a seeded main commit")
    if prior is not None and prior["seed_main"] != seed_main:
        raise RuntimeFault("seeded baseline commit drifted; refusing")
    report("git-seed", seed_main[:12])

    model_sha = prepared["artifacts"]["model"]["sha256"]
    podman.must(
        runner,
        spec.model_populate_args(
            uuid, images["git"], res["volume_names"]["model"],
            prepared["artifacts"]["model"]["path"], model_sha),
        "model populate", timeout=600)
    report("model-vol", "ready")

    _must(runner, ["start", res["container_ids"]["inference"]],
          "start inference", timeout=60)
    _must(runner, ["start", res["container_ids"]["harness"]],
          "start harness", timeout=60)
    deadline = time.monotonic() + profile["timeouts"]["startup_seconds"]
    _wait_http(runner, res["container_ids"]["harness"], spec.PROBE_MODEL,
               deadline, "model api")
    _wait_http(runner, res["container_ids"]["harness"], spec.PROBE_SERVICE,
               deadline, "opencode api")
    report("health", "ready")

    record = {
        "schema": RUNTIME_SCHEMA,
        "instance": name,
        "instance_uuid": uuid,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "subnet": str(subnet),
        "pod_ip": pod_ip,
        "git_ip": git_ip,
        "network": {"id": net_id, "name": n["net"]},
        "tables": {"workload": wl_table, "git": git_table},
        "policy": {"workload": wl_policy, "git": git_policy},
        "objects": {
            "pod": pod_id,
            "infra": infra,
            "containers": dict(res["container_ids"]),
            "volumes": dict(res["volume_names"]),
        },
        "images": images,
        "fingerprints": {
            "profile": profile_fp["sha256"],
            "artifacts_lock": lock_fp["sha256"],
            "source_config": source_config_sha,
        },
        "control_sha256": control_fps,
        "seed_sha256": spec.seed_sha256(),
        "seed_main": seed_main,
    }
    save_runtime(inst, name, record)
    return record


def _pid_status_fields(text):
    out = {}
    for line in text.splitlines():
        key, _, val = line.partition(":")
        out[key.strip()] = val.strip()
    return out


def _wait_http(runner, harness_id, script, deadline, label):
    while time.monotonic() < deadline:
        res = runner.podman(
            ["exec", harness_id, "python3", "-I", "-B", "-c", script],
            timeout=20)
        if res.returncode == 0 and not res.timed_out:
            return True
        time.sleep(2)
    raise RuntimeFault(f"{label} readiness timed out")


def _verified_member(runner, cid, role, uuid, pod_id):
    res = runner.podman(["inspect", cid], timeout=30)
    if res.returncode != 0 or res.timed_out:
        raise RuntimeFault(f"cannot inspect recorded {role} {cid[:12]}")
    try:
        info = json.loads(res.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError) as exc:
        raise RuntimeFault(f"unparsable inspect for {cid[:12]}") from exc
    labels = info.get("Config", {}).get("Labels") or {}
    if labels.get(spec.LABEL_INSTANCE) != uuid \
            or labels.get(spec.LABEL_ROLE) != role:
        raise RuntimeFault(f"recorded {role} {cid[:12]} labels drifted")
    if role != "git" and info.get("Pod") != pod_id:
        raise RuntimeFault(f"recorded {role} {cid[:12]} pod drifted")


def stop(root_dir, name, runner):
    try:
        with locked_instance(root_dir, name) as inst:
            return _stop(Path(root_dir), name, runner)
    except (StateError, RunnerError, podman.PodmanError) as exc:
        raise RuntimeFault(str(exc)) from exc


def _verified_pod(runner, pod_id, uuid):
    res = runner.podman(["pod", "inspect", pod_id, "--format",
                         "{{json .Labels}}"], timeout=30)
    labels = {}
    if res.returncode == 0 and not res.timed_out:
        try:
            labels = json.loads(res.stdout)
        except json.JSONDecodeError:
            labels = {}
    if not isinstance(labels, dict) \
            or labels.get(spec.LABEL_INSTANCE) != uuid \
            or labels.get(spec.LABEL_ROLE) != "pod":
        raise RuntimeFault("recorded pod labels drifted; refusing stop")


def _stop(root_dir, name, runner):
    manifest = load_manifest(root_dir, name)
    if manifest is None:
        raise RuntimeFault(f'instance "{name}": not initialized')
    uuid = manifest["identity"]["uuid"]
    res = manifest["resources"]
    pod_id = res.get("pod_id")
    targets = sorted(res.get("container_ids", {}).items())
    for role, cid in targets:
        _verified_member(runner, cid, role, uuid, pod_id)
    if pod_id:
        _verified_pod(runner, pod_id, uuid)
    stopped = []
    failed = []
    for role, cid in targets:
        out = runner.podman(["stop", "-t", "10", cid], timeout=30)
        if out.returncode != 0 or out.timed_out:
            failed.append(f"{role} rc={out.returncode}")
        else:
            stopped.append(role)
    if pod_id:
        out = runner.podman(["pod", "stop", "-t", "10", pod_id],
                            timeout=30)
        if out.returncode != 0 or out.timed_out:
            failed.append(f"pod rc={out.returncode}")
        else:
            stopped.append("pod")
    if failed:
        raise RuntimeFault(
            f"stop failures: {failed} (stopped: {stopped})")
    return {"stopped": stopped}


def status(root_dir, name, runner):
    try:
        return _status(Path(root_dir), name, runner)
    except (StateError, RunnerError, podman.PodmanError) as exc:
        raise RuntimeFault(str(exc)) from exc


def _status(root_dir, name, runner):
    manifest = load_manifest(root_dir, name)
    if manifest is None:
        return {"initialized": False}
    res = manifest["resources"]
    info = {
        "initialized": True,
        "uuid": manifest["identity"]["uuid"],
        "profile": manifest["profile"]["name"],
        "pod_id": res.get("pod_id"),
        "containers": {},
    }
    for role, cid in sorted(res.get("container_ids", {}).items()):
        out = runner.podman(
            ["inspect", cid, "--format", "{{.State.Status}}"], timeout=30)
        info["containers"][role] = (
            out.stdout.strip()
            if out.returncode == 0 and not out.timed_out
            else "unknown")
    if res.get("pod_id"):
        out = runner.podman(
            ["pod", "inspect", res["pod_id"], "--format", "{{.State}}"],
            timeout=30)
        info["pod_state"] = (
            out.stdout.strip()
            if out.returncode == 0 and not out.timed_out
            else "unknown")
    return info
