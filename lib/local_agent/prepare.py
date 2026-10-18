"""Artifact staging and image preparation for one instance."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from . import artifacts, state
from .config import fingerprint_file, load_profile
from .downloads import _stage_file, fetch_url
from .runner import base_env
from .state import (
    StateError,
    _ensure_private_dir,
    _require_private_dir,
    cache_root,
    load_git_prepared,
    load_manifest,
    load_prepared,
    locked_instance,
    save_git_prepared_locked,
    save_prepared_locked,
)

BUILD_TIMEOUT_SECONDS = 1800
BUILD_LOG_BYTES = 32 << 20
BUILD_LOG_TAIL = 8000
IMAGE_LABEL = "org.secure-local-llm.instance"
IMAGE_ROLE_LABEL = "org.secure-local-llm.role"


class PrepareError(Exception):
    pass


def _harness_context(cache, containerfile, archive, spec):
    ctx = Path(tempfile.mkdtemp(prefix="ctx-harness-", dir=str(cache)))
    try:
        shutil.copyfile(containerfile, ctx / "Containerfile")
        stage = Path(tempfile.mkdtemp(prefix="oc-x-", dir=str(cache)))
        try:
            artifacts.extract_tar(archive, stage, spec, "binary-tar")
            shutil.copyfile(
                stage / "package" / "bin" / "opencode", ctx / "opencode"
            )
            os.chmod(ctx / "opencode", 0o755)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        return ctx
    except BaseException:
        shutil.rmtree(ctx, ignore_errors=True)
        raise


def _git_context(cache, repo):
    ctx = Path(tempfile.mkdtemp(prefix="ctx-git-", dir=str(cache)))
    try:
        shutil.copyfile(
            repo / "containers" / "git-fixture.Containerfile",
            ctx / "Containerfile",
        )
        for fname in ("sshd_config", "serve_git.py", "pre_receive.py"):
            shutil.copyfile(repo / "git-fixture" / fname, ctx / fname)
        return ctx
    except BaseException:
        shutil.rmtree(ctx, ignore_errors=True)
        raise


def _inference_context(cache, containerfile, archive, spec):
    ctx = Path(tempfile.mkdtemp(prefix="ctx-inference-", dir=str(cache)))
    try:
        shutil.copyfile(containerfile, ctx / "Containerfile")
        src = ctx / "src"
        src.mkdir(mode=0o700)
        artifacts.extract_tar(archive, src, spec, "source-tar")
        return ctx
    except BaseException:
        shutil.rmtree(ctx, ignore_errors=True)
        raise


def _run_build(argv, timeout=BUILD_TIMEOUT_SECONDS):
    try:
        out = tempfile.TemporaryFile(mode="w+t")
        proc = subprocess.Popen(
            list(argv),
            env=base_env(),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise PrepareError(f"cannot run build: {exc}") from exc
    deadline = time.monotonic() + timeout
    reason = None
    while reason is None:
        try:
            proc.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            if time.monotonic() > deadline:
                reason = "timeout"
            elif os.fstat(out.fileno()).st_size > BUILD_LOG_BYTES:
                reason = "log bound"
            if reason:
                with contextlib.suppress(OSError):
                    os.killpg(proc.pid, signal.SIGKILL)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    out.seek(0, os.SEEK_END)
    out.seek(max(0, out.tell() - BUILD_LOG_TAIL))
    tail = out.read(BUILD_LOG_TAIL)
    out.close()
    if reason == "timeout":
        raise PrepareError(
            f"build timed out after {timeout}s: {tail[-1000:]}")
    if reason == "log bound":
        raise PrepareError(
            f"build log exceeded {BUILD_LOG_BYTES} bytes: {tail[-1000:]}")
    if proc.returncode != 0:
        raise PrepareError(f"build failed rc={proc.returncode}: {tail}")
    return tail


def _image_id(runner, tag):
    res = runner.podman(
        ["image", "inspect", tag, "--format", "{{.Id}}"], timeout=60
    )
    if res.returncode != 0 or res.timed_out:
        return None
    return res.stdout.strip() or None


def _inspect_labels(runner, ref):
    res = runner.podman(
        ["image", "inspect", ref, "--format", "{{json .Config.Labels}}"],
        timeout=60,
    )
    if res.returncode != 0 or res.timed_out:
        return None
    try:
        labels = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    return labels if isinstance(labels, dict) else {}


def _labels_match(labels, instance_uuid, role):
    return (
        labels.get(IMAGE_LABEL) == instance_uuid
        and labels.get(IMAGE_ROLE_LABEL) == role
    )


def _dpkg_manifest(runner, image_id):
    res = runner.podman(
        ["run", "--rm", "--network", "none", "--cap-drop", "ALL",
         "--read-only", image_id,
         "dpkg-query", "-W", "-f=${Package} ${Version}\n"],
        timeout=120,
    )
    if res.returncode != 0:
        raise PrepareError(f"dpkg manifest failed for {image_id[:12]}")
    return sorted(
        line for line in res.stdout.splitlines() if line.strip()
    )


def _ensure_image(runner, role, tag, instance_uuid, recorded_id, recipe_same,
                  make_context, ensure_base, builder, status, *, base_image):
    if recorded_id and recipe_same:
        labels = _inspect_labels(runner, recorded_id)
        if labels is not None and _labels_match(labels, instance_uuid, role):
            status and status(f"image-{role}", "present")
            return recorded_id
    existing = _image_id(runner, tag)
    if existing:
        labels = _inspect_labels(runner, existing)
        if labels is not None and _labels_match(labels, instance_uuid, role):
            status and status(f"image-{role}", "present")
            return existing
        raise PrepareError(
            f"tag collision on {tag}: image not owned by this instance"
        )
    ctx = make_context()
    try:
        ensure_base()
        status and status(f"image-{role}", "building")
        builder(
            [
                "podman", "--remote=false", "build", "--pull=never",
                "--build-arg", f"BASE_IMAGE={base_image}",
                "--label", f"{IMAGE_LABEL}={instance_uuid}",
                "--label", f"{IMAGE_ROLE_LABEL}={role}",
                "-t", tag, "-f", str(ctx / "Containerfile"), str(ctx),
            ]
        )
        image_id = _image_id(runner, tag)
        if not image_id:
            raise PrepareError(f"build succeeded but {tag} not inspectable")
        return image_id
    finally:
        try:
            shutil.rmtree(ctx)
        except OSError as exc:
            raise PrepareError(
                f"cannot remove build context {ctx}: {exc}") from exc


def cached_source_path(spec):
    return cache_root() / f"llama.cpp-{spec['inference_source']['version']}.tar.gz"


def _artifact_record(spec, path):
    return {
        spec["hash"]["algorithm"]: spec["hash"]["hex"],
        "path": str(path),
    }


def prepare(root_dir, name, repo, runner, allow_network,
            fetcher=fetch_url, builder=_run_build, status=None):
    if not allow_network:
        raise PrepareError(
            "prepare requires explicit --allow-network for online staging"
        )
    try:
        _require_private_dir(Path(root_dir) / "instances" / name)
    except FileNotFoundError as exc:
        raise PrepareError(f'instance "{name}": not initialized') from exc
    except StateError as exc:
        raise PrepareError(str(exc)) from exc
    try:
        with locked_instance(root_dir, name):
            manifest = load_manifest(root_dir, name)
            if manifest is None:
                raise PrepareError(f'instance "{name}": not initialized')
            return _prepare_locked(
                root_dir, name, repo, runner, manifest, fetcher, builder,
                status,
            )
    except StateError as exc:
        raise PrepareError(str(exc)) from exc


def _prepare_locked(root_dir, name, repo, runner, manifest, fetcher, builder,
                    status):
    res = manifest["resources"]
    if res.get("pod_id") or res.get("container_ids"):
        raise PrepareError(
            "instance has workload bindings; refusing to change bindings"
        )
    lock_path = Path(manifest["artifacts_lock"]["path"])
    lock, lock_fp = artifacts.load_lock(lock_path)
    recorded_lock = manifest["artifacts_lock"]
    if (
        lock_fp["sha256"] != recorded_lock["sha256"]
        or lock_fp["bytes"] != recorded_lock["bytes"]
    ):
        raise PrepareError("artifacts lock drifted since init; re-init required")
    profile, profile_fp = load_profile(repo, manifest["profile"]["name"])
    if profile_fp["sha256"] != manifest["profile"]["sha256"]:
        raise PrepareError("profile drifted since init; re-init required")
    try:
        _ensure_private_dir(cache_root())
        _ensure_private_dir(cache_root() / "staging")
        cache = _ensure_private_dir(cache_root() / "staging" / name)
    except StateError as exc:
        raise PrepareError(f"cannot create cache: {exc}") from exc
    spec = lock["artifacts"]
    model = _stage_file(
        cache, "model", spec["model"], fetcher, status=status)
    src_tar = _stage_file(
        cache, "inference_source", spec["inference_source"], fetcher,
        cached_path=cached_source_path(spec), status=status)
    oc_tar = _stage_file(
        cache, "opencode", spec["opencode"], fetcher, status=status)
    instance_uuid = manifest["identity"]["uuid"]
    uuid8 = instance_uuid.replace("-", "")[:8]
    cf_dir = repo / "containers"
    cf_fps = {
        role: fingerprint_file(cf_dir / f"{role}.Containerfile")["sha256"]
        for role in ("harness", "inference")
    }
    try:
        prior = load_prepared(root_dir, name)
    except StateError as exc:
        raise PrepareError(f"cannot read prepared record: {exc}") from exc
    prior_fps = prior["fingerprints"] if prior else {}
    prior_images = prior["images"] if prior else {}
    pulled = []

    def ensure_base():
        if not pulled:
            res = runner.podman(["pull", lock["base_image"]], timeout=300)
            if res.returncode != 0 or res.timed_out:
                raise PrepareError(
                    f"base image pull failed: {res.stderr.strip()[-500:]}"
                )
            pulled.append(True)

    def make_context(role):
        if role == "harness":
            return _harness_context(
                cache, cf_dir / "harness.Containerfile", oc_tar,
                spec["opencode"])
        return _inference_context(
            cache, cf_dir / "inference.Containerfile", src_tar,
            spec["inference_source"])

    images = {}
    for role in ("harness", "inference"):
        tag = f"localhost/sll-{uuid8}-{role}:{cf_fps[role][:12]}"
        recipe_same = prior_fps.get(f"{role}_containerfile") == cf_fps[role]
        images[role] = _ensure_image(
            runner, role, tag, instance_uuid, prior_images.get(role),
            recipe_same,
            lambda role=role: make_context(role),
            ensure_base, builder, status,
            base_image=lock["base_image"])
    packages = {r: _dpkg_manifest(runner, i) for r, i in images.items()}
    record = {
        "schema": state.PREPARED_SCHEMA,
        "instance": name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "fingerprints": {
            "artifacts_lock": lock_fp["sha256"],
            "profile": profile_fp["sha256"],
            "harness_containerfile": cf_fps["harness"],
            "inference_containerfile": cf_fps["inference"],
        },
        "artifacts": {
            "model": _artifact_record(spec["model"], model),
            "opencode": _artifact_record(spec["opencode"], oc_tar),
            "inference_source": _artifact_record(
                spec["inference_source"], src_tar),
        },
        "images": images,
        "packages": packages,
    }
    save_prepared_locked(root_dir, name, record)
    try:
        prior_git = load_git_prepared(root_dir, name)
    except StateError as exc:
        raise PrepareError(f"cannot read git-prepared record: {exc}") from exc
    git_files = {
        rel: fingerprint_file(repo / rel)["sha256"]
        for rel in state.GIT_PREPARED_FILES
    }
    if prior_git is not None:
        if (
            prior_git["instance_uuid"] != instance_uuid
            or prior_git["artifacts_lock_sha256"] != lock_fp["sha256"]
            or prior_git["profile_sha256"] != profile_fp["sha256"]
        ):
            raise PrepareError(
                "git-prepared record is stale; re-init required"
            )
    tag_digest = hashlib.sha256(
        json.dumps(git_files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    git_tag = f"localhost/sll-{uuid8}-git:{tag_digest[:12]}"
    git_same = prior_git is not None and prior_git["files"] == git_files
    git_image = _ensure_image(
        runner, "git", git_tag, instance_uuid,
        prior_git["image_id"] if prior_git else None,
        git_same,
        lambda: _git_context(cache, repo),
        ensure_base, builder, status,
        base_image=lock["base_image"])
    git_record = {
        "schema": state.GIT_PREPARED_SCHEMA,
        "instance": name,
        "instance_uuid": instance_uuid,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "artifacts_lock_sha256": lock_fp["sha256"],
        "profile_sha256": profile_fp["sha256"],
        "files": git_files,
        "image_id": git_image,
        "packages": _dpkg_manifest(runner, git_image),
    }
    save_git_prepared_locked(root_dir, name, git_record)
    return record
