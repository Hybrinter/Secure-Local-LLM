"""Quiesced backup/restore orchestration for data volumes.

Exports only the workspace/state/repo volumes of a fully stopped,
statically admitted instance through an offline hardened helper; strict
`backup@1` USTAR archives. Restore validates the entire untrusted
archive before creating a fresh instance (new UUID, volumes, controls).
Archives are plaintext and sensitive — see docs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from . import podman, runtime_spec as spec
from . import verify_spec as vspec
from . import backup_format as fmt
from .backup_format import BACKUP_SCHEMA, DATA_ROLES
from .backup_helper import (
    EXPORT_PY,
    IMPORT_PY,
    MAX_LOG_BYTES,
    helper_argv,
    run_helper,
)
from .artifacts import load_lock
from .config import ConfigError, load_profile, validate_instance_name
from .runtime_record import RuntimeFault, load_runtime
from .state import (
    StateError,
    _ensure_private_dir,
    _instance_dir,
    _require_private_dir,
    cache_root,
    init_instance,
    load_git_prepared,
    load_manifest,
    load_prepared,
    locked_instance,
    save_manifest_locked,
)


def _inspect_labels(runner, kind, ident, field=".Labels"):
    res = runner.podman(
        [kind, "inspect", ident, "--format", f"{{{{json {field}}}}}"],
        timeout=30)
    if res.returncode != 0 or res.timed_out:
        raise RuntimeFault(f"cannot inspect {kind} {ident[:16]}")
    try:
        labels = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeFault(f"unparsable {kind} labels") from exc
    return labels if isinstance(labels, dict) else {}


def _require_labels(labels, uuid, role, label_key=spec.LABEL_INSTANCE):
    if (
        labels.get(label_key) != uuid
        or labels.get(spec.LABEL_ROLE) != role
    ):
        raise RuntimeFault(f"labels drifted for role {role}")


def _member_admitted(runner, cid, role, uuid, pod_id,
                     require_stopped):
    res = runner.podman(["inspect", cid], timeout=30)
    if res.returncode != 0 or res.timed_out:
        raise RuntimeFault(f"cannot inspect recorded {role}")
    try:
        info = json.loads(res.stdout)[0]
    except (json.JSONDecodeError, IndexError) as exc:
        raise RuntimeFault(f"unparsable inspect for {role}") from exc
    if not isinstance(info, dict):
        raise RuntimeFault(f"unexpected inspect for {role}")
    labels = info.get("Config", {}).get("Labels") or {}
    if labels.get(spec.LABEL_INSTANCE) != uuid \
            or labels.get(spec.LABEL_ROLE) != role:
        raise RuntimeFault(f"recorded {role} labels drifted")
    if role != "git" and info.get("Pod") != pod_id:
        raise RuntimeFault(f"recorded {role} pod drifted")
    if require_stopped \
            and info.get("State", {}).get("Running") is not False:
        raise RuntimeFault(
            f"{role} not quiesced; stop the instance first")
    return info


def _member_spec_check(info_map, expects, images):
    from .verify_spec import Result, _check_container_spec
    r = Result()
    for role, info in info_map.items():
        if info.get("Image") != images.get(role):
            r.expect(f"{role} image", False, str(info.get("Image")))
        _check_container_spec(r, role, info, expects[role])
    failed = [c for c in r.checks if c["status"] == "fail"]
    if failed:
        raise RuntimeFault(
            "member spec mismatch: "
            + "; ".join(c["name"] for c in failed[:6]))


def _admit(runner, root_dir, name, manifest, record, uuid,
           repo=None, require_stopped=True):
    """Static offline admission: bindings, fingerprints, prepared
    images, member spec, labels, and (optionally) quiescence."""
    _static_admission_shape(manifest, record)
    if record.get("instance_uuid") != uuid:
        raise RuntimeFault("record uuid drifted from manifest")
    prepared = load_prepared(root_dir, name)
    if prepared is None:
        raise RuntimeFault("instance not prepared")
    for role in ("harness", "inference"):
        if prepared["images"].get(role) != record["images"].get(role):
            raise RuntimeFault(f"prepared image drifted for {role}")
    pfps = prepared["fingerprints"]
    if pfps["artifacts_lock"] != manifest["artifacts_lock"]["sha256"] \
            or pfps["profile"] != manifest["profile"]["sha256"]:
        raise RuntimeFault("prepared fingerprints drifted")
    git_prepared = load_git_prepared(root_dir, name)
    if git_prepared is None \
            or git_prepared.get("image_id") \
            != record["images"].get("git"):
        raise RuntimeFault("git prepared image drifted")
    if git_prepared.get("instance_uuid") != uuid \
            or git_prepared.get("profile_sha256") \
            != manifest["profile"]["sha256"] \
            or git_prepared.get("artifacts_lock_sha256") \
            != manifest["artifacts_lock"]["sha256"]:
        raise RuntimeFault("git prepared metadata drifted")

    if repo is not None:
        profile, profile_fp = load_profile(
            Path(repo), manifest["profile"]["name"])
        if profile_fp["sha256"] != manifest["profile"]["sha256"]:
            raise RuntimeFault("current profile drifted")
        lock_path = Path(manifest["artifacts_lock"]["path"])
        _lock, lock_fp = load_lock(lock_path)
        if lock_fp["sha256"] != manifest["artifacts_lock"]["sha256"]:
            raise RuntimeFault("current artifacts lock drifted")
    else:
        raise RuntimeFault("repo path required for admission")

    inst = _instance_dir(root_dir, name)
    control = inst / "control"
    expects = vspec._member_expect(
        record["objects"]["volumes"], control, profile,
        record["objects"]["infra"], record["network"]["name"])

    pod_id = record["objects"]["pod"]
    info_map = {}
    for role, cid in sorted(record["objects"]["containers"].items()):
        info_map[role] = _member_admitted(
            runner, cid, role, uuid, pod_id, require_stopped)
    _member_spec_check(info_map, expects, record["images"])
    _require_labels(
        _inspect_labels(runner, "pod", pod_id), uuid, "pod")
    for role, vname in record["objects"]["volumes"].items():
        if not podman.object_exists(runner, "volume", vname):
            raise RuntimeFault(f"volume {role} missing")
        _require_labels(
            _inspect_labels(runner, "volume", vname), uuid, role)
    for role, image_id in record["images"].items():
        labels = _inspect_labels(
            runner, "image", image_id, ".Config.Labels")
        _require_labels(labels, uuid, role)
        res = runner.podman(
            ["image", "inspect", image_id, "--format", "{{.Id}}"],
            timeout=30)
        if res.returncode != 0 or res.timed_out:
            raise RuntimeFault(f"image {role} missing")
        if not res.stdout.strip().endswith(image_id):
            raise RuntimeFault(f"image {role} id drifted")
    return record["images"]["git"]


def _static_admission_shape(manifest, record):
    res = manifest["resources"]
    if res.get("container_ids") != record["objects"]["containers"]:
        raise RuntimeFault("manifest/record container bindings differ")
    if res.get("pod_id") != record["objects"]["pod"]:
        raise RuntimeFault("manifest/record pod binding differs")
    if res.get("network_id") != record["network"]["id"]:
        raise RuntimeFault("manifest/record network binding differs")
    if res.get("volume_names") != record["objects"]["volumes"]:
        raise RuntimeFault("manifest/record volume bindings differ")
    fps = record["fingerprints"]
    if fps["artifacts_lock"] != manifest["artifacts_lock"]["sha256"] \
            or fps["profile"] != manifest["profile"]["sha256"]:
        raise RuntimeFault("record fingerprints drifted from manifest")


def _validate_produced(fd, role, count_cap):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
        raise RuntimeFault(f"exported {role}: unsafe file")
    size = st.st_size
    if size > fmt.MAX_ROLE_TAR_BYTES:
        raise RuntimeFault(f"exported {role} exceeds bound")
    os.lseek(fd, 0, os.SEEK_SET)
    sha = fmt.hash_stream(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    members, _ = fmt.scan_ustar_fd(
        fd, count_cap, fmt.MAX_ROLE_TAR_BYTES, role)
    fmt.validate_inner_inventory(members, role)
    return {"member": f"{role}.tar", "sha256": sha, "bytes": size,
            "members": len(members)}


def backup(root_dir, name, runner, output_dir=None, repo=None):
    root_dir = Path(root_dir)
    with locked_instance(root_dir, name) as inst:
        manifest = load_manifest(root_dir, name)
        if manifest is None:
            raise RuntimeFault(f'instance "{name}": not initialized')
        record = load_runtime(inst, name)
        if record is None:
            raise RuntimeFault(f'instance "{name}": no runtime record')
        uuid = manifest["identity"]["uuid"]
        image = _admit(runner, root_dir, name, manifest, record, uuid,
                       repo=repo, require_stopped=True)
        vols = record["objects"]["volumes"]

        if output_dir is None:
            outdir = _ensure_private_dir(root_dir / "backups")
        else:
            outdir = Path(output_dir)
            if not outdir.is_absolute():
                raise RuntimeFault("--output must be an absolute path")
            try:
                _require_private_dir(outdir)
            except FileNotFoundError:
                outdir.mkdir(mode=0o700)
                _require_private_dir(outdir)
            except StateError as exc:
                raise RuntimeFault(str(exc)) from exc
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        nonce = secrets.token_hex(4)
        archive = outdir / f"backup-{name}-{stamp}-{nonce}.tar"
        if os.path.lexists(archive):
            raise RuntimeFault("archive collision; refusing")

        partials = []
        try:
            volumes_out = {}
            total_members = 0
            for role in DATA_ROLES:
                partial = outdir / f".partial-{nonce}-{role}.tar"
                err_path = outdir / f".partial-{nonce}-{role}.err"
                partials += [partial, err_path]
                argv = helper_argv(image, vols[role], "ro", EXPORT_PY)
                run_helper(argv, partial, err_path,
                           fmt.MAX_ROLE_TAR_BYTES)
                fd = os.open(
                    str(partial), os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    info = _validate_produced(
                        fd, role,
                        fmt.MAX_MEMBERS_TOTAL - total_members)
                finally:
                    os.close(fd)
                total_members += info["members"]
                volumes_out[role] = {
                    "member": info["member"],
                    "sha256": info["sha256"],
                    "bytes": info["bytes"],
                }
            payload = (json.dumps({
                "schema": BACKUP_SCHEMA,
                "created_utc": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "profile_name": manifest["profile"]["name"],
                "profile_sha256": manifest["profile"]["sha256"],
                "artifacts_lock_sha256":
                    manifest["artifacts_lock"]["sha256"],
                "seed_main": record["seed_main"],
                "volumes": volumes_out,
            }, indent=2, sort_keys=True) + "\n").encode()
            outer_partial = outdir / f".partial-{nonce}-outer.tar"
            partials.append(outer_partial)
            fd = os.open(
                str(outer_partial),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600)
            try:
                written = 0

                class _BoundedWriter:
                    def write(self, data):
                        nonlocal written
                        written += len(data)
                        if written > fmt.MAX_OUTER_BYTES:
                            raise RuntimeFault(
                                "outer archive exceeds bound")
                        _write_all(fd, data)
                        return len(data)

                with tarfile.open(
                        fileobj=_BoundedWriter(), mode="w|",
                        format=tarfile.USTAR_FORMAT) as tf:
                    ti = tarfile.TarInfo("manifest.json")
                    ti.size = len(payload)
                    ti.mode = 0o600
                    ti.mtime = 0
                    tf.addfile(ti, io.BytesIO(payload))
                    for role in DATA_ROLES:
                        partial = outdir / (
                            f".partial-{nonce}-{role}.tar")
                        info = tarfile.TarInfo(f"{role}.tar")
                        info.size = os.lstat(partial).st_size
                        info.mode = 0o600
                        info.mtime = 0
                        with open(partial, "rb") as src:
                            tf.addfile(info, src)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(outer_partial, 0o600)
            os.link(outer_partial, archive)
            outer_partial.unlink()
            dir_fd = os.open(str(outdir), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            for p in partials:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
            raise
        finally:
            for p in partials:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
        return {
            "archive": str(archive),
            "schema": BACKUP_SCHEMA,
            "instance": name,
            "volumes": volumes_out,
        }


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _extract_member(fd, offset, size, dest):
    os.lseek(fd, offset, os.SEEK_SET)
    out = os.open(
        str(dest),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    h = hashlib.sha256()
    try:
        remaining = size
        while remaining > 0:
            chunk = os.read(fd, min(4 << 20, remaining))
            if not chunk:
                raise RuntimeFault("archive: truncated member")
            h.update(chunk)
            _write_all(out, chunk)
            remaining -= len(chunk)
    finally:
        os.close(out)
    return h.hexdigest()


def _open_source_cache(src_cache, want, spec_entry):
    """Open a staged source artifact: private, regular, owner, nlink1,
    0600, bounded, then hash with the declared algorithm. Caller owns
    the returned fd; bytes are pinned to the validated inode."""
    _check_private_source(src_cache)
    path = src_cache / want
    fd = os.open(
        str(path),
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_size > spec_entry["max_bytes"]
        ):
            raise RuntimeFault(f"source cache file unsafe: {want}")
        h = hashlib.new(spec_entry["hash"]["algorithm"])
        while True:
            chunk = os.read(fd, 4 << 20)
            if not chunk:
                break
            h.update(chunk)
        if h.hexdigest() != spec_entry["hash"]["hex"]:
            raise RuntimeFault(f"source cache {want} hash mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_private_source(path):
    try:
        _require_private_dir(path)
    except FileNotFoundError:
        return
    except StateError as exc:
        raise RuntimeFault(f"unsafe cache dir: {exc}") from exc


def _copy_source_cache(src_fds, dst_cache, lock):
    """src_fds: {name: (fd, want)} validated under the source lock."""
    dst = _ensure_private_dir(dst_cache)
    copied = []
    for name, (fd, want, entry) in sorted(src_fds.items()):
        dest = dst / want
        if os.path.lexists(dest):
            dfd = _open_source_cache(dst, want, entry)
            os.close(dfd)
            continue
        out = os.open(
            str(dest),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600)
        h = hashlib.new(entry["hash"]["algorithm"])
        written = 0
        try:
            while True:
                chunk = os.read(fd, 4 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > entry["max_bytes"]:
                    raise RuntimeFault(f"cache copy bound: {want}")
                h.update(chunk)
                _write_all(out, chunk)
        except BaseException:
            os.close(out)
            try:
                dest.unlink()
            except FileNotFoundError:
                pass
            raise
        os.close(out)
        if h.hexdigest() != entry["hash"]["hex"]:
            dest.unlink()
            raise RuntimeFault(f"copied cache {want} hash mismatch")
        copied.append(want)
    return copied


def _repo_seed_commit(path):
    """Read refs/heads/main from an extracted repo volume tar."""
    target = None
    with tarfile.open(str(path), "r:") as tf:
        for member in tf:
            name = member.name.rstrip("/")
            if name == "demo.git/refs/heads/main" or name.endswith(
                    "/refs/heads/main"):
                target = member
                break
    if target is None or not target.isreg():
        raise RuntimeFault(
            "restored repository is missing refs/heads/main")
    with tarfile.open(str(path), "r:") as tf:
        extracted = tf.extractfile(target)
        if extracted is None:
            raise RuntimeFault(
                "restored repository refs/heads/main is unreadable")
        try:
            raw = extracted.read().strip()
        finally:
            extracted.close()
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeFault(
            "restored repository refs/heads/main is not text") from exc
    if len(value) != 40 or any(
            c not in "0123456789abcdef" for c in value):
        raise RuntimeFault(
            "restored repository refs/heads/main is not a commit")
    return value


def restore(root_dir, source_name, archive_path, new_name, repo, runner):
    root_dir = Path(root_dir)
    repo = Path(repo)
    try:
        validate_instance_name(new_name)
    except ConfigError as exc:
        raise RuntimeFault(str(exc)) from exc
    archive = Path(archive_path)
    if not archive.is_absolute():
        raise RuntimeFault("--archive must be an absolute path")
    if load_manifest(root_dir, new_name) is not None \
            or _instance_dir(root_dir, new_name).exists():
        raise RuntimeFault(
            f'target "{new_name}": already exists; refusing')

    src_fds = {}
    try:
        with locked_instance(root_dir, source_name) as src_inst:
            source_manifest = load_manifest(root_dir, source_name)
            if source_manifest is None:
                raise RuntimeFault(
                    f'source "{source_name}": not initialized')
            record = load_runtime(src_inst, source_name)
            if record is None:
                raise RuntimeFault("source runtime record missing")
            uuid = source_manifest["identity"]["uuid"]
            image = _admit(runner, root_dir, source_name,
                           source_manifest, record, uuid,
                           repo=repo, require_stopped=False)
            profile, profile_fp = load_profile(
                repo, source_manifest["profile"]["name"])
            lock, _lock_fp = load_lock(
                Path(source_manifest["artifacts_lock"]["path"]))
            src_cache = cache_root() / "staging" / source_name
            if src_cache.is_dir():
                for aname in ("model", "opencode",
                              "inference_source"):
                    entry = lock["artifacts"][aname]
                    want = f"{aname}-{entry['hash']['hex'][:16]}"
                    if (src_cache / want).exists():
                        src_fds[aname] = (
                            _open_source_cache(src_cache, want, entry),
                            want, entry)

        staging_parent = _ensure_private_dir(
            root_dir / "restore-staging")
        staging = _ensure_private_dir(
            staging_parent / f"{new_name}-{secrets.token_hex(4)}")
        try:
            fd = fmt.open_archive(archive)
            try:
                members, _ = fmt.scan_ustar_fd(
                    fd, 8, fmt.MAX_OUTER_BYTES, "archive")
                pos = 0
                offsets = {}
                for m in members:
                    offsets[m["name"]] = pos + fmt.BLOCK
                    pos += fmt.BLOCK + (m["size"] + fmt.BLOCK - 1) \
                        // fmt.BLOCK * fmt.BLOCK
                names = [m["name"] for m in members]
                if sorted(names) != sorted(
                        ("manifest.json",) + fmt.MEMBER_NAMES):
                    raise RuntimeFault("archive: unexpected members")
                if len(set(names)) != len(names):
                    raise RuntimeFault("archive: duplicate members")
                for m in members:
                    if m["type"] != "reg":
                        raise RuntimeFault(
                            "archive: non-regular member")
                man = members[names.index("manifest.json")]
                if man["size"] > fmt.MAX_MANIFEST_BYTES:
                    raise RuntimeFault("archive: manifest too large")
                os.lseek(fd, offsets["manifest.json"], os.SEEK_SET)
                data = b""
                while len(data) < man["size"]:
                    chunk = os.read(fd, man["size"] - len(data))
                    if not chunk:
                        raise RuntimeFault(
                            "archive: truncated manifest")
                    data += chunk
                manifest_obj = fmt.parse_manifest_bytes(data)
                staged = {}
                for role in DATA_ROLES:
                    entry = manifest_obj["volumes"][role]
                    m = members[names.index(entry["member"])]
                    if m["size"] != entry["bytes"]:
                        raise RuntimeFault(
                            f"archive {role}: bytes mismatch")
                    dest = staging / entry["member"]
                    sha = _extract_member(
                        fd, offsets[entry["member"]],
                        m["size"], dest)
                    if sha != entry["sha256"]:
                        raise RuntimeFault(
                            f"archive {role}: sha256 mismatch")
                    staged[role] = dest
                os.lseek(fd, 0, os.SEEK_SET)
                outer_sha = fmt.hash_stream(fd)
            finally:
                os.close(fd)
            if manifest_obj["profile_name"] \
                    != source_manifest["profile"]["name"] \
                    or manifest_obj["profile_sha256"] \
                    != source_manifest["profile"]["sha256"]:
                raise RuntimeFault(
                    "archive profile does not match source")
            if manifest_obj["artifacts_lock_sha256"] \
                    != source_manifest["artifacts_lock"]["sha256"]:
                raise RuntimeFault(
                    "archive artifacts lock does not match source")
            if manifest_obj["seed_main"] != record["seed_main"]:
                raise RuntimeFault(
                    "archive seed_main does not match source runtime")
            imported_seed = _repo_seed_commit(staged["repo"])
            if imported_seed != manifest_obj["seed_main"]:
                raise RuntimeFault(
                    "restored repository seed_main does not match manifest")
            total_members = 0
            for role in DATA_ROLES:
                tfd = os.open(
                    str(staged[role]), os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    inner, _ = fmt.scan_ustar_fd(
                        tfd, fmt.MAX_MEMBERS_TOTAL - total_members,
                        fmt.MAX_ROLE_TAR_BYTES, role)
                    info = fmt.validate_inner_inventory(inner, role)
                    total_members += info["members"]
                finally:
                    os.close(tfd)

            manifest = init_instance(
                root_dir, new_name, profile, profile_fp,
                source_manifest["artifacts_lock"], True)
            new_uuid = manifest["identity"]["uuid"]
            n = spec.names(new_uuid)
            with locked_instance(root_dir, new_name):
                vols = manifest["resources"]["volume_names"]
                for role in DATA_ROLES:
                    vname = n[f"vol_{role}"]
                    if podman.object_exists(runner, "volume", vname):
                        raise RuntimeFault(
                            f"volume {vname} exists; refusing import "
                            "into pre-existing volume")
                    podman.must(runner, [
                        "volume", "create",
                        "--label",
                        f"{spec.LABEL_INSTANCE}={new_uuid}",
                        "--label", f"{spec.LABEL_ROLE}={role}",
                        vname], f"create volume {vname}")
                    vols[role] = vname
                    save_manifest_locked(root_dir, new_name, manifest)
                for role in DATA_ROLES:
                    member = f"{role}.tar"
                    argv = helper_argv(
                        image, vols[role], "rw", IMPORT_PY,
                        extra_args=(
                            manifest_obj["volumes"][role]["sha256"],
                            member),
                        extra_vol=f"{staging}:/archive:ro")
                    run_helper(
                        argv, staging / f".{role}.log",
                        staging / f".{role}.err", MAX_LOG_BYTES)
                copied = _copy_source_cache(
                    src_fds, cache_root() / "staging" / new_name,
                    lock)
            return {
                "instance": new_name,
                "source": source_name,
                "archive": str(archive),
                "archive_sha256": outer_sha,
                "volumes": vols,
                "cache_copied": copied,
                "next": [
                    f"prepare --instance {new_name} --allow-network",
                    f"up --instance {new_name}",
                ],
            }
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    finally:
        for fd, _w, _e in src_fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
