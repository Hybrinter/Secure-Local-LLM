# Operations

## Lifecycle

1. `doctor` — host prerequisite report (read-only).
2. `init --profile cpu --acknowledge-prototype-no-lsm --artifacts-lock PATH`
   — creates private instance state bound to the profile and lock hashes.
3. `prepare --allow-network` — the **only** online step; stages pinned
   artifacts and builds labeled images.
4. `up` — runs `doctor`, then creates or adopts owned resources
   (labels: instance UUID + role), installs nftables policy *before*
   starting workload members, seeds the fixture repo, populates the model
   volume, waits for authenticated readiness, runs shared verification,
   and freezes the runtime record.
5. `stop` — prevalidates every recorded target (UUID + role + pod
   membership) before stopping; per-target failures are reported, never
   masked. Volumes, keys, repos, model data, and session state persist.
6. `verify` — independent re-check of the frozen record vs. live state;
   fails closed (exit 1) on stopped/missing members or failed probes. On
   failure it stops the affected owned members before returning, so this
   command has the side effect of terminating a live session when a check
   fails.
7. `evidence` — allowlisted JSON + Markdown report, written 0600 under
   the private instance state directory. Never committed.

`backup` exports the three data volumes (workspace, state, repo) of a
**stopped** instance — including anything the workload persisted inside
them (session state in `/state`, repository content in `/repos`) —
through an offline helper (recorded git image, volume read-only,
network none, cap-drop ALL). The artifact cache, model volume, control
keys, and runtime bindings are **not** in the archive; they are
reconstructed from pins and fresh controls at restore time.

Archives are plaintext, sensitive `backup@1` **strict USTAR** tars
(manifest + one tar per role): no PAX/GNU extensions, no sparse files,
no ACL/xattr metadata, no links — names must be USTAR-encodable and
files containing symlinked trees (e.g. Python venvs) fail closed and
need a separate strategy. Member hashes are integrity checks, not
authenticity — treat restored repository/session data as untrusted
content in a contained instance. Archives are written 0600 under a
private 0700 directory; encryption-at-rest is an acknowledged gap.

`restore` validates the entire archive (outer + nested headers, hashes,
names, bounds) before creating a fresh instance with a new UUID and new
volumes; it refuses to touch any existing instance or volume. Verified
source cache artifacts are copied with matching hashes so `prepare`
need not redownload. Sequence:

```bash
./scripts/stop.sh --instance demo
./scripts/local-agent.sh backup --instance demo
ARCHIVE="/absolute/path/printed-by-backup.tar"
./scripts/local-agent.sh restore --instance demo --archive "$ARCHIVE" \
    --new-instance recovery-check
./scripts/local-agent.sh prepare --instance recovery-check --allow-network
./scripts/start.sh --instance recovery-check
./scripts/verify.sh --instance recovery-check
./scripts/start.sh --instance demo
```

Set `ARCHIVE` to the absolute path printed by `backup` before running
`restore`. Choose a new destination name; existing instances are never
overwritten. Restoring does not start a model or make a new inference
request. Model artifacts are staged again from verified local cache
where available; `--allow-network` remains explicit for preparation.

The synthetic coding demo requires the pristine seed and never resets
an existing worktree. A completed demo leaves its successful agent branch
and commit intact. Use `chat` for subsequent work; another fresh demo
needs a separately initialized instance.

## State layout

```
$XDG_STATE_HOME/secure-local-llm/
  instances/<name>/
    manifest.json          # identity + profile/lock fingerprints + resource bindings
    prepared.json          # prepared images + artifact fingerprints
    git-prepared.json      # git fixture prepared record
    runtime.json           # frozen secure-local-llm/runtime@1 record
    control/               # generated keys/config; fingerprinted; 0600
    demo-*.json            # operator workflow records
    evidence-*.{json,md}   # sanitized reports
```

State dirs are `0700`, files `0600`, fcntl-locked atomic writes, symlink
and collision refusal. `doctor`/`status` never create state.

## What `up` refuses

- remote-engine environment variables (`PODMAN_HOST`, `CONTAINER_HOST`, …)
- foreign labels, recorded-ID mismatches, renamed/missing bound objects
- control-file, recipe, profile, lock, or native-config drift
- unbounded or non-canonical policy; policy always precedes member start
- unrecognized or drifted existing worktrees/repos, symlink key/model paths, unknown writable
  tmpfs, unexpected mounts, proxy env, published ports, restart policies

## Chat

`chat` re-runs shared verification first; on failure it stops verifiably
owned members and refuses. Before exec it prepares a private per-attach
scratch dir `/state/.cache/opencode-tui` (0700, harness-owned, created via
an isolated `python3 -I -B -c` probe using dirfd/`O_NOFOLLOW`; symlink,
foreign-owner, or mode mismatch refuses). The TUI then execs
`podman --remote=false exec -it -w /workspace/repo -e PWD=/workspace/repo
-e TMPDIR=/state/.cache/opencode-tui <harness-id> opencode /workspace/repo`
on the operator's TTY — no captured output, no credentials in argv or
environment, instance lock released before exec.

`TMPDIR` is required because bun extracts its native OpenTUI library into
TMPDIR and `mmap`s it executable, which the hardened `noexec` `/tmp`
tmpfs rejects. The state volume is exec-capable and already approved for
code/venvs, so the scratch dir lives there rather than weakening `/tmp`,
mounts, or capabilities. This is a per-attach process environment only —
no container spec, service, or model environment changes. Note the
prototype's unverified-storage-quota exception applies: the TUI cache is
a private 0700 dir on the state volume but is not bounded by a verified
disk quota.
