# Architecture

Restricted single-tenant prototype. All orchestration is stdlib Python;
all container operations are rootless Podman on the operator's own UID.

## Topology

```
host (operator UID)
└── internal bridge network (/28, --internal --disable-dns, no IPv6)
    ├── workload pod (.2)  -- shared net+user namespace
    │   ├── infra container (pod owner, default runtime profile)
    │   ├── inference      llama.cpp server, 127.0.0.1:<model port> only
    │   └── harness        opencode serve, 127.0.0.1:<service port> only
    └── git fixture (.3)   restricted sshd -> git-upload-pack/receive-pack
```

nftables default-deny policy is applied inside each network namespace via
a `podman unshare` helper that validates the namespace handles it touches.
The workload pod may reach only the Git fixture on its fixed SSH port.
The Git fixture only *answers* approved SSH sessions — it cannot initiate
connections back to the pod. Nothing else is reachable in either
direction.

## Resource envelope (profile `cpu`)

| Object | Memory (+swap=memory) | CPUs | PIDs |
|---|---|---|---|
| pod (total) | 8192 MiB | 4.0 | — |
| inference | 6144 MiB | 4.0 | half of profile |
| harness | 2048 MiB | 4.0 | half of profile |
| git fixture | 512 MiB | 1.0 | 64 |

Member swap is always set equal to member memory (no anonymous swap head-room);
`memory.swap.max == 0` is verified live. These are the prototype's
profile values, not universal hardware minima.

## Member controls

- `--pull=never`, read-only rootfs, `--cap-drop ALL`,
  `--security-opt no-new-privileges` (pod level and per member)
- private PID/IPC/UTS/mount/cgroup namespaces; pod members share infra's
  net and user namespaces (verified by namespace inode equality)
- bounded tmpfs: `/run/local-agent` (root-owned 0755, 16 MiB) and `/tmp`
  (1777 nosuid/nodev/noexec, 64 MiB)
- `--log-driver=k8s-file --log-opt max-size=4mb`
- `--http-proxy=false`, `--image-volume=ignore`, no restart policy,
  no published ports, no proxy/agent environment, `--dns=none` where
  appropriate
- secret/config material bind-mounted `ro,nosuid,nodev,noexec` from the
  private control directory; all control files are fingerprinted and
  drift is refused
- all trusted in-container probes run `python3 -I -B -c` so user site
  packages, `sitecustomize`, and repository shadowing cannot spoof
  readiness or verification

## Trust boundaries

- Same kernel, same operator UID: the **repository and agent are
  contained**, but the human operator — and any same-UID host process —
  stands outside the boundary and can manage Podman directly. Workload
  confinement is namespace + cgroup + seccomp + capability drop only
  (no LSM — see production-gaps).
- The Git fixture's `ForceCommand` accepts exactly
  `git-upload-pack|git-receive-pack '/repos/demo.git'` over publickey-only
  auth; a `pre-receive` hook allows `refs/heads/agent/*` new or
  fast-forward commits only.
- Data volumes (workspace/state/model/repo) persist across stop/up; model
  population is hash-checked atomic promotion inside the owned volume;
  seed bootstrap never overwrites an existing worktree and validates the
  known baseline commit, test-file hash, and remote identity.
- Runtime bindings (pod/container/volume/network IDs, tables, policy
  hashes, image IDs, fingerprints, seed metadata) are frozen in an
  exact-schema runtime record; missing, renamed, or ID-mismatched bound
  objects are refused before anything is created.
