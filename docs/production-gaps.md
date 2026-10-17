# Production gaps

This prototype demonstrates controls for a future FedRAMP High
environment; it is **not** an authorized system. Known exceptions and
future work, reported honestly rather than assumed:

## Active prototype exceptions (reported by doctor/verify/evidence)

| Exception | Status |
|---|---|
| No active LSM confinement (AppArmor/SELinux) on this host | reported; `init` requires explicit `--acknowledge-prototype-no-lsm` |
| Writable storage quotas unverified (not established) | reported |
| Infra container runs the default runtime profile | degraded in verify; Podman 4.9 does not apply member hardening to infra; pod-level cgroup limits **are** enforced and verified, and `no-new-privileges` is applied pod-wide |

## Boundary of the prototype

- Same kernel and same operator UID as the workload — defense is
  namespace, cgroup, seccomp, capability, and network policy only.
- Repository tests execute inside the contained harness; the workload
  may use a Git identity, but only for `agent/*` branches via the
  fixture's restricted SSH path.
- This is a **demonstration/test harness**, not a benchmark,
  authorization, or tamper-proof attestation. Reported checks show the
  configured controls exist — they are not proof against a determined
  in-kernel or hypervisor-level adversary.

## Future integration (not implemented here)

- Real GitLab or internal mirror endpoint (fixture stands in)
- An approved OS baseline with active LSM and verified quotas
- GPU inference runtime and request batching
- Multi-tenancy, RBAC, central audit, and production networking
- Backup archives are **plaintext and sensitive** (sessions and
  repository data may contain secrets): stored 0600/0700 only;
  encryption-at-rest remains a gap. Symlinked trees are refused by the
  strict archive format.

## Measured resource use (one smoke workload, not a benchmark)

Kernel cgroup counters captured after the successful synthetic task
(pod cgroup lifetime, including initialization and prior activity; Git
fixture outside the pod): `memory.peak` 2,609,176,576 bytes (~2.43 GiB),
`memory.max` 8 GiB, `cpu.max` 400000/100000, `memory.swap.max` 0.
Describe the prototype as an **8 GiB pod + 512 MiB Git budget, 4 CPUs**
— not a minimum requirement or a fit guarantee for any machine.

## GPU candidates evaluated for a future build (researched, untested)

- Muse Glimmer 30B: ~29.6B parameters, 131072 context; ~48 GB A40-class
  card advertised. Quantized artifact/runtime compatibility untested.
- Beam 1.0: 501.3B total / 23.4B active parameters; 4× RTX PRO 6000
  Blackwell Server (96 GB each, ~384 GB aggregate advertised). Raw
  weights lower bound alone ≈ 251 GB before precision, metadata, runtime
  and KV; active-parameter count is not a storage budget, aggregate
  VRAM is not unified, and topology/sharding/backend/batching limits are
  untested. A stable OpenAI-compatible provider seam permits a backend
  change but is not compatibility proof. No GPU setup ran in this
  prototype; the CPU 8k-context/1-slot profile is what was tested.
- The first real synthetic task run reached the model and made real tool
  calls but **failed the independent check**: the seeded worktree files
  were read-only (mode 0400, propagated by `cp` from the control seed), so
  the agent's correct edit could not be written. That platform defect was
  confirmed and repaired (seed now lands writable; existing seeded files
  were mode-repaired without content change). A controlled retry on the
  repaired runtime **passed all checks** (independent AST oracle, six
  test cases, unchanged protected test, clean committed change, remote
  tree match). Both attempts are preserved as data; these demonstrations
  are not a benchmark or attestation.
