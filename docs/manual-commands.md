# Manual command reference

`./scripts/local-agent.sh commands` (or `./scripts/commands.sh`) renders
the exact argv the controller would use for the recorded instance as
shell-quoted lines. It is **dry-run only**: it executes nothing, and the
managed lifecycle (`up` / `stop` / `verify`) remains authoritative.
Do not paste rendered creation commands over existing objects — the
controller refuses foreign or drifted bindings for a reason.

Secrets never appear in the output; only bind-mount file paths are shown.

Rendered sections:

| Section | Source |
|---|---|
| internal network | `podman network create --internal --disable-dns --subnet <recorded>` |
| workload pod | `runtime_spec.pod_args` (pod-level limits + `no-new-privileges`) |
| members | `runtime_spec.inference_args` / `harness_args` / `git_args` |
| namespace policy | `podman unshare python3 -I -B netns_helper.py` with the stdin JSON request shape (namespace handles are read live from the target at apply time) |

Equivalent operator commands, grouped:

```bash
./scripts/local-agent.sh doctor
./scripts/local-agent.sh init --profile cpu --acknowledge-prototype-no-lsm
./scripts/local-agent.sh prepare --allow-network
./scripts/start.sh            # == local-agent.sh up
./scripts/status.sh
./scripts/verify.sh
./scripts/chat.sh             # requires a TTY
./scripts/demo.sh --protocol-only
./scripts/local-agent.sh evidence
./scripts/commands.sh
./scripts/stop.sh
```

Use `./scripts/demo.sh` without `--protocol-only` only when intentionally
running the real coding task on a pristine synthetic seed.

`doctor` is not instance-specific. Instance commands accept
`--instance NAME` (default `demo`). `init` uses the repository's managed
artifacts lock unless `--artifacts-lock PATH` names a different approved
pin file. The operator entry point always execs `python3 -I -B` with
only `lib/` on `sys.path`.
