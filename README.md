# Secure-Local-LLM

Security-oriented **proof of concept** for a restricted, CPU-only, local
coding-agent runtime intended to inform a future FedRAMP High design. It is
**not** an authorized system, not production-ready, and not a multi-tenant
deployment.

The controller (`lib/local_agent/`) is Python standard library only. It
orchestrates **rootless Podman** (`podman --remote=false` only; remote-engine
environment variables fail closed) with:

- an isolated pod (private PID/IPC/UTS/mount/cgroup namespaces, shared
  net+user namespace) containing an inference member (`llama.cpp`,
  loopback-only model API) and a harness member (OpenCode V2);
- a separate Git fixture member on the same internal network providing a
  restricted SSH `git-upload-pack`/`git-receive-pack` path;
- default-deny nftables policy per network namespace (loopback +
  approved-peers only);
- read-only root filesystems, `cap-drop ALL`, `no-new-privileges`, bounded
  tmpfs, bounded logs, no published ports, no restart policy;
- immutable runtime records, fingerprinted control material, fail-closed
  verification, and sanitized evidence reports.

## Quickstart

Requires Linux x86_64, Python 3.11+, rootless Podman 4.9.x, `nft`,
`nsenter`, `ssh`, `ssh-keygen`.

```bash
./scripts/local-agent.sh doctor                    # host prerequisites
./scripts/local-agent.sh init --profile cpu --acknowledge-prototype-no-lsm
    # artifacts lock defaults to the managed .devin/artifacts.lock.json
./scripts/local-agent.sh prepare --allow-network   # online staging (explicit only)
./scripts/local-agent.sh up                        # create + verify + start
./scripts/chat.sh                                  # interactive opencode session (TTY)
./scripts/demo.sh --protocol-only                  # protocol check, no agent task
./scripts/verify.sh                                # independent live verification
./scripts/local-agent.sh evidence                   # sanitized evidence report
./scripts/commands.sh                              # dry-run argv reference
./scripts/stop.sh                                  # stop members (volumes preserved)
```

`prepare` is the only network-online step; the runtime itself is offline
except the restricted fixture SSH path inside the internal network.

## Commands

| Command | Effect |
|---|---|
| `doctor` | read-only host prerequisite report; creates no state |
| `init` | create private instance state + profile/lock binding |
| `prepare` | pinned artifact staging + image builds (requires `--allow-network`) |
| `up` | doctor gate → create/adopt owned resources → policy → start → verify |
| `stop` | prevalidated stop of recorded members; volumes preserved |
| `status` | read-only instance summary |
| `verify` | shared live verification (fails closed on stopped/missing members) |
| `chat` | verify, then `podman exec -it ... opencode` on the host TTY |
| `demo` | operator-controlled synthetic task workflow (`--protocol-only` skips the task) |
| `evidence` | sanitized allowlisted report (JSON + Markdown, 0600, private state) |
| `commands` | dry-run rendering of managed argv (never executes) |
| `backup` / `restore` | quiesced data-volume export to a private `backup@1` archive; restore into a fresh instance (plaintext — encryption gap documented) |

## Documentation

- `docs/architecture.md` — topology, trust boundaries, controls
- `docs/manual-commands.md` — argv reference rendered by `commands`
- `docs/operations.md` — lifecycle, evidence, state layout
- `docs/production-gaps.md` — known prototype exceptions and future work

## Tests

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py'
(for script in scripts/*.sh; do bash -n "$script" || exit 1; done)
git diff --check
```

Integration gates (`tests/integration/`) are opt-in, disposable, and
self-cleaning.
