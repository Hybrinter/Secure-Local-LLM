# AGENTS.md

Restricted local coding-agent prototype controller. Python standard library
only; rootless Podman orchestration only.

## Layout

- `scripts/local-agent.sh` — operator entry point; resolves repo root, then
  execs `python3 -I -B -c <bootstrap> <repo>/lib <args>`: isolated mode, only
  `lib/` is inserted into `sys.path`, argv is forwarded verbatim.
- `lib/local_agent/` — controller package (`cli`, `config`, `state`, `runner`).
- `.devin/profiles/` — strict versioned runtime profiles.
- `containers/` — digest-pinned image build recipes.
- `tests/` — `unittest` suite.

## Commands

```bash
./scripts/local-agent.sh doctor    # host prerequisite check (read-only)
./scripts/local-agent.sh status    # instance state (read-only)
./scripts/local-agent.sh up        # create/verify network+pod+containers, then start
./scripts/local-agent.sh stop      # stop workload members (volumes preserved)
./scripts/verify.sh                # effective verification of a running instance
./scripts/chat.sh                  # verify, then interactive opencode TUI (TTY only)
./scripts/demo.sh                  # lead-owned workflow; --protocol-only skips task
./scripts/local-agent.sh evidence  # sanitized allowlisted report (JSON+Markdown)
./scripts/commands.sh              # dry-run rendering of managed argv
./scripts/local-agent.sh init --profile cpu --acknowledge-prototype-no-lsm \
    --artifacts-lock /absolute/path/to/lock.json
./scripts/local-agent.sh prepare --allow-network   # online staging, explicit only
./scripts/local-agent.sh backup [--output /abs/private/dir]
./scripts/local-agent.sh restore --archive /abs/backup.tar --new-instance NAME
```

`backup` exports only quiesced workspace/state/repo volumes through an
offline hardened helper; `restore` imports into a fresh instance with new
UUID/volumes, then `prepare --allow-network` and `up` are explicit steps.

## Checks

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py'
bash -n scripts/local-agent.sh
git diff --check
```

## Boundaries

- Stdlib only; argv arrays (never shell); bounded timeouts; `podman` always
  invoked as `podman --remote=false`; remote engine env vars fail closed.
- State under `${XDG_STATE_HOME:-~/.local/state}/secure-local-llm`, cache under
  `${XDG_CACHE_HOME:-~/.cache}/secure-local-llm`: 0700 dirs / 0600 files,
  fcntl-locked atomic writes, symlink/collision refusal. `doctor`/`status`
  never create state.
- Instance names match `[a-z][a-z0-9-]{0,31}`. Profiles reject unknown keys,
  bool-as-int, and out-of-range values.
- No credentials, keys, weights, or machine-local config in the repo.
- No new Podman objects, downloads, or builds without approval; no global
  prune/reset, sudo, or host security changes.
