# AGENTS.md

Restricted local coding-agent prototype controller. Python standard library
only; rootless Podman orchestration only.

## Layout

- `scripts/local-agent.sh` — operator entry point; resolves repo root, then
  execs `python3 -I -B -c <bootstrap> <repo>/lib <args>`: isolated mode, only
  `lib/` is inserted into `sys.path`, argv is forwarded verbatim.
- `lib/local_agent/` — controller package (`cli`, `config`, `state`, `runner`).
- `.devin/profiles/` — strict versioned runtime profiles.
- `tests/` — `unittest` suite.

## Commands

```bash
./scripts/local-agent.sh doctor    # host prerequisite check (read-only)
./scripts/local-agent.sh status    # instance state (read-only)
./scripts/local-agent.sh init --profile cpu --acknowledge-prototype-no-lsm \
    --artifacts-lock /absolute/path/to/lock.json
```

`up`, `stop`, `prepare`, `verify`, `chat`, `demo`, `backup`, `restore`, and
`evidence` are registered and fail closed (exit 3) until implemented.

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
