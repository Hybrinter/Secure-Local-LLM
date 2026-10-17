#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd -P)"
exec python3 -I -B -c 'import sys
sys.path.insert(0, sys.argv[1])
from local_agent.cli import main
sys.exit(main(sys.argv[2:]))' "${REPO_ROOT}/lib" "$@"
