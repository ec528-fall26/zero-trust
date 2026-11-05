#!/usr/bin/env bash
set -euo pipefail

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec node "$repository/experiments/demo2_bootstrap.mjs" "$@"
