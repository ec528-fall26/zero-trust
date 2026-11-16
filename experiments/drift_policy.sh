#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT=${1:-"$REPOSITORY_ROOT/results/drift-policy.json"}

cd "$REPOSITORY_ROOT"
node experiments/drift_policy.mjs "$OUTPUT"
