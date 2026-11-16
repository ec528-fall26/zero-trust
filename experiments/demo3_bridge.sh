#!/bin/sh
# Demo 3 bridge experiment.  Local by default; pass --aws to run against the
# deployed node (after make demo2-bootstrap and infra/aws/prepare-demo.sh).
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
cd "$repository_root"
exec node experiments/demo3_bridge.mjs "$@"
