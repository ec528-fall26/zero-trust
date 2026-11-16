#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: demo_workload.sh INPUT" >&2
  exit 64
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$1"
else
  shasum -a 256 "$1"
fi
