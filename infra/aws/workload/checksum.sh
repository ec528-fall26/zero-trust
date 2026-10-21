#!/bin/sh
set -eu
[ "$#" -eq 1 ] || exit 64
exec sha256sum "$1"
