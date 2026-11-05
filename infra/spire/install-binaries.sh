#!/usr/bin/env bash
set -euo pipefail

[ "$(uname -s)" = Linux ] || { echo "SPIRE installation requires Linux" >&2; exit 69; }
[ "$(uname -m)" = x86_64 ] || { echo "only x86_64 is pinned by this installer" >&2; exit 69; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }

spire_version=1.15.5
helper_version=0.12.3
spire_sha256=f0d1740504fc95e49860ea22dcbe878ebbfee4c9bb077c6a586ed66b9c82a62e
helper_sha256=b275a572d36ec02f5da995c11c736b3300ab5210af21f3deff1b5fc727cecd69
spire_archive="spire-${spire_version}-linux-amd64-musl.tar.gz"
helper_archive="spiffe-helper_v${helper_version}_Linux-x86_64.tar.gz"

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 69; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 69; }

work_dir=$(mktemp -d /tmp/ec528-spire-install.XXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work_dir/$spire_archive" \
  "https://github.com/spiffe/spire/releases/download/v${spire_version}/${spire_archive}"
printf '%s  %s\n' "$spire_sha256" "$work_dir/$spire_archive" | sha256sum --check --status

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work_dir/$helper_archive" \
  "https://github.com/spiffe/spiffe-helper/releases/download/v${helper_version}/${helper_archive}"
printf '%s  %s\n' "$helper_sha256" "$work_dir/$helper_archive" | sha256sum --check --status

tar -xzf "$work_dir/$spire_archive" -C "$work_dir"
tar -xzf "$work_dir/$helper_archive" -C "$work_dir"
spire_root=$(find "$work_dir" -mindepth 1 -maxdepth 1 -type d -name 'spire-*' -print -quit)
[ -n "$spire_root" ] || { echo "SPIRE archive layout is invalid" >&2; exit 65; }

install -d -o root -g root -m 0755 /opt/spire/bin /usr/local/bin
install -o root -g root -m 0755 "$spire_root/bin/spire-server" /opt/spire/bin/spire-server
install -o root -g root -m 0755 "$spire_root/bin/spire-agent" /opt/spire/bin/spire-agent
helper_binary=$(find "$work_dir" -type f -name spiffe-helper -print -quit)
[ -n "$helper_binary" ] || { echo "SPIFFE Helper archive layout is invalid" >&2; exit 65; }
install -o root -g root -m 0755 "$helper_binary" /usr/local/bin/spiffe-helper

/opt/spire/bin/spire-server --version
/opt/spire/bin/spire-agent --version
/usr/local/bin/spiffe-helper -version
