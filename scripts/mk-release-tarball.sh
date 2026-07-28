#!/usr/bin/env bash
# Assemble the vpn.tar.gz release asset from this repo's own flake.
#
# Layout matches the historical Docker-built asset (last shipped in v1.0.25):
#
#   <arch>/vpn            guest binary per arch, regular file, 0755
#   README.txt            provenance stamp: source commit + build time
#
# plus the vpn/vpn.<arch> flat symlinks that .#dist already owns. Those are an
# addition over the pre-v1.0.26 asset: penguin's host side execs
# igloo_static/vpn/vpn.x86_64 directly (pyplugins/actuation/vpn.py), so keeping
# them makes the tarball drop-in usable as penguin/local_packages/vpn.tar.gz.
#
# One arch the old asset had is absent here: 32-bit big-endian `powerpc`, which
# is not in src/archs.nix (deliberately kept in sync with penguin-tools'
# matrix). Nothing in penguin can select a ppc32 guest today.
#
# Usage: scripts/mk-release-tarball.sh [output.tar.gz]

set -euo pipefail

out=$(realpath -m "${1:-vpn.tar.gz}")

cd "$(dirname "${BASH_SOURCE[0]}")/.."

dist=$(nix build --accept-flake-config .#dist --no-link --print-out-paths -L)

stage=$(mktemp -d)
trap 'chmod -R u+w "$stage" 2>/dev/null || true; rm -rf "$stage"' EXIT

# cp -a keeps the relative vpn/vpn.<arch> symlinks as symlinks; the store tree
# is read-only, so make the copy writable before restamping modes.
cp -a "$dist"/. "$stage"/
chmod -R u+w "$stage"

# GITHUB_SHA in CI; git otherwise (which can fail in a bare worktree container).
rev=${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}
epoch=$(date -u +%s)
printf 'vsock_vpn at %s built at %s\n' \
    "$rev" "$(date -u -d "@$epoch" '+%a %b %e %H:%M:%S UTC %Y')" \
    >"$stage/README.txt"

find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -name vpn -exec chmod 0755 {} +
chmod 0644 "$stage/README.txt"

# Deliberately NOT `tar -h`: the nix store shares inodes between the flat
# symlink targets and the per-arch copies, so dereferencing emits hardlink
# records instead of copies and moves which path holds the real bytes.
tar czf "$out" -C "$stage" \
    --owner=root --group=root --mtime="@$epoch" --sort=name \
    .

echo "$out"
