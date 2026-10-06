#!/usr/bin/env bash
# Syncs or checks the vendored protocol files (conformance/vectors/, docs/generated/openapi.json) against avalon-protocol main.
#   scripts/sync-protocol.sh check    fail when they differ (needs network; not part of `make check`)
#   scripts/sync-protocol.sh update   overwrite them byte for byte from protocol main
# PROTOCOL_REPO=<url-or-path> compares against another clone source. languages/rust/openapi.json is a symlink to the same file.
set -euo pipefail

cd "$(dirname "$0")/.."
mode="${1:-check}"
repo="${PROTOCOL_REPO:-https://github.com/avalon-initiative/avalon-protocol}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 "$repo" "$tmp/protocol"
echo "sync-protocol: protocol $(git -C "$tmp/protocol" rev-parse --short HEAD)"
p="$tmp/protocol"

case "$mode" in
  update)
    rm -rf conformance/vectors
    cp -r "$p/conformance/vectors" conformance/vectors
    cp "$p/docs/generated/openapi.json" docs/generated/openapi.json
    echo "sync-protocol: updated; regenerate types (languages/typescript: npm run generate; languages/csharp: dotnet run --project codegen)"
    ;;
  check)
    status=0
    diff -rq "$p/conformance/vectors" conformance/vectors || status=1
    diff -q "$p/docs/generated/openapi.json" docs/generated/openapi.json || status=1
    if [ "$status" -eq 0 ]; then
      echo "sync-protocol: vectors and openapi.json match protocol main"
    else
      echo "sync-protocol: FAILED; vendored files differ from protocol main (run scripts/sync-protocol.sh update)" >&2
      exit 1
    fi
    ;;
  *) echo "usage: sync-protocol.sh [check|update]" >&2; exit 1 ;;
esac
