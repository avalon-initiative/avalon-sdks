#!/usr/bin/env bash
# Fails when conformance/vectors/ differs from avalon-protocol's main (needs network; not part of `make check`).
#   scripts/check-vector-sync.sh                 compare against github.com/avalon-initiative/avalon-protocol main
#   PROTOCOL_REPO=<url-or-path> scripts/check-vector-sync.sh   compare against another clone source
set -euo pipefail

cd "$(dirname "$0")/.."
repo="${PROTOCOL_REPO:-https://github.com/avalon-initiative/avalon-protocol}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 "$repo" "$tmp/protocol"
echo "vector-sync: protocol $(git -C "$tmp/protocol" rev-parse --short HEAD)"

if diff -rq "$tmp/protocol/conformance/vectors" conformance/vectors \
  | sed -e "s#$tmp/protocol/#protocol: #" -e 's#^Only in #only in #' -e 's#^Files #differs: #'; [ "${PIPESTATUS[0]}" -eq 0 ]; then
  echo "vector-sync: conformance/vectors/ matches protocol main"
else
  echo "vector-sync: FAILED; vendored vectors differ from protocol main (copy the protocol's files byte for byte)" >&2
  exit 1
fi
