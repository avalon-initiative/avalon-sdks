#!/usr/bin/env bash
# Fails unless every SDK's version matches the version in a release tag.
# Usage: scripts/verify-release-version.sh v0.2.0[-title]
set -euo pipefail

tag="${1:?usage: verify-release-version.sh <tag>}"
cd "$(git rev-parse --show-toplevel)"

if [[ ! "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)([-.].*)?$ ]]; then
  echo "verify-release-version: tag '$tag' must look like vX.Y.Z[-title]"
  exit 1
fi
want="${BASH_REMATCH[1]}"

ts="$(node -p "require('./languages/typescript/package.json').version")"
csharp="$(sed -nE 's|.*<Version>([^<]+)</Version>.*|\1|p' languages/csharp/AvalonSdk/AvalonSdk.csproj | head -n1)"
rust="$(sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"

status=0
for entry in "TypeScript:$ts" "C#:$csharp" "Rust:$rust"; do
  name="${entry%%:*}"; have="${entry#*:}"
  if [[ "$have" != "$want" ]]; then
    echo "verify-release-version: tag $tag is $want but the $name SDK is $have"
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "verify-release-version: $tag matches all three SDKs ($want)"
exit "$status"
