#!/usr/bin/env bash
# Fails unless the version in a release tag matches that SDK's version files.
# Usage: scripts/verify-release-version.sh ts-v0.2.0[-title] | csharp-v0.2.0[-title] | rust-v0.2.0[-title]
set -euo pipefail

tag="${1:?usage: verify-release-version.sh <tag>}"
cd "$(git rev-parse --show-toplevel)"

case "$tag" in
  ts-v*) lang=ts; rest="${tag#ts-v}" ;;
  csharp-v*) lang=csharp; rest="${tag#csharp-v}" ;;
  rust-v*) lang=rust; rest="${tag#rust-v}" ;;
  *) echo "verify-release-version: tag '$tag' must start with ts-v, csharp-v or rust-v"; exit 1 ;;
esac
if [[ ! "$rest" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]]; then
  echo "verify-release-version: cannot derive X.Y.Z from tag '$tag'"
  exit 1
fi
want="${BASH_REMATCH[1]}"

case "$lang" in
  ts) have="$(node -p "require('./languages/typescript/package.json').version")"; where="languages/typescript/package.json" ;;
  csharp) have="$(sed -nE 's|.*<Version>([^<]+)</Version>.*|\1|p' languages/csharp/AvalonSdk/AvalonSdk.csproj | head -n1)"; where="AvalonSdk.csproj" ;;
  rust) have="$(sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"; where="Cargo.toml" ;;
esac

if [[ "$have" != "$want" ]]; then
  echo "verify-release-version: tag $tag is $want but $where is $have"
  exit 1
fi
echo "verify-release-version: $tag matches $where ($want)"
