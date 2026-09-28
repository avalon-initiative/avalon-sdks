#!/usr/bin/env bash
# Gathers every file a release attaches into release-assets/ and writes SHA256SUMS over them:
# the packed npm tarball, the NuGet package(s) from out/, and the two Rust .crate files.
# Run after the TypeScript and C# packs; it packs the crates itself.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

rm -rf release-assets target/package
mkdir -p release-assets

cargo package --workspace --locked ${PACKAGE_ARGS:-}

shopt -s nullglob
files=(languages/typescript/*.tgz out/*.nupkg target/package/*.crate)
if [ "${#files[@]}" -ne 4 ]; then
  echo "release-assets: expected 1 tgz, 1 nupkg and 2 crates, found: ${files[*]}"
  exit 1
fi
cp "${files[@]}" release-assets/

(cd release-assets && sha256sum -- * > SHA256SUMS)
cat release-assets/SHA256SUMS
