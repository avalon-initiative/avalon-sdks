#!/usr/bin/env bash
# Cut a release of one SDK: run its checks, bump only its own version files,
# commit, and create an annotated tag. Pushing the tag starts the release workflow.
#
#   scripts/release.sh ts     0.2.0 ["Optional title"]   ->  tag ts-v0.2.0[-optional-title]
#   scripts/release.sh csharp 0.2.0 ["Optional title"]   ->  tag csharp-v0.2.0[-optional-title]
#   scripts/release.sh rust   0.2.0 ["Optional title"]   ->  tag rust-v0.2.0[-optional-title]
#
# Environment: SKIP_CHECKS=1 skips the checks.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

lang="${1:-}"
ver="${2:-}"
title="${3:-}"

read_version() {
  case "$1" in
    ts) node -p "require('./languages/typescript/package.json').version" ;;
    csharp) sed -nE 's|.*<Version>([^<]+)</Version>.*|\1|p' languages/csharp/AvalonSdk/AvalonSdk.csproj | head -n1 ;;
    rust) sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' | head -n1 ;;
  esac
}

case "$lang" in
  ts|csharp|rust) prefix="${lang}-v" ;;
  *) echo "usage: release.sh <ts|csharp|rust> <X.Y.Z> [title]"; exit 1 ;;
esac

current="$(read_version "$lang")"
if [ -z "$ver" ]; then
  read -r -p "Release version for $lang (current: $current): " ver
  ver="${ver:-$current}"
fi
if ! [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release: invalid version '$ver' (expected X.Y.Z)"
  exit 1
fi

slug="$(printf '%s' "$title" | sed -E 's/[[:space:]]+/-/g; s/[^A-Za-z0-9._-]//g; s/^-+//; s/-+$//')"
tag="${prefix}${ver}${slug:+-$slug}"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "release: tag '$tag' already exists"
  exit 1
fi

if [ "${SKIP_CHECKS:-}" = "1" ]; then
  echo "release: skipping checks (SKIP_CHECKS=1)"
else
  echo "release: running checks for $lang"
  if ! bash scripts/release-checks.sh "$lang"; then
    echo "release: checks failed; nothing was changed"
    exit 1
  fi
fi

echo "release: sdk=$lang version=$ver tag=$tag"
case "$lang" in
  ts)
    (cd languages/typescript && npm version --no-git-tag-version --allow-same-version "$ver" >/dev/null)
    files=(languages/typescript/package.json languages/typescript/package-lock.json)
    ;;
  csharp)
    sed -i -E "s|<Version>[^<]+</Version>|<Version>${ver}</Version>|" languages/csharp/AvalonSdk/AvalonSdk.csproj
    files=(languages/csharp/AvalonSdk/AvalonSdk.csproj)
    ;;
  rust)
    tmp="$(mktemp)"
    awk -v ver="$ver" '
      $0 == "[workspace.package]" { in_pkg = 1; print; next }
      in_pkg && /^\[/ { in_pkg = 0 }
      in_pkg && /^version[[:space:]]*=/ { $0 = "version = \"" ver "\"" }
      { print }' Cargo.toml > "$tmp"
    mv "$tmp" Cargo.toml
    cargo update -q --workspace
    files=(Cargo.toml Cargo.lock)
    ;;
esac

git add -- "${files[@]}"
if git diff --cached --quiet -- "${files[@]}"; then
  echo "release: no version changes to commit (continuing with tag)"
else
  git commit -q -m "Release $tag"
fi
git tag -a "$tag" -m "$tag"
echo "release done: $tag"
echo "Next: git push origin main --follow-tags   (pushing the tag starts the release workflow)"
