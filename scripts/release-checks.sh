#!/usr/bin/env bash
# Offline checks for one SDK or all of them (live/integration tests need a running
# avalon-server and are never part of this).
#
#   scripts/release-checks.sh rust      fmt, clippy, tests
#   scripts/release-checks.sh csharp    build and tests (Release)
#   scripts/release-checks.sh ts        lint, type-check, tests, generated-types check
#   scripts/release-checks.sh all       all three, plus the SDK route-coverage check
#
# `make release-*` runs the matching gate before it changes anything, and CI runs
# the same script.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
target="${1:-all}"

check_rust() {
  echo "checks: rust: fmt"
  cargo fmt --all -- --check
  echo "checks: rust: clippy"
  cargo clippy --workspace --all-targets -- -D warnings
  echo "checks: rust: tests"
  cargo test --workspace
}

check_csharp() {
  echo "checks: csharp: build"
  dotnet build languages/csharp/AvalonSdk.sln -c Release --nologo -v q
  echo "checks: csharp: tests"
  dotnet test languages/csharp/AvalonSdk.sln -c Release --no-build --nologo -v q
}

check_ts() {
  (
    cd languages/typescript
    echo "checks: ts: lint"
    npm run lint
    echo "checks: ts: type-check"
    npx tsc --noEmit
    echo "checks: ts: tests"
    npm test
    echo "checks: ts: generated types are current"
    npm run generate:check
  )
}

check_coverage() {
  echo "checks: every SDK-facing server route is covered"
  python3 scripts/check-sdk-coverage.py
}

case "$target" in
  rust) check_rust ;;
  csharp) check_csharp ;;
  ts) check_ts ;;
  all) check_rust; check_csharp; check_ts; check_coverage ;;
  *) echo "usage: release-checks.sh [rust|csharp|ts|all]"; exit 1 ;;
esac

echo "checks: all checks passed"
