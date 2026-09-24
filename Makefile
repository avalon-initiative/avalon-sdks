SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help check check-rust check-csharp check-ts coverage \
	release-ts release-csharp release-rust \
	release-ts-skip-tests release-csharp-skip-tests release-rust-skip-tests

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  make %-26s %s\n", $$1, $$2}'

check: ## Offline checks for all three SDKs plus the route-coverage check (what CI runs)
	bash scripts/release-checks.sh all

check-rust: ## Rust SDK: fmt, clippy, tests
	bash scripts/release-checks.sh rust

check-csharp: ## C# SDK: build and tests
	bash scripts/release-checks.sh csharp

check-ts: ## TypeScript SDK: lint, type-check, tests, generated-types check
	bash scripts/release-checks.sh ts

coverage: ## Every SDK-facing server route is covered by each SDK
	python3 scripts/check-sdk-coverage.py

## Cut a release of one SDK: checks, bump only that SDK's version files, commit, tag.
##   make release-ts VER=0.2.0 TITLE="Optional title"     (tag ts-v0.2.0-Optional-title)
## VER prompts if missing. Pushing the tag starts that SDK's release workflow.
release-ts: ## Release the TypeScript SDK (VER=x.y.z [TITLE="..."]); publishes to GitHub Packages
	bash scripts/release.sh ts "$(VER)" "$(TITLE)"

release-csharp: ## Release the C# SDK (VER=x.y.z [TITLE="..."]); publishes to the GitHub Packages NuGet feed
	bash scripts/release.sh csharp "$(VER)" "$(TITLE)"

release-rust: ## Release the Rust SDK (VER=x.y.z [TITLE="..."]); creates a GitHub Release (no registry publish yet)
	bash scripts/release.sh rust "$(VER)" "$(TITLE)"

release-ts-skip-tests: ## release-ts without the checks
	SKIP_CHECKS=1 bash scripts/release.sh ts "$(VER)" "$(TITLE)"

release-csharp-skip-tests: ## release-csharp without the checks
	SKIP_CHECKS=1 bash scripts/release.sh csharp "$(VER)" "$(TITLE)"

release-rust-skip-tests: ## release-rust without the checks
	SKIP_CHECKS=1 bash scripts/release.sh rust "$(VER)" "$(TITLE)"
