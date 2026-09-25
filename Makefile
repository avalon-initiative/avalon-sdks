SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help check check-rust check-csharp check-ts coverage \
	release-bump release-tag release-tag-skip-tests

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

## One release covers all three SDKs at one shared version.
##   make release-bump VER=0.2.0     set every SDK's version files (commit them and open a PR)
##   make release-tag  VER=0.2.0 [TITLE="Optional title"]   on up-to-date main after that PR merges: checks, then tag v0.2.0[-Optional-title]
## Pushing the tag (git push origin v0.2.0) starts the release workflow.
release-bump: ## Set the version in all three SDKs (VER=x.y.z), staged for a PR
	bash scripts/release.sh bump "$(VER)"

release-tag: ## Tag the release on main (VER=x.y.z [TITLE="..."]); pushing the tag publishes all SDKs
	bash scripts/release.sh tag "$(VER)" "$(TITLE)"

release-tag-skip-tests: ## release-tag without the checks
	SKIP_CHECKS=1 bash scripts/release.sh tag "$(VER)" "$(TITLE)"
