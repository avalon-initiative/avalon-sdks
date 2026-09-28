# Publishing the Rust crates to crates.io

For when [#64](https://github.com/avalon-initiative/avalon-sdks/issues/64) is approved. Nothing here
runs automatically and the release workflow never publishes to crates.io. Publishing is effectively
irreversible: a published version can be yanked (hidden from new resolution) but never deleted or
overwritten, and the name is claimed for good.

As of 2026-09-28 neither `avalon-sdk` nor `avalon-schema-derive` exists on crates.io.

## Prerequisites

- A crates.io account (GitHub login) belonging to a maintainer, with a verified email.
- An API token from crates.io account settings, scoped to `publish-new` and `publish-update`
  (limit it to the two crate names once they exist). Keep it out of the repo and out of CI.
- The release already tagged and merged: publish only from the tagged commit, on a clean checkout.
- `cargo package --workspace --locked` passing, and the `.crate` files matching the ones on the
  release page.

## Steps

1. Check out the release tag (`git checkout vX.Y.Z`) and confirm `git status` is clean.
2. Log in: `cargo login` (paste the token).
3. Dry run both crates: `cargo publish --workspace --dry-run --locked`.
4. Publish for real: `cargo publish --workspace --locked`. Cargo publishes `avalon-schema-derive`
   first, waits for it to be available, then publishes `avalon-sdk`, which depends on it. If done one
   crate at a time, the order is `cargo publish -p avalon-schema-derive`, then
   `cargo publish -p avalon-sdk`.
5. Add the ownership set: `cargo owner --add github:avalon-initiative:<team> avalon-sdk` and the same
   for `avalon-schema-derive`, so publishing does not depend on one person's account.
6. Check the crates.io pages and docs.rs builds, then update the install section of both READMEs.

## Policy

- Versions are immutable; a fix ships as a new patch version.
- Yank (`cargo yank --version X.Y.Z avalon-sdk`) only for a version that is broken or unsafe to
  depend on; yanking does not break existing lockfiles. Yank both crates of a release together.
- Both crates always publish at the same version, matching the release tag.
- If a name is ever taken before publication, choose the replacement before changing any manifest,
  since the name appears in every consumer's `Cargo.toml`.
