# Releasing CipherFS

Releases are produced only after local Linux tests and the GitHub test job pass.

## One-time Signing Setup

1. Generate a Minisign keypair with an unencrypted CI key:
   `minisign -G -W -p minisign.pub -s minisign.key`.
2. Store the complete `minisign.key` contents in the protected GitHub
   environment secret `CIPHERFS_MINISIGN_SECRET_KEY`.
3. Store the base64 public-key line from `minisign.pub` in the repository
   variable `CIPHERFS_MINISIGN_PUBLIC_KEY`.
4. Require approval for the GitHub `release` environment and protect release
   tags.

The public key is embedded at compile time. To rotate it, first publish a
release signed by the old key whose repository variable contains the old and
new base64 public-key lines separated by a comma; switch the signing secret only
after that release is deployed.

## Release Checklist

1. Run on Linux or WSL: `cargo fmt --check`.
2. Run: `cargo clippy --locked --all-targets -- -D warnings`.
3. Run: `cargo test --locked`.
4. Run the release build and pack/verify/extract/mount E2E workflow locally.
5. Update README, `FORMAT_V2.md`, and the matching release note.
6. Confirm `Cargo.toml` and `Cargo.lock` contain the release version.
7. Tag that tested commit as `vX.Y.Z`.

The tag workflow builds once, tests that binary, signs a canonical manifest,
creates GitHub Artifact Attestations, and publishes the tested artifacts.
