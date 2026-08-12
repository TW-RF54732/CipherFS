# Releasing CipherFS

Releases are produced only after Windows and Linux runtime tests and all GitHub
release gates pass. A cross-compile is never recorded as a FUSE or WinFsp
runtime validation; the pinned GitHub Linux runner may be the authoritative
Linux environment when the local WSL toolchain is not cleanly reproducible.

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

1. Confirm the branch, clean worktree, recent commits, `.github` workflows and
   intended version. Do not stage unrelated changes.
2. On a clean Windows runner before WinFsp installation, verify non-mount CLI
   and shell headless startup, both PE delay imports, and the missing-runtime error/install URL.
   Then, on Windows with the official WinFsp runtime installed, run:
   `cipherfs-shell.exe --headless-smoke`, `cargo fmt --check`,
   `cargo clippy --locked --workspace --all-targets -- -D warnings`,
   `cargo test --locked --workspace -- --test-threads=1`, the release build, and actual
   folder/drive/`auto` mount smoke including corruption and Ctrl+C unmount.
3. On the pinned GitHub Linux runner with FUSE 3 and `musl-tools`, repeat fmt,
   Clippy, tests,
   `cargo build --locked --release --target x86_64-unknown-linux-musl`, and the
   FUSE pack/read/corruption/unmount smoke.
4. Run `cargo audit --ignore RUSTSEC-2024-0436` and
   `cargo deny --locked check advisories licenses sources`. The paste advisory
   plus the pinned Slint `bincode`, `rustybuzz` and `ttf-parser` unmaintained
   advisories are the only accepted warnings and must be reconsidered every
   release.
5. Update README, SECURITY, `FORMAT_V2.md`, testing instructions and the exact
   release note. Regenerate `THIRD_PARTY_DEPENDENCIES.md`; confirm the GPLv3
   text, third-party notices and vendored WinFsp provenance are current.
6. For a release candidate set the Cargo version and note to `X.Y.Z-rc.N`, run
   every local gate, then push/tag `vX.Y.Z-rc.N`. Download and test both CI
   artifacts on clean platform installations.
7. After the candidate passes, set the final `X.Y.Z` version/note, repeat every
   local gate, and only then push/tag `vX.Y.Z`.
8. The final workflow creates a draft release. Download the exact draft assets,
   verify Minisign, SHA-256, Artifact Attestation, `--version`, `licenses`, and
   one real mount on each platform before publishing the draft. Until publish,
   `/releases/latest` and the updater must continue to point at the old release.

The tag workflow does not rebuild in the release job. It downloads only the
Linux and Windows binaries already produced by their runtime-tested jobs,
packages licenses/source, signs canonical manifests, creates attestations and
then creates the prerelease or final draft. The Windows release must include
`cipherfs.exe`, `cipherfs-shell.exe`, the legacy CLI manifest, and the strict
eight-field integration manifest plus Minisign signatures. Verify both before
publishing; the latter controls managed two-binary replacement only.

The managed installer/updater remains an isolated but deferred-hardening area:
do not describe it as fully transactional until install-root locking, active
operation exclusion, and failure-injection rollback coverage are implemented.
