# CipherFS testing

Passing unit tests or cross-compiling is not equivalent to validating a mounted
filesystem. Record each platform runtime result separately.

## Common checks

```text
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --test-threads=1
cargo build --locked --release
cargo audit --ignore RUSTSEC-2024-0436
cargo deny --locked check advisories licenses sources
```

The only advisory exception is the unmaintained `paste` dependency currently
introduced by `winfsp`. A new vulnerability, unsoundness advisory, license or
unknown source fails the release gate.

## Windows runtime

Run the non-mount CLI smoke before installing WinFsp on a clean VM. `--help`,
`--version`, `licenses`, pack, verify, extract and passwd must run without
loading `winfsp-x64.dll`; `mount` must give the official runtime URL.
The pre-install CI test sets `CIPHERFS_EXPECT_WINFSP_MISSING=1` and calls the
runtime loader directly, so a hosted image that already contains WinFsp fails
instead of silently weakening this gate.

After installing the pinned official WinFsp 2.1 MSI, set
`CIPHERFS_WINFSP_E2E=1` and `CIPHERFS_WINFSP_FOLDER_E2E=1`, then run the tests
single-threaded. The harness covers folder paths with a trailing separator,
explicit and automatic drive letters, empty directories, a 4 MiB boundary,
read-only mutations, exact corruption failure and clean unmount. Junction tests
verify that extraction and directory mounts do not traverse reparse ancestors.
The updater suite also runs a copied test executable and replaces it while it
is executing, then verifies the installed bytes from the parent process.

## Linux runtime

Install FUSE 3, `expect`, and `musl-tools`; add the
`x86_64-unknown-linux-musl` target. Build the static release and use that exact
binary for pack/verify/extract and FUSE smoke. Read a valid file from a container
whose separate final chunk was corrupted, require `EIO` for the corrupted file,
then send Ctrl+C and confirm the mount is gone.

## Extraction acceptance

The destination must not exist. Successful extraction appears only after the
complete staging tree was authenticated and atomically renamed. Wrong password,
corruption, write failure, unsafe ancestor, Windows name mapping failure or a
destination race must leave the destination absent and remove staging entries.
Deterministic fault-injection tests cover pack output failure, source mutation
after scanning, and extraction write failure before the single commit point.
