# CipherFS Architecture

CipherFS is a Cargo workspace with compile-time dependency boundaries. The v2
container format and the `cipherfs` command-line contract remain at version
3.0.0; the Rust crate API is internal and may change.

```text
                         cipherfs-core
                         /           \
                 cipherfs-fuse   cipherfs-winfsp
                         \           /
                          cipherfs-cli

    cipherfs-update --> cipherfs-cli
                    \-> cipherfs-windows-shell <- cipherfs-winfsp/core
```

- `cipherfs-core` owns format v2, cryptography, safe paths, transactional
  pack/extract, verification, password mutation, and the read-only filesystem
  model. It has no terminal, network, FUSE, WinFsp, Registry, or Win32 UI
  dependency.
- `cipherfs-fuse` and `cipherfs-winfsp` translate the read-only model to their
  platform runtimes. Integrity failures map to `EIO`/`STATUS_DATA_ERROR` and
  never return partial plaintext.
- `cipherfs-update` authenticates metadata and downloaded bytes. It does not
  choose terminal, GUI, or replacement behavior.
- `cipherfs-cli` owns Clap, password prompts, terminal progress, Ctrl+C, and
  portable self-replacement. It selects FUSE on Unix and WinFsp on Windows.
- `cipherfs-windows-shell` owns native dialogs, Explorer/Registry integration,
  managed-update presentation, and isolated operation workers.

WinFsp delay-load linker policy belongs only to the final Windows CLI and shell
build scripts. The adapter crate does not impose linker policy on consumers.

## Operation lifecycle

Core requests accept `OperationControl`, which carries a cancellation token and
an event sink. Events identify Scan, KeyDerivation, Encrypt, SelfVerify,
Extract, Verify, and Commit phases; byte progress is serialized and monotonic.
Cancellation is checked before and after key derivation and at scan,
file/chunk, self-verification, and pre-commit boundaries. Once `CommitStarted`
or `MutationStarted` is emitted, the frontend must wait for the short mutation
to finish.

Pack writes a create-new sibling temporary container and publishes it only
after complete self-verification. Extract builds a private sibling staging tree
and publishes the whole tree at one commit point. Drop cleanup removes
uncommitted artifacts.

## Windows worker boundary

Long GUI operations run as `cipherfs-shell.exe --operation-worker`; no third
release binary is introduced. The parent sends a versioned, length-prefixed
MessagePack request over anonymous pipes. Passwords are zeroized and never
placed in command-line arguments, environment variables, files, history, or
logs. Frames over 8 MiB, unknown operations/versions, malformed data, and
truncation are rejected.

The first Cancel requests cooperative cancellation. A confirmed second Cancel
terminates only the worker. The parent may clean only the 128-bit-random exact
sibling artifact recorded in its request. Commit and password-mutation zones
disable cancellation. A mount worker owns the WinFsp RAII session until an
Unmount command or pipe teardown.

## Deferred boundary

Installer/updater code is isolated from operations, core, and adapters, but its
cross-process lock, active-session exclusion, and fully failure-injected
two-binary transaction remain deferred. Release documentation must not claim
those properties until implemented and tested.
