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

    cipherfs-update --> cipherfs-cli (Unix only)
    cipherfs-windows-shell <- cipherfs-winfsp/core
    WiX Burn/Setup --> CipherFS MSI + pinned official WinFsp MSI
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
  Linux portable self-replacement. On Windows, `update` only presents the Setup
  download location. It selects FUSE on Unix and WinFsp on Windows.
- `cipherfs-windows-shell` owns a Slint-rendered single-window frontend,
  Windows file pickers, container workflows, and isolated operation workers.
  CipherFS-owned prompts,
  progress, results and errors are Slint views; Windows owns only file pickers,
  Explorer launching and the title bar.
- WiX declarative components exclusively own installed Windows files, system
  PATH, Explorer Registry verbs, Start Menu state, repair, upgrade and removal.
  Burn supplies the single offline Setup and conditionally chains the pinned
  official WinFsp MSI. Both packages are machine-wide.

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

The Slint event loop remains on the main thread. Operation and mount controllers
run blocking work off-thread and post typed state changes back to
that event loop. Password fields are cleared immediately after conversion to
zeroizing worker secrets. Slint-managed strings may have framework-owned
copies, so the frontend does not claim complete password-memory erasure.

## Installer boundary

The Windows Shell and portable ZIP never copy installed executables or write
PATH/Registry integration. Setup asks Windows Installer to stop on files in use
and never forcibly terminates an operation or mount. Linux updater replacement
remains isolated from core and adapters.
