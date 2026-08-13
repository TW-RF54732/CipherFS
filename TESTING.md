# CipherFS testing

Passing unit tests or cross-compiling is not equivalent to validating a mounted
filesystem. Record each platform runtime result separately.

## Local, resource-aware checks

Use the change-aware runner for normal development instead of the whole
workspace gate:

```powershell
.\scripts\test-local.ps1
.\scripts\test-local.ps1 -Scope Shell -Level Fast
.\scripts\test-local.ps1 -Scope Shell -Level Runtime
.\scripts\test-local.ps1 -Scope All -Level Full
```

```bash
bash ./scripts/test-local.sh
bash ./scripts/test-local.sh --scope Cli --level Fast
bash ./scripts/test-local.sh --scope Fuse --level Runtime
```

`Auto` includes working-tree, staged, untracked and branch changes. `Fast`
runs formatting, diff validation, selected-package tests and Clippy only.
`Runtime` must be selected explicitly and adds real Windows dialogs/WinFsp or
the Linux release CLI/FUSE exercise. `Full` adds the expensive workspace and
supply-chain gates. The scripts never start WSL, install runtimes or download
development tools. Core changes include current-platform consumers; frontend
changes do not test unrelated adapters. Validation remains platform-complete
across its layers: shared Core/Update/CLI/FUSE formatting, Clippy and unit tests
run in lightweight CI
for build-related changes. The `v*` tag workflow is the platform-complete gate:
it runs Linux release/FUSE behavior plus Windows-specific CLI, WinFsp, Shell,
Slint and native-dialog behavior. Documentation-only changes do not start Rust
CI, and CodeQL runs for code-related changes plus its weekly schedule.

### What each layer proves

- Core tests cover container, integrity, path safety, cancellation and atomic
  commit, but not whether a frontend invokes Core correctly.
- Shell simulation uses real Slint component callbacks and pure controller
  transitions with scheduled native/worker outcomes, but not a real COM window.
- Worker E2E starts the real child executable for Pack, Extract, Verify,
  password change, cancellation, crash and exact cleanup, but does not click a
  desktop control.
- `--headless-smoke` now shows the window, enters the event loop, visits every
  representative page and exits on a timer.
- `--native-dialog-smoke extract|pack` uses the production Windows picker and
  an automatic cancellation watchdog. Timeout or HRESULT failure is fatal.
- WinFsp/FUSE runtime tests prove mounted behavior only with the corresponding
  runtime. WinFsp runtime tests are explicitly ignored until Runtime or CI
  invokes them; an ordinary green test run is not a mount result.

## Common checks

```text
cargo fmt --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace -- --test-threads=1
cargo build --locked --release
cargo audit --ignore RUSTSEC-2024-0436
cargo deny --locked check advisories licenses sources
```

Each of the six workspace packages must also pass an independent
`cargo check -p <package>`. The `cipherfs-core` dependency tree must not contain
Clap, rpassword, Indicatif, reqwest, self-replace, FUSE, WinFsp, or Win32
UI/Registry features.

The advisory exceptions are the unmaintained `paste` dependency introduced by
`winfsp` and the unmaintained `bincode`/`rustybuzz`/`ttf-parser` versions in
Slint 1.17.1's rendering stack. These are not known-vulnerability exceptions
and must be reconsidered whenever WinFsp or Slint changes. A new vulnerability,
unsoundness advisory, license or unknown source fails the release gate.

## Windows runtime

Run the non-mount CLI smoke before installing WinFsp on a clean VM. `--help`,
`--version`, `licenses`, pack, verify, extract and passwd must run without
loading `winfsp-x64.dll`; `mount` must give the official runtime URL.
The pre-install CI shell smoke uses `--winfsp-runtime-missing-smoke` to call the
adapter runtime loader through a delay-linked final binary. A hosted image that
already contains WinFsp fails instead of silently weakening this gate.

The standalone `cipherfs-winfsp` test harness is excluded before runtime
installation because it is intentionally not delay-linked at the adapter
boundary. After installation, add the official WinFsp `bin` directory to
`PATH` and run that package's runtime tests. The final CLI and shell binaries
are independently checked for delay-load imports before installation.

Also build `cipherfs-shell.exe`. In a disposable current-user profile, verify
that Install writes only `%LOCALAPPDATA%\Programs\CipherFS` and HKCU Classes
entries, does not change `UserChoice`, registers quoted `.cfs` and directory
commands, and Uninstall removes only CipherFS-owned registration. Confirm that
the Windows 11 folder verb is present under **Show more options**. Exercise
mount/open/unmount, safe and forced worker cancellation cleanup for
Pack/Extract/Verify, wrong password, existing extraction destination and the
WinFsp-missing download prompt. A managed update must reject a
changed/truncated executable. Cross-process locking and exhaustive replacement
rollback testing remain deferred and must not be claimed as completed.

CI runs `cipherfs-shell.exe --headless-smoke` with
`SLINT_BACKEND=winit-software`, then runs both native-dialog smoke commands.
Hosted Windows runners do not provide a stable accelerated desktop, so the
default FemtoVG renderer is a manual release check on a real Windows desktop.
On Windows 10 and 11, exercise the
single Slint window at 100%, 150% and 200% scaling, keyboard focus/activation,
screen-reader labels, owned native file-picker cancellation, every password
form, progress and two-stage cancellation, protected commit close handling,
mount close/unmount, and the WinFsp-missing error link.

After installing the pinned official WinFsp 2.1 MSI, set
`CIPHERFS_WINFSP_E2E=1` and `CIPHERFS_WINFSP_FOLDER_E2E=1`, then run the tests
single-threaded. The harness covers folder paths with a trailing separator,
explicit and automatic drive letters, empty directories, a 4 MiB boundary,
read-only mutations, exact corruption failure and clean unmount. Junction tests
verify that extraction and directory mounts do not traverse reparse ancestors.
The updater suite also runs a copied test executable and replaces it while it
is executing, then verifies the installed bytes from the parent process.
It additionally validates the strict eight-field Windows integration manifest;
the legacy five-field portable CLI manifest remains separately compatible.

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

## Required manual Windows UI acceptance

Automation cannot honestly validate visual focus, Narrator speech, DPI layout
or Explorer policy surfaces. Before release, use the release shell and record:

1. Open a valid `.cfs`, click Extract, and cancel the picker. The actions page
   remains visible and no error page appears.
2. Select a new destination and separately exercise wrong password, correct
   password, an existing destination and a corrupted container. Verify the
   response and that no failed destination or staging tree remains.
3. Recursively compare a successful extraction with its source.
4. Exercise Tab, Shift+Tab, Enter, Escape, close overlays, Narrator labels and
   100%, 150% and 200% DPI.
5. Exercise Explorer context menus, `.cfs` double-click, install/repair/update/
   uninstall and the WinFsp-missing recovery link.

Compilation, Clippy, unit tests or component construction alone must never be
reported as successful Windows native interaction.
