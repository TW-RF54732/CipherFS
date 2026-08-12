# Third-party notices

CipherFS source written by the CipherFS contributors is available under the
MIT License in `LICENSE`.

The Windows build uses `winfsp-rs`, which is licensed under GNU GPL version 3.
A distributed `cipherfs-shell.exe` also uses Slint under its GPL-3.0-only
option. Slint is Copyright SixtyFPS GmbH and contributors; source is available
from <https://github.com/slint-ui/slint> at the exact version recorded in
`Cargo.lock` and `THIRD_PARTY_DEPENDENCIES.md`.
A distributed Windows executable containing that dependency is conveyed under
the GPLv3 requirements for the combined work. The corresponding source is the
exact tagged repository source archive, its `Cargo.lock`, the vendored binding
source, and the exact-version source URLs in `THIRD_PARTY_DEPENDENCIES.md`.
The full license is included in `LICENSE-GPL-3.0` and is available from
<https://www.gnu.org/licenses/gpl-3.0.html>.

The vendored `winfsp-sys` 0.12.1+winfsp-2.1 build script is modified to reuse
the crate's pregenerated bindings instead of requiring libclang. The final
Windows CLI and Shell build scripts separately enable delay-load linking of
`winfsp-x64.dll`. See `VENDORED_WINFSP.md` for provenance, hashes and review
rules.

WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos.
<https://github.com/winfsp/winfsp>

WinFsp is installed separately and is licensed under GPLv3 with a special FLOSS
exception. CipherFS does not bundle or rebrand the WinFsp installer.

CipherFS is experimental software and comes with no warranty. Keep independent
backups and use it only for non-critical files.
