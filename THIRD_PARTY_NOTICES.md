# Third-party notices

CipherFS source written by the CipherFS contributors is available under the
MIT License in `LICENSE`.

The Windows build uses `winfsp-rs`, which is licensed under GNU GPL version 3.
A distributed Windows executable containing that dependency is conveyed under
the GPLv3 requirements for the combined work. The corresponding source is this
repository and its locked Cargo dependencies. A copy of GPLv3 is available at
<https://www.gnu.org/licenses/gpl-3.0.html>.

The vendored `winfsp-sys` 0.12.1 build script was modified by CipherFS
contributors on 2026-08-11 to copy the crate's pregenerated WinFsp 2.1 bindings
instead of regenerating them with libclang. The bindings and import libraries
remain from the upstream crate.

WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos.
<https://github.com/winfsp/winfsp>

WinFsp is installed separately and is licensed under GPLv3 with a special FLOSS
exception. CipherFS does not bundle or rebrand the WinFsp installer.

CipherFS is experimental software and comes with no warranty. Keep independent
backups and use it only for non-critical files.
