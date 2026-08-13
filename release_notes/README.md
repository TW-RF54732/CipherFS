# Release note download guide

Every new release note must put this short guide before change details:

- `CipherFS-Setup-x64.exe` — recommended Windows installer; includes the pinned
  WinFsp runtime and installs it only when needed.
- `cipherfs-windows-portable-x64.zip` — advanced Windows portable package; no
  PATH, Registry, Explorer integration, or Installed apps changes.
- `cipherfs-linux-x64.tar.gz` — Linux archive.
- `cipherfs` — directly downloadable Linux portable ELF.

The Windows builds are not Authenticode-signed, so Windows may display Unknown
publisher. Minisign manifests, SHA-256 files, Artifact Attestations, raw
binaries, source, licenses, and compatibility manifests remain available as
advanced verification material.
