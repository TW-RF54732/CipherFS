# CipherFS Security Model

CipherFS is an experimental personal-privacy project, not a professionally
audited security product. Its intended use is hiding non-critical files that
would be embarrassing or inconvenient if casually viewed.

## What v2 Tries to Protect

- File contents, names, sizes, and directory structure inside an offline
  container when the password and derived keys are unknown.
- Integrity of the authenticated v2 header, index, and individual file chunks.
- Extraction roots from `..`, absolute paths, symlink, junction and reparse
  point traversal. Extraction has one whole-directory commit point.
- Users from treating partially decrypted or partially committed files as a
  successful extraction.
- Linux portable automatic updates from unsigned or hash-mismatched release
  assets. Windows updates are delegated to the offline Setup and are not
  automatically downloaded or applied by CipherFS.

## What It Does Not Protect

- Weak, empty, guessed, reused, logged, or observed passwords.
- Plaintext and the DEK while a container is mounted or being extracted.
- Decrypted chunks retained in the configured in-process mount cache until
  eviction or process exit; buffers are cleared on normal drop, not guaranteed
  against crash dumps or hostile same-user processes.
- A system already controlled by malware, another same-user process, root, a
  debugger, core dumps, swap, or hibernation.
- Complete copying, replacement, or replay of an otherwise valid container.
- Deleted source files, backups, snapshots, cloud history, SSD remapping, or
  forensic remnants.
- Vulnerabilities in applications that later parse decrypted images, media,
  documents, or other payloads.
- Availability against intentionally extreme input beyond the documented local
  limits.

## Duress Password

The v2 Duress password has its own Argon2id-derived key and authenticated token.
When entered, CipherFS overwrites both wrapped DEK keyslots and synchronizes the
header. This is a best-effort experiment, not secure erase. Any other copy of
the wrapped DEK, the live DEK, or the container can preserve access.

Legacy v1 containers used a public, fast BLAKE3 password verifier. CipherFS
v3.0.0 does not include the v1 reader. Removing that reader is a breaking
compatibility change and is the reason for the v3 major version.

## Untrusted Containers

v2 validates names, parent relationships, IDs, depths, lengths, offsets,
contiguity, and exact container size before extraction. Resource limits remain
important. Decrypt untrusted containers as an unprivileged user and avoid
automatically opening their contents.

v1 is detected only to return an unsupported-format migration message. If a
trusted v1 container must be migrated, use an archived beta in an isolated
environment, extract it and immediately re-pack it as v2.

## Reporting

Report suspected vulnerabilities privately to the repository owner before
publishing exploit details. Include the affected version, platform, smallest
reproduction, expected behavior, observed behavior, and whether confidentiality,
integrity, or only availability was affected.
