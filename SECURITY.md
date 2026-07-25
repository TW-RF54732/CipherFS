# CipherFS Security Model

CipherFS is an experimental personal-privacy project, not a professionally
audited security product. Its intended use is hiding non-critical files that
would be embarrassing or inconvenient if casually viewed.

## What v2 Tries to Protect

- File contents, names, sizes, and directory structure inside an offline
  container when the password and derived keys are unknown.
- Integrity of the authenticated v2 header, index, and individual file chunks.
- Extraction roots from `..`, absolute-path, and symbolic-link traversal.
- Users from treating partially decrypted files as successful extraction.
- Automatic updates from unsigned or hash-mismatched release assets.

## What It Does Not Protect

- Weak, empty, guessed, reused, logged, or observed passwords.
- Plaintext and the DEK while a container is mounted or being extracted.
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

Legacy v1 containers use a public, fast BLAKE3 password verifier and should not
be treated as providing strong Duress protection.

## Untrusted Containers

v2 validates names, parent relationships, IDs, depths, lengths, offsets,
contiguity, and exact container size before extraction. Resource limits remain
important. Decrypt untrusted containers as an unprivileged user and avoid
automatically opening their contents.

v1 support exists only for compatibility. Do not open an untrusted v1
container; extract trusted v1 data and re-pack it as v2.

## Reporting

Report suspected vulnerabilities privately to the repository owner before
publishing exploit details. Include the affected version, platform, smallest
reproduction, expected behavior, observed behavior, and whether confidentiality,
integrity, or only availability was affected.
