# CipherFS v2 Format

This document describes the implementation invariants required for compatible
CipherFS v2 readers. It is not a claim of formal cryptographic verification.

## Container Layout

```text
4096-byte Header
Encrypted MessagePack Index + 16-byte AEAD tag
File 1 chunk 0 + tag
File 1 chunk 1 + tag
...
File N chunk M + tag
```

The expected file length is exactly `4096 + index_size + data_size`. Trailing,
missing, overlapping, or unreferenced bytes are invalid.

The magic bytes are `43 46 53 02`. The chunk size is fixed at 4 MiB.

## Keys and Authentication

- Argon2id derives a 256-bit KEK from each password keyslot.
- The KEK wraps a random 256-bit DEK with ChaCha20-Poly1305.
- HKDF-SHA256 derives a dedicated index key and one key per random file ID.
- A file Chunk nonce is `C2CH || little_endian_u64(chunk_index)`.
- Index and Chunk AAD bind their format version, container identity, relevant
  file identity, positions, and lengths.
- A DEK wrapper keyslot authenticates immutable header layout and its own salt,
  Argon2 parameters, generation, and nonce.

The two main keyslots allow a password change to write and synchronize a newer
generation before invalidating the previous slot. Password changes do not
rewrite encrypted file data.

## Index

The authenticated MessagePack Index is a flat list. Entry `1` is the root
directory. Every other entry contains a unique ID, parent ID, one UTF-8 filename
component, depth, and kind.

Files additionally contain a nonzero unique 128-bit file ID, plaintext size,
relative data offset, encrypted size, and chunk count. Directories must have
zeroed file fields.

Readers must reject:

- missing, duplicate, or cyclic parent relationships;
- duplicate sibling names, entry IDs, or file IDs;
- names that are empty, absolute, multi-component, `.` or `..`;
- depths above 1024 or names above 255 bytes;
- inconsistent chunk counts or encrypted lengths;
- non-contiguous, overlapping, overflowing, or out-of-range data;
- indexes above 512 MiB or 5,000,000 entries.

## Per-file Chunk Records

Each non-empty file has `ceil(size / 4 MiB)` records. All records except the
last contain 4 MiB plaintext; every record adds a 16-byte AEAD tag. Empty files
have no data record.

Chunk ciphertext cannot be moved between files, containers, or chunk indexes
without authentication failure.

## Legacy v1

v1 uses magic `43 46 53 01`, a 512-byte header, a recursive Index, and a shared
cross-file Chunk stream. v2 writers never emit it. Compatibility readers apply
local resource and path restrictions that old releases did not enforce.
