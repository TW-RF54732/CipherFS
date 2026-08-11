# CipherFS

CipherFS is an experimental side project that explores a read-only encrypted
virtual filesystem for Linux and Windows. It is a hobby project and a playground for trying
out filesystem and encryption-related ideas - not a production security product.

**Rust 2024** · **Linux / FUSE 3** · **Windows / WinFsp** · **Argon2id** ·
**ChaCha20-Poly1305** · **HKDF** · **Authenticated Random Access** ·
**Versioned Binary Format** · **Capability-style Safe I/O** · **GitHub Actions**

## Architecture at a Glance

```mermaid
flowchart LR
    SOURCE["Source directory"]
    PASSWORD["Master password"]

    subgraph PACK["Pack pipeline"]
        SCAN["Safe scan<br/>metadata validation"]
        INDEX["Encrypted index<br/>MessagePack"]
        CHUNKS["Per-file encryption<br/>4 MiB AEAD chunks"]
    end

    subgraph KEYS["Key hierarchy"]
        KDF["Argon2id"]
        KEK["KEK"]
        DEK["Random DEK"]
        DERIVE["HKDF<br/>index key + per-file keys"]
    end

    CONTAINER[("CipherFS v2 container<br/>authenticated header + index + chunks")]

    subgraph ACCESS["Verified access paths"]
        OPEN["Format and bounds validation<br/>AEAD authentication"]
        CORE["Platform-neutral read-only core<br/>v1 + v2 random access"]
        FUSE["Linux FUSE adapter"]
        WINFSP["Windows WinFsp adapter"]
        EXTRACT["Safe extraction<br/>capability root + no link traversal"]
        VERIFY["Full-container verification"]
    end

    SOURCE --> SCAN
    SCAN --> INDEX
    SCAN --> CHUNKS
    PASSWORD --> KDF --> KEK --> DEK
    DEK --> DERIVE
    DERIVE --> INDEX
    DERIVE --> CHUNKS
    INDEX --> CONTAINER
    CHUNKS --> CONTAINER
    CONTAINER --> OPEN
    OPEN --> CORE
    CORE --> FUSE
    CORE --> WINFSP
    OPEN --> EXTRACT
    OPEN --> VERIFY
```

| Engineering area | What this project demonstrates |
| --- | --- |
| Systems programming | Shared read-only core, Linux FUSE and Windows WinFsp adapters, range reads, bounded chunk cache |
| Applied cryptography | Password KDF, key hierarchy, domain-separated keys, AEAD-bound metadata and chunks |
| Storage design | Versioned container format, encrypted index, random-access chunk layout, v1 compatibility |
| Defensive I/O | Overflow and resource limits, atomic pack/replace, source-change detection, safe extraction |
| Verification and delivery | Tamper/replay/truncation tests, Linux FUSE and Windows WinFsp E2E jobs, signed self-update releases |

> [!WARNING]
> CipherFS has not received a professional security audit or extensive
> real-world testing. Although it uses established cryptographic primitives and
> common key-management patterns, their use in this project may contain design
> or implementation mistakes. Do not rely on CipherFS as the sole protection
> for sensitive, valuable, or irreplaceable data. Keep independent backups and
> evaluate the code and risks for your own use case.

## Project Status

- Experimental and developed as a side project.
- APIs, file formats, and behavior may change without notice.
- Testing currently covers basic pack, extract, and mount workflows; it does
  not establish security, reliability, data-recovery, or performance guarantees.
- Bug reports and contributions are welcome, but maintenance and support are
  provided on a best-effort basis.

## What It Experiments With

### Encryption and Key Management

- Argon2id-based password key derivation.
- ChaCha20-Poly1305 authenticated encryption.
- Separate Data Encryption Key (DEK) and Key Encryption Key (KEK), allowing a
  password to be changed without re-encrypting all file data.
- CipherFS v2 gives every file a random ID and independently derived key.
- Files are encrypted in independent 4 MiB chunks to support authenticated
  random access and isolate corruption to one file.

These choices describe the current implementation; they should not be
interpreted as proof that the overall system is secure.

### Read-only Filesystem Access

- Packs a directory into an encrypted container.
- Mounts a container read-only through FUSE on Linux or WinFsp on Windows.
- Extracts files from a container without mounting it.
- Includes a self-update command for GitHub releases.

### Experimental Duress Password

CipherFS v2 protects an optional secondary password with its own Argon2id
derivation and authenticated keyslot. Entering it overwrites both wrapped DEK
slots stored in the container header.

This feature is especially sensitive to implementation details and storage
behavior. It has not been independently verified and must not be treated as a
guaranteed secure-erasure or anti-forensics mechanism. Copies, backups,
snapshots, SSD remapping, and previously recovered keys can defeat it.

## Container Compatibility

- New containers are always written in the CipherFS v2 format.
- v1 containers can still be mounted or extracted, with a legacy warning.
- v1 containers cannot use `passwd` or the full `verify` command.
- There is no automatic migration. Extract a v1 container and pack the result
  again to create a v2 container.

## Installation

On Linux, install FUSE 3 and its development package. On Windows, install the
official [WinFsp 2.1 runtime](https://winfsp.dev/rel/). The portable CipherFS
download does not install or rebrand the WinFsp driver. The repository pins
`winfsp-rs` 0.13 and vendors its generated WinFsp 2.1 bindings so a source build
does not require libclang.

### Download a Release

Download a binary from the
[GitHub Releases](https://github.com/TW-RF54732/CipherFS/releases) page, then
make it executable:

```bash
chmod +x cipherfs
```

Release binaries are provided for convenience and remain subject to the same
experimental status and limitations described above.

### Build from Source

```bash
cargo build --release
```

## Usage

### Pack a Directory

```bash
./cipherfs pack <source_directory> [output_file] [--threads 0]
```

CipherFS encrypts independent 4 MiB chunks concurrently. `--threads 0` (the
default) uses the available CPU parallelism; set a positive value to limit the
worker count when sharing the machine with other workloads.

### Mount a Container

```bash
./cipherfs mount <container.cfs> <mount_point> [--cache-mib 64]
```

The filesystem is mounted read-only. Press **Ctrl+C** to unmount.

On Windows, `<mount_point>` may be a drive such as `X:`, an empty directory, or
the literal `auto` to select the next free drive letter. Containers with names
that Windows cannot represent are exposed through deterministic `~cfs-<id>`
names and reported as warnings; the encrypted container is not modified.

Run `cipherfs licenses` to view the bundled third-party attribution and
no-warranty notice.

### Extract a Container

```bash
./cipherfs extract <container.cfs> <output_dir> [--threads 0]
```

Extraction rejects unsafe paths and symbolic-link traversal. A file is installed
under its final name only after every encrypted chunk has authenticated. Chunk
decryption is concurrent, while a bounded ordered buffer preserves file order
without retaining an entire large file in memory.

### Verify Without Extracting

```bash
./cipherfs verify <container.cfs> [--threads 0]
```

This authenticates the v2 header, index, and every encrypted data chunk. Data
chunks are verified concurrently.

### Performance Notes

- Pack, extract, and verify parallelize v2 chunk cryptography on the CPU.
- Performance comparisons must use a release build (`cargo build --release` or
  `cargo run --release`). The default `cargo run` development build is not a
  meaningful encryption-throughput benchmark.
- Pack writes encrypted chunks directly to their authenticated index offsets;
  the v2 on-disk format remains compatible with existing v2 containers.
- Parallelism is bounded by the worker count, so processing a 100 GB file does
  not require holding the whole file in memory.
- More threads only help until storage bandwidth becomes the bottleneck. On a
  slower disk, a lower `--threads` value may provide similar throughput with
  less CPU and memory pressure.
- WSL access to Windows-mounted paths such as `/mnt/c` crosses a filesystem
  boundary and may behave very differently from native WSL ext4 storage. Test
  `--threads 1`, `4`, and `0` on representative data before choosing a default
  for large jobs.
- GPU encryption is not currently used. ChaCha20-Poly1305 is CPU-friendly, and
  transferring 4 MiB chunks through GPU memory adds portability, driver, and
  plaintext-exposure costs that need measured benefits before adoption.

### Install a Signed Update

```bash
./cipherfs update
```

Official release builds contain a Minisign public key. The updater refuses to
replace itself unless the release manifest signature, version, target, file
size, and SHA-256 digest all match. Source builds without an embedded trusted
key intentionally disable automatic replacement.

## Platform Support

- Linux x86-64 with FUSE 3
- Windows x86-64 with the separately installed WinFsp 2.1 runtime

Windows releases are portable and may trigger SmartScreen because CipherFS does
not currently have an Authenticode certificate. Release manifests remain
Minisign-signed and include SHA-256 hashes.

## Security Boundaries

CipherFS is intended to keep an offline container private from casual access
when the password is not known. It does not prevent copying or replaying an
entire valid container, protect plaintext while mounted, resist a compromised
operating system, or guarantee recovery from damaged media.

See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance, and
[FORMAT_V2.md](FORMAT_V2.md) for the v2 format and validation rules.

## License and Disclaimer

CipherFS-authored source is available under the [MIT License](LICENSE). The
Windows executable incorporates the GPLv3 `winfsp-rs` binding and is distributed
subject to GPLv3 for the combined binary. Run `cipherfs licenses` or see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the complete distinction
and WinFsp attribution.

This README is a practical project warning, not legal or security advice.
