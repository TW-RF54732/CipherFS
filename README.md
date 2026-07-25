# CipherFS

CipherFS is an experimental side project that explores a read-only encrypted
virtual filesystem for Linux. It is a hobby project and a playground for trying
out filesystem and encryption-related ideas—not a production security product.

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
- Fixed-size encrypted chunks to support partial reads and random access.

These choices describe the current implementation; they should not be
interpreted as proof that the overall system is secure.

### Read-only Filesystem Access

- Packs a directory into an encrypted container.
- Mounts a container as a read-only FUSE filesystem on Linux.
- Extracts files from a container without mounting it.
- Includes a self-update command for GitHub releases.

### Experimental Duress Password

An optional secondary password can overwrite the wrapped DEK stored in the
container header, with the intention of making the encrypted contents
unrecoverable.

This feature is especially sensitive to implementation details and storage
behavior. It has not been independently verified and must not be treated as a
guaranteed secure-erasure or anti-forensics mechanism.

## Installation

CipherFS currently targets Linux and requires FUSE 3. Install `fuse3` and the
FUSE 3 development package provided by your distribution.

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
./cipherfs pack <source_directory> [output_file]
```

### Mount a Container

```bash
./cipherfs mount <container.cfs> <mount_point>
```

The filesystem is mounted read-only. Press **Ctrl+C** to unmount.

### Extract a Container

```bash
./cipherfs extract <container.cfs> <output_dir>
```

### Check for Updates

```bash
./cipherfs update
```

## Platform Support

- Linux
- FUSE 3

Other platforms are not currently supported.

## License and Disclaimer

CipherFS is made available under the MIT License. As stated by that license, the
software is provided **“as is”**, without warranty of any kind. You are
responsible for deciding whether it is appropriate for your use and for any
consequences of using it.

This README is a practical project warning, not legal or security advice.
