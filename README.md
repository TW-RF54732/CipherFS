# CipherFS

CipherFS is a high-performance, read-only encrypted virtual filesystem (FUSE) implemented in Rust. It is designed for securing TB-scale data storage with a focus on random access efficiency and duress protection.

## Core Features

### Security Architecture
- KDF: Argon2 is utilized for strong key derivation from master passwords.
- Encryption: ChaCha20-Poly1305 (AEAD) provides high-performance authenticated encryption, ideal for software-based decryption.
- Key Management: Separated Data Encryption Key (DEK) and Key Encryption Key (KEK) allow for password changes without re-encrypting the entire archive.

### Performance and Scalability
- Parallel Processing: High-speed packing engine using Rayon for multi-threaded encryption of 4MB data chunks.
- Random Access: Fixed-size chunking and independent nonce derivation enable instant seeking and partial decryption.
- Memory Efficiency: Optimized index mapping using Arc-based directory trees to handle millions of files with minimal footprint.

### Duress Protection
- Duress Password: A secondary password that, when entered, triggers immediate and silent destruction of the Data Encryption Key.
- Neutralization: Once triggered, the vault becomes permanently inaccessible, providing a "scorched earth" security layer under coercion.

### FUSE Integration
- Userspace Mounting: Integrated with the fuser crate for standard filesystem interaction.
- Stability: Implements automatic unmounting and robust mount point handling to prevent stale mount endpoints.

## Installation

Ensure you have the Rust toolchain and FUSE3 libraries installed on your Linux system.

```bash
cargo build --release
```

## Usage

### Packing a Directory
To create an encrypted container from a source directory:

```bash
./target/release/CipherFS pack <source_directory> [output_file]
```
If the output file is not specified, it defaults to `source_name.cfs`.

### Mounting a Container
To mount a container to a local directory:

```bash
./target/release/CipherFS mount <container.cfs> <mount_point>
```
The filesystem is mounted as read-only. Use Ctrl+C to unmount gracefully.

## Technical Details

- Chunk Size: 4,096 KB
- Header Format: Magic Bytes, Salt, Argon2 Parameters, Master Nonce, Duress Hash, Encrypted DEK Slot, Index Size.
- Inode Mapping: Deterministic 64-bit inodes derived from parent-child relationship hashes.

## Platform Support

- Primary: Linux (with FUSE3)
- Experimental: macOS (requires macFUSE)
- Windows: Support via WSL2 or cross-platform extract tools (planned).
