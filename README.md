# CipherFS

CipherFS is a high-performance, read-only encrypted virtual filesystem (FUSE) specifically designed for Linux. It focuses on large-scale data access efficiency and features a robust "Duress Protection" mechanism.

## Core Features

### Security Architecture
- **KDF**: Argon2id for strong key derivation from master passwords.
- **Encryption**: ChaCha20-Poly1305 (AEAD) for high-performance authenticated encryption.
- **Key Management**: Separated Data Encryption Key (DEK) and Key Encryption Key (KEK), allowing password changes without re-encrypting the data.

### Performance and Scalability
- **Parallel Processing**: Leverages Linux-native concurrent read patterns to eliminate FUSE bottlenecks.
- **Random Access**: 4MB fixed-size chunking and independent Nonce derivation for instant seeking and partial decryption.
- **Low-Overhead Indexing**: Optimized flat index mapping capable of handling millions of files efficiently.

### Duress Protection
- **Duress Password**: Supports a secondary "Duress Password" that, when entered, immediately and silently destroys the Data Encryption Key (DEK).
- **Physical Neutralization**: Once triggered, the container becomes permanently inaccessible, providing a "scorched earth" security layer.

### CLI Features
- **Auto-Update**: Built-in `update` command to fetch the latest stable release directly from GitHub.
- **Graceful Unmount**: Integrated Linux signal handling for safe, automatic unmounting via Ctrl+C.

## Installation

CipherFS is designed exclusively for Linux. Ensure you have `fuse3` and `libfuse3-dev` installed.

### Download Stable Binary (Recommended)
1. Go to the [Releases](https://github.com/TW-RF54732/CipherFS/releases) page and download the latest binary.
2. Grant execution permissions: `chmod +x cipherfs`.

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
The filesystem is mounted in read-only mode. Press **Ctrl+C** to unmount gracefully.

### Extract a Container
```bash
./cipherfs extract <container.cfs> <output_dir>
```

### Automatic Update
```bash
./cipherfs update
```

## Platform Support

- **Native Support**: Linux (Kernel 5.4+ recommended)
- **Dependencies**: FUSE3

## License

MIT License
