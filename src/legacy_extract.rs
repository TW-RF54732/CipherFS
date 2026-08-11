use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{CHUNK_SIZE, HEADER_SIZE, Header, MAGIC_BYTES};
use crate::safe_fs::SafeRoot;
use crate::v2::{MAX_INDEX_SIZE, validate_name};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::platform_io::PlatformFileExt;

pub fn extract_legacy(container_path: &Path, output_dir: &Path, password: &str) -> Result<()> {
    println!("[Info] Opening container {}...", container_path.display());
    let file = File::open(container_path)?;
    let metadata = file.metadata()?;

    let mut header_buffer = [0u8; HEADER_SIZE];
    file.read_exact_at(&mut header_buffer, 0)
        .context("Failed to read header")?;

    let mut cursor = std::io::Cursor::new(&header_buffer);
    let header: Header = rmp_serde::from_read(&mut cursor)?;

    if header.magic != MAGIC_BYTES {
        anyhow::bail!("Not a CipherFS file or invalid version.");
    }

    if header.index_size > MAX_INDEX_SIZE
        || header.index_size > metadata.len().saturating_sub(HEADER_SIZE as u64)
    {
        anyhow::bail!("Legacy index exceeds local safety limits");
    }

    let kek = derive_kek(password, &header.salt, &header.argon2_params)?;
    let dek_vec = decrypt_data(&kek, &header.dek_nonce, &header.encrypted_dek)
        .context("Invalid password or corrupted header.")?;
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);

    let mut encrypted_index = vec![0u8; header.index_size as usize];
    file.read_exact_at(&mut encrypted_index, HEADER_SIZE as u64)?;

    let serialized_index = decrypt_data(&dek, &header.index_nonce, &encrypted_index)
        .context("Failed to decrypt index.")?;
    let root_index: Inode = rmp_serde::from_slice(&serialized_index)?;

    let data_offset = (HEADER_SIZE as u64) + header.index_size;

    let mut total_size = 0u64;
    let mut stack = vec![&root_index];
    while let Some(node) = stack.pop() {
        match node {
            Inode::File { size, .. } => {
                total_size = total_size
                    .checked_add(*size)
                    .context("Legacy size overflow")?
            }
            Inode::Directory { entries, .. } => {
                for child in entries.values() {
                    stack.push(child);
                }
            }
        }
    }

    println!("[Info] Extracting files...");
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));

    let mut root = SafeRoot::open(output_dir)?;
    root.install_root_id(root_index.ino())?;
    let mut directories = vec![&root_index];
    let mut pending_files = Vec::new();
    while let Some(node) = directories.pop() {
        let Inode::Directory { entries, .. } = node else {
            anyhow::bail!("Legacy root/index structure is invalid");
        };
        for (name, child) in entries {
            validate_name(name)?;
            match child {
                Inode::Directory { ino, .. } => {
                    root.create_directory(*ino, node.ino(), name)?;
                    directories.push(child);
                }
                Inode::File {
                    ino,
                    size,
                    offset: file_start_offset,
                    ..
                } => {
                    let mut pending = root.begin_file(node.ino(), name, *ino)?;
                    let mut remaining = *size;
                    let mut current_file_pos = 0u64;
                    while remaining > 0 {
                        let abs_offset = file_start_offset
                            .checked_add(current_file_pos)
                            .context("Legacy file offset overflow")?;
                        let chunk_idx = abs_offset / CHUNK_SIZE as u64;
                        let chunk_start = chunk_idx
                            .checked_mul(CHUNK_SIZE as u64)
                            .context("Legacy chunk offset overflow")?;
                        let offset_in_chunk = abs_offset - chunk_start;
                        let chunk_file_pos = data_offset
                            .checked_add(
                                chunk_idx
                                    .checked_mul(CHUNK_SIZE as u64 + 16)
                                    .context("Legacy chunk position overflow")?,
                            )
                            .context("Legacy chunk position overflow")?;
                        if chunk_file_pos >= metadata.len() {
                            anyhow::bail!("Legacy file references data outside the container");
                        }
                        let nonce = derive_chunk_nonce(&header.master_nonce, chunk_idx);
                        let available = metadata.len() - chunk_file_pos;
                        let cipher_len = std::cmp::min(CHUNK_SIZE as u64 + 16, available) as usize;
                        let mut encrypted_chunk = vec![0u8; cipher_len];
                        file.read_exact_at(&mut encrypted_chunk, chunk_file_pos)?;
                        let decrypted = decrypt_data(&dek, &nonce, &encrypted_chunk)?;
                        if offset_in_chunk >= decrypted.len() as u64 {
                            anyhow::bail!("Legacy index references an invalid chunk offset");
                        }
                        let to_write =
                            std::cmp::min(remaining, decrypted.len() as u64 - offset_in_chunk);
                        if to_write == 0 {
                            anyhow::bail!("Legacy extraction made no progress");
                        }
                        pending.writer()?.write_all(
                            &decrypted
                                [offset_in_chunk as usize..(offset_in_chunk + to_write) as usize],
                        )?;
                        remaining -= to_write;
                        current_file_pos += to_write;
                        pb.inc(to_write);
                    }
                    pending.finish_writing()?;
                    pending_files.push(pending);
                }
            }
        }
    }

    for pending in pending_files {
        pending.commit()?;
    }
    pb.finish_with_message("Done");
    println!("[Success] Extraction complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Argon2Params;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };
    use std::collections::HashMap;

    fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        ChaCha20Poly1305::new(key.into())
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .unwrap()
    }

    #[test]
    fn fixed_v1_fixture_extracts() {
        let temp = tempfile::tempdir().unwrap();
        let container = temp.path().join("legacy.cfs");
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();

        let plaintext = b"fixed CipherFS v1 fixture\n";
        let salt = [1u8; 16];
        let params = Argon2Params {
            m_cost: crate::v2::MIN_ARGON_MEMORY_KIB,
            t_cost: 1,
            p_cost: 1,
        };
        let kek = derive_kek("legacy password", &salt, &params).unwrap();
        let dek = [2u8; 32];
        let dek_nonce = [3u8; 12];
        let index_nonce = [4u8; 12];
        let master_nonce = [5u8; 32];
        let encrypted_dek_vec = encrypt(&kek, &dek_nonce, &dek);
        let mut encrypted_dek = [0u8; 48];
        encrypted_dek.copy_from_slice(&encrypted_dek_vec);

        let mut entries = HashMap::new();
        entries.insert(
            "legacy.txt".to_string(),
            Inode::File {
                ino: 2,
                parent_ino: 1,
                size: plaintext.len() as u64,
                offset: 0,
            },
        );
        let root = Inode::Directory {
            ino: 1,
            parent_ino: 1,
            entries,
        };
        let encrypted_index = encrypt(&dek, &index_nonce, &rmp_serde::to_vec(&root).unwrap());
        let header = Header {
            magic: MAGIC_BYTES,
            salt,
            argon2_params: params,
            master_nonce,
            dek_nonce,
            index_nonce,
            duress_hash: [0; 32],
            encrypted_dek,
            index_size: encrypted_index.len() as u64,
            max_index_size: MAX_INDEX_SIZE,
        };
        let encoded_header = rmp_serde::to_vec(&header).unwrap();
        let mut padded_header = [0u8; HEADER_SIZE];
        padded_header[..encoded_header.len()].copy_from_slice(&encoded_header);
        let encrypted_data = encrypt(&dek, &derive_chunk_nonce(&master_nonce, 0), plaintext);
        let mut fixture = Vec::new();
        fixture.extend_from_slice(&padded_header);
        fixture.extend_from_slice(&encrypted_index);
        fixture.extend_from_slice(&encrypted_data);
        std::fs::write(&container, fixture).unwrap();

        extract_legacy(&container, &output, "legacy password").unwrap();
        assert_eq!(std::fs::read(output.join("legacy.txt")).unwrap(), plaintext);
    }
}
