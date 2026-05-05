use anyhow::{Context, Result};
use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{Header, CHUNK_SIZE, MAGIC_BYTES, HEADER_SIZE};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf, Component};

pub fn extract(container_path: &Path, output_dir: &Path, password: &str) -> Result<()> {
    println!("[Info] Opening container {}...", container_path.display());
    let file = File::open(container_path)?;
    let metadata = file.metadata()?;
    
    let mut header_buffer = [0u8; HEADER_SIZE];
    file.read_exact_at(&mut header_buffer, 0).context("Failed to read header")?;
    
    let mut cursor = std::io::Cursor::new(&header_buffer);
    let header: Header = rmp_serde::from_read(&mut cursor)?;
    
    if header.magic != MAGIC_BYTES {
        anyhow::bail!("Not a CipherFS file or invalid version.");
    }

    // Use max_index_size from header
    if header.index_size > header.max_index_size || header.index_size > metadata.len() {
        anyhow::bail!("Invalid or too large index size: {} (Limit: {})", header.index_size, header.max_index_size);
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

    fs::create_dir_all(output_dir)?;

    let data_offset = (HEADER_SIZE as u64) + header.index_size;

    let mut total_size = 0u64;
    let mut stack = vec![&root_index];
    while let Some(node) = stack.pop() {
        match node {
            Inode::File { size, .. } => total_size += *size,
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

    let mut current_extracted = 0u64;
    
    // Expert Mode: Allow .. and absolute-style paths but ground them in output_dir
    let mut extract_stack = vec![(&root_index, output_dir.to_path_buf())];
    while let Some((node, current_path)) = extract_stack.pop() {
        match node {
            Inode::Directory { entries, .. } => {
                fs::create_dir_all(&current_path)?;
                for (name, child_inode) in entries.iter() {
                    // Expert Logic: Strip root components to ensure it's relative to current_path
                    let sanitized_name: PathBuf = Path::new(name)
                        .components()
                        .filter(|c| matches!(c, Component::Normal(_) | Component::CurDir | Component::ParentDir))
                        .collect();
                    
                    let child_path = current_path.join(sanitized_name);
                    extract_stack.push((child_inode, child_path));
                }
            }
            Inode::File { size, offset: file_start_offset, .. } => {
                // Ensure parent directory exists for files that might have been jumped via ..
                if let Some(parent) = current_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                let mut out_file = File::create(&current_path)?;
                let mut remaining = *size;
                let mut current_file_pos = 0u64;

                while remaining > 0 {
                    let abs_offset = file_start_offset + current_file_pos;
                    let chunk_idx = abs_offset / CHUNK_SIZE as u64;
                    let chunk_start_in_file = chunk_idx * CHUNK_SIZE as u64;
                    let offset_in_chunk = abs_offset - chunk_start_in_file;
                    
                    let chunk_file_pos = data_offset + chunk_idx * (CHUNK_SIZE as u64 + 16);
                    let nonce = derive_chunk_nonce(&header.master_nonce, chunk_idx);
                    
                    let mut encrypted_chunk = vec![0u8; CHUNK_SIZE + 16];
                    let n = file.read_at(&mut encrypted_chunk, chunk_file_pos)?;
                    
                    let decrypted = decrypt_data(&dek, &nonce, &encrypted_chunk[..n])?;
                    
                    let to_write = std::cmp::min(remaining, (decrypted.len() as u64) - offset_in_chunk);
                    out_file.write_all(&decrypted[offset_in_chunk as usize .. (offset_in_chunk + to_write) as usize])?;
                    
                    remaining -= to_write;
                    current_file_pos += to_write;
                    current_extracted += to_write;
                    pb.set_position(current_extracted);
                }
            }
        }
    }

    pb.finish_with_message("Done");
    println!("[Success] Extraction complete.");
    Ok(())
}
