use anyhow::{Context, Result};
use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{Header, CHUNK_SIZE, MAGIC_BYTES, HEADER_SIZE};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;

pub fn extract(container_path: &Path, output_dir: &Path, password: &str) -> Result<()> {
    println!("[Info] Opening container {}...", container_path.display());
    let mut file = File::open(container_path)?;
    
    // 1. Read Header
    let mut header_buffer = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_buffer).context("Failed to read header")?;
    
    let mut cursor = std::io::Cursor::new(&header_buffer);
    let header: Header = rmp_serde::from_read(&mut cursor)?;
    
    if header.magic != MAGIC_BYTES {
        anyhow::bail!("Not a CipherFS file or invalid version.");
    }

    // 2. Derive Keys
    let kek = derive_kek(password, &header.salt, &header.argon2_params)?;
    let dek_vec = decrypt_data(&kek, &[0u8; 12], &header.encrypted_dek)
        .context("Invalid password or corrupted header.")?;
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);

    // 3. Decrypt Index
    let mut encrypted_index = vec![0u8; header.index_size as usize];
    file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
    file.read_exact(&mut encrypted_index)?;

    let serialized_index = decrypt_data(&dek, &[0u8; 12], &encrypted_index)
        .context("Failed to decrypt index.")?;
    let root_index: Inode = rmp_serde::from_slice(&serialized_index)?;

    // 4. Create Output Directory
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let data_offset = (HEADER_SIZE as u64) + header.index_size;

    // Calculate total size for progress bar
    let mut total_size = 0u64;
    calculate_total_size(&root_index, &mut total_size);
    
    // 5. Recursive Extraction
    println!("[Info] Extracting files...");
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));

    let mut current_extracted = 0u64;
    extract_inode(&mut file, &root_index, output_dir, &dek, &header.master_nonce, data_offset, &pb, &mut current_extracted)?;

    pb.finish_with_message("Done");
    println!("[Success] Extraction complete.");
    Ok(())
}

fn calculate_total_size(inode: &Inode, total_size: &mut u64) {
    match inode {
        Inode::File { size, .. } => *total_size += *size,
        Inode::Directory { entries, .. } => {
            for child in entries.values() {
                calculate_total_size(child, total_size);
            }
        }
    }
}

fn extract_inode(
    container_file: &mut File,
    inode: &Inode,
    current_path: &Path,
    dek: &[u8; 32],
    master_nonce: &[u8; 32],
    data_offset: u64,
    pb: &ProgressBar,
    current_extracted: &mut u64,
) -> Result<()> {
    match inode {
        Inode::Directory { entries, .. } => {
            if !current_path.exists() {
                fs::create_dir_all(current_path)?;
            }
            for (name, child_inode) in entries.iter() {
                let child_path = current_path.join(name);
                extract_inode(container_file, child_inode, &child_path, dek, master_nonce, data_offset, pb, current_extracted)?;
            }
        }
        Inode::File { size, offset: file_start_offset, .. } => {
            let mut out_file = File::create(current_path)?;
            let mut remaining = *size;
            let mut current_file_pos = 0u64;

            while remaining > 0 {
                let chunk_idx = (file_start_offset + current_file_pos) / CHUNK_SIZE as u64;
                let chunk_start_in_file = chunk_idx * CHUNK_SIZE as u64;
                let offset_in_chunk = (file_start_offset + current_file_pos) - chunk_start_in_file;
                
                let chunk_file_pos = data_offset + chunk_idx * (CHUNK_SIZE as u64 + 16);
                let nonce = derive_chunk_nonce(master_nonce, chunk_idx);
                
                container_file.seek(SeekFrom::Start(chunk_file_pos))?;
                let mut encrypted_chunk = vec![0u8; CHUNK_SIZE + 16];
                let n = container_file.read(&mut encrypted_chunk)?;
                
                let decrypted = decrypt_data(dek, &nonce, &encrypted_chunk[..n])?;
                
                let to_write = std::cmp::min(remaining, (decrypted.len() as u64) - offset_in_chunk);
                out_file.write_all(&decrypted[offset_in_chunk as usize .. (offset_in_chunk + to_write) as usize])?;
                
                remaining -= to_write;
                current_file_pos += to_write;
                *current_extracted += to_write;
                pb.set_position(*current_extracted);
            }
        }
    }
    Ok(())
}
