use anyhow::{Context, Result};
use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{Argon2Params, Header, CHUNK_SIZE, MAGIC_BYTES};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write, BufWriter};
use std::path::Path;
use walkdir::WalkDir;

pub fn pack(
    source_dir: &Path,
    output_file: &Path,
    password: &str,
    duress_password: Option<&str>,
) -> Result<()> {
    println!("[Info] Scanning {}...", source_dir.display());

    let mut entries = Vec::new();
    let mut total_size = 0u64;

    for entry in WalkDir::new(source_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let relative_path = entry.path().strip_prefix(source_dir)?;
            let metadata = entry.metadata()?;
            let size = metadata.len();
            entries.push((relative_path.to_path_buf(), size, entry.path().to_path_buf()));
            total_size += size;
        }
    }

    println!("[Info] Found {} files ({} bytes).", entries.len(), total_size);

    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let argon2_params = Argon2Params::default();
    let kek = derive_kek(password, &salt, &argon2_params)?;

    let mut dek = [0u8; 32];
    rand::rng().fill_bytes(&mut dek);

    let mut dek_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut dek_nonce);

    let encrypted_dek_vec = encrypt_data(&kek, &dek_nonce, &dek)?;
    let mut encrypted_dek = [0u8; 48];
    encrypted_dek.copy_from_slice(&encrypted_dek_vec);

    let mut master_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut master_nonce);

    let mut index_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut index_nonce);

    let duress_hash = if let Some(dp) = duress_password {
        hash_duress_password(dp)
    } else {
        [0u8; 32]
    };

    let mut root = Inode::Directory {
        ino: 1,
        parent_ino: 1,
        entries: HashMap::new(),
    };

    let mut current_offset = 0u64;
    let mut ino_counter = 2u64;
    for (rel_path, size, _abs_path) in &entries {
        add_to_index(&mut root, rel_path, *size, current_offset, &mut ino_counter)?;
        current_offset += *size;
    }

    let serialized_index = rmp_serde::to_vec(&root)?;
    let encrypted_index = encrypt_data(&dek, &index_nonce, &serialized_index)?;
    let index_size = encrypted_index.len() as u64;

    let header = Header {
        magic: MAGIC_BYTES,
        salt,
        argon2_params,
        master_nonce,
        dek_nonce,
        index_nonce,
        duress_hash,
        encrypted_dek,
        index_size,
    };

    let out_file = File::create(output_file).context("Failed to create output file")?;
    let mut writer = BufWriter::new(out_file);

    let header_bytes = rmp_serde::to_vec(&header)?;
    let mut padded_header = [0u8; crate::layout::HEADER_SIZE];
    padded_header[..header_bytes.len()].copy_from_slice(&header_bytes);
    writer.write_all(&padded_header)?;
    writer.write_all(&encrypted_index)?;

    println!("[Info] Packing Data Blocks...");
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));

    let mut chunk_index = 0u64;
    let mut buffer = Vec::with_capacity(CHUNK_SIZE);
    let mut total_processed = 0u64;

    for (_rel_path, _size, abs_path) in &entries {
        let mut file = File::open(abs_path)?;
        let mut file_buf = vec![0u8; 64 * 1024]; // 64KB read buffer
        loop {
            let n = file.read(&mut file_buf)?;
            if n == 0 { break; }
            
            let mut pos = 0;
            while pos < n {
                let keep = std::cmp::min(n - pos, CHUNK_SIZE - buffer.len());
                buffer.extend_from_slice(&file_buf[pos..pos+keep]);
                pos += keep;

                if buffer.len() == CHUNK_SIZE {
                    let nonce = derive_chunk_nonce(&master_nonce, chunk_index);
                    let encrypted = encrypt_data(&dek, &nonce, &buffer)?;
                    writer.write_all(&encrypted)?;
                    chunk_index += 1;
                    total_processed += buffer.len() as u64;
                    pb.set_position(total_processed);
                    buffer.clear();
                }
            }
        }
    }

    if !buffer.is_empty() {
        let nonce = derive_chunk_nonce(&master_nonce, chunk_index);
        let encrypted = encrypt_data(&dek, &nonce, &buffer)?;
        writer.write_all(&encrypted)?;
        total_processed += buffer.len() as u64;
        pb.set_position(total_processed);
    }
    
    pb.finish_with_message("Done");
    writer.flush()?;

    println!("[Success] {} created.", output_file.display());
    Ok(())
}

fn add_to_index(
    root: &mut Inode,
    path: &Path,
    size: u64,
    offset: u64,
    ino_counter: &mut u64,
) -> Result<()> {
    let components: Vec<_> = path.components().collect();
    let mut current = root;

    for (i, comp) in components.iter().enumerate() {
        let name = comp.as_os_str().to_str().context("Non-UTF8 path")?.to_string();
        let current_ino = current.ino();

        if i == components.len() - 1 {
            if let Inode::Directory { entries, .. } = current {
                entries.insert(
                    name,
                    Inode::File {
                        ino: *ino_counter,
                        parent_ino: current_ino,
                        size,
                        offset,
                    },
                );
                *ino_counter += 1;
            }
        } else {
            if let Inode::Directory { entries, .. } = current {
                let next_ino = *ino_counter;
                current = entries.entry(name).or_insert_with(|| {
                    *ino_counter += 1;
                    Inode::Directory {
                        ino: next_ino,
                        parent_ino: current_ino,
                        entries: HashMap::new(),
                    }
                });
            }
        }
    }
    Ok(())
}
