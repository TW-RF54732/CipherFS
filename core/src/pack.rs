use anyhow::{Context, Result};
use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{Argon2Params, Header, CHUNK_SIZE, MAGIC_BYTES};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write, BufWriter};
use std::path::Path;
use std::sync::Arc;
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

    // 1. Prepare Keys
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let argon2_params = Argon2Params::default();
    let kek = derive_kek(password, &salt, &argon2_params)?;

    let mut dek = [0u8; 32];
    rand::rng().fill_bytes(&mut dek);

    let encrypted_dek_vec = encrypt_data(&kek, &[0u8; 12], &dek)?;
    let mut encrypted_dek = [0u8; 48];
    encrypted_dek.copy_from_slice(&encrypted_dek_vec);

    let mut master_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut master_nonce);

    let duress_hash = if let Some(dp) = duress_password {
        hash_duress_password(dp)
    } else {
        [0u8; 32]
    };

    // 2. Build Index and Calculate Offsets
    let mut root = Inode::Directory {
        entries: Arc::new(HashMap::new()),
    };

    let mut current_offset = 0u64;
    for (rel_path, size, _abs_path) in &entries {
        add_to_index(&mut root, rel_path, *size, current_offset)?;
        current_offset += *size;
    }

    let serialized_index = rmp_serde::to_vec(&root)?;
    let encrypted_index = encrypt_data(&dek, &[0u8; 12], &serialized_index)?;
    let index_size = encrypted_index.len() as u64;

    let header = Header {
        magic: MAGIC_BYTES,
        salt,
        argon2_params,
        master_nonce,
        duress_hash,
        encrypted_dek,
        index_size,
    };

    // 3. Write to File
    if output_file.is_dir() {
        anyhow::bail!("Output path {} is a directory, not a file.", output_file.display());
    }
    let out_file = File::create(output_file).context(format!("Failed to create output file: {}", output_file.display()))?;
    let mut writer = BufWriter::new(out_file);

    // Header
    let header_bytes = rmp_serde::to_vec(&header)?;
    writer.write_all(&header_bytes)?;

    // Encrypted Index
    writer.write_all(&encrypted_index)?;

    // Data Blocks
    println!("[Info] Packing Data Blocks...");
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));

    let mut total_written = 0u64;
    let mut chunk_index = 0u64;
    
    const BATCH_SIZE: usize = 8; 
    let mut current_batch = Vec::with_capacity(BATCH_SIZE);
    let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
    let mut buffer_pos = 0;

    for (_rel_path, _size, abs_path) in &entries {
        let mut file = File::open(abs_path)?;
        loop {
            let n = file.read(&mut chunk_buffer[buffer_pos..])?;
            if n == 0 { break; }
            buffer_pos += n;

            if buffer_pos == CHUNK_SIZE {
                current_batch.push((chunk_index, chunk_buffer.clone()));
                chunk_index += 1;
                buffer_pos = 0;

                if current_batch.len() == BATCH_SIZE {
                    process_batch(&mut writer, &current_batch, &dek, &master_nonce, &pb, &mut total_written)?;
                    current_batch.clear();
                }
            }
        }
    }

    if buffer_pos > 0 {
        current_batch.push((chunk_index, chunk_buffer[..buffer_pos].to_vec()));
    }

    if !current_batch.is_empty() {
        process_batch(&mut writer, &current_batch, &dek, &master_nonce, &pb, &mut total_written)?;
    }
    
    pb.finish_with_message("Done");
    writer.flush()?;

    println!("[Success] {} created.", output_file.display());
    Ok(())
}

fn process_batch<W: Write>(
    writer: &mut W,
    batch: &[(u64, Vec<u8>)],
    dek: &[u8; 32],
    master_nonce: &[u8; 32],
    pb: &ProgressBar,
    total_written: &mut u64,
) -> Result<()> {
    let encrypted_batch: Vec<Result<Vec<u8>>> = batch
        .into_par_iter()
        .map(|(idx, data)| {
            let nonce = derive_chunk_nonce(master_nonce, *idx);
            encrypt_data(dek, &nonce, data)
        })
        .collect();

    for (i, res) in encrypted_batch.into_iter().enumerate() {
        let encrypted = res?;
        writer.write_all(&encrypted)?;
        let original_size = batch[i].1.len() as u64;
        *total_written += original_size;
        pb.set_position(*total_written);
    }
    Ok(())
}

fn add_to_index(root: &mut Inode, path: &Path, size: u64, offset: u64) -> Result<()> {
    let components: Vec<_> = path.components().collect();
    let mut current = root;

    for (i, comp) in components.iter().enumerate() {
        let name = comp.as_os_str().to_str().context("Non-UTF8 path")?.to_string();
        if i == components.len() - 1 {
            if let Inode::Directory { entries } = current {
                Arc::make_mut(entries).insert(name, Inode::File { size, offset });
            }
        } else {
            if let Inode::Directory { entries } = current {
                current = Arc::make_mut(entries).entry(name).or_insert(Inode::Directory {
                    entries: Arc::new(HashMap::new()),
                });
            }
        }
    }
    Ok(())
}
