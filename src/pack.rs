use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

use crate::v2::{
    self, Argon2Params, CHUNK_SIZE, Entry, EntryKind, HEADER_SIZE, Header, Index, KeySlot, MAGIC,
    MAX_INDEX_SIZE, VERSION,
};

#[derive(Clone)]
struct SourceSnapshot {
    path: PathBuf,
    size: u64,
    inode: u64,
    mtime: i64,
    mtime_nsec: i64,
}

type ScanResult = (Vec<Entry>, Vec<(u64, SourceSnapshot)>, u64, u64);

struct TempOutput {
    path: PathBuf,
    keep: bool,
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn pack(
    source_dir: &Path,
    output_file: &Path,
    password: &str,
    duress_password: Option<&str>,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    max_index_size: u64,
) -> Result<()> {
    let source_meta = std::fs::metadata(source_dir)
        .with_context(|| format!("Unable to inspect {}", source_dir.display()))?;
    if !source_meta.is_dir() {
        anyhow::bail!("Pack source must be a directory");
    }
    if duress_password.is_some_and(|duress| duress == password) {
        anyhow::bail!("Duress password must differ from the master password");
    }
    let params = Argon2Params {
        m_cost: argon2_m_cost,
        t_cost: argon2_t_cost,
        p_cost: argon2_p_cost,
    };
    v2::validate_argon2(&params)?;

    println!("[Info] Scanning {}...", source_dir.display());
    let (entries, sources, total_plaintext, data_size) = scan_source(source_dir)?;
    println!(
        "[Info] Found {} entries and {} bytes.",
        entries.len().saturating_sub(1),
        total_plaintext
    );

    let index = Index { entries };
    let serialized_index = Zeroizing::new(rmp_serde::to_vec(&index)?);
    let index_size = (serialized_index.len() as u64)
        .checked_add(v2::TAG_SIZE)
        .context("Index size overflow")?;
    let configured_index_limit = std::cmp::min(max_index_size, MAX_INDEX_SIZE);
    if index_size > configured_index_limit {
        anyhow::bail!(
            "Encrypted index is {} bytes, exceeding the configured/local limit of {} bytes",
            index_size,
            configured_index_limit
        );
    }

    let mut container_id = [0u8; 16];
    let mut index_nonce = [0u8; 12];
    let mut dek = Zeroizing::new([0u8; 32]);
    let mut rng = rand::rng();
    rng.fill_bytes(&mut container_id);
    rng.fill_bytes(&mut index_nonce);
    rng.fill_bytes(dek.as_mut());

    let mut header = Header {
        magic: MAGIC,
        version: VERSION,
        header_size: HEADER_SIZE as u32,
        container_id,
        chunk_size: CHUNK_SIZE as u32,
        index_size,
        data_size,
        entry_count: index.entries.len() as u64,
        index_nonce,
        slots: [KeySlot::random_disabled(), KeySlot::random_disabled()],
        duress: v2::DuressSlot::random_disabled(),
    };
    v2::configure_duress(&mut header, duress_password, params)?;
    header.slots[0] = v2::make_key_slot(&header, password, &dek, 1, params)?;

    let index_key = Zeroizing::new(v2::derive_index_key(&dek, &header.container_id)?);
    let mut encrypted_index = v2::encrypt_aead(
        &index_key,
        &header.index_nonce,
        &v2::index_aad(&header),
        &serialized_index,
    )?;
    if encrypted_index.len() as u64 != header.index_size {
        anyhow::bail!("Internal index size mismatch");
    }

    let temp_path = temporary_path(output_file)?;
    let mut temp_guard = TempOutput {
        path: temp_path.clone(),
        keep: false,
    };
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .context("Unable to create temporary container")?;
    let mut writer = BufWriter::new(output);
    writer.write_all(&v2::serialize_header(&header)?)?;
    writer.write_all(&encrypted_index)?;
    encrypted_index.zeroize();

    let progress = ProgressBar::new(total_plaintext);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )?
            .progress_chars("#>-"),
    );

    let entry_by_id: HashMap<u64, &Entry> = index
        .entries
        .iter()
        .map(|entry| (entry.id, entry))
        .collect();
    let mut processed = 0u64;
    for (entry_id, snapshot) in &sources {
        let entry = entry_by_id
            .get(entry_id)
            .context("Internal source entry mismatch")?;
        encrypt_source_file(
            &mut writer,
            snapshot,
            entry,
            &header,
            &dek,
            &progress,
            &mut processed,
        )?;
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    progress.finish_with_message("Encrypted");

    let opened = v2::open(&temp_path, password)
        .context("Self-verification could not reopen v2 container")?;
    v2::verify_all(&opened).context("Self-verification of packed container failed")?;
    drop(opened);

    std::fs::rename(&temp_path, output_file)
        .with_context(|| format!("Unable to install {}", output_file.display()))?;
    File::open(output_file.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    temp_guard.keep = true;
    println!("[Success] {} created and verified.", output_file.display());
    Ok(())
}

fn scan_source(source_dir: &Path) -> Result<ScanResult> {
    let mut entries = vec![Entry {
        id: 1,
        parent_id: 1,
        name: String::new(),
        depth: 0,
        kind: EntryKind::Directory,
        file_id: [0; 16],
        size: 0,
        data_offset: 0,
        encrypted_size: 0,
        chunk_count: 0,
    }];
    let mut path_ids: HashMap<PathBuf, u64> = HashMap::new();
    path_ids.insert(PathBuf::new(), 1);
    let mut file_ids = HashSet::new();
    let mut sources = Vec::new();
    let mut next_id = 2u64;
    let mut total_plaintext = 0u64;
    let mut data_offset = 0u64;

    for item in WalkDir::new(source_dir)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
    {
        let item = item?;
        if item.path() == source_dir {
            continue;
        }
        let relative = item.path().strip_prefix(source_dir)?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let parent_id = *path_ids
            .get(parent)
            .context("Directory traversal did not visit parent first")?;
        let name = relative
            .file_name()
            .and_then(|value| value.to_str())
            .context("CipherFS v2 requires UTF-8 filenames")?
            .to_string();
        v2::validate_name(&name)?;
        let depth = relative.components().count() as u32;
        if depth > v2::MAX_DEPTH {
            anyhow::bail!("Source directory is too deeply nested");
        }
        if entries.len() >= v2::MAX_ENTRIES {
            anyhow::bail!("Source exceeds the maximum entry count");
        }

        let metadata = std::fs::symlink_metadata(item.path())?;
        let id = next_id;
        next_id = next_id.checked_add(1).context("Entry id overflow")?;
        if metadata.is_dir() {
            entries.push(Entry {
                id,
                parent_id,
                name,
                depth,
                kind: EntryKind::Directory,
                file_id: [0; 16],
                size: 0,
                data_offset: 0,
                encrypted_size: 0,
                chunk_count: 0,
            });
            path_ids.insert(relative.to_path_buf(), id);
        } else if metadata.is_file() {
            let mut file_id = [0u8; 16];
            loop {
                rand::rng().fill_bytes(&mut file_id);
                if file_id != [0; 16] && file_ids.insert(file_id) {
                    break;
                }
            }
            let size = metadata.len();
            let (chunk_count, encrypted_size) = v2::encrypted_file_size(size)?;
            entries.push(Entry {
                id,
                parent_id,
                name,
                depth,
                kind: EntryKind::File,
                file_id,
                size,
                data_offset,
                encrypted_size,
                chunk_count,
            });
            sources.push((
                id,
                SourceSnapshot {
                    path: item.path().to_path_buf(),
                    size,
                    inode: metadata.ino(),
                    mtime: metadata.mtime(),
                    mtime_nsec: metadata.mtime_nsec(),
                },
            ));
            total_plaintext = total_plaintext
                .checked_add(size)
                .context("Total source size overflow")?;
            data_offset = data_offset
                .checked_add(encrypted_size)
                .context("Encrypted data size overflow")?;
        } else {
            anyhow::bail!(
                "Unsupported special file in source: {}",
                item.path().display()
            );
        }
    }
    Ok((entries, sources, total_plaintext, data_offset))
}

fn encrypt_source_file(
    writer: &mut BufWriter<File>,
    snapshot: &SourceSnapshot,
    entry: &Entry,
    header: &Header,
    dek: &[u8; 32],
    progress: &ProgressBar,
    processed: &mut u64,
) -> Result<()> {
    let file = File::open(&snapshot.path)
        .with_context(|| format!("Unable to open {}", snapshot.path.display()))?;
    ensure_unchanged(snapshot, &file.metadata()?)?;
    let key = Zeroizing::new(v2::derive_file_key(
        dek,
        &header.container_id,
        &entry.file_id,
    )?);
    let mut reader = BufReader::new(file);
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut total_read = 0u64;
    for chunk_index in 0..entry.chunk_count {
        let remaining = entry.size - total_read;
        let expected = std::cmp::min(CHUNK_SIZE as u64, remaining) as usize;
        reader.read_exact(&mut buffer[..expected])?;
        let mut encrypted = v2::encrypt_aead(
            &key,
            &v2::chunk_nonce(chunk_index),
            &v2::chunk_aad(header, entry, chunk_index, expected as u64),
            &buffer[..expected],
        )?;
        writer.write_all(&encrypted)?;
        encrypted.zeroize();
        buffer[..expected].zeroize();
        total_read += expected as u64;
        *processed += expected as u64;
        progress.set_position(*processed);
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 || total_read != entry.size {
        anyhow::bail!(
            "Source file changed while packing: {}",
            snapshot.path.display()
        );
    }
    ensure_unchanged(snapshot, &reader.get_ref().metadata()?)?;
    Ok(())
}

fn ensure_unchanged(snapshot: &SourceSnapshot, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.len() != snapshot.size
        || metadata.ino() != snapshot.inode
        || metadata.mtime() != snapshot.mtime
        || metadata.mtime_nsec() != snapshot.mtime_nsec
    {
        anyhow::bail!(
            "Source file changed while packing: {}",
            snapshot.path.display()
        );
    }
    Ok(())
}

fn temporary_path(output: &Path) -> Result<PathBuf> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.cfs");
    for _ in 0..32 {
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let candidate = parent.join(format!(".{name}.{}.tmp", hex::encode(random)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("Unable to allocate a temporary output name")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek};
    use std::os::unix::fs::FileExt;

    #[test]
    fn v2_round_trip_and_tamper_detection() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let extracted = temp.path().join("extracted");
        let container = temp.path().join("vault.cfs");
        std::fs::create_dir_all(source.join("empty")).unwrap();
        std::fs::write(source.join("small.txt"), b"private data").unwrap();
        std::fs::write(source.join("twin-a.txt"), b"identical secret").unwrap();
        std::fs::write(source.join("twin-b.txt"), b"identical secret").unwrap();
        let mut boundary = vec![0x5au8; CHUNK_SIZE + 1];
        std::fs::write(source.join("boundary.bin"), &boundary).unwrap();
        boundary.zeroize();

        pack(
            &source,
            &container,
            "master",
            Some("duress"),
            v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            MAX_INDEX_SIZE,
        )
        .unwrap();
        crate::extract::extract_v2(&container, &extracted, "master").unwrap();
        assert_eq!(
            std::fs::read(extracted.join("small.txt")).unwrap(),
            b"private data"
        );
        assert_eq!(
            std::fs::metadata(extracted.join("boundary.bin"))
                .unwrap()
                .len(),
            (CHUNK_SIZE + 1) as u64
        );
        assert!(extracted.join("empty").is_dir());

        let replay_copy = temp.path().join("replay.cfs");
        std::fs::copy(&container, &replay_copy).unwrap();
        let opened = v2::open(&replay_copy, "master").unwrap();
        let twin_a = opened
            .index
            .entries
            .values()
            .find(|entry| entry.name == "twin-a.txt")
            .unwrap()
            .clone();
        let twin_b = opened
            .index
            .entries
            .values()
            .find(|entry| entry.name == "twin-b.txt")
            .unwrap()
            .clone();
        let cipher_len = twin_a.encrypted_size as usize;
        let mut replayed = vec![0u8; cipher_len];
        opened
            .file
            .read_exact_at(&mut replayed, opened.data_start + twin_a.data_offset)
            .unwrap();
        let replay_offset = opened.data_start + twin_b.data_offset;
        drop(opened);
        let replay_file = OpenOptions::new().write(true).open(&replay_copy).unwrap();
        replay_file.write_all_at(&replayed, replay_offset).unwrap();
        replay_file.sync_all().unwrap();
        let opened = v2::open(&replay_copy, "master").unwrap();
        assert!(v2::verify_all(&opened).is_err());
        drop(opened);
        let failed_extract = temp.path().join("failed-extract");
        assert!(crate::extract::extract_v2(&replay_copy, &failed_extract, "master").is_err());
        assert!(
            std::fs::read_dir(&failed_extract)
                .unwrap()
                .all(|entry| entry.unwrap().file_type().unwrap().is_dir())
        );

        let appended = temp.path().join("appended.cfs");
        std::fs::copy(&container, &appended).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&appended)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(v2::open(&appended, "master").is_err());

        let truncated = temp.path().join("truncated.cfs");
        std::fs::copy(&container, &truncated).unwrap();
        let truncated_file = OpenOptions::new().write(true).open(&truncated).unwrap();
        truncated_file
            .set_len(truncated_file.metadata().unwrap().len() - 1)
            .unwrap();
        assert!(v2::open(&truncated, "master").is_err());

        let index_tamper = temp.path().join("index-tamper.cfs");
        std::fs::copy(&container, &index_tamper).unwrap();
        let mut index_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&index_tamper)
            .unwrap();
        index_file
            .seek(std::io::SeekFrom::Start(HEADER_SIZE as u64))
            .unwrap();
        let mut index_byte = [0u8; 1];
        index_file.read_exact(&mut index_byte).unwrap();
        index_byte[0] ^= 1;
        index_file
            .seek(std::io::SeekFrom::Start(HEADER_SIZE as u64))
            .unwrap();
        index_file.write_all(&index_byte).unwrap();
        index_file.sync_all().unwrap();
        assert!(v2::open(&index_tamper, "master").is_err());

        let header_tamper = temp.path().join("header-tamper.cfs");
        std::fs::copy(&container, &header_tamper).unwrap();
        let mut header_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&header_tamper)
            .unwrap();
        let mut header = v2::read_header(&header_file).unwrap();
        header.chunk_size -= 1;
        v2::write_header(&mut header_file, &header).unwrap();
        assert!(v2::open(&header_tamper, "master").is_err());

        let duress_copy = temp.path().join("duress.cfs");
        std::fs::copy(&container, &duress_copy).unwrap();
        assert!(v2::open(&duress_copy, "duress").is_err());
        assert!(v2::open(&duress_copy, "master").is_err());

        v2::change_password(&container, "master", "new master").unwrap();
        assert!(v2::open(&container, "master").is_err());
        v2::verify_all(&v2::open(&container, "new master").unwrap()).unwrap();

        let opened = v2::open(&container, "new master").unwrap();
        let tamper_position = opened.data_start;
        drop(opened);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&container)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(tamper_position))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(std::io::SeekFrom::Start(tamper_position))
            .unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        let opened = v2::open(&container, "new master").unwrap();
        assert!(v2::verify_all(&opened).is_err());
    }
}
