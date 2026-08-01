use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

use crate::safe_fs::SafeRoot;
use crate::v2::{self, EntryKind};

pub fn extract_v2(
    container_path: &Path,
    output_dir: &Path,
    password: &str,
    threads: usize,
) -> Result<()> {
    crate::parallel::install(threads, || {
        extract_v2_inner(container_path, output_dir, password)
    })
}

fn extract_v2_inner(container_path: &Path, output_dir: &Path, password: &str) -> Result<()> {
    let opened = v2::open(container_path, password)?;
    let total: u64 = opened
        .index
        .entries
        .values()
        .filter(|entry| entry.kind == EntryKind::File)
        .try_fold(0u64, |sum, entry| sum.checked_add(entry.size))
        .context("Total extraction size overflow")?;
    let progress = ProgressBar::new(total);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )?
            .progress_chars("#>-"),
    );

    let mut root = SafeRoot::open(output_dir)?;
    root.install_root_id(1)?;
    let mut entries: Vec<_> = opened.index.entries.values().collect();
    entries.sort_by_key(|entry| (entry.depth, entry.id));
    let mut pending_files = Vec::new();

    for entry in entries {
        if entry.id == 1 {
            continue;
        }
        match entry.kind {
            EntryKind::Directory => {
                root.create_directory(entry.id, entry.parent_id, &entry.name)?;
            }
            EntryKind::File => {
                let mut pending = root.begin_file(entry.parent_id, &entry.name, entry.id)?;
                let batch_size = crate::parallel::ordered_batch_size() as u64;
                let mut batch_start = 0u64;
                while batch_start < entry.chunk_count {
                    let batch_end = std::cmp::min(entry.chunk_count, batch_start + batch_size);
                    let chunks: Result<Vec<_>> = (batch_start..batch_end)
                        .into_par_iter()
                        .map(|chunk_index| {
                            v2::decrypt_chunk(&opened, entry, chunk_index).with_context(|| {
                                format!(
                                    "Entry {} chunk {} failed authentication",
                                    entry.id, chunk_index
                                )
                            })
                        })
                        .collect();
                    for mut plaintext in chunks? {
                        pending.writer()?.write_all(&plaintext)?;
                        progress.inc(plaintext.len() as u64);
                        plaintext.zeroize();
                    }
                    batch_start = batch_end;
                }
                pending.finish_writing()?;
                pending_files.push(pending);
            }
        }
    }

    for pending in pending_files {
        pending.commit()?;
    }
    progress.finish_with_message("Verified and extracted");
    println!("[Success] Extraction complete.");
    Ok(())
}
