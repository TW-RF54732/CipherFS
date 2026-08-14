use anyhow::{Context, Result};
use rand::Rng;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::operation::NoProgress;
use crate::operation::{
    CancellationToken, OperationControl, OperationEvent, OperationPhase, OperationProgress,
    ProgressReporter, ProgressTracker, TemporaryArtifactKind,
};
use crate::platform_io::PlatformFileExt;
use crate::platform_metadata::FileFingerprint;

use crate::v2::{
    self, Argon2Params, CHUNK_SIZE, Entry, EntryKind, HEADER_SIZE, Header, Index, KeySlot, MAGIC,
    MAX_INDEX_SIZE, VERSION,
};

#[derive(Clone)]
struct SourceSnapshot {
    path: PathBuf,
    fingerprint: FileFingerprint,
}

type ScanResult = (Vec<Entry>, Vec<(u64, SourceSnapshot)>, u64, u64);

struct TempOutput {
    path: PathBuf,
    keep: bool,
}

struct SelfVerifyReporter<'a>(&'a dyn ProgressReporter);

impl ProgressReporter for SelfVerifyReporter<'_> {
    fn report(&self, mut progress: OperationProgress) {
        if progress.phase == OperationPhase::Verify {
            progress.phase = OperationPhase::SelfVerify;
        }
        self.0.report(progress);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PackFault {
    None,
    OutputAfterTemp,
    SourceChangedAfterScan,
}

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub max_index_size: u64,
    pub threads: usize,
    /// Frontend-selected sibling temporary path. Intended for an isolated
    /// worker whose parent must be able to clean up one exact artifact.
    pub temporary_path: Option<PathBuf>,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            argon2_m_cost: 65_536,
            argon2_t_cost: 3,
            argon2_p_cost: 4,
            max_index_size: MAX_INDEX_SIZE,
            threads: crate::parallel::default_threads(),
            temporary_path: None,
        }
    }
}

pub struct PackRequest<'a> {
    pub source: &'a Path,
    pub output: &'a Path,
    pub password: &'a str,
    pub duress_password: Option<&'a str>,
    pub options: PackOptions,
}

pub fn execute(request: PackRequest<'_>, control: OperationControl<'_>) -> Result<()> {
    pack_with_control_and_temp(
        request.source,
        request.output,
        request.password,
        request.duress_password,
        request.options.argon2_m_cost,
        request.options.argon2_t_cost,
        request.options.argon2_p_cost,
        request.options.max_index_size,
        request.options.threads,
        request.options.temporary_path.as_deref(),
        control.cancellation,
        control.reporter,
    )
    .map_err(crate::operation::typed)
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn pack(
    source_dir: &Path,
    output_file: &Path,
    password: &str,
    duress_password: Option<&str>,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    max_index_size: u64,
    threads: usize,
) -> Result<()> {
    let cancellation = CancellationToken::default();
    let progress = NoProgress;
    pack_with_control(
        source_dir,
        output_file,
        password,
        duress_password,
        argon2_m_cost,
        argon2_t_cost,
        argon2_p_cost,
        max_index_size,
        threads,
        &cancellation,
        &progress,
    )
}

/// Pack a v2 container while reporting presentation-neutral progress.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn pack_with_control(
    source_dir: &Path,
    output_file: &Path,
    password: &str,
    duress_password: Option<&str>,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    max_index_size: u64,
    threads: usize,
    cancellation: &CancellationToken,
    reporter: &dyn ProgressReporter,
) -> Result<()> {
    pack_with_control_and_temp(
        source_dir,
        output_file,
        password,
        duress_password,
        argon2_m_cost,
        argon2_t_cost,
        argon2_p_cost,
        max_index_size,
        threads,
        None,
        cancellation,
        reporter,
    )
}

#[allow(clippy::too_many_arguments)]
fn pack_with_control_and_temp(
    source_dir: &Path,
    output_file: &Path,
    password: &str,
    duress_password: Option<&str>,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    max_index_size: u64,
    threads: usize,
    requested_temporary_path: Option<&Path>,
    cancellation: &CancellationToken,
    reporter: &dyn ProgressReporter,
) -> Result<()> {
    crate::parallel::install(threads, || {
        pack_inner(
            source_dir,
            output_file,
            password,
            duress_password,
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            max_index_size,
            PackFault::None,
            requested_temporary_path,
            cancellation,
            reporter,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn pack_inner(
    source_dir: &Path,
    output_file: &Path,
    password: &str,
    duress_password: Option<&str>,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    max_index_size: u64,
    injected_fault: PackFault,
    requested_temporary_path: Option<&Path>,
    cancellation: &CancellationToken,
    reporter: &dyn ProgressReporter,
) -> Result<()> {
    cancellation.check()?;
    let source_meta = std::fs::symlink_metadata(source_dir)
        .with_context(|| format!("Unable to inspect {}", source_dir.display()))?;
    if !source_meta.is_dir() || is_reparse_point(&source_meta) {
        anyhow::bail!("Pack source must be a real directory, not a link or reparse point");
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
    cancellation.check()?;

    reporter.event(OperationEvent::PhaseStarted(OperationPhase::Scan));
    reporter.event(OperationEvent::Progress(OperationProgress {
        phase: OperationPhase::Scan,
        completed: 0,
        total: 0,
    }));
    let (entries, sources, total_plaintext, data_size) = scan_source(source_dir, cancellation)?;
    reporter.event(OperationEvent::ScanCompleted {
        entries: entries.len().saturating_sub(1),
        bytes: total_plaintext,
    });

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
    reporter.event(OperationEvent::PhaseStarted(OperationPhase::KeyDerivation));
    v2::configure_duress(&mut header, duress_password, params)?;
    cancellation.check()?;
    header.slots[0] = v2::make_key_slot(&header, password, &dek, 1, params)?;
    cancellation.check()?;

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

    let temp_path = match requested_temporary_path {
        Some(path) => validate_requested_temporary_path(output_file, path)?,
        None => temporary_path(output_file)?,
    };
    let mut temp_guard = TempOutput {
        path: temp_path.clone(),
        keep: false,
    };
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .context("Unable to create temporary container")?;
    reporter.event(OperationEvent::TemporaryArtifact {
        kind: TemporaryArtifactKind::PackContainer,
        path: temp_path.clone(),
    });
    let data_start = (HEADER_SIZE as u64)
        .checked_add(header.index_size)
        .context("Container data offset overflow")?;
    let container_size = data_start
        .checked_add(header.data_size)
        .context("Container size overflow")?;
    output.set_len(container_size)?;
    output.write_all_at(&v2::serialize_header(&header)?, 0)?;
    output.write_all_at(&encrypted_index, HEADER_SIZE as u64)?;
    encrypted_index.zeroize();
    if injected_fault == PackFault::OutputAfterTemp {
        anyhow::bail!("Injected container output failure");
    }
    if injected_fault == PackFault::SourceChangedAfterScan {
        let source = sources
            .first()
            .context("Injected source-change test requires a source file")?;
        OpenOptions::new()
            .append(true)
            .open(&source.1.path)?
            .write_all(b"changed")?;
    }

    let progress = ProgressTracker::new(OperationPhase::Encrypt, total_plaintext, reporter);

    let entry_by_id: HashMap<u64, &Entry> = index
        .entries
        .iter()
        .map(|entry| (entry.id, entry))
        .collect();
    sources
        .par_iter()
        .try_for_each(|(entry_id, snapshot)| -> Result<()> {
            cancellation.check()?;
            let entry = entry_by_id
                .get(entry_id)
                .context("Internal source entry mismatch")?;
            encrypt_source_file(
                &output,
                data_start,
                snapshot,
                entry,
                &header,
                &dek,
                &progress,
                cancellation,
            )
        })?;

    output.sync_all()?;
    drop(output);
    cancellation.check()?;
    reporter.event(OperationEvent::PhaseStarted(OperationPhase::KeyDerivation));
    let opened = v2::open(&temp_path, password)
        .context("Self-verification could not reopen v2 container")?;
    cancellation.check()?;
    reporter.event(OperationEvent::PhaseStarted(OperationPhase::SelfVerify));
    reporter.event(OperationEvent::Progress(OperationProgress {
        phase: OperationPhase::SelfVerify,
        completed: 0,
        total: total_plaintext,
    }));
    let self_verify_reporter = SelfVerifyReporter(reporter);
    v2::verify_all_with_control(&opened, cancellation, &self_verify_reporter)
        .context("Self-verification of packed container failed")?;
    drop(opened);
    cancellation.check()?;

    cancellation.check()?;
    reporter.event(OperationEvent::PhaseStarted(OperationPhase::Commit));
    reporter.event(OperationEvent::CommitStarted);
    rename_file_no_replace(&temp_path, output_file)
        .with_context(|| format!("Unable to install {}", output_file.display()))?;
    if let Err(error) = sync_parent(output_parent(output_file)) {
        reporter.event(OperationEvent::Warning(format!(
            "Unable to sync output parent after commit: {error:#}"
        )));
    }
    temp_guard.keep = true;
    reporter.event(OperationEvent::Committed);
    Ok(())
}

fn scan_source(source_dir: &Path, cancellation: &CancellationToken) -> Result<ScanResult> {
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
        cancellation.check()?;
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
        if is_reparse_point(&metadata) {
            anyhow::bail!(
                "Refusing to pack a link or Windows reparse point: {}",
                item.path().display()
            );
        } else if metadata.is_dir() {
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
            let source_file = File::open(item.path())?;
            let source_metadata = source_file.metadata()?;
            let mut file_id = [0u8; 16];
            loop {
                rand::rng().fill_bytes(&mut file_id);
                if file_id != [0; 16] && file_ids.insert(file_id) {
                    break;
                }
            }
            let size = source_metadata.len();
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
                    fingerprint: FileFingerprint::from_file(&source_file)?,
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

#[allow(clippy::too_many_arguments)]
fn encrypt_source_file(
    output: &File,
    data_start: u64,
    snapshot: &SourceSnapshot,
    entry: &Entry,
    header: &Header,
    dek: &[u8; 32],
    progress: &ProgressTracker<'_>,
    cancellation: &CancellationToken,
) -> Result<()> {
    let file = File::open(&snapshot.path)
        .with_context(|| format!("Unable to open {}", snapshot.path.display()))?;
    ensure_unchanged(snapshot, &file)?;
    let key = Zeroizing::new(v2::derive_file_key(
        dek,
        &header.container_id,
        &entry.file_id,
    )?);
    (0..entry.chunk_count)
        .into_par_iter()
        .try_for_each(|chunk_index| -> Result<()> {
            cancellation.check()?;
            let plain_offset = chunk_index
                .checked_mul(CHUNK_SIZE as u64)
                .context("Source chunk offset overflow")?;
            let expected = std::cmp::min(CHUNK_SIZE as u64, entry.size - plain_offset) as usize;
            let mut buffer = Zeroizing::new(vec![0u8; expected]);
            file.read_exact_at(&mut buffer, plain_offset)
                .with_context(|| {
                    format!(
                        "Unable to read {} chunk {}",
                        snapshot.path.display(),
                        chunk_index
                    )
                })?;
            let mut encrypted = v2::encrypt_aead(
                &key,
                &v2::chunk_nonce(chunk_index),
                &v2::chunk_aad(header, entry, chunk_index, expected as u64),
                &buffer,
            )?;
            let relative = chunk_index
                .checked_mul(CHUNK_SIZE as u64 + v2::TAG_SIZE)
                .context("Encrypted chunk offset overflow")?;
            let destination = data_start
                .checked_add(entry.data_offset)
                .and_then(|value| value.checked_add(relative))
                .context("Encrypted chunk position overflow")?;
            output.write_all_at(&encrypted, destination)?;
            encrypted.zeroize();
            progress.advance(expected as u64);
            Ok(())
        })?;
    ensure_unchanged(snapshot, &file)?;
    Ok(())
}

fn ensure_unchanged(snapshot: &SourceSnapshot, file: &File) -> Result<()> {
    if FileFingerprint::from_file(file)? != snapshot.fingerprint {
        anyhow::bail!(
            "Source file changed while packing: {}",
            snapshot.path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn rename_file_no_replace(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } as libc::c_int;
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(windows)]
fn rename_file_no_replace(source: &Path, target: &Path) -> Result<()> {
    crate::windows_fs::rename_no_replace(source, target)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(_path: &Path) -> Result<()> {
    // Windows does not expose a stable-directory sync operation through std.
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

fn validate_requested_temporary_path(output: &Path, requested: &Path) -> Result<PathBuf> {
    let output_absolute: PathBuf = std::path::absolute(output)?.components().collect();
    let requested_absolute: PathBuf = std::path::absolute(requested)?.components().collect();
    anyhow::ensure!(
        requested_absolute.parent() == output_absolute.parent(),
        "Temporary container must be a sibling of the final output"
    );
    anyhow::ensure!(
        requested_absolute != output_absolute,
        "Temporary container must differ from the final output"
    );
    anyhow::ensure!(
        requested_absolute.file_name().is_some(),
        "Temporary container must name a file"
    );
    anyhow::ensure!(
        std::fs::symlink_metadata(&requested_absolute).is_err(),
        "Temporary container already exists"
    );
    Ok(requested_absolute)
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CancelAt<'a> {
        token: &'a CancellationToken,
        phase: Option<OperationPhase>,
        commit: bool,
    }

    struct CancelAtMutation<'a>(&'a CancellationToken);

    impl ProgressReporter for CancelAtMutation<'_> {
        fn report(&self, _progress: OperationProgress) {}

        fn event(&self, event: OperationEvent) {
            if event == OperationEvent::MutationStarted {
                self.0.cancel();
            }
        }
    }

    impl ProgressReporter for CancelAt<'_> {
        fn report(&self, _progress: OperationProgress) {}

        fn event(&self, event: OperationEvent) {
            if matches!(event, OperationEvent::PhaseStarted(phase) if Some(phase) == self.phase)
                || (self.commit && event == OperationEvent::CommitStarted)
            {
                self.token.cancel();
            }
        }
    }

    fn random_test_password() -> String {
        let mut value = [0u8; 32];
        rand::rng().fill_bytes(&mut value);
        hex::encode(value)
    }
    use crate::platform_io::PlatformFileExt;
    use std::io::{Read, Seek, Write};

    #[test]
    fn relative_output_without_directory_syncs_current_directory() {
        assert_eq!(output_parent(Path::new("vault.cfs")), Path::new("."));
        assert_eq!(
            output_parent(Path::new("containers/vault.cfs")),
            Path::new("containers")
        );
    }

    #[test]
    fn requested_temporary_path_must_be_a_new_output_sibling() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("vault.cfs");
        let sibling = temp.path().join(".worker.tmp");
        assert_eq!(
            validate_requested_temporary_path(&output, &sibling).unwrap(),
            std::path::absolute(&sibling).unwrap()
        );
        let elsewhere = tempfile::tempdir().unwrap().path().join(".worker.tmp");
        assert!(validate_requested_temporary_path(&output, &elsewhere).is_err());
        std::fs::write(&sibling, b"occupied").unwrap();
        assert!(validate_requested_temporary_path(&output, &sibling).is_err());
    }

    #[test]
    fn injected_output_failure_removes_temporary_container() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("vault.cfs");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), b"private").unwrap();
        let password = random_test_password();
        let cancellation = CancellationToken::default();
        let reporter = NoProgress;

        let error = pack_inner(
            &source,
            &output,
            &password,
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            16 * 1024 * 1024,
            PackFault::OutputAfterTemp,
            None,
            &cancellation,
            &reporter,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("Injected container output failure"));
        assert!(!output.exists());
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vault.cfs.")
        }));
    }

    #[test]
    fn cancellation_before_pack_creates_no_output() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("vault.cfs");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), b"private").unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let reporter = NoProgress;
        assert!(
            pack_with_control(
                &source,
                &output,
                "master",
                None,
                crate::v2::MIN_ARGON_MEMORY_KIB,
                1,
                1,
                16 * 1024 * 1024,
                1,
                &cancellation,
                &reporter,
            )
            .is_err()
        );
        assert!(!output.exists());
    }

    fn phase_cancellation_case(phase: OperationPhase, should_commit: bool) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("vault.cfs");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), b"small cancellation fixture").unwrap();
        let cancellation = CancellationToken::default();
        let reporter = CancelAt {
            token: &cancellation,
            phase: (!should_commit).then_some(phase),
            commit: should_commit,
        };
        let result = execute(
            PackRequest {
                source: &source,
                output: &output,
                password: "master",
                duress_password: None,
                options: PackOptions {
                    argon2_m_cost: crate::v2::MIN_ARGON_MEMORY_KIB,
                    argon2_t_cost: 1,
                    argon2_p_cost: 1,
                    max_index_size: 16 * 1024 * 1024,
                    threads: 1,
                    temporary_path: None,
                },
            },
            OperationControl::new(&cancellation, &reporter),
        );
        if should_commit {
            result.unwrap();
            assert!(
                output.is_file(),
                "commit zone must ignore late cancellation"
            );
        } else {
            assert_eq!(
                crate::operation::error_kind(&result.unwrap_err()),
                crate::operation::CoreErrorKind::Cancelled
            );
            assert!(!output.exists());
        }
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vault.cfs.")
        }));
    }

    #[test]
    fn scan_key_derivation_encrypt_and_self_verify_can_cancel_safely() {
        for phase in [
            OperationPhase::Scan,
            OperationPhase::KeyDerivation,
            OperationPhase::Encrypt,
            OperationPhase::SelfVerify,
        ] {
            phase_cancellation_case(phase, false);
        }
    }

    #[test]
    fn cancellation_after_commit_started_does_not_create_partial_failure() {
        phase_cancellation_case(OperationPhase::Commit, true);
    }

    #[test]
    fn cancellation_after_password_mutation_started_is_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("vault.cfs");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), b"password mutation fixture").unwrap();
        pack(
            &source,
            &container,
            "old password",
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            16 * 1024 * 1024,
            1,
        )
        .unwrap();
        let cancellation = CancellationToken::default();
        let reporter = CancelAtMutation(&cancellation);
        crate::v2::change_password_with_control(
            &container,
            "old password",
            "new password",
            &cancellation,
            &reporter,
        )
        .unwrap();
        assert!(cancellation.is_cancelled());
        assert!(crate::v2::open(&container, "new password").is_ok());
        assert!(crate::v2::open(&container, "old password").is_err());
    }

    #[test]
    fn source_change_after_scan_aborts_and_removes_temporary_container() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("vault.cfs");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), b"private").unwrap();
        let password = random_test_password();
        let cancellation = CancellationToken::default();
        let reporter = NoProgress;

        let error = pack_inner(
            &source,
            &output,
            &password,
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            16 * 1024 * 1024,
            PackFault::SourceChangedAfterScan,
            None,
            &cancellation,
            &reporter,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("Source file changed while packing"));
        assert!(!output.exists());
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vault.cfs.")
        }));
    }

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
        let mut boundary = vec![0x5au8; CHUNK_SIZE * 4 + 1];
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
            2,
        )
        .unwrap();
        crate::extract::extract_v2(&container, &extracted, "master", 2).unwrap();
        assert_eq!(
            std::fs::read(extracted.join("small.txt")).unwrap(),
            b"private data"
        );
        assert_eq!(
            std::fs::metadata(extracted.join("boundary.bin"))
                .unwrap()
                .len(),
            (CHUNK_SIZE * 4 + 1) as u64
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
        assert!(crate::extract::extract_v2(&replay_copy, &failed_extract, "master", 2).is_err());
        assert!(!failed_extract.exists());

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
