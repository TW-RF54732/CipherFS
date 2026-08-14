use anyhow::{Context, Result};
use rayon::prelude::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[cfg(test)]
use crate::operation::NoProgress;
use crate::operation::{
    CancellationToken, OperationControl, OperationEvent, OperationPhase, ProgressReporter,
    ProgressTracker, TemporaryArtifactKind,
};
use crate::safe_fs::SafeRoot;
use crate::v2::{self, EntryKind};

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub threads: usize,
    /// Frontend-selected sibling staging path for exact crash cleanup.
    pub staging_path: Option<PathBuf>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            threads: crate::parallel::default_threads(),
            staging_path: None,
        }
    }
}

pub struct ExtractRequest<'a> {
    pub container: &'a Path,
    pub output: &'a Path,
    pub password: &'a str,
    pub options: ExtractOptions,
}

pub fn execute(request: ExtractRequest<'_>, control: OperationControl<'_>) -> Result<()> {
    crate::parallel::install(request.options.threads, || {
        extract_v2_inner(
            request.container,
            request.output,
            request.password,
            None,
            request.options.staging_path.as_deref(),
            control.cancellation,
            control.reporter,
        )
    })
    .map_err(crate::operation::typed)
}

#[cfg(test)]
pub fn extract_v2(
    container_path: &Path,
    output_dir: &Path,
    password: &str,
    threads: usize,
) -> Result<()> {
    let cancellation = CancellationToken::default();
    let progress = NoProgress;
    extract_v2_with_control(
        container_path,
        output_dir,
        password,
        threads,
        &cancellation,
        &progress,
    )
}

#[cfg(test)]
pub fn extract_v2_with_control(
    container_path: &Path,
    output_dir: &Path,
    password: &str,
    threads: usize,
    cancellation: &CancellationToken,
    reporter: &dyn ProgressReporter,
) -> Result<()> {
    crate::parallel::install(threads, || {
        extract_v2_inner(
            container_path,
            output_dir,
            password,
            None,
            None,
            cancellation,
            reporter,
        )
    })
}

fn extract_v2_inner(
    container_path: &Path,
    output_dir: &Path,
    password: &str,
    inject_write_failure_after: Option<u64>,
    requested_staging_path: Option<&Path>,
    cancellation: &CancellationToken,
    reporter: &dyn ProgressReporter,
) -> Result<()> {
    cancellation.check()?;
    reporter.event(OperationEvent::PhaseStarted(OperationPhase::KeyDerivation));
    let opened = v2::open(container_path, password)?;
    cancellation.check()?;
    #[cfg(windows)]
    let windows_names = {
        let nodes: Vec<_> = opened
            .index
            .entries
            .values()
            .map(crate::readonly_fs::Node::from)
            .collect();
        let map = crate::windows_names::WindowsNameMap::new(&nodes);
        for (original, display) in map.changes() {
            reporter.event(OperationEvent::Warning(format!(
                "Windows name mapping: {original:?} -> {display:?}"
            )));
        }
        if !map.changes().is_empty() {
            reporter.event(OperationEvent::Warning(format!(
                "{} name(s) were mapped for Windows compatibility.",
                map.changes().len()
            )));
        }
        map
    };
    let total: u64 = opened
        .index
        .entries
        .values()
        .filter(|entry| entry.kind == EntryKind::File)
        .try_fold(0u64, |sum, entry| sum.checked_add(entry.size))
        .context("Total extraction size overflow")?;
    let progress = ProgressTracker::new(OperationPhase::Extract, total, reporter);

    let mut root = SafeRoot::open_new_at(output_dir, requested_staging_path)?;
    reporter.event(OperationEvent::TemporaryArtifact {
        kind: TemporaryArtifactKind::ExtractionTree,
        path: root.staging_path(),
    });
    root.install_root_id(1)?;
    let mut entries: Vec<_> = opened.index.entries.values().collect();
    entries.sort_by_key(|entry| (entry.depth, entry.id));
    let mut pending_files = Vec::new();

    for entry in entries {
        cancellation.check()?;
        if entry.id == 1 {
            continue;
        }
        match entry.kind {
            EntryKind::Directory => {
                #[cfg(windows)]
                let output_name = windows_names.name_for(entry.id, &entry.name);
                #[cfg(not(windows))]
                let output_name = entry.name.as_str();
                root.create_directory(entry.id, entry.parent_id, output_name)?;
            }
            EntryKind::File => {
                #[cfg(windows)]
                let output_name = windows_names.name_for(entry.id, &entry.name);
                #[cfg(not(windows))]
                let output_name = entry.name.as_str();
                let mut pending = root.begin_file(entry.parent_id, output_name, entry.id)?;
                let batch_size = crate::parallel::ordered_batch_size() as u64;
                let mut batch_start = 0u64;
                while batch_start < entry.chunk_count {
                    cancellation.check()?;
                    let batch_end = std::cmp::min(entry.chunk_count, batch_start + batch_size);
                    let chunks: Result<Vec<_>> = (batch_start..batch_end)
                        .into_par_iter()
                        .map(|chunk_index| {
                            cancellation.check()?;
                            v2::decrypt_chunk(&opened, entry, chunk_index).with_context(|| {
                                format!(
                                    "Entry {} chunk {} failed authentication",
                                    entry.id, chunk_index
                                )
                            })
                        })
                        .collect();
                    for mut plaintext in chunks? {
                        if inject_write_failure_after.is_some_and(|limit| {
                            progress.position().saturating_add(plaintext.len() as u64) > limit
                        }) {
                            anyhow::bail!("Injected extraction write failure");
                        }
                        pending.writer()?.write_all(&plaintext)?;
                        progress.advance(plaintext.len() as u64);
                        plaintext.zeroize();
                    }
                    batch_start = batch_end;
                }
                pending.finish_writing()?;
                pending_files.push(pending);
            }
        }
    }

    cancellation.check()?;
    for pending in pending_files {
        pending.commit()?;
    }
    cancellation.check()?;
    reporter.event(OperationEvent::PhaseStarted(OperationPhase::Commit));
    reporter.event(OperationEvent::CommitStarted);
    if let Some(warning) = root.commit()? {
        reporter.event(OperationEvent::Warning(warning));
    }
    reporter.event(OperationEvent::Committed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    struct CancelAfterStaging<'a>(&'a CancellationToken);

    impl ProgressReporter for CancelAfterStaging<'_> {
        fn report(&self, _progress: crate::operation::OperationProgress) {}

        fn event(&self, event: OperationEvent) {
            if matches!(event, OperationEvent::TemporaryArtifact { .. }) {
                self.0.cancel();
            }
        }
    }

    fn random_test_password() -> String {
        let mut value = [0u8; 32];
        rand::rng().fill_bytes(&mut value);
        hex::encode(value)
    }

    #[test]
    fn injected_write_failure_removes_staging_and_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("vault.cfs");
        let output = temp.path().join("output");
        let password = random_test_password();
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), vec![0x5a; 8192]).unwrap();
        crate::pack::pack(
            &source,
            &container,
            &password,
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            16 * 1024 * 1024,
            1,
        )
        .unwrap();

        let cancellation = CancellationToken::default();
        let reporter = NoProgress;
        let error = extract_v2_inner(
            &container,
            &output,
            &password,
            Some(1),
            None,
            &cancellation,
            &reporter,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("Injected extraction write failure"));
        assert!(!output.exists());
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("cipherfs-stage")
        }));
    }

    #[test]
    fn cancellation_before_extract_creates_no_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("vault.cfs");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), b"private").unwrap();
        crate::pack::pack(
            &source,
            &container,
            "master",
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            16 * 1024 * 1024,
            1,
        )
        .unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let reporter = NoProgress;
        assert!(
            extract_v2_with_control(&container, &output, "master", 1, &cancellation, &reporter)
                .is_err()
        );
        assert!(!output.exists());
    }

    #[test]
    fn cancellation_after_staging_removes_only_staging_and_not_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("vault.cfs");
        let output = temp.path().join("output");
        let staging = temp.path().join(".exact-worker.stage");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file.bin"), vec![0x5a; 8192]).unwrap();
        crate::pack::pack(
            &source,
            &container,
            "master",
            None,
            crate::v2::MIN_ARGON_MEMORY_KIB,
            1,
            1,
            16 * 1024 * 1024,
            1,
        )
        .unwrap();
        let cancellation = CancellationToken::default();
        let reporter = CancelAfterStaging(&cancellation);
        let error = execute(
            ExtractRequest {
                container: &container,
                output: &output,
                password: "master",
                options: ExtractOptions {
                    threads: 1,
                    staging_path: Some(staging.clone()),
                },
            },
            OperationControl::new(&cancellation, &reporter),
        )
        .unwrap_err();
        assert_eq!(
            crate::operation::error_kind(&error),
            crate::operation::CoreErrorKind::Cancelled
        );
        assert!(!output.exists());
        assert!(!staging.exists());
    }
}
