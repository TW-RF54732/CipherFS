use anyhow::{Context, Result};
use cipherfs_core::operation::{
    CancellationToken, OperationControl, OperationEvent, OperationPhase, OperationProgress,
    ProgressReporter,
};
use cipherfs_core::require_v2;
use cipherfs_core::{ExtractOptions, ExtractRequest, PackOptions, PackRequest};
use cipherfs_core::{VerifyOptions, VerifyRequest};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

static RUNNING: AtomicBool = AtomicBool::new(true);
static CANCELLATION: OnceLock<CancellationToken> = OnceLock::new();

#[derive(Parser)]
#[command(name = "cipherfs")]
#[command(version)]
#[command(
    about = "CipherFS: experimental read-only encrypted filesystem for personal privacy",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pack a directory into a new CipherFS v2 container
    Pack {
        source: PathBuf,
        output: Option<PathBuf>,
        #[arg(long, default_value_t = 65_536)]
        m_cost: u32,
        #[arg(long, default_value_t = 3)]
        t_cost: u32,
        #[arg(long, default_value_t = 4)]
        p_cost: u32,
        /// Maximum index size accepted during this pack, in MiB (local hard cap: 512)
        #[arg(long, default_value_t = 512)]
        max_index: u64,
        /// Worker threads for chunk encryption (0 uses the available CPU parallelism)
        #[arg(long, default_value_t = 0, value_parser = parse_threads)]
        threads: usize,
    },
    /// Extract a v2 container into a destination that does not yet exist
    Extract {
        container: PathBuf,
        output: PathBuf,
        /// Worker threads for v2 chunk decryption (0 uses the available CPU parallelism)
        #[arg(long, default_value_t = 0, value_parser = parse_threads)]
        threads: usize,
    },
    /// Mount a v2 container read-only
    Mount {
        container: PathBuf,
        mountpoint: PathBuf,
        /// Decrypted v2 chunk cache in MiB (0 disables it)
        #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u64).range(0..=1024))]
        cache_mib: u64,
    },
    /// Change the master password of a v2 container
    Passwd { container: PathBuf },
    /// Authenticate the complete header, index, and data without extracting
    Verify {
        container: PathBuf,
        /// Worker threads for v2 chunk verification (0 uses the available CPU parallelism)
        #[arg(long, default_value_t = 0, value_parser = parse_threads)]
        threads: usize,
    },
    /// Install the latest release only after Minisign verification
    Update,
    /// Show CipherFS and third-party licensing notices
    Licenses,
}

struct CliProgress {
    active: Mutex<Option<(OperationPhase, ProgressBar)>>,
}

impl CliProgress {
    fn new() -> Self {
        Self {
            active: Mutex::new(None),
        }
    }

    fn bar(total: u64) -> ProgressBar {
        let bar = ProgressBar::new(total);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .expect("constant progress template is valid")
            .progress_chars("=>-"),
        );
        bar
    }

    fn finish_active(&self) {
        if let Some((phase, bar)) = self.active.lock().expect("progress state poisoned").take() {
            let message = match phase {
                OperationPhase::Encrypt => "Encrypted",
                OperationPhase::SelfVerify | OperationPhase::Verify => "Verified",
                OperationPhase::Extract => "Verified and extracted",
                _ => "Complete",
            };
            bar.finish_with_message(message);
        }
    }
}

impl ProgressReporter for CliProgress {
    fn report(&self, progress: OperationProgress) {
        if matches!(
            progress.phase,
            OperationPhase::Scan | OperationPhase::KeyDerivation | OperationPhase::Commit
        ) {
            return;
        }
        let mut active = self.active.lock().expect("progress state poisoned");
        let replace = active.as_ref().is_none_or(|(phase, bar)| {
            *phase != progress.phase || bar.length() != Some(progress.total)
        });
        if replace {
            if let Some((_, old)) = active.take() {
                old.finish_and_clear();
            }
            *active = Some((progress.phase, Self::bar(progress.total)));
        }
        if let Some((_, bar)) = active.as_ref() {
            bar.set_position(progress.completed);
        }
    }

    fn event(&self, event: OperationEvent) {
        match event {
            OperationEvent::Progress(progress) => self.report(progress),
            OperationEvent::ScanCompleted { entries, bytes } => {
                println!("[Info] Found {entries} entries and {bytes} bytes.");
            }
            OperationEvent::PhaseStarted(OperationPhase::SelfVerify) => {
                self.finish_active();
                println!("[Info] Verifying completed container...");
            }
            OperationEvent::PhaseStarted(OperationPhase::Commit) => self.finish_active(),
            OperationEvent::Warning(message) => eprintln!("[Warning] {message}"),
            OperationEvent::Committed => self.finish_active(),
            OperationEvent::PhaseStarted(_)
            | OperationEvent::TemporaryArtifact { .. }
            | OperationEvent::CommitStarted
            | OperationEvent::MutationStarted => {}
        }
    }
}

fn parse_threads(value: &str) -> std::result::Result<usize, String> {
    let threads = value
        .parse::<usize>()
        .map_err(|_| "threads must be an integer from 0 through 256".to_string())?;
    if threads > 256 {
        return Err("threads must be an integer from 0 through 256".to_string());
    }
    Ok(threads)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Update => update_interactive(),
        Commands::Licenses => {
            println!("{}", include_str!("../../../THIRD_PARTY_NOTICES.md"));
            println!("\n--- Locked Rust dependencies ---\n");
            println!("{}", include_str!("../../../THIRD_PARTY_DEPENDENCIES.md"));
            println!("\n--- GNU GPL version 3 ---\n");
            println!("{}", include_str!("../../../LICENSE-GPL-3.0"));
            Ok(())
        }
        Commands::Pack {
            source,
            output,
            m_cost,
            t_cost,
            p_cost,
            max_index,
            threads,
        } => {
            let output = output.unwrap_or_else(|| {
                source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| PathBuf::from(format!("{name}.cfs")))
                    .unwrap_or_else(|| PathBuf::from("vault.cfs"))
            });
            let password = Zeroizing::new(rpassword::prompt_password("Set Master Password: ")?);
            let verify = Zeroizing::new(rpassword::prompt_password("Verify Master Password: ")?);
            if password.as_str() != verify.as_str() {
                anyhow::bail!("Passwords do not match");
            }
            let duress = Zeroizing::new(rpassword::prompt_password(
                "Set Duress Password (optional): ",
            )?);
            let duress = (!duress.is_empty()).then_some(duress.as_str());
            let max_index_size = max_index
                .checked_mul(1024 * 1024)
                .context("Index limit overflow")?;
            println!("[Info] Scanning {}...", source.display());
            let cancellation = operation_token()?;
            let reporter = CliProgress::new();
            cipherfs_core::pack(
                PackRequest {
                    source: &source,
                    output: &output,
                    password: &password,
                    duress_password: duress,
                    options: PackOptions {
                        argon2_m_cost: m_cost,
                        argon2_t_cost: t_cost,
                        argon2_p_cost: p_cost,
                        max_index_size,
                        threads,
                        temporary_path: None,
                    },
                },
                OperationControl::new(cancellation, &reporter),
            )?;
            reporter.finish_active();
            println!("[Success] {} created and verified.", output.display());
            Ok(())
        }
        Commands::Extract {
            container,
            output,
            threads,
        } => {
            require_v2(&container)?;
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            let cancellation = operation_token()?;
            let reporter = CliProgress::new();
            cipherfs_core::extract(
                ExtractRequest {
                    container: &container,
                    output: &output,
                    password: &password,
                    options: ExtractOptions {
                        threads,
                        staging_path: None,
                    },
                },
                OperationControl::new(cancellation, &reporter),
            )?;
            reporter.finish_active();
            println!("[Success] Extraction complete.");
            Ok(())
        }
        Commands::Mount {
            container,
            mountpoint,
            cache_mib,
        } => {
            require_v2(&container)?;
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            mount_filesystem(&container, &mountpoint, &password, cache_mib)
        }
        Commands::Passwd { container } => {
            require_v2(&container)?;
            let old = Zeroizing::new(rpassword::prompt_password("Enter Current Password: ")?);
            let new = Zeroizing::new(rpassword::prompt_password("Set New Master Password: ")?);
            let verify =
                Zeroizing::new(rpassword::prompt_password("Verify New Master Password: ")?);
            if new.as_str() != verify.as_str() {
                anyhow::bail!("Passwords do not match");
            }
            let cancellation = operation_token()?;
            let reporter = CliProgress::new();
            cipherfs_core::change_password_with_control(
                &container,
                &old,
                &new,
                cancellation,
                &reporter,
            )?;
            println!("[Success] Password keyslot updated.");
            Ok(())
        }
        Commands::Verify { container, threads } => {
            require_v2(&container)?;
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            let cancellation = operation_token()?;
            let reporter = CliProgress::new();
            cipherfs_core::verify(
                VerifyRequest {
                    container: &container,
                    password: &password,
                    options: VerifyOptions { threads },
                },
                OperationControl::new(cancellation, &reporter),
            )?;
            reporter.finish_active();
            println!("[Success] Header, index, and all encrypted chunks are valid.");
            Ok(())
        }
    }
}

fn install_signal_handler() -> Result<()> {
    let token = CANCELLATION.get_or_init(CancellationToken::default).clone();
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if INSTALLED.get().is_none() {
        ctrlc::set_handler(move || {
            RUNNING.store(false, Ordering::SeqCst);
            token.cancel();
        })
        .context("Unable to install Ctrl+C handler")?;
        let _ = INSTALLED.set(());
    }
    Ok(())
}

fn operation_token() -> Result<&'static CancellationToken> {
    install_signal_handler()?;
    Ok(CANCELLATION.get_or_init(CancellationToken::default))
}

fn wait_for_unmount() {
    while RUNNING.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn mount_filesystem(
    container: &Path,
    mountpoint: &Path,
    password: &str,
    cache_mib: u64,
) -> Result<()> {
    install_signal_handler()?;
    let _session =
        cipherfs_fuse::FuseMountSession::start(container, mountpoint, password, cache_mib)?;
    println!("[Success] CipherFS is mounted read-only.");
    println!("[Info] Press Ctrl+C to unmount.");
    wait_for_unmount();
    println!("\n[Info] Unmounting...");
    Ok(())
}

#[cfg(windows)]
fn mount_filesystem(
    container: &Path,
    mountpoint: &Path,
    password: &str,
    cache_mib: u64,
) -> Result<()> {
    install_signal_handler()?;
    println!("[Info] WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos.");
    println!("[Info] https://github.com/winfsp/winfsp");
    println!("[Info] Run `cipherfs licenses` for licensing and no-warranty notices.");
    let mut session =
        cipherfs_winfsp::WinFspMountSession::start(container, mountpoint, password, cache_mib)?;
    println!(
        "[Success] CipherFS is mounted read-only through WinFsp at {}.",
        session.mount_path().display()
    );
    println!("[Info] Press Ctrl+C to unmount.");
    wait_for_unmount();
    println!("\n[Info] Unmounting...");
    session.unmount();
    Ok(())
}

struct TempUpdate(PathBuf);

impl Drop for TempUpdate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn update_interactive() -> Result<()> {
    let Some(update) = cipherfs_update::download_portable_update()? else {
        println!(
            "[Info] Already up to date (Version: {}).",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    };
    println!(
        "[Info] Signed update available: {} (Current: {})",
        update.version, update.current_version
    );
    if let Some(notes) = update.release_notes.as_deref() {
        println!(
            "--- Release Notes ---\n{}\n---------------------",
            terminal_safe(notes)
        );
    }
    print!("Install verified update {}? [y/N]: ", update.version);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("[Info] Update cancelled.");
        return Ok(());
    }

    let current_exe = std::env::current_exe()?;
    let parent = current_exe
        .parent()
        .context("Current executable has no parent directory")?;
    let mut random = [0u8; 8];
    rand::rng().fill_bytes(&mut random);
    let temp_path = parent.join(format!(
        ".cipherfs-update-{}{}",
        hex::encode(random),
        std::env::consts::EXE_SUFFIX
    ));
    let temp = TempUpdate(temp_path.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    file.write_all(&update.bytes)?;
    file.sync_all()?;
    drop(file);
    set_executable(&temp_path)?;
    std::fs::File::open(&temp_path)?.sync_all()?;
    self_replace::self_replace(&temp_path)?;
    sync_parent(parent)?;
    drop(temp);
    println!("[Success] Updated to {}.", update.version);
    Ok(())
}

fn terminal_safe(text: &str) -> String {
    text.chars()
        .filter(|character| *character == '\n' || *character == '\t' || !character.is_control())
        .collect()
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(windows)]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_notes_strip_terminal_controls() {
        assert_eq!(terminal_safe("ok\u{1b}[31m\nnext"), "ok[31m\nnext");
    }
}
