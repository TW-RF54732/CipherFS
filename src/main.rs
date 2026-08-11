use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

use cipherfs::format::require_v2;

static RUNNING: AtomicBool = AtomicBool::new(true);

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
        Commands::Update => cipherfs::updater::update_interactive(),
        Commands::Licenses => {
            println!("{}", include_str!("../THIRD_PARTY_NOTICES.md"));
            println!("\n--- Locked Rust dependencies ---\n");
            println!("{}", include_str!("../THIRD_PARTY_DEPENDENCIES.md"));
            println!("\n--- GNU GPL version 3 ---\n");
            println!("{}", include_str!("../LICENSE-GPL-3.0"));
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
            let duress = if duress.is_empty() {
                None
            } else {
                Some(duress.as_str())
            };
            let max_index_bytes = max_index
                .checked_mul(1024 * 1024)
                .context("Index limit overflow")?;
            cipherfs::pack::pack(
                &source,
                &output,
                &password,
                duress,
                m_cost,
                t_cost,
                p_cost,
                max_index_bytes,
                threads,
            )
        }
        Commands::Extract {
            container,
            output,
            threads,
        } => {
            require_v2(&container)?;
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            cipherfs::extract::extract_v2(&container, &output, &password, threads)
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
            cipherfs::v2::change_password(&container, &old, &new)?;
            println!("[Success] Password keyslot updated.");
            Ok(())
        }
        Commands::Verify { container, threads } => {
            require_v2(&container)?;
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            let opened = cipherfs::v2::open(&container, &password)?;
            cipherfs::parallel::install(threads, || cipherfs::v2::verify_all(&opened))?;
            println!("[Success] Header, index, and all encrypted chunks are valid.");
            Ok(())
        }
    }
}

fn install_signal_handler() -> Result<()> {
    ctrlc::set_handler(|| RUNNING.store(false, Ordering::SeqCst))
        .context("Unable to install Ctrl+C handler")
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
    use fuser::MountOption;
    let filesystem = cipherfs::fuse_mount::CipherFS::new(container, password, cache_mib)?;
    std::fs::create_dir_all(mountpoint).context("Unable to create mount point directory")?;
    let mut config = fuser::Config::default();
    config.mount_options = vec![MountOption::RO, MountOption::FSName("cipherfs".to_string())];
    let _session =
        fuser::spawn_mount2(filesystem, mountpoint, &config).context("FUSE mount failed")?;
    install_signal_handler()?;
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
    cipherfs::winfsp_mount::mount(container, mountpoint, password, cache_mib, wait_for_unmount)
}
