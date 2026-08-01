mod crypto;
mod extract;
mod format;
mod index;
mod layout;
mod legacy_extract;
mod legacy_mount;
mod mount;
mod pack;
mod parallel;
mod safe_fs;
mod updater;
mod v2;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fuser::MountOption;
use rand::Rng;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

use crate::format::{Format, detect as detect_format};
use crate::mount::CipherFS;

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser)]
#[command(name = "cipherfs")]
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
    /// Extract a v1 or v2 container
    Extract {
        container: PathBuf,
        output: PathBuf,
        /// Worker threads for v2 chunk decryption (0 uses the available CPU parallelism)
        #[arg(long, default_value_t = 0, value_parser = parse_threads)]
        threads: usize,
    },
    /// Mount a v1 or v2 container read-only
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
        Commands::Update => updater::update_interactive(),
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
            pack::pack(
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
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            match detect_format(&container)? {
                Format::V2 => extract::extract_v2(&container, &output, &password, threads),
                Format::V1 => {
                    eprintln!(
                        "[Warning] Legacy v1 has known design limitations; only open trusted containers."
                    );
                    check_legacy_duress_and_wipe(&container, &password)?;
                    legacy_extract::extract_legacy(&container, &output, &password)
                }
            }
        }
        Commands::Mount {
            container,
            mountpoint,
            cache_mib,
        } => {
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            if matches!(detect_format(&container)?, Format::V1) {
                check_legacy_duress_and_wipe(&container, &password)?;
            }
            let filesystem = CipherFS::new(&container, &password, cache_mib)?;
            std::fs::create_dir_all(&mountpoint)
                .context("Unable to create mount point directory")?;
            let mut config = fuser::Config::default();
            config.mount_options =
                vec![MountOption::RO, MountOption::FSName("cipherfs".to_string())];
            let _session = fuser::spawn_mount2(filesystem, &mountpoint, &config)
                .context("FUSE mount failed")?;
            println!("[Success] CipherFS is mounted read-only.");
            println!("[Info] Press Ctrl+C to unmount.");
            unsafe {
                libc::signal(
                    libc::SIGINT,
                    handle_signal as *const () as libc::sighandler_t,
                );
                libc::signal(
                    libc::SIGTERM,
                    handle_signal as *const () as libc::sighandler_t,
                );
            }
            while RUNNING.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            println!("\n[Info] Unmounting...");
            Ok(())
        }
        Commands::Passwd { container } => {
            if !matches!(detect_format(&container)?, Format::V2) {
                anyhow::bail!(
                    "Legacy v1 containers are read-only; extract and re-pack to change the password"
                );
            }
            let old = Zeroizing::new(rpassword::prompt_password("Enter Current Password: ")?);
            let new = Zeroizing::new(rpassword::prompt_password("Set New Master Password: ")?);
            let verify =
                Zeroizing::new(rpassword::prompt_password("Verify New Master Password: ")?);
            if new.as_str() != verify.as_str() {
                anyhow::bail!("Passwords do not match");
            }
            v2::change_password(&container, &old, &new)?;
            println!("[Success] Password keyslot updated.");
            Ok(())
        }
        Commands::Verify { container, threads } => {
            let password = Zeroizing::new(rpassword::prompt_password("Enter Password: ")?);
            match detect_format(&container)? {
                Format::V2 => {
                    let opened = v2::open(&container, &password)?;
                    parallel::install(threads, || v2::verify_all(&opened))?;
                    println!("[Success] Header, index, and all encrypted chunks are valid.");
                    Ok(())
                }
                Format::V1 => {
                    anyhow::bail!("Full verify is only available for v2 containers")
                }
            }
        }
    }
}

extern "C" fn handle_signal(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn check_legacy_duress_and_wipe(container: &Path, password: &str) -> Result<()> {
    use crate::crypto::hash_duress_password;
    use crate::layout::{HEADER_SIZE, Header};
    use std::fs::OpenOptions;

    let mut file = OpenOptions::new().read(true).open(container)?;
    let mut buffer = [0u8; HEADER_SIZE];
    file.read_exact(&mut buffer)?;
    let header: Header = rmp_serde::from_read(std::io::Cursor::new(buffer))?;
    let input_hash = hash_duress_password(password);
    if header.duress_hash == [0u8; 32] || header.duress_hash != input_hash {
        return Ok(());
    }

    let mut file = OpenOptions::new().write(true).open(container)?;
    let mut new_header = header;
    rand::rng().fill_bytes(&mut new_header.encrypted_dek);
    let encoded = rmp_serde::to_vec(&new_header)?;
    if encoded.len() > HEADER_SIZE {
        anyhow::bail!("Legacy header overflow during duress handling");
    }
    let mut padded = [0u8; HEADER_SIZE];
    padded[..encoded.len()].copy_from_slice(&encoded);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&padded)?;
    file.sync_all()?;
    anyhow::bail!("Unable to unlock container (wrong password or damage)")
}
