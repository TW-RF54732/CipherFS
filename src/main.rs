mod crypto;
mod extract;
mod index;
mod layout;
mod mount;
mod pack;

use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::mount::CipherFS;
use fuser::MountOption;
use rand::Rng;
use std::io::{Read, Write, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser)]
#[command(name = "cipherfs")]
#[command(about = "CipherFS: High-performance read-only encrypted virtual filesystem (Linux Only)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pack a directory into a CipherFS container
    Pack {
        /// Source directory to pack
        source: PathBuf,
        /// Output .cfs file
        output: Option<PathBuf>,
        /// Argon2 m_cost (default: 65536)
        #[arg(long, default_value_t = 65536)]
        m_cost: u32,
        /// Argon2 t_cost (default: 3)
        #[arg(long, default_value_t = 3)]
        t_cost: u32,
        /// Argon2 p_cost (default: 4)
        #[arg(long, default_value_t = 4)]
        p_cost: u32,
        /// Max index size in MB (default: 512)
        #[arg(long, default_value_t = 512)]
        max_index: u64,
    },
    /// Extract a CipherFS container to a directory
    Extract {
        /// CipherFS container (.cfs)
        container: PathBuf,
        /// Output directory
        output: PathBuf,
    },
    /// Mount a CipherFS container
    Mount {
        /// CipherFS container (.cfs)
        container: PathBuf,
        /// Mount point
        mountpoint: PathBuf,
    },
    /// Change the master password of a container
    Passwd {
        /// CipherFS container (.cfs)
        container: PathBuf,
    },
    /// Update cipherfs to the latest version from GitHub
    Update,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Update => {
            println!("[Info] Checking for updates...");
            let updater = self_update::backends::github::Update::configure()
                .repo_owner("TW-RF54732")
                .repo_name("cipherfs")
                .bin_name("cipherfs")
                .target("cipherfs")
                .show_download_progress(true)
                .current_version(env!("CARGO_PKG_VERSION"))
                .build()
                .map_err(|e| anyhow::anyhow!("Update configuration failed: {}", e))?;

            let latest = updater.get_latest_release()
                .map_err(|e| anyhow::anyhow!("Failed to fetch latest release: {}", e))?;

            if self_update::version::bump_is_greater(env!("CARGO_PKG_VERSION"), &latest.version)? {
                println!("\n[Info] New version available: {} (Current: {})", latest.version, env!("CARGO_PKG_VERSION"));
                println!("--- Release Notes ---\n{}\n---------------------", latest.body.as_deref().unwrap_or("No notes available."));
                
                print!("\nDo you want to update to {}? [y/N]: ", latest.version);
                std::io::stdout().flush()?;
                
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                
                if input.trim().to_lowercase() == "y" {
                    println!("[Info] Starting update...");
                    let status = updater.update()
                        .map_err(|e| anyhow::anyhow!("Update failed: {}", e))?;
                    println!("[Success] Update status: `{}`!", status.version());
                } else {
                    println!("[Info] Update cancelled.");
                }
            } else {
                println!("[Info] Already up to date (Version: {}).", env!("CARGO_PKG_VERSION"));
            }
            return Ok(());
        }
        Commands::Pack { source, output, m_cost, t_cost, p_cost, max_index } => {
            let output = match output {
                Some(p) => p,
                None => {
                    let name = source.file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| format!("{}.cfs", s))
                        .unwrap_or_else(|| "vault.cfs".to_string());
                    PathBuf::from(name)
                }
            };

            let password = rpassword::prompt_password("Set Master Password: ")?;
            let verify = rpassword::prompt_password("Verify Master Password: ")?;
            if password != verify {
                anyhow::bail!("Passwords do not match.");
            }

            let duress = rpassword::prompt_password("Set Duress Password (Optional, Enter to skip): ")?;
            let duress = if duress.is_empty() { None } else { Some(duress.as_str()) };

            pack::pack(&source, &output, &password, duress, m_cost, t_cost, p_cost, max_index * 1024 * 1024)?;
        }
        Commands::Extract { container, output } => {
            let password = rpassword::prompt_password("Enter Password: ")?;
            
            if let Err(e) = check_duress_and_wipe(&container, &password) {
                eprintln!("[Warning] Could not check/perform duress wipe: {}. Continuing.", e);
            }

            extract::extract(&container, &output, &password)?;
        }
        Commands::Mount { container, mountpoint } => {
            let password = rpassword::prompt_password("Enter Password: ")?;
            
            if let Err(e) = check_duress_and_wipe(&container, &password) {
                eprintln!("[Warning] Could not check/perform duress wipe: {}. Continuing.", e);
            }

            let fs = CipherFS::new(&container, &password)?;

            if !mountpoint.exists() {
                println!("[Info] Creating mount point {}...", mountpoint.display());
                std::fs::create_dir_all(&mountpoint).context("Failed to create mount point directory")?;
            }

            println!("[Info] Mounting CipherFS at {}...", mountpoint.display());
            
            let options = vec![
                MountOption::RO,
                MountOption::FSName("cipherfs".to_string()),
            ];
            let mut config = fuser::Config::default();
            config.mount_options = options;
            
            let _session = fuser::spawn_mount2(fs, &mountpoint, &config)
                .context("FUSE mount failed")?;

            println!("[Success] CipherFS is mounted and ready.");
            println!("[Info] Press Ctrl+C to unmount and exit.");

            unsafe {
                libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
                libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
            }

            while RUNNING.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            
            println!("\n[Info] Unmounting...");
        }
        Commands::Passwd { container } => {
            let old_password = rpassword::prompt_password("Enter Current Password: ")?;
            
            println!("[Info] Verifying current password...");
            let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&container)?;
            let mut buffer = [0u8; crate::layout::HEADER_SIZE];
            file.read_exact(&mut buffer).context("Failed to read header")?;
            
            let mut cursor = std::io::Cursor::new(&buffer);
            let mut header: crate::layout::Header = rmp_serde::from_read(&mut cursor)?;

            let old_kek = crate::crypto::derive_kek(&old_password, &header.salt, &header.argon2_params)?;
            let dek = crate::crypto::decrypt_data(&old_kek, &header.dek_nonce, &header.encrypted_dek)
                .context("Invalid current password.")?;

            let new_password = rpassword::prompt_password("Set New Master Password: ")?;
            let verify = rpassword::prompt_password("Verify New Master Password: ")?;
            if new_password != verify {
                anyhow::bail!("Passwords do not match.");
            }

            println!("[Info] Re-encrypting Vault...");
            let mut new_salt = [0u8; 16];
            rand::rng().fill_bytes(&mut new_salt);
            header.salt = new_salt;
            
            let mut new_dek_nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut new_dek_nonce);
            header.dek_nonce = new_dek_nonce;

            let new_kek = crate::crypto::derive_kek(&new_password, &header.salt, &header.argon2_params)?;
            let encrypted_dek_vec = crate::crypto::encrypt_data(&new_kek, &header.dek_nonce, &dek)?;
            header.encrypted_dek.copy_from_slice(&encrypted_dek_vec);

            let header_bytes = rmp_serde::to_vec(&header)?;
            let mut padded_header = [0u8; crate::layout::HEADER_SIZE];
            padded_header[..header_bytes.len()].copy_from_slice(&header_bytes);

            file.seek(SeekFrom::Start(0))?;
            file.write_all(&padded_header)?;
            file.sync_all()?;

            println!("[Success] Password updated successfully.");
        }
    }

    Ok(())
}

extern "C" fn handle_signal(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn check_duress_and_wipe(container: &std::path::Path, password: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use crate::layout::{Header, MAGIC_BYTES, HEADER_SIZE};
    use crate::crypto::hash_duress_password;

    let file_res = OpenOptions::new().read(true).open(container);
    let mut file = match file_res {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };

    let mut buffer = [0u8; HEADER_SIZE];
    if file.read_exact(&mut buffer).is_err() { return Ok(()); }
    
    let mut cursor = std::io::Cursor::new(&buffer);
    let header_res: Result<Header, _> = rmp_serde::from_read(&mut cursor);
    let header = match header_res {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };
    
    if header.magic != MAGIC_BYTES {
        return Ok(());
    }

    let input_hash = hash_duress_password(password);
    if header.duress_hash != [0u8; 32] && header.duress_hash == input_hash {
        println!("[Error] Duress password detected! Wiping Data Encryption Key...");
        
        let mut file = OpenOptions::new().write(true).open(container)?;
        
        let mut new_header = header;
        rand::rng().fill_bytes(&mut new_header.encrypted_dek);
        
        let header_bytes = rmp_serde::to_vec(&new_header)?;
        let mut padded_header = [0u8; HEADER_SIZE];
        padded_header[..header_bytes.len()].copy_from_slice(&header_bytes);

        file.seek(SeekFrom::Start(0))?;
        file.write_all(&padded_header)?;
        file.sync_all()?;
        
        println!("[Success] Vault neutralized.");
        std::process::exit(1);
    }
    
    Ok(())
}
