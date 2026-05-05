mod crypto;
mod extract;
mod index;
mod layout;
mod mount;
mod pack;

use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[cfg(unix)]
use crate::mount::CipherFS;
#[cfg(unix)]
use fuser::MountOption;
use rand::Rng;
use std::io::{Read, Write, Seek, SeekFrom};

#[derive(Parser)]
#[command(name = "cipherfs")]
#[command(about = "CipherFS: Read-only encrypted virtual filesystem", long_about = None)]
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
        /// Output .cfs file (defaults to source_name.cfs)
        output: Option<PathBuf>,
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack { source, output } => {
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

            pack::pack(&source, &output, &password, duress)?;
        }
        Commands::Extract { container, output } => {
            let password = rpassword::prompt_password("Enter Password: ")?;
            
            if let Err(e) = check_duress_and_wipe(&container, &password) {
                eprintln!("[Warning] Could not check/perform duress wipe: {}. Continuing extraction.", e);
            }

            extract::extract(&container, &output, &password)?;
        }
        Commands::Mount { container, mountpoint } => {
            #[cfg(unix)]
            {
                let password = rpassword::prompt_password("Enter Password: ")?;
                
                // 1. Try to open for duress wipe check (needs write if hash matches)
                // If we only have read access, skip the wipe check or warn
                if let Err(e) = check_duress_and_wipe(&container, &password) {
                    eprintln!("[Warning] Could not check/perform duress wipe: {}. Continuing in Read-Only mode.", e);
                }

                let fs = CipherFS::new(&container, &password)?;

                // Robust mountpoint check
                if !mountpoint.exists() {
                    println!("[Info] Creating mount point {}...", mountpoint.display());
                    std::fs::create_dir_all(&mountpoint).context("Failed to create mount point directory")?;
                } else if !mountpoint.is_dir() {
                    anyhow::bail!("Mount point {} exists but is not a directory.", mountpoint.display());
                }

                println!("[Info] Mounting CipherFS at {}...", mountpoint.display());
                
                let options = vec![
                    MountOption::RO,
                    MountOption::FSName("cipherfs".to_string()),
                ];
                let mut config = fuser::Config::default();
                config.mount_options = options;
                
                // Use spawn_mount2 to run FUSE in a background thread
                let _session = fuser::spawn_mount2(fs, &mountpoint, &config)
                    .context("FUSE mount failed")?;

                println!("[Success] CipherFS is mounted and ready.");
                println!("[Info] Press Ctrl+C to unmount and exit.");

                // Set up signal handling for elegant unmount
                use std::sync::atomic::{AtomicBool, Ordering};
                use std::sync::Arc;
                
                let running = Arc::new(AtomicBool::new(true));
                let r = running.clone();
                
                // Use libc to handle signals since we already depend on it
                extern "C" fn handle_signal(_: libc::c_int) {
                    // We can't easily change the AtomicBool from a C-style signal handler
                    // without a static global, so we'll just exit, 
                    // but we want the drop() of _session to run.
                    // The most robust way in a simple CLI is a loop with sleep or a dedicated signal crate.
                    // Since we want to avoid adding deps, we'll use a simple approach.
                    std::process::exit(0);
                }

                unsafe {
                    libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
                    libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
                }

                while running.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                
                // When _session is dropped here, it will attempt to unmount.
            }
            #[cfg(not(unix))]
            {
                let _ = (container, mountpoint);
                anyhow::bail!("Mounting is only supported on Unix platforms.");
            }
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
            let dek = crate::crypto::decrypt_data(&old_kek, &[0u8; 12], &header.encrypted_dek)
                .context("Invalid current password.")?;

            let new_password = rpassword::prompt_password("Set New Master Password: ")?;
            let verify = rpassword::prompt_password("Verify New Master Password: ")?;
            if new_password != verify {
                anyhow::bail!("Passwords do not match.");
            }

            println!("[Info] Re-encrypting Vault...");
            // Generate new salt and re-encrypt DEK
            let mut new_salt = [0u8; 16];
            rand::rng().fill_bytes(&mut new_salt);
            header.salt = new_salt;
            
            let new_kek = crate::crypto::derive_kek(&new_password, &header.salt, &header.argon2_params)?;
            let encrypted_dek_vec = crate::crypto::encrypt_data(&new_kek, &[0u8; 12], &dek)?;
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

fn check_duress_and_wipe(container: &std::path::Path, password: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use crate::layout::{Header, MAGIC_BYTES, HEADER_SIZE};
    use crate::crypto::hash_duress_password;

    let mut file = OpenOptions::new().read(true).open(container)?;
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
        
        // Reopen for writing
        let mut file = OpenOptions::new().write(true).open(container)?;
        
        let mut new_header = header;
        rand::rng().fill_bytes(&mut new_header.encrypted_dek);
        
        let header_bytes = rmp_serde::to_vec(&new_header)?;
        if header_bytes.len() > HEADER_SIZE {
            anyhow::bail!("Header size exceeds reserved space during wipe!");
        }
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
