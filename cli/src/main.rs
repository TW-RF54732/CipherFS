mod mount;

use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::mount::CipherFS;
use fuser::MountOption;
use rand::Rng;
use cipherfs_core::{pack, layout::{self, Header, MAGIC_BYTES}, crypto::{self, hash_duress_password}};

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
        Commands::Mount { container, mountpoint } => {
            let password = rpassword::prompt_password("Enter Password: ")?;
            
            // 1. Try to open for duress wipe check (needs write if hash matches)
            if let Err(e) = check_duress_and_wipe(&container, &password) {
                eprintln!("[Warning] Could not check/perform duress wipe: {}. Continuing in Read-Only mode.", e);
            }

            let fs = CipherFS::new(&container, &password)?;
            
            // Robust mountpoint check
            if !mountpoint.is_dir() {
                if mountpoint.exists() {
                    anyhow::bail!("Mount point {} exists but is not a directory.", mountpoint.display());
                } else {
                    println!("[Info] Creating mount point {}...", mountpoint.display());
                    std::fs::create_dir_all(&mountpoint).context("Failed to create mount point directory")?;
                }
            }

            println!("[Info] Mounting CipherFS at {}...", mountpoint.display());
            
            let options = vec![
                MountOption::RO,
                MountOption::FSName("cipherfs".to_string()),
            ];
            
            let mut config = fuser::Config::default();
            config.mount_options = options;
            
            let _session = fuser::spawn_mount2(fs, &mountpoint, &config).context("FUSE mount failed")?;
            
            println!("[Success] Vault is active.");
            println!("[Info] Press Ctrl+C to unmount and exit.");

            // Keep the main thread alive until interrupted
            let (tx, rx) = std::sync::mpsc::channel();
            ctrlc::set_handler(move || {
                let _ = tx.send(());
            }).context("Error setting Ctrl-C handler")?;

            rx.recv().ok();
            println!("\n[Info] Unmounting safely...");
            // _session is dropped here, which triggers unmount
        }
        Commands::Passwd { .. } => {
            println!("Passwd command not yet implemented.");
        }
    }

    Ok(())
}

fn check_duress_and_wipe(container: &std::path::Path, password: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write, Seek, SeekFrom};

    let mut file = OpenOptions::new().read(true).open(container)?;
    let mut buffer = [0u8; 1024];
    if file.read(&mut buffer).is_err() { return Ok(()); }
    
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
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header_bytes)?;
        file.sync_all()?;
        
        println!("[Success] Vault neutralized.");
        std::process::exit(1);
    }
    
    Ok(())
}
