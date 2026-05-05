mod crypto;
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
        /// Output .cfs file
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
            // If we only have read access, skip the wipe check or warn
            if let Err(e) = check_duress_and_wipe(&container, &password) {
                eprintln!("[Warning] Could not check/perform duress wipe: {}. Continuing in Read-Only mode.", e);
            }

            let fs = CipherFS::new(&container, &password)?;
            
            if !mountpoint.exists() {
                anyhow::bail!("Mount point {} does not exist.", mountpoint.display());
            }

            println!("[Info] Mounting CipherFS at {}...", mountpoint.display());
            println!("[Info] Press Ctrl+C to unmount.");
            
            let options = vec![
                MountOption::RO,
                MountOption::FSName("cipherfs".to_string()),
            ];
            
            let mut config = fuser::Config::default();
            config.mount_options = options;
            
            fuser::mount2(fs, mountpoint, &config).context("FUSE mount failed")?;
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
    use crate::layout::{Header, MAGIC_BYTES};
    use crate::crypto::hash_duress_password;

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
