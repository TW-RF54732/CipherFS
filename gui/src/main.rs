#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod mount_windows;

use std::path::PathBuf;
use tauri::Manager;
use cipherfs_core::pack;

// Tauri 指令：打包
#[tauri::command]
async fn pack_vault(source: String, output: Option<String>, password: String) -> Result<String, String> {
    let source_path = PathBuf::from(source);
    let output_path = match output {
        Some(o) => PathBuf::from(o),
        None => {
            let name = source_path.file_name()
                .and_then(|n| n.to_str())
                .map(|s| format!("{}.cfs", s))
                .unwrap_or_else(|| "vault.cfs".to_string());
            PathBuf::from(name)
        }
    };

    pack::pack(&source_path, &output_path, &password, None)
        .map_err(|e| e.to_string())?;

    Ok(format!("Successfully created {}", output_path.display()))
}

// Tauri 指令：掛載 (Windows 專用)
#[tauri::command]
async fn mount_vault(container: String, mountpoint: String, password: String) -> Result<String, String> {
    let container_path = PathBuf::from(container);
    let mount_path = PathBuf::from(mountpoint);

    #[cfg(target_os = "windows")]
    {
        mount_windows::mount_vault_windows(&container_path, &mount_path, &password)
            .map_err(|e| e.to_string())?;
        Ok("Mounted successfully on Windows".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Native mounting via GUI is currently optimized for Windows/WinFsp. Please use CLI on Linux.".to_string())
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![pack_vault, mount_vault])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
