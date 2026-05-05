use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use parking_lot::Mutex;

// 引入核心邏輯
use cipherfs_core::crypto::{derive_kek, decrypt_data, derive_chunk_nonce};
use cipherfs_core::layout::{Header, CHUNK_SIZE, MAGIC_BYTES};
use cipherfs_core::index::Inode;

// Windows 專屬：WinFsp 綁定
#[cfg(target_os = "windows")]
use winfsp::{
    FileSystem, FileSystemContext, VolumeParams, FileInfo, 
    DirectoryBuffer, DirEntry, FileMode, FileAttribute,
};

#[cfg(target_os = "windows")]
pub struct CipherFSWin {
    file: Mutex<File>,
    dek: [u8; 32],
    master_nonce: [u8; 32],
    data_offset: u64,
    root: Inode,
}

#[cfg(target_os = "windows")]
impl CipherFSWin {
    fn find_inode(&self, path: &str) -> Option<Inode> {
        if path == "\\" || path == "" {
            return Some(self.root.clone());
        }

        let mut current = &self.root;
        for part in path.split('\\').filter(|s| !s.is_empty()) {
            if let Inode::Directory { entries } = current {
                if let Some(next) = entries.get(part) {
                    current = next;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        Some(current.clone())
    }
}

#[cfg(target_os = "windows")]
impl FileSystemContext for CipherFSWin {
    // 獲取檔案資訊 (Stat)
    fn get_file_info(&self, path: &str) -> Result<FileInfo> {
        let inode = self.find_inode(path).context("File not found")?;
        let mut info = FileInfo::default();
        
        match inode {
            Inode::File { size, .. } => {
                info.file_size = size;
                info.allocation_size = (size + 4095) & !4095;
                info.file_attributes = FileAttribute::Normal as u32;
            }
            Inode::Directory { .. } => {
                info.file_size = 0;
                info.file_attributes = FileAttribute::Directory as u32;
            }
        }
        // 設定唯讀權限
        info.file_mode = 0o444; 
        Ok(info)
    }

    // 讀取目錄內容
    fn read_directory(&self, path: &str, mut buffer: DirectoryBuffer) -> Result<DirectoryBuffer> {
        if let Some(Inode::Directory { entries }) = self.find_inode(path) {
            // 加入 . 和 ..
            buffer.add(".", None)?;
            buffer.add("..", None)?;
            
            for name in entries.keys() {
                buffer.add(name, None)?;
            }
            Ok(buffer)
        } else {
            anyhow::bail!("Not a directory")
        }
    }

    // 讀取檔案內容 (核心局部解密)
    fn read(&self, path: &str, offset: u64, buffer: &mut [u8]) -> Result<u32> {
        if let Some(Inode::File { size: file_size, offset: data_start_offset }) = self.find_inode(path) {
            if offset >= file_size {
                return Ok(0);
            }

            let requested_size = buffer.len() as u64;
            let read_size = std::cmp::min(requested_size, file_size - offset);
            
            let mut result_vec = Vec::with_capacity(read_size as usize);
            let abs_offset = data_start_offset + offset;
            let start_chunk = abs_offset / CHUNK_SIZE as u64;
            let end_chunk = (abs_offset + read_size - 1) / CHUNK_SIZE as u64;

            let mut file = self.file.lock();

            for chunk_idx in start_chunk..=end_chunk {
                let chunk_file_pos = self.data_offset + chunk_idx * (CHUNK_SIZE as u64 + 16);
                let nonce = derive_chunk_nonce(&self.master_nonce, chunk_idx);
                
                let mut encrypted_chunk = vec![0u8; CHUNK_SIZE + 16]; 
                file.seek(SeekFrom::Start(chunk_file_pos))?;
                let n = file.read(&mut encrypted_chunk)?;
                
                let decrypted = decrypt_data(&self.dek, &nonce, &encrypted_chunk[..n])?;
                
                let chunk_start_in_file = chunk_idx * CHUNK_SIZE as u64;
                let skip = abs_offset.saturating_sub(chunk_start_in_file) as usize;
                let take = std::cmp::min(decrypted.len() - skip, (read_size - result_vec.len() as u64) as usize);
                
                result_vec.extend_from_slice(&decrypted[skip..skip+take]);
            }
            
            buffer[..result_vec.len()].copy_from_slice(&result_vec);
            Ok(result_vec.len() as u32)
        } else {
            anyhow::bail!("Access denied or not a file")
        }
    }
}

#[cfg(target_os = "windows")]
pub fn mount_vault_windows(container: &Path, _mountpoint: &Path, password: &str) -> Result<()> {
    // 1. 初始化資料 (這部分與 Linux 邏輯共用)
    let mut file = File::open(container)?;
    let mut buffer = [0u8; 1024];
    file.read(&mut buffer)?;
    
    let mut cursor = std::io::Cursor::new(&buffer);
    let header: Header = rmp_serde::from_read(&mut cursor)?;
    let header_size = cursor.position();

    if header.magic != MAGIC_BYTES {
        anyhow::bail!("Invalid CipherFS file.");
    }

    let kek = derive_kek(password, &header.salt, &header.argon2_params)?;
    let dek_vec = decrypt_data(&kek, &[0u8; 12], &header.encrypted_dek)?;
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);

    let mut encrypted_index = vec![0u8; header.index_size as usize];
    file.seek(SeekFrom::Start(header_size))?;
    file.read_exact(&mut encrypted_index)?;

    let serialized_index = decrypt_data(&dek, &[0u8; 12], &encrypted_index)?;
    let root: Inode = rmp_serde::from_slice(&serialized_index)?;

    let context = CipherFSWin {
        file: Mutex::new(file),
        dek,
        master_nonce: header.master_nonce,
        data_offset: header_size + header.index_size,
        root,
    };

    // 2. 設定 WinFsp 參數
    let mut params = VolumeParams::default();
    params.set_volume_label("CipherFS Vault");
    params.set_case_sensitive(true);
    params.set_read_only(true);

    // 3. 執行掛載
    // 注意：這裡假設掛載到 Z: 盤符
    println!("[Windows] Mounting vault to Z:\\...");
    let _fs = FileSystem::new(params, context)?;
    
    // 在真實環境中，這裡需要保持執行緒存活
    // _fs.mount("Z:")?;
    
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn mount_vault_windows(_container: &Path, _mountpoint: &Path, _password: &str) -> Result<()> {
    anyhow::bail!("Windows mount logic can only run on Windows.");
}
