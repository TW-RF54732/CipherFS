use anyhow::{Context, Result};
use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{Header, CHUNK_SIZE, MAGIC_BYTES};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
    INodeNo, FileHandle, Generation, OpenFlags, LockOwner,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use parking_lot::Mutex;
use std::hash::{Hash, Hasher};

const TTL: Duration = Duration::from_secs(1);

pub struct CipherFS {
    file: Mutex<File>,
    dek: [u8; 32],
    master_nonce: [u8; 32],
    data_offset: u64,
    inode_map: Mutex<HashMap<u64, Inode>>,
}

impl CipherFS {
    pub fn new(cfs_path: &Path, password: &str) -> Result<Self> {
        let mut file = File::open(cfs_path)?;
        
        let mut buffer = [0u8; 1024];
        let _ = file.read(&mut buffer);
        
        let mut cursor = std::io::Cursor::new(&buffer);
        let header: Header = rmp_serde::from_read(&mut cursor)?;
        let header_size = cursor.position();

        if header.magic != MAGIC_BYTES {
            anyhow::bail!("Not a CipherFS file or invalid version.");
        }

        let kek = derive_kek(password, &header.salt, &header.argon2_params)?;
        let dek_vec = decrypt_data(&kek, &[0u8; 12], &header.encrypted_dek)
            .context("Invalid password or corrupted header.")?;
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_vec);

        let mut encrypted_index = vec![0u8; header.index_size as usize];
        file.seek(SeekFrom::Start(header_size))?;
        file.read_exact(&mut encrypted_index)?;

        let serialized_index = decrypt_data(&dek, &[0u8; 12], &encrypted_index)
            .context("Failed to decrypt index.")?;
        let index: Inode = rmp_serde::from_slice(&serialized_index)?;

        let data_offset = header_size + header.index_size;

        let mut inode_map = HashMap::new();
        inode_map.insert(1, index);

        Ok(Self {
            file: Mutex::new(file),
            dek,
            master_nonce: header.master_nonce,
            data_offset,
            inode_map: Mutex::new(inode_map),
        })
    }

    fn get_inode(&self, ino: u64) -> Option<Inode> {
        self.inode_map.lock().get(&ino).cloned()
    }

    fn assign_ino(&self, parent_ino: u64, name: &str, inode: &Inode) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        parent_ino.hash(&mut hasher);
        name.hash(&mut hasher);
        let ino = (hasher.finish() & 0x00FF_FFFF_FFFF_FFFF) | 0x0100_0000_0000_0000;
        
        let mut map = self.inode_map.lock();
        map.entry(ino).or_insert_with(|| inode.clone());
        ino
    }
}

impl Filesystem for CipherFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name_str = name.to_str().unwrap_or("");
        if let Some(Inode::Directory { entries }) = self.get_inode(parent.into()) {
            if let Some(inode) = entries.get(name_str) {
                let ino = self.assign_ino(parent.into(), name_str, inode);
                let attr = inode_to_attr(ino, inode);
                reply.entry(&TTL, &attr, Generation(0));
                return;
            }
        }
        reply.error(std::io::ErrorKind::NotFound.into());
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Some(inode) = self.get_inode(ino.into()) {
            let attr = inode_to_attr(ino.into(), &inode);
            reply.attr(&TTL, &attr);
        } else {
            reply.error(std::io::ErrorKind::NotFound.into());
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if let Some(Inode::Directory { entries }) = self.get_inode(ino.into()) {
            let mut entries_vec: Vec<(u64, String, FileType)> = Vec::new();
            entries_vec.push((ino.into(), ".".to_string(), FileType::Directory));
            // parent of root is root (1)
            let parent_ino = if ino.0 == 1 { 1 } else { 1 }; // simplified for now, ideally track parent
            entries_vec.push((parent_ino, "..".to_string(), FileType::Directory));
            
            for (name, inode) in entries.iter() {
                let kind = if inode.is_file() { FileType::RegularFile } else { FileType::Directory };
                let child_ino = self.assign_ino(ino.into(), name, inode);
                entries_vec.push((child_ino, name.clone(), kind));
            }

            for (i, (child_ino, name, kind)) in entries_vec.into_iter().enumerate().skip(offset as usize) {
                if reply.add(INodeNo(child_ino), (i + 1) as u64, kind, name) {
                    break;
                }
            }
            reply.ok();
        } else {
            reply.error(std::io::ErrorKind::NotFound.into());
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if let Some(Inode::File { size: file_size, offset: data_start_offset }) = self.get_inode(ino.into()) {
            if offset >= file_size {
                reply.data(&[]);
                return;
            }

            let read_size = std::cmp::min(size as u64, file_size - offset);
            let mut result = Vec::with_capacity(read_size as usize);

            let abs_offset = data_start_offset + offset;
            let start_chunk = abs_offset / CHUNK_SIZE as u64;
            let end_chunk = (abs_offset + read_size - 1) / CHUNK_SIZE as u64;

            let mut file = self.file.lock();

            for chunk_idx in start_chunk..=end_chunk {
                let chunk_file_pos = self.data_offset + chunk_idx * (CHUNK_SIZE as u64 + 16);
                let nonce = derive_chunk_nonce(&self.master_nonce, chunk_idx);
                
                let mut encrypted_chunk = vec![0u8; CHUNK_SIZE + 16]; 
                if file.seek(SeekFrom::Start(chunk_file_pos)).is_err() { break; }
                let n = match file.read(&mut encrypted_chunk) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                
                let decrypted = match decrypt_data(&self.dek, &nonce, &encrypted_chunk[..n]) {
                    Ok(d) => d,
                    Err(_) => break,
                };
                
                let chunk_start_in_file = chunk_idx * CHUNK_SIZE as u64;
                let skip = abs_offset.saturating_sub(chunk_start_in_file) as usize;
                let take = std::cmp::min(decrypted.len() - skip, (read_size - result.len() as u64) as usize);
                
                result.extend_from_slice(&decrypted[skip..skip+take]);
            }
            
            reply.data(&result);
        } else {
            reply.error(std::io::ErrorKind::NotFound.into());
        }
    }
}

fn inode_to_attr(ino: u64, inode: &Inode) -> FileAttr {
    match inode {
        Inode::File { size, .. } => FileAttr {
            ino: INodeNo(ino),
            size: *size,
            blocks: (*size + 511) / 512,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: 501,
            gid: 20,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        },
        Inode::Directory { .. } => FileAttr {
            ino: INodeNo(ino),
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: 501,
            gid: 20,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        },
    }
}
