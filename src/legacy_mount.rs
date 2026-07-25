use crate::crypto::*;
use crate::index::Inode;
use crate::layout::{CHUNK_SIZE, Header, MAGIC_BYTES};
use crate::v2::MAX_INDEX_SIZE;
use anyhow::{Context, Result};
use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

pub struct LegacyCipherFS {
    file: File,
    dek: [u8; 32],
    master_nonce: [u8; 32],
    data_offset: u64,
    inode_map: HashMap<u64, Inode>,
}

impl LegacyCipherFS {
    pub fn new(cfs_path: &Path, password: &str) -> Result<Self> {
        let file = File::open(cfs_path)?;
        let metadata = file.metadata()?;

        let mut buffer = [0u8; crate::layout::HEADER_SIZE];
        file.read_exact_at(&mut buffer, 0)
            .context("Failed to read header")?;

        let mut cursor = std::io::Cursor::new(&buffer);
        let header: Header = rmp_serde::from_read(&mut cursor)?;
        let header_size = crate::layout::HEADER_SIZE as u64;

        if header.magic != MAGIC_BYTES {
            anyhow::bail!("Not a CipherFS file or invalid version.");
        }

        if header.index_size > MAX_INDEX_SIZE
            || header.index_size
                > metadata
                    .len()
                    .saturating_sub(crate::layout::HEADER_SIZE as u64)
        {
            anyhow::bail!("Legacy index exceeds local safety limits");
        }

        let kek = derive_kek(password, &header.salt, &header.argon2_params)?;
        let dek_vec = decrypt_data(&kek, &header.dek_nonce, &header.encrypted_dek)
            .context("Invalid password or corrupted header.")?;
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_vec);

        let mut encrypted_index = vec![0u8; header.index_size as usize];
        file.read_exact_at(&mut encrypted_index, header_size)
            .context("Failed to read index")?;

        let serialized_index = decrypt_data(&dek, &header.index_nonce, &encrypted_index)
            .context("Failed to decrypt index.")?;
        let index: Inode = rmp_serde::from_slice(&serialized_index)?;

        let data_offset = header_size + header.index_size;

        let mut inode_map = HashMap::new();
        // Iterative population
        let mut stack = vec![&index];
        while let Some(node) = stack.pop() {
            inode_map.insert(node.ino(), node.clone());
            if let Inode::Directory { entries, .. } = node {
                for child in entries.values() {
                    stack.push(child);
                }
            }
        }

        Ok(Self {
            file,
            dek,
            master_nonce: header.master_nonce,
            data_offset,
            inode_map,
        })
    }

    fn get_inode(&self, ino: u64) -> Option<&Inode> {
        self.inode_map.get(&ino)
    }
}

impl Filesystem for LegacyCipherFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let name_str = name.to_str().unwrap_or("");
        if let Some(Inode::Directory { entries, .. }) = self.get_inode(parent.into())
            && let Some(inode) = entries.get(name_str)
        {
            let attr = inode_to_attr(inode.ino(), inode);
            reply.entry(&TTL, &attr, Generation(0));
            return;
        }
        reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Some(inode) = self.get_inode(ino.into()) {
            let attr = inode_to_attr(ino.into(), inode);
            reply.attr(&TTL, &attr);
        } else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
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
        if let Some(inode) = self.get_inode(ino.into()) {
            if let Inode::Directory {
                entries,
                parent_ino,
                ..
            } = inode
            {
                let mut entries_vec: Vec<(u64, &str, FileType)> = Vec::new();
                entries_vec.push((ino.into(), ".", FileType::Directory));
                entries_vec.push((*parent_ino, "..", FileType::Directory));

                for (name, child_inode) in entries.iter() {
                    let kind = if child_inode.is_file() {
                        FileType::RegularFile
                    } else {
                        FileType::Directory
                    };
                    entries_vec.push((child_inode.ino(), name, kind));
                }

                for (i, (child_ino, name, kind)) in
                    entries_vec.into_iter().enumerate().skip(offset as usize)
                {
                    if reply.add(INodeNo(child_ino), (i + 1) as u64, kind, name) {
                        break;
                    }
                }
                reply.ok();
            } else {
                reply.error(std::io::Error::from_raw_os_error(libc::ENOTDIR).into());
            }
        } else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
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
        if let Some(Inode::File {
            size: file_size,
            offset: data_start_offset,
            ..
        }) = self.get_inode(ino.into())
        {
            if offset >= *file_size {
                reply.data(&[]);
                return;
            }

            let read_size = std::cmp::min(size as u64, *file_size - offset);
            let mut result = Vec::with_capacity(read_size as usize);

            let abs_offset = *data_start_offset + offset;
            let start_chunk = abs_offset / CHUNK_SIZE as u64;
            let end_chunk = (abs_offset + read_size - 1) / CHUNK_SIZE as u64;

            for chunk_idx in start_chunk..=end_chunk {
                let chunk_file_pos = self.data_offset + chunk_idx * (CHUNK_SIZE as u64 + 16);
                let nonce = derive_chunk_nonce(&self.master_nonce, chunk_idx);

                let mut encrypted_chunk = vec![0u8; CHUNK_SIZE + 16];
                let n = match self.file.read_at(&mut encrypted_chunk, chunk_file_pos) {
                    Ok(n) => n,
                    Err(_) => {
                        reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
                        return;
                    }
                };

                let decrypted = match decrypt_data(&self.dek, &nonce, &encrypted_chunk[..n]) {
                    Ok(d) => d,
                    Err(_) => {
                        reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
                        return;
                    }
                };

                let chunk_start_in_file = chunk_idx * CHUNK_SIZE as u64;
                let skip = abs_offset.saturating_sub(chunk_start_in_file) as usize;
                if skip > decrypted.len() {
                    reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
                    return;
                }
                let take = std::cmp::min(
                    decrypted.len() - skip,
                    (read_size - result.len() as u64) as usize,
                );

                result.extend_from_slice(&decrypted[skip..skip + take]);
            }

            if result.len() as u64 != read_size {
                reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
            } else {
                reply.data(&result);
            }
        } else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
        }
    }
}

fn inode_to_attr(ino: u64, inode: &Inode) -> FileAttr {
    match inode {
        Inode::File { size, .. } => FileAttr {
            ino: INodeNo(ino),
            size: *size,
            blocks: (*size).div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
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
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            flags: 0,
            blksize: 4096,
        },
    }
}
