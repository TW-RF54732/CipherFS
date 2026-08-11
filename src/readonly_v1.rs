use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use zeroize::Zeroizing;

use crate::crypto::{decrypt_data, derive_chunk_nonce, derive_kek};
use crate::index::Inode;
use crate::layout::{CHUNK_SIZE, HEADER_SIZE, Header, MAGIC_BYTES};
use crate::platform_io::PlatformFileExt;
use crate::readonly_fs::{FsError, FsErrorKind, Node, NodeKind};
use crate::v2::MAX_INDEX_SIZE;

pub struct ReadOnlyV1Fs {
    file: File,
    dek: [u8; 32],
    master_nonce: [u8; 32],
    data_offset: u64,
    nodes: HashMap<u64, Node>,
    inodes: HashMap<u64, Inode>,
    children: HashMap<u64, Vec<u64>>,
}

impl ReadOnlyV1Fs {
    pub fn new(path: &Path, password: &str) -> Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let mut buffer = [0u8; HEADER_SIZE];
        file.read_exact_at(&mut buffer, 0)?;
        let header: Header = rmp_serde::from_read(std::io::Cursor::new(buffer))?;
        if header.magic != MAGIC_BYTES {
            anyhow::bail!("Not a CipherFS v1 container");
        }
        if header.index_size > MAX_INDEX_SIZE
            || header.index_size > metadata.len().saturating_sub(HEADER_SIZE as u64)
        {
            anyhow::bail!("Legacy index exceeds local safety limits");
        }
        let kek = derive_kek(password, &header.salt, &header.argon2_params)?;
        let dek_bytes = decrypt_data(&kek, &header.dek_nonce, &header.encrypted_dek)
            .context("Invalid password or corrupted legacy header")?;
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        let mut encrypted_index = vec![0u8; header.index_size as usize];
        file.read_exact_at(&mut encrypted_index, HEADER_SIZE as u64)?;
        let serialized = decrypt_data(&dek, &header.index_nonce, &encrypted_index)
            .context("Failed to decrypt legacy index")?;
        let root: Inode = rmp_serde::from_slice(&serialized)?;

        let mut nodes = HashMap::new();
        let mut inodes = HashMap::new();
        let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut stack = vec![(String::new(), root)];
        while let Some((name, inode)) = stack.pop() {
            let (id, parent_id, size, kind) = match &inode {
                Inode::File {
                    ino,
                    parent_ino,
                    size,
                    ..
                } => (*ino, *parent_ino, *size, NodeKind::File),
                Inode::Directory {
                    ino, parent_ino, ..
                } => (*ino, *parent_ino, 0, NodeKind::Directory),
            };
            if id != parent_id {
                children.entry(parent_id).or_default().push(id);
            }
            if let Inode::Directory { entries, .. } = &inode {
                for (child_name, child) in entries {
                    stack.push((child_name.clone(), child.clone()));
                }
            }
            nodes.insert(
                id,
                Node {
                    id,
                    parent_id,
                    name,
                    kind,
                    size,
                },
            );
            inodes.insert(id, inode);
        }
        for ids in children.values_mut() {
            ids.sort_by(|left, right| {
                nodes[left]
                    .name
                    .cmp(&nodes[right].name)
                    .then(left.cmp(right))
            });
        }
        Ok(Self {
            file,
            dek,
            master_nonce: header.master_nonce,
            data_offset: HEADER_SIZE as u64 + header.index_size,
            nodes,
            inodes,
            children,
        })
    }

    pub fn metadata(&self, id: u64) -> Result<Node, FsError> {
        self.nodes
            .get(&id)
            .cloned()
            .ok_or_else(|| FsError::semantic(FsErrorKind::NotFound))
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub fn lookup(&self, parent: u64, name: &str) -> Result<Node, FsError> {
        self.children
            .get(&parent)
            .into_iter()
            .flatten()
            .find_map(|id| self.nodes.get(id).filter(|node| node.name == name).cloned())
            .ok_or_else(|| FsError::semantic(FsErrorKind::NotFound))
    }

    pub fn read_dir(&self, id: u64) -> Result<Vec<Node>, FsError> {
        if self.metadata(id)?.kind != NodeKind::Directory {
            return Err(FsError::semantic(FsErrorKind::NotDirectory));
        }
        Ok(self
            .children
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|child| self.nodes.get(child).cloned())
            .collect())
    }

    pub fn read(&self, id: u64, offset: u64, size: u32) -> Result<Zeroizing<Vec<u8>>, FsError> {
        let inode = self
            .inodes
            .get(&id)
            .ok_or_else(|| FsError::semantic(FsErrorKind::NotFound))?;
        let Inode::File {
            size: file_size,
            offset: data_start,
            ..
        } = inode
        else {
            return Err(FsError::semantic(FsErrorKind::IsDirectory));
        };
        if offset >= *file_size {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let read_size = u64::from(size).min(*file_size - offset);
        let absolute = data_start
            .checked_add(offset)
            .ok_or_else(|| FsError::integrity(anyhow::anyhow!("Legacy read offset overflow")))?;
        let start_chunk = absolute / CHUNK_SIZE as u64;
        let end_chunk = (absolute + read_size - 1) / CHUNK_SIZE as u64;
        let mut output = Zeroizing::new(Vec::with_capacity(read_size as usize));
        for chunk_index in start_chunk..=end_chunk {
            let position = self.data_offset + chunk_index * (CHUNK_SIZE as u64 + 16);
            let remaining = self
                .file
                .metadata()
                .map_err(FsError::integrity)?
                .len()
                .saturating_sub(position);
            let encrypted_len = remaining.min((CHUNK_SIZE + 16) as u64) as usize;
            let mut encrypted = vec![0u8; encrypted_len];
            self.file
                .read_exact_at(&mut encrypted, position)
                .map_err(FsError::integrity)?;
            let decrypted = decrypt_data(
                &self.dek,
                &derive_chunk_nonce(&self.master_nonce, chunk_index),
                &encrypted,
            )
            .map_err(FsError::integrity)?;
            let chunk_start = chunk_index * CHUNK_SIZE as u64;
            let skip = absolute.saturating_sub(chunk_start) as usize;
            if skip > decrypted.len() {
                return Err(FsError::integrity(anyhow::anyhow!(
                    "Legacy chunk range is invalid"
                )));
            }
            let take = (read_size - output.len() as u64) as usize;
            output.extend_from_slice(&decrypted[skip..skip + take.min(decrypted.len() - skip)]);
        }
        if output.len() as u64 != read_size {
            return Err(FsError::integrity(anyhow::anyhow!(
                "Legacy read returned incomplete plaintext"
            )));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };
    use std::io::Write;

    fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        ChaCha20Poly1305::new(key.into())
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .unwrap()
    }

    fn write_test_container(path: &Path) -> u64 {
        let first = b"first-private";
        let second = b"second-private";
        let mut entries = HashMap::new();
        entries.insert(
            "z.txt".to_string(),
            Inode::File {
                ino: 3,
                parent_ino: 1,
                size: second.len() as u64,
                offset: first.len() as u64,
            },
        );
        entries.insert(
            "a.txt".to_string(),
            Inode::File {
                ino: 2,
                parent_ino: 1,
                size: first.len() as u64,
                offset: 0,
            },
        );
        let root = Inode::Directory {
            ino: 1,
            parent_ino: 1,
            entries,
        };
        let salt = [1u8; 16];
        let params = crate::layout::Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let master_nonce = [2u8; 32];
        let dek_nonce = [3u8; 12];
        let index_nonce = [4u8; 12];
        let dek = [5u8; 32];
        let kek = derive_kek("master", &salt, &params).unwrap();
        let encrypted_dek: [u8; 48] = encrypt(&kek, &dek_nonce, &dek).try_into().unwrap();
        let index = rmp_serde::to_vec(&root).unwrap();
        let encrypted_index = encrypt(&dek, &index_nonce, &index);
        let header = Header {
            magic: MAGIC_BYTES,
            salt,
            argon2_params: params,
            master_nonce,
            dek_nonce,
            index_nonce,
            duress_hash: [0; 32],
            encrypted_dek,
            index_size: encrypted_index.len() as u64,
            max_index_size: MAX_INDEX_SIZE,
        };
        let mut encoded_header = rmp_serde::to_vec(&header).unwrap();
        encoded_header.resize(HEADER_SIZE, 0);
        let mut plaintext = first.to_vec();
        plaintext.extend_from_slice(second);
        let encrypted_data = encrypt(&dek, &derive_chunk_nonce(&master_nonce, 0), &plaintext);
        let mut file = File::create(path).unwrap();
        file.write_all(&encoded_header).unwrap();
        file.write_all(&encrypted_index).unwrap();
        file.write_all(&encrypted_data).unwrap();
        file.sync_all().unwrap();
        (HEADER_SIZE + encrypted_index.len() + encrypted_data.len() - 1) as u64
    }

    #[test]
    fn exposes_stable_metadata_lookup_eof_ranges_and_integrity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("legacy.cfs");
        let last_byte = write_test_container(&path);
        let filesystem = ReadOnlyV1Fs::new(&path, "master").unwrap();
        let names: Vec<String> = filesystem
            .read_dir(1)
            .unwrap()
            .into_iter()
            .map(|node| node.name)
            .collect();
        assert_eq!(names, ["a.txt", "z.txt"]);
        let file = filesystem.lookup(1, "a.txt").unwrap();
        assert_eq!(&*filesystem.read(file.id, 2, 5).unwrap(), b"rst-p");
        assert!(filesystem.read(file.id, file.size, 4).unwrap().is_empty());

        let container = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut byte = [0u8; 1];
        container.read_exact_at(&mut byte, last_byte).unwrap();
        byte[0] ^= 1;
        container.write_all_at(&byte, last_byte).unwrap();
        assert_eq!(
            filesystem
                .read(file.id, 0, file.size as u32)
                .unwrap_err()
                .kind(),
            FsErrorKind::Integrity
        );
    }
}
