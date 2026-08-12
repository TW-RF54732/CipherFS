use anyhow::{Context, Error};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::v2::{self, CHUNK_SIZE, Entry, EntryKind, OpenedContainer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: u64,
    pub parent_id: u64,
    pub name: String,
    pub kind: NodeKind,
    pub size: u64,
}

type CacheKey = ([u8; 16], u64);
type CachedChunk = Arc<Zeroizing<Vec<u8>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsErrorKind {
    NotFound,
    NotDirectory,
    IsDirectory,
    Integrity,
}

#[derive(Debug)]
pub struct FsError {
    kind: FsErrorKind,
    source: Option<Error>,
}

impl FsError {
    pub(crate) fn semantic(kind: FsErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub(crate) fn integrity(error: impl Into<Error>) -> Self {
        Self {
            kind: FsErrorKind::Integrity,
            source: Some(error.into()),
        }
    }

    pub fn kind(&self) -> FsErrorKind {
        self.kind
    }
}

impl From<&Entry> for Node {
    fn from(entry: &Entry) -> Self {
        Self {
            id: entry.id,
            parent_id: entry.parent_id,
            name: entry.name.clone(),
            kind: if entry.kind == EntryKind::File {
                NodeKind::File
            } else {
                NodeKind::Directory
            },
            size: entry.size,
        }
    }
}

pub struct ReadOnlyFs(Box<ReadOnlyV2Fs>);

impl ReadOnlyFs {
    pub fn open(path: &Path, password: &str, cache_mib: u64) -> anyhow::Result<Self> {
        crate::format::require_v2(path)?;
        Ok(Self(Box::new(ReadOnlyV2Fs::new(
            path, password, cache_mib,
        )?)))
    }

    pub fn metadata(&self, id: u64) -> Result<Node, FsError> {
        self.0.metadata(id).map(Node::from)
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub fn lookup(&self, parent: u64, name: &str) -> Result<Node, FsError> {
        self.0.lookup(parent, name).map(Node::from)
    }

    pub fn read_dir(&self, id: u64) -> Result<Vec<Node>, FsError> {
        let mut entries: Vec<_> = self.0.read_dir(id)?.into_iter().map(Node::from).collect();
        entries.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(entries)
    }

    pub fn read(&self, id: u64, offset: u64, size: u32) -> Result<Zeroizing<Vec<u8>>, FsError> {
        self.0.read(id, offset, size)
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            return write!(formatter, "{source:#}");
        }
        match self.kind {
            FsErrorKind::NotFound => formatter.write_str("Node not found"),
            FsErrorKind::NotDirectory => formatter.write_str("Node is not a directory"),
            FsErrorKind::IsDirectory => formatter.write_str("Node is a directory"),
            FsErrorKind::Integrity => formatter.write_str("Encrypted data failed validation"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
    }
}

struct Cache {
    max_bytes: usize,
    bytes: usize,
    values: HashMap<CacheKey, CachedChunk>,
    order: VecDeque<CacheKey>,
}

pub struct ReadOnlyV2Fs {
    opened: OpenedContainer,
    cache: Mutex<Cache>,
}

impl ReadOnlyV2Fs {
    pub fn new(path: &Path, password: &str, cache_mib: u64) -> anyhow::Result<Self> {
        if cache_mib > 1024 {
            anyhow::bail!("Chunk cache cannot exceed 1024 MiB");
        }
        let max_bytes = cache_mib
            .checked_mul(1024 * 1024)
            .and_then(|value| usize::try_from(value).ok())
            .context("Cache size overflow")?;
        Ok(Self {
            opened: v2::open(path, password)?,
            cache: Mutex::new(Cache {
                max_bytes,
                bytes: 0,
                values: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    pub fn metadata(&self, id: u64) -> Result<&Entry, FsError> {
        self.opened
            .index
            .entries
            .get(&id)
            .ok_or_else(|| FsError::semantic(FsErrorKind::NotFound))
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub fn lookup(&self, parent: u64, name: &str) -> Result<&Entry, FsError> {
        self.opened
            .index
            .children
            .get(&parent)
            .and_then(|children| {
                children.iter().find_map(|id| {
                    self.opened
                        .index
                        .entries
                        .get(id)
                        .filter(|entry| entry.name == name)
                })
            })
            .ok_or_else(|| FsError::semantic(FsErrorKind::NotFound))
    }

    pub fn read_dir(&self, id: u64) -> Result<Vec<&Entry>, FsError> {
        let entry = self.metadata(id)?;
        if entry.kind != EntryKind::Directory {
            return Err(FsError::semantic(FsErrorKind::NotDirectory));
        }
        Ok(self
            .opened
            .index
            .children
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|child_id| self.opened.index.entries.get(child_id))
            .collect())
    }

    pub fn read(&self, id: u64, offset: u64, size: u32) -> Result<Zeroizing<Vec<u8>>, FsError> {
        let entry = self.metadata(id)?;
        if entry.kind != EntryKind::File {
            return Err(FsError::semantic(FsErrorKind::IsDirectory));
        }
        if offset >= entry.size {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let read_len = std::cmp::min(size as u64, entry.size - offset);
        let last_byte = offset
            .checked_add(read_len)
            .and_then(|value| value.checked_sub(1))
            .context("Read range overflow")
            .map_err(FsError::integrity)?;
        let start_chunk = offset / CHUNK_SIZE as u64;
        let end_chunk = last_byte / CHUNK_SIZE as u64;
        let mut output = Zeroizing::new(Vec::with_capacity(read_len as usize));

        for chunk_index in start_chunk..=end_chunk {
            let chunk = self.load_chunk(entry, chunk_index)?;
            let chunk_start = chunk_index * CHUNK_SIZE as u64;
            let skip = offset.saturating_sub(chunk_start) as usize;
            if skip > chunk.len() {
                return Err(FsError::integrity(anyhow::anyhow!(
                    "Chunk range is outside decrypted data"
                )));
            }
            let remaining = read_len.saturating_sub(output.len() as u64) as usize;
            let take = std::cmp::min(chunk.len() - skip, remaining);
            output.extend_from_slice(&chunk[skip..skip + take]);
        }
        if output.len() as u64 != read_len {
            return Err(FsError::integrity(anyhow::anyhow!(
                "Read returned an incomplete plaintext range"
            )));
        }
        Ok(output)
    }

    fn load_chunk(&self, entry: &Entry, chunk_index: u64) -> Result<CachedChunk, FsError> {
        let cache_key = (entry.file_id, chunk_index);
        {
            let mut cache = self.cache.lock();
            if let Some(value) = cache.values.get(&cache_key).cloned() {
                if let Some(position) = cache.order.iter().position(|key| key == &cache_key) {
                    cache.order.remove(position);
                }
                cache.order.push_back(cache_key);
                return Ok(value);
            }
        }

        let value = Arc::new(
            v2::decrypt_chunk(&self.opened, entry, chunk_index)
                .with_context(|| format!("entry {} chunk {} failed", entry.id, chunk_index))
                .map_err(FsError::integrity)?,
        );
        let mut cache = self.cache.lock();
        if cache.max_bytes == 0 || value.len() > cache.max_bytes {
            return Ok(value);
        }
        while cache.bytes + value.len() > cache.max_bytes {
            let Some(oldest) = cache.order.pop_front() else {
                break;
            };
            if let Some(old) = cache.values.remove(&oldest) {
                cache.bytes = cache.bytes.saturating_sub(old.len());
            }
        }
        cache.bytes += value.len();
        cache.order.push_back(cache_key);
        cache.values.insert(cache_key, value.clone());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::io::{Seek, SeekFrom, Write};

    fn random_test_password() -> String {
        let mut value = [0u8; 32];
        rand::rng().fill_bytes(&mut value);
        hex::encode(value)
    }

    fn pack_test_container(source: &Path, container: &Path, password: &str) {
        crate::pack::pack(
            source,
            container,
            password,
            None,
            8192,
            1,
            1,
            16 * 1024 * 1024,
            1,
        )
        .unwrap();
    }

    #[test]
    fn exposes_platform_neutral_lookup_directory_and_range_reads() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("test.cfs");
        let password = random_test_password();
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(source.join("empty")).unwrap();
        std::fs::write(source.join("empty.bin"), []).unwrap();
        let mut contents = vec![0x41; CHUNK_SIZE];
        contents.extend_from_slice(b"cross-chunk-tail");
        std::fs::write(source.join("boundary.bin"), &contents).unwrap();
        pack_test_container(&source, &container, &password);

        let filesystem = ReadOnlyV2Fs::new(&container, &password, 8).unwrap();
        let root = filesystem.metadata(1).unwrap();
        assert_eq!(root.kind, EntryKind::Directory);
        let children = filesystem.read_dir(root.id).unwrap();
        assert_eq!(children.len(), 3);
        let file = filesystem.lookup(root.id, "boundary.bin").unwrap();
        let offset = CHUNK_SIZE as u64 - 4;
        let actual = filesystem.read(file.id, offset, 10).unwrap();
        assert_eq!(
            actual.as_slice(),
            &contents[offset as usize..offset as usize + 10]
        );
        assert_eq!(
            filesystem.lookup(root.id, "missing").unwrap_err().kind(),
            FsErrorKind::NotFound
        );
        assert_eq!(
            filesystem.read(root.id, 0, 1).unwrap_err().kind(),
            FsErrorKind::IsDirectory
        );

        let shared = Arc::new(ReadOnlyFs::open(&container, &password, 8).unwrap());
        let names: Vec<_> = shared
            .read_dir(1)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec!["boundary.bin", "empty", "empty.bin"]);
        let empty = shared.lookup(1, "empty.bin").unwrap();
        assert!(shared.read(empty.id, 0, 32).unwrap().is_empty());

        let boundary = shared.lookup(1, "boundary.bin").unwrap();
        let ranges = [
            (0u64, 1u32),
            (17, 4097),
            (CHUNK_SIZE as u64 - 9, 31),
            (CHUNK_SIZE as u64, 17),
            (contents.len() as u64 - 1, 32),
            (contents.len() as u64, 32),
        ];
        for (offset, length) in ranges {
            let actual = shared.read(boundary.id, offset, length).unwrap();
            let start = usize::try_from(offset).unwrap().min(contents.len());
            let end = start.saturating_add(length as usize).min(contents.len());
            assert_eq!(actual.as_slice(), &contents[start..end]);
        }

        let expected = Arc::new(contents);
        let threads: Vec<_> = (0..8)
            .map(|worker| {
                let shared = Arc::clone(&shared);
                let expected = Arc::clone(&expected);
                std::thread::spawn(move || {
                    for iteration in 0..16 {
                        let offset =
                            ((worker * 997 + iteration * 4093) as u64) % expected.len() as u64;
                        let actual = shared.read(boundary.id, offset, 8192).unwrap();
                        let start = offset as usize;
                        let end = start.saturating_add(8192).min(expected.len());
                        assert_eq!(actual.as_slice(), &expected[start..end]);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn corrupt_chunk_returns_integrity_error_without_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let container = temp.path().join("corrupt.cfs");
        let password = random_test_password();
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("secret.txt"), b"secret data").unwrap();
        pack_test_container(&source, &container, &password);

        let filesystem = ReadOnlyV2Fs::new(&container, &password, 0).unwrap();
        let file = filesystem.lookup(1, "secret.txt").unwrap();
        let mut handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&container)
            .unwrap();
        handle.seek(SeekFrom::End(-1)).unwrap();
        let last = {
            let mut byte = [0u8; 1];
            std::io::Read::read_exact(&mut handle, &mut byte).unwrap();
            byte[0]
        };
        handle.seek(SeekFrom::End(-1)).unwrap();
        handle.write_all(&[last ^ 1]).unwrap();
        handle.flush().unwrap();

        let error = filesystem.read(file.id, 0, 64).unwrap_err();
        assert_eq!(error.kind(), FsErrorKind::Integrity);
    }
}
