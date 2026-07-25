use anyhow::{Context, Result};
use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::format::{Format, detect as detect_format};
use crate::legacy_mount::LegacyCipherFS;
use crate::v2::{self, CHUNK_SIZE, Entry, EntryKind, OpenedContainer};

const TTL: Duration = Duration::from_secs(1);
type CacheKey = ([u8; 16], u64);
type CachedChunk = Arc<zeroize::Zeroizing<Vec<u8>>>;

pub enum CipherFS {
    Legacy(LegacyCipherFS),
    V2(Box<V2CipherFS>),
}

struct Cache {
    max_bytes: usize,
    bytes: usize,
    values: HashMap<CacheKey, CachedChunk>,
    order: VecDeque<CacheKey>,
}

pub struct V2CipherFS {
    opened: OpenedContainer,
    cache: Mutex<Cache>,
}

impl CipherFS {
    pub fn new(path: &Path, password: &str, cache_mib: u64) -> Result<Self> {
        match detect_format(path)? {
            Format::V2 => Ok(Self::V2(Box::new(V2CipherFS::new(
                path, password, cache_mib,
            )?))),
            Format::V1 => {
                eprintln!(
                    "[Warning] Opening legacy CipherFS v1 container; re-pack as v2 before relying on it."
                );
                Ok(Self::Legacy(LegacyCipherFS::new(path, password)?))
            }
        }
    }
}

impl V2CipherFS {
    fn new(path: &Path, password: &str, cache_mib: u64) -> Result<Self> {
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

    fn entry(&self, ino: u64) -> Option<&Entry> {
        self.opened.index.entries.get(&ino)
    }

    fn load_chunk(&self, entry: &Entry, chunk_index: u64) -> Result<CachedChunk> {
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

        let value = Arc::new(v2::decrypt_chunk(&self.opened, entry, chunk_index)?);
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

impl Filesystem for CipherFS {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        match self {
            Self::Legacy(fs) => fs.lookup(req, parent, name, reply),
            Self::V2(fs) => fs.lookup(req, parent, name, reply),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        match self {
            Self::Legacy(fs) => fs.getattr(req, ino, fh, reply),
            Self::V2(fs) => fs.getattr(req, ino, fh, reply),
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        match self {
            Self::Legacy(fs) => fs.readdir(req, ino, fh, offset, reply),
            Self::V2(fs) => fs.readdir(req, ino, fh, offset, reply),
        }
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self {
            Self::Legacy(fs) => fs.read(req, ino, fh, offset, size, flags, lock_owner, reply),
            Self::V2(fs) => fs.read(req, ino, fh, offset, size, flags, lock_owner, reply),
        }
    }
}

impl Filesystem for V2CipherFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let Some(name) = name.to_str() else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
            return;
        };
        let found = self
            .opened
            .index
            .children
            .get(&u64::from(parent))
            .and_then(|children| {
                children
                    .iter()
                    .find_map(|id| self.entry(*id).filter(|entry| entry.name == name))
            });
        if let Some(entry) = found {
            reply.entry(&TTL, &entry_attr(entry), Generation(0));
        } else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Some(entry) = self.entry(ino.into()) {
            reply.attr(&TTL, &entry_attr(entry));
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
        let Some(entry) = self.entry(ino.into()) else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
            return;
        };
        if entry.kind != EntryKind::Directory {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOTDIR).into());
            return;
        }
        let mut listing: Vec<(u64, &str, FileType)> = vec![
            (entry.id, ".", FileType::Directory),
            (entry.parent_id, "..", FileType::Directory),
        ];
        if let Some(children) = self.opened.index.children.get(&entry.id) {
            for id in children {
                if let Some(child) = self.entry(*id) {
                    listing.push((
                        child.id,
                        child.name.as_str(),
                        if child.kind == EntryKind::File {
                            FileType::RegularFile
                        } else {
                            FileType::Directory
                        },
                    ));
                }
            }
        }
        for (position, (id, name, kind)) in listing.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(id), (position + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
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
        let Some(entry) = self.entry(ino.into()) else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
            return;
        };
        if entry.kind != EntryKind::File {
            reply.error(std::io::Error::from_raw_os_error(libc::EISDIR).into());
            return;
        }
        if offset >= entry.size {
            reply.data(&[]);
            return;
        }
        let read_len = std::cmp::min(size as u64, entry.size - offset);
        let Some(last_byte) = offset
            .checked_add(read_len)
            .and_then(|value| value.checked_sub(1))
        else {
            reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
            return;
        };
        let start_chunk = offset / CHUNK_SIZE as u64;
        let end_chunk = last_byte / CHUNK_SIZE as u64;
        let mut output = Vec::with_capacity(read_len as usize);

        for chunk_index in start_chunk..=end_chunk {
            let chunk = match self.load_chunk(entry, chunk_index) {
                Ok(chunk) => chunk,
                Err(error) => {
                    eprintln!(
                        "[Integrity] entry {} chunk {} failed: {}",
                        entry.id, chunk_index, error
                    );
                    reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
                    return;
                }
            };
            let chunk_start = chunk_index * CHUNK_SIZE as u64;
            let skip = offset.saturating_sub(chunk_start) as usize;
            if skip > chunk.len() {
                reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
                return;
            }
            let remaining = read_len.saturating_sub(output.len() as u64) as usize;
            let take = std::cmp::min(chunk.len() - skip, remaining);
            output.extend_from_slice(&chunk[skip..skip + take]);
        }
        if output.len() as u64 != read_len {
            reply.error(std::io::Error::from_raw_os_error(libc::EIO).into());
            return;
        }
        reply.data(&output);
        output.zeroize();
    }
}

fn entry_attr(entry: &Entry) -> FileAttr {
    let directory = entry.kind == EntryKind::Directory;
    FileAttr {
        ino: INodeNo(entry.id),
        size: entry.size,
        blocks: entry.size.div_ceil(512),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: if directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        },
        perm: if directory { 0o555 } else { 0o444 },
        nlink: if directory { 2 } else { 1 },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        flags: 0,
        blksize: 4096,
    }
}
