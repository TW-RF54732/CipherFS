use anyhow::Result;
use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use crate::format::{Format, detect as detect_format};
use crate::legacy_mount::LegacyCipherFS;
use crate::readonly_fs::{FsError, FsErrorKind, ReadOnlyV2Fs};
use crate::v2::{Entry, EntryKind};

const TTL: Duration = Duration::from_secs(1);
pub enum CipherFS {
    Legacy(LegacyCipherFS),
    V2(Box<ReadOnlyV2Fs>),
}

impl CipherFS {
    pub fn new(path: &Path, password: &str, cache_mib: u64) -> Result<Self> {
        match detect_format(path)? {
            Format::V2 => Ok(Self::V2(Box::new(ReadOnlyV2Fs::new(
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

impl Filesystem for CipherFS {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        match self {
            Self::Legacy(fs) => fs.lookup(req, parent, name, reply),
            Self::V2(fs) => Filesystem::lookup(fs.as_ref(), req, parent, name, reply),
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
            Self::V2(fs) => Filesystem::read(
                fs.as_ref(),
                req,
                ino,
                fh,
                offset,
                size,
                flags,
                lock_owner,
                reply,
            ),
        }
    }
}

impl Filesystem for ReadOnlyV2Fs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let Some(name) = name.to_str() else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
            return;
        };
        match self.lookup(parent.into(), name) {
            Ok(entry) => reply.entry(&TTL, &entry_attr(entry), Generation(0)),
            Err(error) => reply.error(fuse_error(&error).into()),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.metadata(ino.into()) {
            Ok(entry) => reply.attr(&TTL, &entry_attr(entry)),
            Err(error) => reply.error(fuse_error(&error).into()),
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
        let entry = match self.metadata(ino.into()) {
            Ok(entry) => entry,
            Err(error) => {
                reply.error(fuse_error(&error).into());
                return;
            }
        };
        let children = match self.read_dir(ino.into()) {
            Ok(children) => children,
            Err(error) => {
                reply.error(fuse_error(&error).into());
                return;
            }
        };
        let mut listing: Vec<(u64, &str, FileType)> = vec![
            (entry.id, ".", FileType::Directory),
            (entry.parent_id, "..", FileType::Directory),
        ];
        for child in children {
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
        match self.read(ino.into(), offset, size) {
            Ok(output) => reply.data(&output),
            Err(error) => {
                if error.kind() == FsErrorKind::Integrity {
                    eprintln!("[Integrity] {error}");
                }
                reply.error(fuse_error(&error).into());
            }
        }
    }
}

fn fuse_error(error: &FsError) -> std::io::Error {
    let code = match error.kind() {
        FsErrorKind::NotFound => libc::ENOENT,
        FsErrorKind::NotDirectory => libc::ENOTDIR,
        FsErrorKind::IsDirectory => libc::EISDIR,
        FsErrorKind::Integrity => libc::EIO,
    };
    std::io::Error::from_raw_os_error(code)
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
