use fuser::{
    FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use crate::readonly_fs::{FsError, FsErrorKind, Node, NodeKind, ReadOnlyFs};

const TTL: Duration = Duration::from_secs(1);
pub struct CipherFS(ReadOnlyFs);

impl CipherFS {
    pub fn new(path: &Path, password: &str, cache_mib: u64) -> anyhow::Result<Self> {
        Ok(Self(ReadOnlyFs::open(path, password, cache_mib)?))
    }
}

impl Filesystem for CipherFS {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let _ = req;
        let Some(name) = name.to_str() else {
            reply.error(std::io::Error::from_raw_os_error(libc::ENOENT).into());
            return;
        };
        match self.0.lookup(parent.into(), name) {
            Ok(node) => reply.entry(&TTL, &node_attr(&node), Generation(0)),
            Err(error) => reply.error(fuse_error(&error).into()),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let _ = (req, fh);
        match self.0.metadata(ino.into()) {
            Ok(node) => reply.attr(&TTL, &node_attr(&node)),
            Err(error) => reply.error(fuse_error(&error).into()),
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
        let _ = (req, fh);
        let node = match self.0.metadata(ino.into()) {
            Ok(node) => node,
            Err(error) => {
                reply.error(fuse_error(&error).into());
                return;
            }
        };
        let children = match self.0.read_dir(ino.into()) {
            Ok(children) => children,
            Err(error) => {
                reply.error(fuse_error(&error).into());
                return;
            }
        };
        let mut listing = vec![
            (node.id, ".".to_string(), FileType::Directory),
            (node.parent_id, "..".to_string(), FileType::Directory),
        ];
        listing.extend(children.into_iter().map(|child| {
            let kind = if child.kind == NodeKind::File {
                FileType::RegularFile
            } else {
                FileType::Directory
            };
            (child.id, child.name, kind)
        }));
        for (position, (id, name, kind)) in listing.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(id), (position + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
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
        let _ = (req, fh, flags, lock_owner);
        match self.0.read(ino.into(), offset, size) {
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

fn node_attr(entry: &Node) -> FileAttr {
    let directory = entry.kind == NodeKind::Directory;
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
