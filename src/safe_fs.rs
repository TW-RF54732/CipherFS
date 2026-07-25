use anyhow::{Context, Result};
use rand::Rng;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use crate::v2::validate_name;

pub struct SafeRoot {
    root: OwnedFd,
    directories: HashMap<u64, OwnedFd>,
}

pub struct PendingFile {
    parent_fd: RawFd,
    temp_name: CString,
    final_name: CString,
    file: Option<File>,
    committed: bool,
}

impl SafeRoot {
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path)?;
        let c_path = cstring_path(path)?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("Unable to open output root {}", path.display()));
        }
        let root = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            root,
            directories: HashMap::new(),
        })
    }

    pub fn install_root_id(&mut self, id: u64) -> Result<()> {
        let fd = dup_fd(self.root.as_raw_fd())?;
        self.directories.insert(id, fd);
        Ok(())
    }

    pub fn create_directory(&mut self, id: u64, parent_id: u64, name: &str) -> Result<()> {
        validate_name(name)?;
        let parent = self
            .directories
            .get(&parent_id)
            .context("Parent directory has not been created")?;
        let name = CString::new(name.as_bytes()).context("Filename contains NUL")?;
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error).context("Unable to create output directory");
            }
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Output directory is not a safe real directory");
        }
        self.directories
            .insert(id, unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(())
    }

    pub fn begin_file(
        &self,
        parent_id: u64,
        final_name: &str,
        entry_id: u64,
    ) -> Result<PendingFile> {
        validate_name(final_name)?;
        let parent = self
            .directories
            .get(&parent_id)
            .context("Parent directory has not been created")?;
        let final_name = CString::new(final_name.as_bytes()).context("Filename contains NUL")?;
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let temp = format!(".cipherfs-{entry_id}-{}.tmp", hex::encode(random));
        let temp_name = CString::new(temp).expect("generated temporary name contains no NUL");
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temp_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Unable to create temporary output file");
        }
        Ok(PendingFile {
            parent_fd: parent.as_raw_fd(),
            temp_name,
            final_name,
            file: Some(unsafe { File::from_raw_fd(fd) }),
            committed: false,
        })
    }
}

impl PendingFile {
    pub fn writer(&mut self) -> Result<&mut File> {
        self.file
            .as_mut()
            .context("Temporary file is already closed")
    }

    pub fn finish_writing(&mut self) -> Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            file.sync_all()?;
            drop(file);
        }
        Ok(())
    }

    pub fn commit(mut self) -> Result<()> {
        self.finish_writing()?;
        let result = unsafe {
            libc::renameat(
                self.parent_fd,
                self.temp_name.as_ptr(),
                self.parent_fd,
                self.final_name.as_ptr(),
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Unable to atomically install extracted file");
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            unsafe {
                libc::unlinkat(self.parent_fd, self.temp_name.as_ptr(), 0);
            }
        }
    }
}

fn dup_fd(fd: RawFd) -> Result<OwnedFd> {
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("Unable to duplicate directory fd");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

fn cstring_path(path: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).context("Path contains NUL")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn refuses_existing_symlink_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root_path).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root_path.join("linked")).unwrap();
        let mut root = SafeRoot::open(&root_path).unwrap();
        root.install_root_id(1).unwrap();
        assert!(root.create_directory(2, 1, "linked").is_err());
    }
}
