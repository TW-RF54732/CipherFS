use anyhow::{Context, Result};
use cap_std::fs::{Dir, File, OpenOptions};
use rand::Rng;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use crate::v2::validate_name;

/// A capability-scoped extraction tree. Files are built below a private sibling
/// directory and the whole tree is installed at one commit point.
pub struct SafeRoot {
    directories: HashMap<u64, Dir>,
    parent: Dir,
    staging_name: OsString,
    target_name: OsString,
    target_display: PathBuf,
    committed: bool,
}

pub struct PendingFile {
    parent: Dir,
    temp_name: OsString,
    final_name: OsString,
    file: Option<File>,
    committed: bool,
}

impl SafeRoot {
    pub fn open_new(target: &Path) -> Result<Self> {
        if fs::symlink_metadata(target).is_ok() {
            anyhow::bail!(
                "Extraction destination already exists; choose a path that does not exist: {}",
                target.display()
            );
        }
        let absolute: PathBuf = std::path::absolute(target)?.components().collect();
        let parent_path = absolute
            .parent()
            .context("Extraction destination must have a parent directory")?;
        let target_name = absolute
            .file_name()
            .context("Extraction destination must name a directory")?;
        let parent = open_verified_directory(parent_path).with_context(|| {
            format!(
                "Unable to safely open output parent {}",
                parent_path.display()
            )
        })?;
        if parent.symlink_metadata(target_name).is_ok() {
            anyhow::bail!("Extraction destination was created concurrently");
        }

        let staging_name = allocate_staging_name(&parent, target_name)?;
        parent
            .create_dir(&staging_name)
            .context("Unable to create extraction staging directory")?;
        let root = parent
            .open_dir(&staging_name)
            .context("Unable to open extraction staging directory")?;
        let mut directories = HashMap::new();
        directories.insert(1, root);
        Ok(Self {
            directories,
            parent,
            staging_name,
            target_name: target_name.to_os_string(),
            target_display: absolute,
            committed: false,
        })
    }

    pub fn install_root_id(&mut self, id: u64) -> Result<()> {
        let root = self
            .directories
            .get(&1)
            .context("Output root is not open")?
            .try_clone()?;
        self.directories.insert(id, root);
        Ok(())
    }

    pub fn create_directory(&mut self, id: u64, parent_id: u64, name: &str) -> Result<()> {
        validate_output_name(name)?;
        let parent = self
            .directories
            .get(&parent_id)
            .context("Parent directory has not been created")?;
        parent
            .create_dir(name)
            .context("Unable to create output directory")?;
        let metadata = parent.symlink_metadata(name)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!("Output directory is not a safe real directory");
        }
        let child = parent
            .open_dir(name)
            .context("Unable to open output directory without escaping output root")?;
        self.directories.insert(id, child);
        Ok(())
    }

    pub fn begin_file(
        &self,
        parent_id: u64,
        final_name: &str,
        entry_id: u64,
    ) -> Result<PendingFile> {
        validate_output_name(final_name)?;
        let parent = self
            .directories
            .get(&parent_id)
            .context("Parent directory has not been created")?;
        if parent.symlink_metadata(final_name).is_ok() {
            anyhow::bail!("Duplicate output entry {final_name}");
        }
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let temp_name = OsString::from(format!(".cipherfs-{entry_id}-{}.tmp", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let file = parent
            .open_with(&temp_name, &options)
            .context("Unable to create temporary output file")?;
        Ok(PendingFile {
            parent: parent.try_clone()?,
            temp_name,
            final_name: OsString::from(final_name),
            file: Some(file),
            committed: false,
        })
    }

    pub fn commit(mut self) -> Result<()> {
        sync_open_directories(&self.directories)?;
        self.directories.clear();
        rename_directory_no_replace(
            &self.parent,
            &self.staging_name,
            &self.target_name,
            &self.target_display,
        )
        .with_context(|| format!("Unable to install {}", self.target_display.display()))?;
        self.committed = true;
        if let Err(error) = sync_cap_directory(&self.parent) {
            eprintln!("[Warning] Unable to sync extraction parent after commit: {error:#}");
        }
        Ok(())
    }
}

impl Drop for SafeRoot {
    fn drop(&mut self) {
        if !self.committed {
            self.directories.clear();
            let _ = self.parent.remove_dir_all(&self.staging_name);
        }
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
        }
        Ok(())
    }

    pub fn commit(mut self) -> Result<()> {
        self.finish_writing()?;
        self.parent
            .rename(&self.temp_name, &self.parent, &self.final_name)
            .context("Unable to install staged extracted file")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = self.parent.remove_file(&self.temp_name);
        }
    }
}

fn allocate_staging_name(parent: &Dir, target_name: &OsStr) -> Result<OsString> {
    let prefix = target_name.to_string_lossy();
    for _ in 0..32 {
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let candidate = OsString::from(format!(".{prefix}.cipherfs-stage-{}", hex::encode(random)));
        if parent.symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("Unable to allocate an extraction staging directory")
}

#[cfg(unix)]
fn open_verified_directory(path: &Path) -> Result<Dir> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let mut current = fs::File::open("/")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = std::ffi::CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context(
                "Output parent contains a missing, non-directory, or symbolic-link component",
            );
        }
        current = unsafe { fs::File::from_raw_fd(fd) };
    }
    Ok(Dir::from_std_file(current))
}

#[cfg(windows)]
fn open_verified_directory(path: &Path) -> Result<Dir> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;

    let mut current_path = PathBuf::new();
    let mut opened = Vec::new();
    for component in path.components() {
        current_path.push(component.as_os_str());
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            continue;
        }
        let file = fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current_path)
            .with_context(|| {
                format!("Unable to open output ancestor {}", current_path.display())
            })?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!(
                "Output path cannot traverse a link or reparse point: {}",
                current_path.display()
            );
        }
        opened.push(file);
    }
    let parent = opened.pop().context("Output path has no directory root")?;
    Ok(Dir::from_std_file(parent))
}

#[cfg(unix)]
fn rename_directory_no_replace(
    parent: &Dir,
    source: &OsStr,
    target: &OsStr,
    _target_display: &Path,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(source.as_bytes())?;
    let target = std::ffi::CString::new(target.as_bytes())?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } as libc::c_int;
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(windows)]
fn rename_directory_no_replace(
    _parent: &Dir,
    source: &OsStr,
    _target: &OsStr,
    target_display: &Path,
) -> Result<()> {
    let source_display = target_display.with_file_name(source);
    crate::windows_fs::rename_no_replace(&source_display, target_display)
}

#[cfg(unix)]
fn sync_cap_directory(directory: &Dir) -> Result<()> {
    directory.open(".")?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_open_directories(directories: &HashMap<u64, Dir>) -> Result<()> {
    for directory in directories.values() {
        sync_cap_directory(directory)?;
    }
    Ok(())
}

#[cfg(windows)]
fn sync_cap_directory(_directory: &Dir) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn sync_open_directories(_directories: &HashMap<u64, Dir>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_output_name(name: &str) -> Result<()> {
    validate_name(name)
}

#[cfg(windows)]
fn validate_output_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        anyhow::bail!("Invalid Windows output name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_must_not_exist() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("output");
        fs::create_dir(&target).unwrap();
        assert!(SafeRoot::open_new(&target).is_err());
    }

    #[test]
    fn commits_whole_tree_once() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("output");
        let root = SafeRoot::open_new(&target).unwrap();
        let mut file = root.begin_file(1, "file.txt", 2).unwrap();
        file.writer().unwrap().write_all(b"verified").unwrap();
        file.commit().unwrap();
        assert!(!target.exists());
        root.commit().unwrap();
        assert_eq!(fs::read(target.join("file.txt")).unwrap(), b"verified");
    }

    #[test]
    fn concurrent_destination_creation_wins_without_partial_commit() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("output");
        let root = SafeRoot::open_new(&target).unwrap();
        let mut file = root.begin_file(1, "file.txt", 2).unwrap();
        file.writer().unwrap().write_all(b"staged").unwrap();
        file.commit().unwrap();

        fs::create_dir(&target).unwrap();
        fs::write(target.join("winner.txt"), b"winner").unwrap();
        assert!(root.commit().is_err());
        assert_eq!(fs::read(target.join("winner.txt")).unwrap(), b"winner");
        assert!(!target.join("file.txt").exists());
        assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("cipherfs-stage")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_in_output_ancestors() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let linked = temp.path().join("linked");
        symlink(&outside, &linked).unwrap();
        assert!(SafeRoot::open_new(&linked.join("output")).is_err());
        assert!(!outside.join("output").exists());
    }

    #[cfg(windows)]
    #[test]
    fn refuses_junction_in_output_ancestors() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let junction = temp.path().join("junction");
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                junction.to_str().unwrap(),
                outside.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(SafeRoot::open_new(&junction.join("output")).is_err());
        assert!(!outside.join("output").exists());
    }
}
