use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(crate) struct PreparedDirectoryMountpoint {
    original_path: PathBuf,
    pub(crate) mount_path: PathBuf,
    _ancestor_guards: Vec<std::fs::File>,
}

impl Drop for PreparedDirectoryMountpoint {
    fn drop(&mut self) {
        let _ = std::fs::create_dir(&self.original_path);
    }
}

pub(crate) fn prepare(path: &Path) -> Result<Option<PreparedDirectoryMountpoint>> {
    if path.to_string_lossy().eq_ignore_ascii_case("auto") || is_drive_letter(path) {
        return Ok(None);
    }
    let absolute: PathBuf = std::path::absolute(path)?.components().collect();
    let parent = absolute
        .parent()
        .context("WinFsp mount directory must have a parent")?;
    let ancestor_guards = open_ancestor_guards(parent)?;
    match std::fs::create_dir(&absolute) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("Unable to create WinFsp mount directory"),
    }
    let metadata = std::fs::symlink_metadata(&absolute)?;
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!("WinFsp mount directory cannot be a reparse point");
    }
    if std::fs::read_dir(&absolute)?.next().is_some() {
        anyhow::bail!("WinFsp mount directory must be empty");
    }
    std::fs::remove_dir(&absolute).context("Unable to prepare the empty WinFsp mount directory")?;
    Ok(Some(PreparedDirectoryMountpoint {
        original_path: absolute.clone(),
        mount_path: absolute,
        _ancestor_guards: ancestor_guards,
    }))
}

fn open_ancestor_guards(path: &Path) -> Result<Vec<std::fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    let absolute: PathBuf = std::path::absolute(path)?.components().collect();
    let mut current = PathBuf::new();
    let mut guards = Vec::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            continue;
        }
        let file = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)
            .with_context(|| {
                format!("WinFsp mount parent does not exist: {}", current.display())
            })?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!(
                "WinFsp mount path cannot traverse a reparse point: {}",
                current.display()
            );
        }
        guards.push(file);
    }
    Ok(guards)
}

fn is_drive_letter(path: &Path) -> bool {
    let text = path.as_os_str().to_string_lossy();
    let bytes = text.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}
