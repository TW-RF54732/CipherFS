use anyhow::{Context, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
use windows::core::PCWSTR;

/// Atomically renames `source` to `target` without replacing an existing
/// destination. Canonicalizing only the parents produces verbatim paths while
/// preserving the final component and its no-replace semantics.
pub fn rename_no_replace(source: &Path, target: &Path) -> Result<()> {
    let source = verbatim_child(source).context("Unable to resolve rename source")?;
    let target = verbatim_child(target).context("Unable to resolve rename destination")?;
    let source = wide_null(&source);
    let target = wide_null(&target);
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(target.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .context("Atomic no-replace rename failed")
}

fn verbatim_child(path: &Path) -> Result<PathBuf> {
    let absolute: PathBuf = std::path::absolute(path)?.components().collect();
    let parent = absolute
        .parent()
        .context("Rename path must have a parent directory")?;
    let name = absolute
        .file_name()
        .context("Rename path must have a final component")?;
    Ok(std::fs::canonicalize(parent)?.join(name))
}

fn wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_never_replaces_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&target, b"target").unwrap();
        assert!(rename_no_replace(&source, &target).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"source");
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
    }
}
