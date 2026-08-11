use anyhow::{Context, Result};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use rand::Rng;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use crate::v2::validate_name;

pub struct SafeRoot {
    directories: HashMap<u64, Dir>,
}

pub struct PendingFile {
    parent: Dir,
    temp_name: OsString,
    final_name: OsString,
    file: Option<File>,
    committed: bool,
}

impl SafeRoot {
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path)?;
        reject_link_or_reparse(path)?;
        let root = Dir::open_ambient_dir(path, ambient_authority())
            .with_context(|| format!("Unable to open output root {}", path.display()))?;
        let mut directories = HashMap::new();
        directories.insert(1, root);
        Ok(Self { directories })
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
        match parent.create_dir(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("Unable to create output directory"),
        }
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
            anyhow::bail!("Refusing to overwrite existing output entry {final_name}");
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
            .context("Unable to atomically install extracted file")?;
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

fn reject_link_or_reparse(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("Output root cannot be a symbolic link");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("Output root cannot be a Windows reparse point");
        }
    }
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

    #[cfg(unix)]
    #[test]
    fn refuses_existing_symlink_directory() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root_path).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root_path.join("linked")).unwrap();
        let mut root = SafeRoot::open(&root_path).unwrap();
        assert!(root.create_directory(2, 1, "linked").is_err());
    }

    #[test]
    fn refuses_to_overwrite_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("exists.txt"), b"existing").unwrap();
        let root = SafeRoot::open(temp.path()).unwrap();
        assert!(root.begin_file(1, "exists.txt", 2).is_err());
    }
}
