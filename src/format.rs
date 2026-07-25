use anyhow::{Context, Result};
use std::fs::File;
use std::io::Cursor;
use std::os::unix::fs::FileExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    V1,
    V2,
}

pub fn detect(path: &Path) -> Result<Format> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();

    if file_len >= crate::v2::HEADER_SIZE as u64 {
        let mut encoded = [0u8; crate::v2::HEADER_SIZE];
        file.read_exact_at(&mut encoded, 0)
            .context("Unable to read container header")?;
        if let Ok(header) = rmp_serde::from_read::<_, crate::v2::Header>(Cursor::new(encoded))
            && header.magic == crate::v2::MAGIC
        {
            return Ok(Format::V2);
        }
    }

    if file_len >= crate::layout::HEADER_SIZE as u64 {
        let mut encoded = [0u8; crate::layout::HEADER_SIZE];
        file.read_exact_at(&mut encoded, 0)
            .context("Unable to read legacy container header")?;
        if let Ok(header) = rmp_serde::from_read::<_, crate::layout::Header>(Cursor::new(encoded))
            && header.magic == crate::layout::MAGIC_BYTES
        {
            return Ok(Format::V1);
        }
    }

    anyhow::bail!("Not a supported CipherFS container")
}
