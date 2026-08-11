use anyhow::{Context, Result};
use std::fs::File;
use std::io::Cursor;
use std::path::Path;

use crate::platform_io::PlatformFileExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    V1,
    V2,
}

pub const V1_MIGRATION_MESSAGE: &str = "CipherFS v1 is not supported by v2.2.0. Use v2.2.0-beta.1 or earlier to extract a trusted v1 container, then pack the extracted directory as v2. See README.md#legacy-v1-migration";

pub fn require_v2(path: &Path) -> Result<()> {
    match detect(path)? {
        Format::V2 => Ok(()),
        Format::V1 => anyhow::bail!(V1_MIGRATION_MESSAGE),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn legacy_container_is_detected_but_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("legacy.cfs");
        let header = crate::layout::Header {
            magic: crate::layout::MAGIC_BYTES,
            salt: [0; 16],
            argon2_params: crate::layout::Argon2Params::default(),
            master_nonce: [0; 32],
            dek_nonce: [0; 12],
            index_nonce: [0; 12],
            duress_hash: [0; 32],
            encrypted_dek: [0; 48],
            index_size: 0,
            max_index_size: 0,
        };
        let encoded = rmp_serde::to_vec(&header).unwrap();
        let mut bytes = vec![0u8; crate::layout::HEADER_SIZE];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        assert_eq!(detect(&path).unwrap(), Format::V1);
        assert_eq!(
            require_v2(&path).unwrap_err().to_string(),
            V1_MIGRATION_MESSAGE
        );
    }
}
