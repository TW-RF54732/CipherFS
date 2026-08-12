use anyhow::{Context, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_SIZE: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub version: u16,
    pub operation: WorkerOperation,
}

#[derive(Serialize, Deserialize)]
pub enum WorkerOperation {
    Pack {
        source: PathBuf,
        output: PathBuf,
        temporary: PathBuf,
        password: Secret,
        duress_password: Option<Secret>,
    },
    Extract {
        container: PathBuf,
        output: PathBuf,
        staging: PathBuf,
        password: Secret,
    },
    Verify {
        container: PathBuf,
        password: Secret,
    },
    Mount {
        container: PathBuf,
        password: Secret,
    },
    ChangePassword {
        container: PathBuf,
        old_password: Secret,
        new_password: Secret,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ParentCommand {
    Cancel,
    Unmount,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Scan,
    KeyDerivation,
    Encrypt,
    SelfVerify,
    Extract,
    Verify,
    Commit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactKind {
    PackContainer,
    ExtractionTree,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorKindDto {
    Cancelled,
    Authentication,
    Integrity,
    InvalidFormat,
    UnsafePath,
    DestinationExists,
    SourceChanged,
    Io,
    Internal,
    WorkerProtocol,
    WorkerCrashed,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerEvent {
    PhaseStarted(Phase),
    Progress {
        phase: Phase,
        completed: u64,
        total: u64,
    },
    Warning(String),
    TemporaryArtifact {
        kind: ArtifactKind,
        path: PathBuf,
    },
    CommitStarted,
    Committed,
    MutationStarted,
    Mounted {
        path: PathBuf,
    },
    Succeeded,
    Failed {
        kind: ErrorKindDto,
        message: String,
    },
}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let mut payload = Zeroizing::new(rmp_serde::to_vec_named(value)?);
    anyhow::ensure!(
        payload.len() <= MAX_FRAME_SIZE,
        "Worker protocol frame exceeds the size limit"
    );
    let length = u32::try_from(payload.len()).context("Worker frame length overflow")?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    payload.zeroize();
    Ok(())
}

pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<Option<T>> {
    let mut length = [0u8; 4];
    match reader.read(&mut length[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!(),
        Err(error) if error.kind() == ErrorKind::Interrupted => return read_frame(reader),
        Err(error) => return Err(error).context("Unable to read worker frame length"),
    }
    reader
        .read_exact(&mut length[1..])
        .context("Truncated worker frame length")?;
    let length = u32::from_le_bytes(length) as usize;
    anyhow::ensure!(
        length <= MAX_FRAME_SIZE,
        "Worker protocol frame is too large"
    );
    anyhow::ensure!(length > 0, "Worker protocol frame is empty");
    let payload = Zeroizing::new(vec![0u8; length]);
    let mut payload = payload;
    reader
        .read_exact(&mut payload)
        .context("Truncated worker protocol frame")?;
    let decoded = rmp_serde::from_slice(&payload).context("Malformed worker protocol frame")?;
    Ok(Some(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_does_not_need_command_line_secrets() {
        let request = WorkerRequest {
            version: PROTOCOL_VERSION,
            operation: WorkerOperation::Verify {
                container: PathBuf::from("vault.cfs"),
                password: Secret::new("not-on-command-line"),
            },
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();
        let decoded: WorkerRequest = read_frame(&mut bytes.as_slice()).unwrap().unwrap();
        match decoded.operation {
            WorkerOperation::Verify { password, .. } => {
                assert_eq!(password.expose(), "not-on-command-line")
            }
            _ => panic!("wrong operation"),
        }
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let bytes = ((MAX_FRAME_SIZE as u32) + 1).to_le_bytes();
        let error = read_frame::<_, ParentCommand>(&mut bytes.as_slice()).unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let mut bytes = 10u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[1, 2]);
        let error = read_frame::<_, ParentCommand>(&mut bytes.as_slice()).unwrap_err();
        assert!(error.to_string().contains("Truncated"));
    }
}
