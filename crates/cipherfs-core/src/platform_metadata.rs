use std::fs::{File, Metadata};
use std::io;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFingerprint {
    len: u64,
    modified: SystemTime,
    identity: Option<(u64, u64)>,
}

impl FileFingerprint {
    pub fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified()?,
            identity: identity(file, &metadata)?,
        })
    }
}

#[cfg(unix)]
fn identity(_file: &File, metadata: &Metadata) -> io::Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    Ok(Some((metadata.dev(), metadata.ino())))
}

#[cfg(windows)]
fn identity(file: &File, _metadata: &Metadata) -> io::Result<Option<(u64, u64)>> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(|_| io::Error::last_os_error())?;
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok(Some((
        u64::from(information.dwVolumeSerialNumber),
        file_index,
    )))
}
