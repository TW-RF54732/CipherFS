use std::fs::File;
use std::io;

pub trait PlatformFileExt {
    fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()>;
    fn write_all_at(&self, buffer: &[u8], offset: u64) -> io::Result<()>;
}

impl PlatformFileExt for File {
    fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        read_exact_at(self, buffer, offset)
    }

    fn write_all_at(&self, buffer: &[u8], offset: u64) -> io::Result<()> {
        write_all_at(self, buffer, offset)
    }
}

fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buffer.is_empty() {
        let count = read_at(file, buffer, offset)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ));
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("file offset overflow"))?;
        buffer = &mut buffer[count..];
    }
    Ok(())
}

fn write_all_at(file: &File, mut buffer: &[u8], mut offset: u64) -> io::Result<()> {
    while !buffer.is_empty() {
        let count = write_at(file, buffer, offset)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("file offset overflow"))?;
        buffer = &buffer[count..];
    }
    Ok(())
}

#[cfg(unix)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, offset)
}

#[cfg(unix)]
fn write_at(file: &File, buffer: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.write_at(buffer, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset)
}

#[cfg(windows)]
fn write_at(file: &File, buffer: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_write(buffer, offset)
}
