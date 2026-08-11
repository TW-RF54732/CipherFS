use anyhow::{Context, Result};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows::core::{HSTRING, PCWSTR, w};
use winfsp::winfsp_init;

pub(crate) fn initialize() -> Result<winfsp::FspInit> {
    if let Ok(init) = winfsp_init() {
        return Ok(init);
    }
    let install_dir = [w!("SOFTWARE\\WOW6432Node\\WinFsp"), w!("SOFTWARE\\WinFsp")]
        .into_iter()
        .find_map(read_install_dir)
        .context("WinFsp runtime is unavailable; install it from https://winfsp.dev/rel/")?;
    let dll = std::path::PathBuf::from(install_dir).join("bin/winfsp-x64.dll");
    let dll = HSTRING::from(dll.as_os_str());
    unsafe { LoadLibraryW(&dll) }.context("Unable to load the installed WinFsp runtime")?;
    winfsp_init().context("Unable to initialize the installed WinFsp runtime")
}

fn read_install_dir(key: PCWSTR) -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = [0u16; 512];
    let mut bytes = (buffer.len() * std::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            w!("InstallDir"),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if status.is_err() {
        return None;
    }
    let length = (bytes as usize / std::mem::size_of::<u16>()).saturating_sub(1);
    Some(std::ffi::OsString::from_wide(&buffer[..length]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_runner_starts_without_winfsp_runtime() {
        if std::env::var_os("CIPHERFS_EXPECT_WINFSP_MISSING").is_none() {
            return;
        }
        match initialize() {
            Ok(_) => panic!("WinFsp was already available before the pinned CI install step"),
            Err(error) => assert!(
                format!("{error:#}").contains("https://winfsp.dev/rel/"),
                "missing-runtime error did not include the official install URL: {error:#}"
            ),
        }
    }
}
