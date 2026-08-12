//! Windows-owned file dialogs and shell launching. CipherFS-owned presentation lives in Slint.

use crate::controller::DialogOutcome;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::Dialogs::{
    CDN_INITDONE, CommDlgExtendedError, GetSaveFileNameW, OFN_ENABLEHOOK, OFN_EXPLORER,
    OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OFNOTIFYW, OPENFILENAMEW,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    GetParent, IDCANCEL, PostMessageW, SW_SHOWNORMAL, WM_COMMAND, WM_INITDIALOG, WM_NOTIFY,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use zeroize::Zeroize;

static SMOKE_DIALOG_CLOSED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
unsafe extern "system" fn close_smoke_dialog_hook(
    hook_window: HWND,
    message: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> usize {
    let initialized = message == WM_INITDIALOG
        || (message == WM_NOTIFY
            && lparam.0 != 0
            && unsafe { (*(lparam.0 as *const OFNOTIFYW)).hdr.code == CDN_INITDONE });
    if initialized
        && let Ok(dialog) = unsafe { GetParent(hook_window) }
        && unsafe {
            PostMessageW(
                Some(dialog),
                WM_COMMAND,
                WPARAM(IDCANCEL.0 as usize),
                LPARAM(0),
            )
        }
        .is_ok()
    {
        SMOKE_DIALOG_CLOSED.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    0
}

pub(crate) fn choose_pack_output(owner: HWND, default: &Path) -> Result<DialogOutcome<PathBuf>> {
    run_save_dialog(
        owner,
        default,
        "CipherFS containers (*.cfs)\0*.cfs\0\0",
        "Create CipherFS container",
        Some("cfs"),
        false,
    )
}

pub(crate) fn smoke_pack_output(owner: HWND, default: &Path) -> Result<DialogOutcome<PathBuf>> {
    run_save_dialog(
        owner,
        default,
        "CipherFS containers (*.cfs)\0*.cfs\0\0",
        "Create CipherFS container",
        Some("cfs"),
        true,
    )
}

pub(crate) fn choose_extract_destination(
    owner: HWND,
    default_name: &str,
) -> Result<DialogOutcome<PathBuf>> {
    run_save_dialog(
        owner,
        Path::new(default_name),
        "Extraction folders\0*\0\0",
        "Choose a new extraction folder",
        None,
        false,
    )
}

pub(crate) fn smoke_extract_destination(
    owner: HWND,
    default_name: &str,
) -> Result<DialogOutcome<PathBuf>> {
    run_save_dialog(
        owner,
        Path::new(default_name),
        "Extraction folders\0*\0\0",
        "Choose a new extraction folder",
        None,
        true,
    )
}

fn run_save_dialog(
    owner: HWND,
    default: &Path,
    filter: &str,
    title: &str,
    extension: Option<&str>,
    auto_cancel: bool,
) -> Result<DialogOutcome<PathBuf>> {
    let mut path: Vec<u16> = default
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain([0])
        .collect();
    path.resize(32_768, 0);
    let filter: Vec<u16> = filter.encode_utf16().collect();
    let title = HSTRING::from(title);
    let extension = extension.map(HSTRING::from);

    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: PCWSTR::from_raw(filter.as_ptr()),
        lpstrFile: PWSTR(path.as_mut_ptr()),
        nMaxFile: path.len() as u32,
        lpstrTitle: PCWSTR::from_raw(title.as_ptr()),
        lpstrDefExt: extension
            .as_ref()
            .map_or(PCWSTR::null(), |value| PCWSTR::from_raw(value.as_ptr())),
        Flags: OFN_PATHMUSTEXIST
            | OFN_NOCHANGEDIR
            | OFN_EXPLORER
            | if auto_cancel {
                OFN_ENABLEHOOK
            } else {
                Default::default()
            },
        lpfnHook: if auto_cancel {
            Some(close_smoke_dialog_hook)
        } else {
            None
        },
        ..Default::default()
    };

    SMOKE_DIALOG_CLOSED.store(false, std::sync::atomic::Ordering::SeqCst);

    if !unsafe { GetSaveFileNameW(&mut dialog) }.as_bool() {
        path.zeroize();
        let extended_error = unsafe { CommDlgExtendedError() };
        anyhow::ensure!(
            extended_error.0 == 0,
            "GetSaveFileNameW failed with common-dialog error {:#010X}",
            extended_error.0
        );
        if auto_cancel {
            anyhow::ensure!(
                SMOKE_DIALOG_CLOSED.load(std::sync::atomic::Ordering::SeqCst),
                "Native save dialog did not initialize its window"
            );
        }
        return Ok(DialogOutcome::Cancelled);
    }
    if auto_cancel {
        anyhow::bail!("Native dialog smoke unexpectedly returned a selected path");
    }

    let length = path
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(path.len());
    let selected = PathBuf::from(
        String::from_utf16(&path[..length]).context("Selected path is not valid UTF-16")?,
    );
    path.zeroize();
    Ok(DialogOutcome::Selected(selected))
}

pub(crate) fn open_explorer(path: &Path) -> Result<()> {
    shell_open(&path.display().to_string())
}

pub(crate) fn open_url(url: &str) -> Result<()> {
    shell_open(url)
}

fn shell_open(target: &str) -> Result<()> {
    let target = HSTRING::from(target);
    let result = unsafe { ShellExecuteW(None, None, &target, None, None, SW_SHOWNORMAL) };
    anyhow::ensure!(
        result.0 as isize > 32,
        "Windows could not open the requested target"
    );
    Ok(())
}
