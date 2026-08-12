//! Native Win32 dialogs and Explorer launching. No operation or container logic.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::Security::Credentials::{
    CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
    CREDUI_FLAGS_PASSWORD_ONLY_OK, CREDUI_INFOW, CredUIPromptForCredentialsW,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoTaskMemFree, CoUninitialize,
};
use windows::Win32::UI::Controls::Dialogs::{
    GetSaveFileNameW, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TDF_ALLOW_DIALOG_CANCELLATION, TaskDialogIndirect,
};
use windows::Win32::UI::Shell::{
    FOS_DONTADDTORECENT, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_PATHMUSTEXIST,
    FileSaveDialog, IFileDialog, IFileSaveDialog, IModalWindow, SIGDN_FILESYSPATH, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW, SW_SHOWNORMAL};
use windows::core::{HRESULT, HSTRING, Interface, PCWSTR, PWSTR};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn choose_pack_output(default: &Path) -> Result<Option<PathBuf>> {
    let mut path: Vec<u16> = default
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    path.resize(32_768, 0);
    let filter: Vec<u16> = "CipherFS containers (*.cfs)\0*.cfs\0\0"
        .encode_utf16()
        .collect();
    let title = HSTRING::from("Create CipherFS container");
    let extension = HSTRING::from("cfs");
    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        lpstrFilter: PCWSTR::from_raw(filter.as_ptr()),
        lpstrFile: PWSTR(path.as_mut_ptr()),
        nMaxFile: path.len() as u32,
        lpstrTitle: PCWSTR::from_raw(title.as_ptr()),
        lpstrDefExt: PCWSTR::from_raw(extension.as_ptr()),
        Flags: OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    if !unsafe { GetSaveFileNameW(&mut dialog) }.as_bool() {
        path.zeroize();
        return Ok(None);
    }
    let length = path
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(path.len());
    let selected = PathBuf::from(
        String::from_utf16(&path[..length]).context("Selected path is not valid UTF-16")?,
    );
    path.zeroize();
    Ok(Some(selected))
}

struct ComApartment;

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

pub(crate) fn choose_extract_destination(default_name: &str) -> Result<Option<PathBuf>> {
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
        .ok()
        .context("Unable to initialize the Windows file dialog")?;
    let _apartment = ComApartment;
    let dialog: IFileSaveDialog =
        unsafe { CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER) }
            .context("Unable to create the extraction destination dialog")?;
    let file_dialog: IFileDialog = dialog.cast()?;
    unsafe {
        file_dialog.SetTitle(&HSTRING::from("Choose a new extraction folder"))?;
        file_dialog.SetFileName(&HSTRING::from(default_name))?;
        file_dialog.SetFileNameLabel(&HSTRING::from("New folder name:"))?;
        file_dialog.SetOptions(
            FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN | FOS_DONTADDTORECENT,
        )?;
    }
    let modal: IModalWindow = dialog.cast()?;
    if let Err(error) = unsafe { modal.Show(None) } {
        if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            return Ok(None);
        }
        return Err(error).context("Unable to select the extraction destination");
    }
    let item = unsafe { file_dialog.GetResult() }?;
    let display = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }?;
    let selected =
        unsafe { display.to_string() }.context("Selected extraction path is not valid UTF-16")?;
    unsafe { CoTaskMemFree(Some(display.0.cast())) };
    Ok(Some(PathBuf::from(selected)))
}

pub(crate) fn prompt_password(caption: &str) -> Result<Option<Zeroizing<String>>> {
    let caption = HSTRING::from(caption);
    let message = HSTRING::from(
        "CipherFS uses this value only for the current operation and never stores it.",
    );
    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: HWND::default(),
        pszMessageText: PCWSTR::from_raw(message.as_ptr()),
        pszCaptionText: PCWSTR::from_raw(caption.as_ptr()),
        hbmBanner: HBITMAP::default(),
    };
    let target = HSTRING::from("CipherFS container password");
    let mut username = [0u16; 514];
    let mut password = [0u16; 512];
    let status = unsafe {
        CredUIPromptForCredentialsW(
            Some(&info),
            &target,
            None,
            0,
            &mut username,
            &mut password,
            None,
            CREDUI_FLAGS_GENERIC_CREDENTIALS
                | CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_PASSWORD_ONLY_OK,
        )
    };
    if status == ERROR_CANCELLED {
        username.zeroize();
        password.zeroize();
        return Ok(None);
    }
    if let Err(error) = status.ok() {
        username.zeroize();
        password.zeroize();
        return Err(error).context("Unable to show password dialog");
    }
    let length = password
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(password.len());
    let decoded = String::from_utf16(&password[..length]);
    username.zeroize();
    password.zeroize();
    Ok(Some(Zeroizing::new(
        decoded.context("Password is not valid UTF-16")?,
    )))
}

pub(crate) fn choose(
    title: &str,
    instruction: &str,
    content: &str,
    buttons: &[(i32, &str)],
) -> Result<i32> {
    let title = HSTRING::from(title);
    let instruction = HSTRING::from(instruction);
    let content = HSTRING::from(content);
    let labels: Vec<HSTRING> = buttons
        .iter()
        .map(|(_, label)| HSTRING::from(*label))
        .collect();
    let task_buttons: Vec<TASKDIALOG_BUTTON> = buttons
        .iter()
        .zip(&labels)
        .map(|((id, _), label)| TASKDIALOG_BUTTON {
            nButtonID: *id,
            pszButtonText: PCWSTR::from_raw(label.as_ptr()),
        })
        .collect();
    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: HWND::default(),
        hInstance: Default::default(),
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION,
        dwCommonButtons: Default::default(),
        pszWindowTitle: PCWSTR::from_raw(title.as_ptr()),
        Anonymous1: Default::default(),
        pszMainInstruction: PCWSTR::from_raw(instruction.as_ptr()),
        pszContent: PCWSTR::from_raw(content.as_ptr()),
        cButtons: task_buttons.len() as u32,
        pButtons: task_buttons.as_ptr(),
        nDefaultButton: buttons.first().map(|button| button.0).unwrap_or(0),
        ..Default::default()
    };
    let mut selected = 0;
    unsafe { TaskDialogIndirect(&config, Some(&mut selected), None, None) }?;
    Ok(selected)
}

pub(crate) fn info(title: &str, text: &str) -> Result<()> {
    let _ = choose(title, text, "", &[(1, "OK")])?;
    Ok(())
}

pub(crate) fn show_error(text: &str) {
    let title = HSTRING::from("CipherFS error");
    let text = HSTRING::from(text);
    unsafe { MessageBoxW(None, &text, &title, MB_OK | MB_ICONERROR) };
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
    if result.0 as isize <= 32 {
        anyhow::bail!("Windows could not open the requested target")
    }
    Ok(())
}
