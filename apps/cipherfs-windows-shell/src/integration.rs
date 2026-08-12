//! Per-user Explorer registration and the existing managed update path.
//! Replacement locking/transaction hardening remains intentionally deferred.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW,
    RegSetKeyValueW,
};
use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
use windows::core::{HSTRING, PCWSTR};
use zeroize::Zeroize;

const INSTALL_SUBDIR: &str = "Programs\\CipherFS";
const PROG_ID: &str = "CipherFS.Container";
const CONTEXT_KEY: &str = "Software\\Classes\\Directory\\shell\\CipherFSPack";

pub fn install() -> Result<()> {
    let root = install_root()?;
    std::fs::create_dir_all(&root)?;
    let current = std::env::current_exe()?;
    let source_dir = current
        .parent()
        .context("CipherFS shell has no parent directory")?;
    let cli_source = source_dir.join("cipherfs.exe");
    anyhow::ensure!(
        cli_source.is_file(),
        "cipherfs.exe must be next to cipherfs-shell.exe for installation"
    );
    let shell_target = root.join("cipherfs-shell.exe");
    let cli_target = root.join("cipherfs.exe");
    copy_replace(&cli_source, &cli_target)?;
    copy_replace(&current, &shell_target)?;
    register_shell(&shell_target)?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let root = install_root()?;
    unregister_shell(&root.join("cipherfs-shell.exe"));
    let current = std::env::current_exe()?;
    let cli = root.join("cipherfs.exe");
    if current.parent() == Some(root.as_path()) {
        let _ = std::fs::remove_file(&cli);
        self_replace::self_delete_outside_path(&root)
            .context("Unable to schedule removal of the managed CipherFS installation")?;
        Ok(())
    } else {
        let _ = std::fs::remove_file(&cli);
        let _ = std::fs::remove_file(root.join("cipherfs-shell.exe"));
        let _ = std::fs::remove_dir(&root);
        Ok(())
    }
}

pub struct PreparedUpdate {
    pub version: semver::Version,
    helper: PathBuf,
    cli: PathBuf,
    shell: PathBuf,
}

pub fn prepare_update() -> Result<PreparedUpdate> {
    let root = install_root()?;
    let current = std::env::current_exe()?;
    anyhow::ensure!(
        current.parent() == Some(root.as_path()),
        "Install the Windows integration before using managed updates"
    );
    let release = cipherfs_update::download_windows_integration()?;
    let stage = stage_release(&root, &release.cli.bytes, &release.shell.bytes)?;
    let helper = stage.join("cipherfs-shell-helper.exe");
    std::fs::copy(&current, &helper).context("Unable to create update helper")?;
    Ok(PreparedUpdate {
        version: release
            .version
            .parse()
            .context("Verified update version is invalid")?,
        helper,
        cli: stage.join("cipherfs.exe"),
        shell: stage.join("cipherfs-shell.exe"),
    })
}

pub fn launch_prepared_update(update: PreparedUpdate) -> Result<()> {
    let pid = std::process::id().to_string();
    std::process::Command::new(&update.helper)
        .args(["--apply-update"])
        .arg(pid)
        .arg(update.cli)
        .arg(update.shell)
        .spawn()
        .context("Unable to launch update helper")?;
    Ok(())
}

pub fn apply_staged_update(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    let parent_pid: u32 = args
        .next()
        .context("Update helper has no parent PID")?
        .to_string_lossy()
        .parse()
        .context("Update helper parent PID is invalid")?;
    let staged_cli = PathBuf::from(args.next().context("Update helper has no CLI stage")?);
    let staged_shell = PathBuf::from(args.next().context("Update helper has no shell stage")?);
    let root = install_root()?;
    wait_for_process_exit(parent_pid)?;
    let cli_target = root.join("cipherfs.exe");
    let shell_target = root.join("cipherfs-shell.exe");
    let cli_backup = root.join(".cipherfs.exe.backup");
    let shell_backup = root.join(".cipherfs-shell.exe.backup");
    std::fs::copy(&cli_target, &cli_backup).context("Unable to back up CipherFS CLI")?;
    std::fs::copy(&shell_target, &shell_backup).context("Unable to back up CipherFS shell")?;
    let update = copy_replace(&staged_cli, &cli_target)
        .and_then(|_| copy_replace(&staged_shell, &shell_target));
    if let Err(error) = update {
        let _ = copy_replace(&cli_backup, &cli_target);
        let _ = copy_replace(&shell_backup, &shell_target);
        return Err(error).context("Managed update failed and attempted rollback");
    }
    let _ = std::fs::remove_file(cli_backup);
    let _ = std::fs::remove_file(shell_backup);
    let _ = std::fs::remove_file(&staged_cli);
    let _ = std::fs::remove_file(&staged_shell);
    let _ = std::fs::remove_dir(
        staged_shell
            .parent()
            .context("Staged shell has no parent")?,
    );
    std::process::Command::new(&shell_target)
        .spawn()
        .context("Updated CipherFS installed but could not restart")?;
    self_replace::self_delete().context("Updated CipherFS installed but helper cleanup failed")
}

pub fn install_root() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?;
    Ok(PathBuf::from(local).join(INSTALL_SUBDIR))
}

fn stage_release(root: &Path, cli: &[u8], shell: &[u8]) -> Result<PathBuf> {
    let stage = root.join(format!(
        ".cipherfs-update-{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    std::fs::create_dir(&stage).context("Unable to create update staging directory")?;
    let write = |name: &str, bytes: &[u8]| -> Result<()> {
        use std::io::Write;
        let path = stage.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    };
    if let Err(error) = write("cipherfs.exe", cli).and_then(|_| write("cipherfs-shell.exe", shell))
    {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(error);
    }
    Ok(stage)
}

fn wait_for_process_exit(pid: u32) -> Result<()> {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_ACCESS_RIGHTS, WaitForSingleObject,
    };
    let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x0010_0000), false, pid) }
        .context("Unable to wait for update caller")?;
    let status = unsafe { WaitForSingleObject(handle, 60_000) };
    unsafe { CloseHandle(handle) }?;
    anyhow::ensure!(
        status == WAIT_OBJECT_0,
        "Timed out waiting for CipherFS to close before update"
    );
    Ok(())
}

fn copy_replace(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        return Ok(());
    }
    let temporary = destination.with_extension("new.exe");
    std::fs::copy(source, &temporary)
        .with_context(|| format!("Unable to stage {}", source.display()))?;
    if destination.exists() {
        std::fs::remove_file(destination)
            .with_context(|| format!("Unable to replace {}", destination.display()))?;
    }
    std::fs::rename(&temporary, destination)?;
    Ok(())
}

fn register_shell(shell: &Path) -> Result<()> {
    let shell_command = quoted_command(shell, "%1");
    let pack_command = quoted_command(shell, "--pack \"%1\"");
    set_registry_string("Software\\Classes\\.cfs\\OpenWithProgids", PROG_ID, "")?;
    set_registry_string(
        &format!("Software\\Classes\\{PROG_ID}"),
        "",
        "CipherFS encrypted container",
    )?;
    set_registry_string(
        &format!("Software\\Classes\\{PROG_ID}\\shell\\open\\command"),
        "",
        &shell_command,
    )?;
    set_registry_string(&format!("{CONTEXT_KEY}\\command"), "", &pack_command)?;
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
    Ok(())
}

fn unregister_shell(shell: &Path) {
    let expected = shell.display().to_string();
    let prog_command = registry_string(&format!(
        "Software\\Classes\\{PROG_ID}\\shell\\open\\command"
    ));
    let context_command = registry_string(&format!("{CONTEXT_KEY}\\command"));
    unsafe {
        if context_command
            .as_deref()
            .is_some_and(|value| value.contains(&expected))
        {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, &HSTRING::from(CONTEXT_KEY));
        }
        if prog_command
            .as_deref()
            .is_some_and(|value| value.contains(&expected))
        {
            let _ = RegDeleteTreeW(
                HKEY_CURRENT_USER,
                &HSTRING::from(format!("Software\\Classes\\{PROG_ID}")),
            );
            let _ = RegDeleteKeyValueW(
                HKEY_CURRENT_USER,
                &HSTRING::from("Software\\Classes\\.cfs\\OpenWithProgids"),
                &HSTRING::from(PROG_ID),
            );
        }
    }
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
}

fn registry_string(key: &str) -> Option<String> {
    let key = HSTRING::from(key);
    let mut bytes = vec![0u8; 65_536];
    let mut length = bytes.len() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            &key,
            PCWSTR::null(),
            RRF_RT_REG_SZ,
            None,
            Some(bytes.as_mut_ptr().cast()),
            Some(&mut length),
        )
    };
    if status.is_err() || length as usize > bytes.len() || !length.is_multiple_of(2) {
        return None;
    }
    let values =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u16>(), length as usize / 2) };
    let end = values
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(values.len());
    String::from_utf16(&values[..end]).ok()
}

fn set_registry_string(key: &str, value_name: &str, value: &str) -> Result<()> {
    let key = HSTRING::from(key);
    let name = HSTRING::from(value_name);
    let mut utf16: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = unsafe {
        std::slice::from_raw_parts(
            utf16.as_ptr().cast::<u8>(),
            std::mem::size_of_val(utf16.as_slice()),
        )
    };
    unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            &key,
            &name,
            REG_SZ.0,
            Some(bytes.as_ptr().cast()),
            bytes.len() as u32,
        )
    }
    .ok()
    .context("Unable to write current-user Explorer registration")?;
    utf16.zeroize();
    Ok(())
}

fn quoted_command(executable: &Path, tail: &str) -> String {
    format!("\"{}\" {tail}", executable.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_command_quotes_executable_and_argument() {
        let command = quoted_command(Path::new(r"C:\A path\cipherfs-shell.exe"), "%1");
        assert_eq!(command, r#""C:\A path\cipherfs-shell.exe" %1"#);
    }
}
