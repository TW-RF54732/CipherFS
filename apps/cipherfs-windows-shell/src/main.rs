#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--headless-smoke")) {
        return;
    }
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--winfsp-runtime-missing-smoke"))
    {
        if cipherfs_windows_shell::verify_winfsp_is_missing().is_err() {
            std::process::exit(3);
        }
        return;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--operation-worker")) {
        if cipherfs_windows_shell::run_operation_worker().is_err() {
            std::process::exit(2);
        }
        return;
    }
    if let Err(error) = cipherfs_windows_shell::run_application() {
        cipherfs_windows_shell::show_error(&format!("{error:#}"));
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("cipherfs-shell is available only in Windows release packages");
}
