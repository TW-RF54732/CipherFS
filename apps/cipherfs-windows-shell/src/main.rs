#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args
        .get(1)
        .is_some_and(|arg| arg == "--native-dialog-smoke")
    {
        let kind = args.get(2).and_then(|arg| arg.to_str()).unwrap_or("");
        if let Err(error) = cipherfs_windows_shell::native_dialog_smoke(kind) {
            eprintln!("{error:#}");
            if let Some(path) = std::env::var_os("CIPHERFS_SMOKE_ERROR_FILE") {
                let _ = std::fs::write(path, format!("{error:#}\n"));
            }
            std::process::exit(5);
        }
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "--headless-smoke") {
        if cipherfs_windows_shell::headless_smoke().is_err() {
            std::process::exit(4);
        }
        return;
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == "--winfsp-runtime-missing-smoke")
    {
        if cipherfs_windows_shell::verify_winfsp_is_missing().is_err() {
            std::process::exit(3);
        }
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "--operation-worker") {
        if cipherfs_windows_shell::run_operation_worker().is_err() {
            std::process::exit(2);
        }
        return;
    }
    if let Err(error) = cipherfs_windows_shell::run_application() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("cipherfs-shell is available only in Windows release packages");
}
