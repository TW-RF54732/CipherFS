#![cfg(windows)]

mod app;
mod controller;
mod dialogs;
mod mount_controller;
mod operation_controller;
pub mod protocol;
mod worker;

slint::include_modules!();

pub fn run_application() -> anyhow::Result<()> {
    app::run()
}

pub fn run_operation_worker() -> anyhow::Result<()> {
    worker::run_stdio()
}

pub fn headless_smoke() -> anyhow::Result<()> {
    app::headless_smoke()
}

pub fn native_dialog_smoke(kind: &str) -> anyhow::Result<()> {
    app::native_dialog_smoke(kind)
}

pub fn verify_winfsp_is_missing() -> anyhow::Result<()> {
    match cipherfs_winfsp::check_runtime() {
        Ok(()) => anyhow::bail!("WinFsp was already available before the pinned CI install step"),
        Err(error) if format!("{error:#}").contains("https://winfsp.dev/rel/") => Ok(()),
        Err(error) => Err(error),
    }
}
