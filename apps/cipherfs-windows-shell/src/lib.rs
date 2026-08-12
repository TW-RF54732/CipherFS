#![cfg(windows)]

mod app;
mod dialogs;
mod integration;
mod mount_controller;
mod operation_controller;
pub mod protocol;
mod worker;

pub fn run_application() -> anyhow::Result<()> {
    app::run()
}

pub fn run_operation_worker() -> anyhow::Result<()> {
    worker::run_stdio()
}

pub fn show_error(text: &str) {
    dialogs::show_error(text);
}

pub fn verify_winfsp_is_missing() -> anyhow::Result<()> {
    match cipherfs_winfsp::check_runtime() {
        Ok(()) => anyhow::bail!("WinFsp was already available before the pinned CI install step"),
        Err(error) if format!("{error:#}").contains("https://winfsp.dev/rel/") => Ok(()),
        Err(error) => Err(error),
    }
}
