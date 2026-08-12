//! Windows application routing and operation dialogs.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::dialogs::{
    choose, choose_extract_destination, choose_pack_output, info, open_explorer, open_url,
    prompt_password,
};

use crate::mount_controller::MountWorker;
use crate::operation_controller::{random_sibling, run_operation};
use crate::protocol::{Secret, WorkerOperation};

pub fn run() -> Result<()> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let first = args.next();
    match first.as_deref() {
        None => manage(),
        Some(value) if value == "install" => crate::integration::install(),
        Some(value) if value == "uninstall" => crate::integration::uninstall(),
        Some(value) if value == "update" => crate::integration::update(),
        Some(value) if value == "--apply-update" => crate::integration::apply_staged_update(args),
        Some(value) if value == "--pack" => {
            let source = args.next().context("--pack requires a directory")?;
            pack(Path::new(&source))
        }
        Some(value) => container_menu(Path::new(value)),
    }
}

fn manage() -> Result<()> {
    let installed = crate::integration::install_root()?
        .join("cipherfs-shell.exe")
        .is_file();
    let buttons = if installed {
        vec![
            (1, "Repair integration"),
            (2, "Check for update"),
            (3, "Uninstall"),
        ]
    } else {
        vec![(1, "Install Windows integration")]
    };
    match choose(
        "CipherFS",
        if installed {
            "Windows integration"
        } else {
            "Install CipherFS"
        },
        "CipherFS uses a per-user installation and does not install the WinFsp driver.",
        &buttons,
    )? {
        1 => crate::integration::install(),
        2 => crate::integration::update(),
        3 => crate::integration::uninstall(),
        _ => Ok(()),
    }
}

fn container_menu(container: &Path) -> Result<()> {
    cipherfs_core::require_v2(container)?;
    let filename = container
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("container.cfs");
    match choose(
        "CipherFS",
        filename,
        "Choose an operation. Verify authenticates the whole encrypted container and requires its password.",
        &[
            (1, "Mount"),
            (2, "Extract"),
            (3, "Verify"),
            (4, "Change password"),
        ],
    )? {
        1 => mount(container),
        2 => extract(container),
        3 => verify(container),
        4 => change_password(container),
        _ => Ok(()),
    }
}

fn mount(container: &Path) -> Result<()> {
    let password = match prompt_password("Mount CipherFS container")? {
        Some(value) => value,
        None => return Ok(()),
    };
    match MountWorker::start(WorkerOperation::Mount {
        container: container.to_path_buf(),
        password: Secret::new(password.as_str()),
    }) {
        Ok(session) => {
            let mounted = session.path().to_path_buf();
            open_explorer(&mounted)?;
            loop {
                let action = choose(
                    "CipherFS mounted",
                    &format!("Mounted at {}", mounted.display()),
                    "The read-only drive remains mounted while this window is open.",
                    &[(1, "Open in Explorer"), (2, "Unmount")],
                )?;
                match action {
                    1 => open_explorer(&mounted)?,
                    2 => break,
                    _ => {
                        if choose(
                            "Unmount CipherFS?",
                            "Close the mounted container?",
                            "Explorer access to the CipherFS drive will end.",
                            &[(1, "Unmount"), (2, "Keep mounted")],
                        )? == 1
                        {
                            break;
                        }
                    }
                }
            }
            session.unmount()?;
            info("CipherFS", "Container unmounted.")
        }
        Err(error) => {
            let text = format!(
                "Mount failed: {error:#}\n\nInstall the official WinFsp runtime from https://winfsp.dev/rel/"
            );
            let action = choose(
                "CipherFS",
                "WinFsp mount unavailable",
                &text,
                &[(1, "Open WinFsp download page")],
            )?;
            if action == 1 {
                open_url("https://winfsp.dev/rel/")?;
            }
            Ok(())
        }
    }
}

fn extract(container: &Path) -> Result<()> {
    let default_name = container
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("extracted");
    let Some(destination) = choose_extract_destination(default_name)? else {
        return Ok(());
    };
    anyhow::ensure!(
        !destination.exists(),
        "The extraction destination already exists: {}",
        destination.display()
    );
    let password = match prompt_password("Extract CipherFS container")? {
        Some(value) => value,
        None => return Ok(()),
    };
    let staging = random_sibling(&destination, true)?;
    if !run_operation(
        "Extracting CipherFS container",
        WorkerOperation::Extract {
            container: container.to_path_buf(),
            output: destination.clone(),
            staging: staging.clone(),
            password: Secret::new(password.as_str()),
        },
        Some(staging),
    )? {
        return Ok(());
    }
    open_explorer(&destination)
}

fn verify(container: &Path) -> Result<()> {
    let password = match prompt_password("Verify CipherFS container")? {
        Some(value) => value,
        None => return Ok(()),
    };
    if !run_operation(
        "Verifying CipherFS container",
        WorkerOperation::Verify {
            container: container.to_path_buf(),
            password: Secret::new(password.as_str()),
        },
        None,
    )? {
        return Ok(());
    }
    info(
        "CipherFS",
        "Header, index, and every encrypted chunk are valid.",
    )
}

fn change_password(container: &Path) -> Result<()> {
    let old = match prompt_password("Current CipherFS password")? {
        Some(value) => value,
        None => return Ok(()),
    };
    let new = match prompt_password("New CipherFS password")? {
        Some(value) => value,
        None => return Ok(()),
    };
    let confirm = match prompt_password("Confirm new CipherFS password")? {
        Some(value) => value,
        None => return Ok(()),
    };
    if new.as_str() != confirm.as_str() {
        anyhow::bail!("Passwords do not match");
    }
    if !run_operation(
        "Changing CipherFS password",
        WorkerOperation::ChangePassword {
            container: container.to_path_buf(),
            old_password: Secret::new(old.as_str()),
            new_password: Secret::new(new.as_str()),
        },
        None,
    )? {
        return Ok(());
    }
    info("CipherFS", "Password keyslot updated.")
}

fn pack(source: &Path) -> Result<()> {
    let default_output = default_pack_output(source)?;
    let Some(output) = choose_pack_output(&default_output)? else {
        return Ok(());
    };
    anyhow::ensure!(
        !output.exists(),
        "The output container already exists: {}",
        output.display()
    );
    let password = match prompt_password("Set CipherFS master password")? {
        Some(value) => value,
        None => return Ok(()),
    };
    let confirm = match prompt_password("Confirm CipherFS master password")? {
        Some(value) => value,
        None => return Ok(()),
    };
    if password.as_str() != confirm.as_str() {
        anyhow::bail!("Passwords do not match");
    }
    let duress = if choose(
        "CipherFS",
        "Advanced option",
        "Configure an experimental Duress Password? It is not reliable secure erasure or anti-forensics.",
        &[(1, "Configure"), (2, "Skip")],
    )? == 1
    {
        let value = prompt_password("Set experimental Duress Password")?
            .context("Duress Password setup cancelled")?;
        let confirmation = prompt_password("Confirm experimental Duress Password")?
            .context("Duress Password setup cancelled")?;
        if value.as_str() != confirmation.as_str() {
            anyhow::bail!("Duress passwords do not match");
        }
        anyhow::ensure!(
            value.as_str() != password.as_str(),
            "The Duress Password must differ from the master password"
        );
        Some(value)
    } else {
        None
    };
    let temporary = random_sibling(&output, false)?;
    if !run_operation(
        "Creating CipherFS container",
        WorkerOperation::Pack {
            source: source.to_path_buf(),
            output: output.clone(),
            temporary: temporary.clone(),
            password: Secret::new(password.as_str()),
            duress_password: duress.as_ref().map(|value| Secret::new(value.as_str())),
        },
        Some(temporary),
    )? {
        return Ok(());
    }
    info(
        "CipherFS",
        &format!("Created and verified {}", output.display()),
    )
}

fn default_pack_output(source: &Path) -> Result<PathBuf> {
    let name = source
        .file_name()
        .context("Pack source directory has no name")?
        .to_string_lossy();
    Ok(source.with_file_name(format!("{name}.cfs")))
}
