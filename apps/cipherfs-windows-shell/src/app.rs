//! Slint application routing. Windows-owned dialogs and shell integration remain in Win32.

use crate::AppWindow;
use crate::controller::{AppAction, AppState, DialogOutcome, FormKind, Route};
use crate::mount_controller::MountWorker;
use crate::operation_controller::{ControllerEvent, OperationHandle, random_sibling};
use crate::protocol::{Secret, WorkerOperation};
use anyhow::{Context, Result};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use slint::ComponentHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::HWND;
use zeroize::{Zeroize, Zeroizing};

const INTEGRATION: i32 = 0;
const ACTIONS: i32 = 1;
const FORM: i32 = 2;
const PROGRESS: i32 = 3;
const MOUNTED: i32 = 4;
const RESULT: i32 = 5;
const ERROR: i32 = 7;

struct RuntimeState {
    route: Mutex<Option<Route>>,
    controller: Mutex<AppState>,
    operation: Mutex<Option<Arc<OperationHandle>>>,
    mount: Mutex<Option<MountWorker>>,
    prepared_update: Mutex<Option<crate::integration::PreparedUpdate>>,
}

impl RuntimeState {
    fn new(route: Route) -> Self {
        Self {
            route: Mutex::new(Some(route.clone())),
            controller: Mutex::new(AppState::new(route)),
            operation: Mutex::new(None),
            mount: Mutex::new(None),
            prepared_update: Mutex::new(None),
        }
    }
}

pub fn run() -> Result<()> {
    let route = parse_route()?;
    let ui = AppWindow::new().context("Unable to initialize the Slint UI")?;
    let state = Arc::new(RuntimeState::new(route.clone()));
    configure_callbacks(&ui, Arc::clone(&state));
    show_route(&ui, &route)?;
    if matches!(route, Route::Update) {
        prepare_update(&ui, &state)?;
    } else if matches!(route, Route::Install) {
        run_background(&ui, "Installing Windows integration...", move || {
            crate::integration::install()?;
            Ok("Windows integration installed for this user.".into())
        })?;
    } else if matches!(route, Route::Uninstall) {
        run_background(&ui, "Removing Windows integration...", move || {
            crate::integration::uninstall()?;
            Ok("Explorer integration was removed.".into())
        })?;
    }
    ui.run().context("CipherFS Slint event loop failed")
}

pub fn headless_smoke() -> Result<()> {
    let ui = AppWindow::new().context("Unable to initialize the Slint UI")?;
    ui.show().context("Unable to show the Slint smoke window")?;
    let pages = [INTEGRATION, ACTIONS, FORM, PROGRESS, MOUNTED, RESULT, ERROR];
    let index = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    let timer_index = std::rc::Rc::clone(&index);
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(10),
        move || {
            let next = timer_index.get();
            if next == pages.len() {
                let _ = slint::quit_event_loop();
                return;
            }
            if let Some(ui) = weak.upgrade() {
                let page = pages[next];
                ui.set_page(page);
                ui.set_heading(format!("Smoke page {page}").into());
                ui.set_detail("Representative CipherFS state".into());
                ui.set_progress_value(0.5);
            }
            timer_index.set(next + 1);
        },
    );
    slint::run_event_loop().context("Slint smoke event loop failed")?;
    ui.hide().context("Unable to hide the Slint smoke window")?;
    Ok(())
}

pub fn native_dialog_smoke(kind: &str) -> Result<()> {
    let ui = AppWindow::new().context("Unable to initialize the native-dialog smoke UI")?;
    anyhow::ensure!(
        matches!(kind, "pack" | "extract"),
        "Native dialog smoke expects 'pack' or 'extract'"
    );
    ui.show()
        .context("Unable to show the native-dialog smoke owner")?;
    let result = std::rc::Rc::new(std::cell::RefCell::new(None));
    let callback_result = std::rc::Rc::clone(&result);
    let weak = ui.as_weak();
    let kind = kind.to_owned();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::SingleShot,
        std::time::Duration::from_millis(50),
        move || {
            let attempt = (|| -> Result<(&'static str, DialogOutcome<PathBuf>)> {
                let ui = weak
                    .upgrade()
                    .context("Native-dialog smoke UI was dropped")?;
                match kind.as_str() {
                    "extract" => {
                        let title = "Choose a new extraction folder";
                        let owner = owner_hwnd(&ui)?;
                        let outcome = crate::dialogs::smoke_extract_destination(
                            owner,
                            "cipherfs-dialog-smoke",
                        )?;
                        Ok((title, outcome))
                    }
                    "pack" => {
                        let title = "Create CipherFS container";
                        let owner = owner_hwnd(&ui)?;
                        let default = std::env::temp_dir().join("cipherfs-dialog-smoke.cfs");
                        let outcome = crate::dialogs::smoke_pack_output(owner, &default)?;
                        Ok((title, outcome))
                    }
                    _ => unreachable!(),
                }
            })();
            *callback_result.borrow_mut() = Some(attempt.map_err(|error| format!("{error:#}")));
            let _ = slint::quit_event_loop();
        },
    );
    slint::run_event_loop().context("Native-dialog smoke event loop failed")?;
    ui.hide()
        .context("Unable to hide the native-dialog smoke owner")?;
    let (title, outcome) = result
        .borrow_mut()
        .take()
        .context("Native-dialog smoke callback did not run")?
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        matches!(outcome, DialogOutcome::Cancelled),
        "{title} returned a selection instead of cancellation"
    );
    Ok(())
}

fn parse_route() -> Result<Route> {
    let mut args = std::env::args_os();
    let _ = args.next();
    match args.next() {
        None => Ok(Route::Integration),
        Some(value) if value == "install" => Ok(Route::Install),
        Some(value) if value == "uninstall" => Ok(Route::Uninstall),
        Some(value) if value == "update" => Ok(Route::Update),
        Some(value) if value == "--apply-update" => {
            crate::integration::apply_staged_update(args)?;
            Ok(Route::Integration)
        }
        Some(value) if value == "--pack" => {
            let source = PathBuf::from(args.next().context("--pack requires a directory")?);
            let output = default_pack_output(&source)?;
            Ok(Route::Pack { source, output })
        }
        Some(value) => {
            let path = PathBuf::from(value);
            cipherfs_core::require_v2(&path)?;
            Ok(Route::Container(path))
        }
    }
}

fn configure_callbacks(ui: &AppWindow, state: Arc<RuntimeState>) {
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_primary_action(move || {
        if let Some(ui) = weak.upgrade()
            && let Err(e) = primary(&ui, &s)
        {
            show_error(&ui, &format!("{e:#}"));
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_secondary_action(move || {
        if let Some(ui) = weak.upgrade()
            && let Err(e) = secondary(&ui, &s)
        {
            show_error(&ui, &format!("{e:#}"));
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_tertiary_action(move || {
        if let Some(ui) = weak.upgrade()
            && let Err(e) = tertiary(&ui, &s)
        {
            show_error(&ui, &format!("{e:#}"));
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_quaternary_action(move || {
        if let Some(ui) = weak.upgrade()
            && let Err(e) = quaternary(&ui, &s)
        {
            show_error(&ui, &format!("{e:#}"));
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_choose_path(move || {
        if let Some(ui) = weak.upgrade()
            && let Err(e) = choose_path(&ui, &s)
        {
            show_error(&ui, &format!("{e:#}"));
        }
    });
    let weak = ui.as_weak();
    ui.on_toggle_duress(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_show_duress(!ui.get_show_duress());
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_cancel_operation(move || {
        if let Some(ui) = weak.upgrade() {
            cancel(&ui, &s);
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.on_overlay_confirm(move || {
        if let Some(ui) = weak.upgrade() {
            confirm_overlay(&ui, &s);
        }
    });
    let weak = ui.as_weak();
    ui.on_overlay_cancel(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_overlay_visible(false);
        }
    });
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    let close_handler = move || {
        let Some(ui) = weak.upgrade() else {
            return false;
        };
        if s.mount.lock().expect("mount poisoned").is_some() {
            show_overlay(
                &ui,
                "Unmount CipherFS?",
                "Explorer access to the read-only drive will end.",
                "Unmount",
            );
            true
        } else if let Some(op) = s.operation.lock().expect("operation poisoned").as_ref() {
            if op.is_protected() {
                show_overlay(
                    &ui,
                    "CipherFS is finishing",
                    "The completed result is being committed and cannot be cancelled safely.",
                    "Keep open",
                );
            } else {
                show_overlay(
                    &ui,
                    "Cancel operation?",
                    "Request safe cancellation before closing CipherFS.",
                    "Cancel operation",
                );
            }
            true
        } else {
            false
        }
    };
    ui.on_window_close(close_handler);
    let weak = ui.as_weak();
    let s = Arc::clone(&state);
    ui.window().on_close_requested(move || {
        let Some(ui) = weak.upgrade() else {
            return slint::CloseRequestResponse::HideWindow;
        };
        if s.mount.lock().expect("mount poisoned").is_some() {
            show_overlay(
                &ui,
                "Unmount CipherFS?",
                "Explorer access to the read-only drive will end.",
                "Unmount",
            );
            slint::CloseRequestResponse::KeepWindowShown
        } else if let Some(op) = s.operation.lock().expect("operation poisoned").as_ref() {
            if op.is_protected() {
                show_overlay(
                    &ui,
                    "CipherFS is finishing",
                    "The completed result is being committed and cannot be cancelled safely.",
                    "Keep open",
                )
            } else {
                show_overlay(
                    &ui,
                    "Cancel operation?",
                    "Request safe cancellation before closing CipherFS.",
                    "Cancel operation",
                )
            };
            slint::CloseRequestResponse::KeepWindowShown
        } else {
            slint::CloseRequestResponse::HideWindow
        }
    });
}

fn show_route(ui: &AppWindow, route: &Route) -> Result<()> {
    clear_secrets(ui);
    match route {
        Route::Integration | Route::Install | Route::Uninstall | Route::Update => {
            let installed = crate::integration::install_root()?
                .join("cipherfs-shell.exe")
                .is_file();
            ui.set_page(INTEGRATION);
            ui.set_heading("Windows integration".into());
            ui.set_detail(
                "Per-user Explorer integration. CipherFS does not install the WinFsp driver."
                    .into(),
            );
            ui.set_primary_label(
                if installed {
                    "Repair integration"
                } else {
                    "Install Windows integration"
                }
                .into(),
            );
            ui.set_secondary_label(
                if installed {
                    "Check for update"
                } else {
                    "Close"
                }
                .into(),
            );
            ui.set_tertiary_label(if installed { "Uninstall" } else { "" }.into());
            ui.set_quaternary_label("".into());
        }
        Route::Container(path) => {
            ui.set_page(ACTIONS);
            ui.set_heading(
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
                    .into(),
            );
            ui.set_detail(
                "Choose an operation. Verify authenticates the complete encrypted container."
                    .into(),
            );
            ui.set_primary_label("Mount".into());
            ui.set_secondary_label("Extract".into());
            ui.set_tertiary_label("Verify".into());
            ui.set_quaternary_label("Change password".into());
        }
        Route::Pack { source, output } => show_form(
            ui,
            &FormKind::Pack {
                source: source.clone(),
                output: output.clone(),
            },
        ),
        Route::Form(kind) => show_form(ui, kind),
    }
    Ok(())
}

fn show_form(ui: &AppWindow, kind: &FormKind) {
    ui.set_page(FORM);
    ui.set_old_password("__unused__".into());
    ui.set_password_confirm("__unused__".into());
    ui.set_show_duress(false);
    ui.set_tertiary_label("".into());
    match kind {
        FormKind::Mount(path) => {
            ui.set_heading("Mount CipherFS container".into());
            ui.set_detail("The password is used only for this operation.".into());
            ui.set_path_text(path.display().to_string().into());
            ui.set_primary_label("Mount".into());
        }
        FormKind::Verify(path) => {
            ui.set_heading("Verify CipherFS container".into());
            ui.set_detail("Authenticates the header, index, and every encrypted chunk.".into());
            ui.set_path_text(path.display().to_string().into());
            ui.set_primary_label("Verify".into());
        }
        FormKind::Extract { container, output } => {
            ui.set_heading("Extract CipherFS container".into());
            ui.set_detail("The destination must not already exist.".into());
            ui.set_path_text(output.display().to_string().into());
            ui.set_primary_label("Extract".into());
            let _ = container;
        }
        FormKind::ChangePassword(path) => {
            ui.set_heading("Change CipherFS password".into());
            ui.set_detail("Updates the encrypted keyslot without re-encrypting file data.".into());
            ui.set_path_text(path.display().to_string().into());
            ui.set_old_password("".into());
            ui.set_password_confirm("".into());
            ui.set_primary_label("Change password".into());
        }
        FormKind::Pack { source, output } => {
            ui.set_heading("Create CipherFS container".into());
            ui.set_detail(format!("Source: {}", source.display()).into());
            ui.set_path_text(output.display().to_string().into());
            ui.set_password_confirm("".into());
            ui.set_tertiary_label("duress".into());
            ui.set_primary_label("Create container".into());
        }
    }
}

fn primary(ui: &AppWindow, state: &Arc<RuntimeState>) -> Result<()> {
    if ui.get_page() == MOUNTED
        && let Some(m) = state.mount.lock().unwrap().as_ref()
    {
        return crate::dialogs::open_explorer(m.path());
    }
    if ui.get_page() == RESULT {
        if let Some(update) = state.prepared_update.lock().unwrap().take() {
            crate::integration::launch_prepared_update(update)?;
            slint::quit_event_loop()?;
            return Ok(());
        }
        slint::quit_event_loop()?;
        return Ok(());
    }
    if ui.get_page() == ERROR {
        if ui.get_primary_label().as_str().contains("WinFsp") {
            return crate::dialogs::open_url("https://winfsp.dev/rel/");
        }
        slint::quit_event_loop()?;
        return Ok(());
    }
    let route = state
        .route
        .lock()
        .expect("route poisoned")
        .clone()
        .context("route missing")?;
    match route {
        Route::Integration | Route::Install | Route::Uninstall | Route::Update => {
            run_background(ui, "Updating Windows integration...", move || {
                crate::integration::install()?;
                Ok("Windows integration installed for this user.".into())
            })
        }
        Route::Container(path) => set_form(ui, state, FormKind::Mount(path)),
        Route::Pack { source, output } => submit(ui, state, FormKind::Pack { source, output }),
        Route::Form(kind) => submit(ui, state, kind),
    }
}

fn secondary(ui: &AppWindow, state: &Arc<RuntimeState>) -> Result<()> {
    if ui.get_page() == MOUNTED {
        show_overlay(
            ui,
            "Unmount CipherFS?",
            "Explorer access to the read-only drive will end.",
            "Unmount",
        );
        return Ok(());
    }
    if ui.get_page() == RESULT {
        slint::quit_event_loop()?;
        return Ok(());
    }
    let route = state
        .route
        .lock()
        .expect("route poisoned")
        .clone()
        .context("route missing")?;
    match route {
        Route::Integration | Route::Install | Route::Uninstall | Route::Update
            if ui.get_secondary_label().as_str() == "Close" =>
        {
            slint::quit_event_loop()?;
            Ok(())
        }
        Route::Integration | Route::Install | Route::Uninstall | Route::Update => {
            prepare_update(ui, state)
        }
        Route::Container(path) => {
            let name = path
                .file_stem()
                .and_then(|x| x.to_str())
                .unwrap_or("extracted")
                .to_owned();
            match crate::dialogs::choose_extract_destination(owner_hwnd(ui)?, &name) {
                Ok(DialogOutcome::Selected(output)) => set_form(
                    ui,
                    state,
                    FormKind::Extract {
                        container: path,
                        output,
                    },
                ),
                Ok(DialogOutcome::Cancelled) => {
                    state
                        .controller
                        .lock()
                        .unwrap()
                        .transition(AppAction::DialogCancelled);
                    Ok(())
                }
                Err(error) => {
                    state
                        .controller
                        .lock()
                        .unwrap()
                        .transition(AppAction::DialogFailed(format!("{error:#}")));
                    Err(error)
                }
            }
        }
        Route::Form(_) | Route::Pack { .. } => {
            let back = match &route {
                Route::Form(FormKind::Pack { source, output }) => Route::Pack {
                    source: source.clone(),
                    output: output.clone(),
                },
                Route::Pack { source, output } => Route::Pack {
                    source: source.clone(),
                    output: output.clone(),
                },
                Route::Form(
                    FormKind::Mount(p) | FormKind::Verify(p) | FormKind::ChangePassword(p),
                ) => Route::Container(p.clone()),
                Route::Form(FormKind::Extract { container, .. }) => {
                    Route::Container(container.clone())
                }
                _ => Route::Integration,
            };
            *state.route.lock().unwrap() = Some(back.clone());
            show_route(ui, &back)
        }
    }
}

fn tertiary(ui: &AppWindow, state: &Arc<RuntimeState>) -> Result<()> {
    let route = state
        .route
        .lock()
        .unwrap()
        .clone()
        .context("route missing")?;
    match route {
        Route::Integration | Route::Install | Route::Uninstall | Route::Update => {
            run_background(ui, "Removing Windows integration...", move || {
                crate::integration::uninstall()?;
                Ok("Explorer integration was removed.".into())
            })
        }
        Route::Container(path) => set_form(ui, state, FormKind::Verify(path)),
        _ => Ok(()),
    }
}

fn quaternary(ui: &AppWindow, state: &Arc<RuntimeState>) -> Result<()> {
    let route = state
        .route
        .lock()
        .unwrap()
        .clone()
        .context("route missing")?;
    if let Route::Container(path) = route {
        set_form(ui, state, FormKind::ChangePassword(path))
    } else {
        Ok(())
    }
}

fn set_form(ui: &AppWindow, state: &Arc<RuntimeState>, kind: FormKind) -> Result<()> {
    let route = Route::Form(kind);
    *state.route.lock().unwrap() = Some(route.clone());
    state
        .controller
        .lock()
        .unwrap()
        .transition(AppAction::ShowRoute(route.clone()));
    show_route(ui, &route)
}

fn choose_path(ui: &AppWindow, state: &Arc<RuntimeState>) -> Result<()> {
    let route = state
        .route
        .lock()
        .unwrap()
        .clone()
        .context("route missing")?;
    if let Route::Form(FormKind::Pack { source, output }) | Route::Pack { source, output } = route
        && let DialogOutcome::Selected(chosen) =
            crate::dialogs::choose_pack_output(owner_hwnd(ui)?, &output)?
    {
        set_form(
            ui,
            state,
            FormKind::Pack {
                source,
                output: chosen,
            },
        )?;
    }
    Ok(())
}

fn submit(ui: &AppWindow, state: &Arc<RuntimeState>, kind: FormKind) -> Result<()> {
    let mut password = Zeroizing::new(ui.get_password().to_string());
    let mut confirm = Zeroizing::new(ui.get_password_confirm().to_string());
    let mut old = Zeroizing::new(ui.get_old_password().to_string());
    let mut duress = Zeroizing::new(ui.get_duress_password().to_string());
    let mut duress_confirm = Zeroizing::new(ui.get_duress_confirm().to_string());
    clear_secrets(ui);
    anyhow::ensure!(!password.is_empty(), "Password must not be empty");
    let (operation, artifact, title, success) = match kind {
        FormKind::Mount(container) => {
            return start_mount(ui, state, container, Secret::new(password.as_str()));
        }
        FormKind::Verify(container) => (
            WorkerOperation::Verify {
                container,
                password: Secret::new(password.as_str()),
            },
            None,
            "Verifying CipherFS container",
            "Container verification completed.".into(),
        ),
        FormKind::Extract { container, output } => {
            anyhow::ensure!(
                !output.exists(),
                "The extraction destination already exists: {}",
                output.display()
            );
            let staging = random_sibling(&output, true)?;
            (
                WorkerOperation::Extract {
                    container,
                    output: output.clone(),
                    staging: staging.clone(),
                    password: Secret::new(password.as_str()),
                },
                Some(staging),
                "Extracting CipherFS container",
                format!("Extracted to {}", output.display()),
            )
        }
        FormKind::ChangePassword(container) => {
            anyhow::ensure!(!old.is_empty(), "Current password must not be empty");
            validate_new_password(password.as_str(), confirm.as_str(), None)?;
            (
                WorkerOperation::ChangePassword {
                    container,
                    old_password: Secret::new(old.as_str()),
                    new_password: Secret::new(password.as_str()),
                },
                None,
                "Changing CipherFS password",
                "Password keyslot updated.".into(),
            )
        }
        FormKind::Pack { source, output } => {
            anyhow::ensure!(
                !output.exists(),
                "The output container already exists: {}",
                output.display()
            );
            let d = if ui.get_show_duress() {
                validate_new_password(
                    password.as_str(),
                    confirm.as_str(),
                    Some((duress.as_str(), duress_confirm.as_str())),
                )?;
                Some(Secret::new(duress.as_str()))
            } else {
                validate_new_password(password.as_str(), confirm.as_str(), None)?;
                None
            };
            let temporary = random_sibling(&output, false)?;
            (
                WorkerOperation::Pack {
                    source,
                    output: output.clone(),
                    temporary: temporary.clone(),
                    password: Secret::new(password.as_str()),
                    duress_password: d,
                },
                Some(temporary),
                "Creating CipherFS container",
                format!("Created and verified {}", output.display()),
            )
        }
    };
    password.zeroize();
    confirm.zeroize();
    old.zeroize();
    duress.zeroize();
    duress_confirm.zeroize();
    start_operation(ui, state, operation, artifact, title, &success)
}

fn start_operation(
    ui: &AppWindow,
    state: &Arc<RuntimeState>,
    operation: WorkerOperation,
    artifact: Option<PathBuf>,
    title: &str,
    success: &str,
) -> Result<()> {
    state
        .controller
        .lock()
        .unwrap()
        .transition(AppAction::OperationStarted);
    ui.set_page(PROGRESS);
    ui.set_heading(title.into());
    ui.set_detail("Starting isolated operation...".into());
    ui.set_progress_value(0.);
    ui.set_cancel_enabled(true);
    let weak = ui.as_weak();
    let success = success.to_string();
    let runtime = Arc::clone(state);
    let handle = OperationHandle::start(operation, artifact, move |event| {
        let weak = weak.clone();
        let success = success.clone();
        let runtime = Arc::clone(&runtime);
        let _ = weak.upgrade_in_event_loop(move |ui| match event {
            ControllerEvent::Phase(p) => ui.set_detail(phase_text(p).into()),
            ControllerEvent::Progress {
                phase,
                completed,
                total,
            } => {
                ui.set_detail(progress_text(phase, completed, total).into());
                ui.set_progress_value(if total == 0 {
                    0.
                } else {
                    (completed as f32 / total as f32).min(1.)
                });
            }
            ControllerEvent::Warning(message) => {
                ui.set_detail(format!("Warning: {message}").into());
            }
            ControllerEvent::Protected => {
                runtime
                    .controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::OperationProtected);
                ui.set_cancel_enabled(false);
                ui.set_detail(
                    "Committing the completed result. This short step cannot be cancelled safely."
                        .into(),
                );
            }
            ControllerEvent::Finished(Ok(())) => {
                runtime
                    .controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::OperationFinished(Ok(())));
                runtime.operation.lock().unwrap().take();
                show_result(&ui, &success)
            }
            ControllerEvent::Finished(Err(e)) if e == "Operation cancelled" => {
                runtime
                    .controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::OperationFinished(Err(e.clone())));
                runtime.operation.lock().unwrap().take();
                show_result(&ui, "Operation cancelled safely.")
            }
            ControllerEvent::Finished(Err(e)) => {
                runtime
                    .controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::OperationFinished(Err(e.clone())));
                runtime.operation.lock().unwrap().take();
                show_error(&ui, &e)
            }
        });
    })?;
    *state.operation.lock().unwrap() = Some(handle);
    Ok(())
}

fn cancel(ui: &AppWindow, state: &Arc<RuntimeState>) {
    state
        .controller
        .lock()
        .unwrap()
        .transition(AppAction::CancelPressed);
    if let Some(op) = state.operation.lock().unwrap().as_ref() {
        match op.request_cancel() {
            Ok(true) => show_overlay(
                ui,
                "Force close operation worker?",
                "The worker is still waiting for a safe boundary. Only its exact recorded temporary artifact will be removed.",
                "Force close",
            ),
            Ok(false) => ui.set_detail(
                "Cancelling safely... Click Cancel again to request force close.".into(),
            ),
            Err(e) => show_error(ui, &format!("{e:#}")),
        }
    }
}

fn start_mount(
    ui: &AppWindow,
    state: &Arc<RuntimeState>,
    container: PathBuf,
    password: Secret,
) -> Result<()> {
    ui.set_page(PROGRESS);
    ui.set_heading("Mounting CipherFS container".into());
    ui.set_detail("Starting isolated mount worker...".into());
    ui.set_cancel_enabled(false);
    let weak = ui.as_weak();
    let s = Arc::clone(state);
    std::thread::spawn(move || {
        match MountWorker::start(WorkerOperation::Mount {
            container,
            password,
        }) {
            Ok(mount) => {
                s.controller.lock().unwrap().transition(AppAction::Mounted);
                let path = mount.path().to_path_buf();
                *s.mount.lock().unwrap() = Some(mount);
                let _ = crate::dialogs::open_explorer(&path);
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    ui.set_page(MOUNTED);
                    ui.set_heading("CipherFS mounted".into());
                    ui.set_detail(
                        "The read-only drive remains mounted while this window is open.".into(),
                    );
                    ui.set_path_text(path.display().to_string().into());
                    ui.set_primary_label("Open in Explorer".into());
                    ui.set_secondary_label("Unmount".into());
                });
            }
            Err(e) => {
                let text = format!("Mount failed: {e:#}");
                s.controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::MountFailed(text.clone()));
                let _ = weak.upgrade_in_event_loop(move |ui| show_error(&ui, &text));
            }
        }
    });
    Ok(())
}

fn prepare_update(ui: &AppWindow, state: &Arc<RuntimeState>) -> Result<()> {
    ui.set_page(PROGRESS);
    ui.set_heading("Checking for update".into());
    ui.set_detail("Downloading and verifying the signed Windows integration...".into());
    ui.set_cancel_enabled(false);
    let weak = ui.as_weak();
    let s = Arc::clone(state);
    std::thread::spawn(move || match crate::integration::prepare_update() {
        Ok(p) => {
            let v = p.version.to_string();
            *s.prepared_update.lock().unwrap() = Some(p);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_page(RESULT);
                ui.set_heading("Verified update ready".into());
                ui.set_detail(format!("CipherFS {v} is staged and verified.").into());
                ui.set_primary_label("Close and install".into());
                ui.set_secondary_label("Not now".into());
            });
        }
        Err(e) => {
            let t = format!("{e:#}");
            let _ = weak.upgrade_in_event_loop(move |ui| show_error(&ui, &t));
        }
    });
    Ok(())
}

fn run_background(
    ui: &AppWindow,
    title: &str,
    task: impl FnOnce() -> Result<String> + Send + 'static,
) -> Result<()> {
    ui.set_page(PROGRESS);
    ui.set_heading(title.into());
    ui.set_cancel_enabled(false);
    let weak = ui.as_weak();
    std::thread::spawn(move || match task() {
        Ok(m) => {
            let _ = weak.upgrade_in_event_loop(move |ui| show_result(&ui, &m));
        }
        Err(e) => {
            let t = format!("{e:#}");
            let _ = weak.upgrade_in_event_loop(move |ui| show_error(&ui, &t));
        }
    });
    Ok(())
}

fn confirm_overlay(ui: &AppWindow, state: &Arc<RuntimeState>) {
    ui.set_overlay_visible(false);
    if let Some(op) = state.operation.lock().unwrap().as_ref() {
        if ui.get_overlay_confirm_label().as_str() == "Force close" {
            op.force_close()
        } else {
            let _ = op.request_cancel();
        }
        return;
    }
    let mount = state.mount.lock().unwrap().take();
    if let Some(mount) = mount {
        ui.set_page(PROGRESS);
        ui.set_heading("Unmounting CipherFS".into());
        ui.set_cancel_enabled(false);
        let weak = ui.as_weak();
        let runtime = Arc::clone(state);
        std::thread::spawn(move || match mount.unmount() {
            Ok(()) => {
                runtime
                    .controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::Unmounted(Ok(())));
                let _ =
                    weak.upgrade_in_event_loop(move |ui| show_result(&ui, "Container unmounted."));
            }
            Err(e) => {
                let t = format!("{e:#}");
                runtime
                    .controller
                    .lock()
                    .unwrap()
                    .transition(AppAction::Unmounted(Err(t.clone())));
                let _ = weak.upgrade_in_event_loop(move |ui| show_error(&ui, &t));
            }
        });
    }
}

fn owner_hwnd(ui: &AppWindow) -> Result<HWND> {
    let slint_handle = ui.window().window_handle();
    let h = slint_handle
        .window_handle()
        .context("Slint window handle is unavailable")?;
    match h.as_raw() {
        RawWindowHandle::Win32(w) => Ok(HWND(w.hwnd.get() as *mut _)),
        _ => anyhow::bail!("Slint is not using a Win32 window"),
    }
}
fn clear_secrets(ui: &AppWindow) {
    ui.set_password("".into());
    ui.set_password_confirm("".into());
    ui.set_old_password("".into());
    ui.set_duress_password("".into());
    ui.set_duress_confirm("".into());
}
fn show_result(ui: &AppWindow, text: &str) {
    ui.set_page(RESULT);
    ui.set_heading("Completed".into());
    ui.set_detail(text.into());
    ui.set_path_text("".into());
    ui.set_primary_label("Close".into());
    ui.set_secondary_label("".into());
}
fn show_error(ui: &AppWindow, text: &str) {
    ui.set_page(ERROR);
    ui.set_heading("CipherFS error".into());
    ui.set_detail(text.into());
    ui.set_path_text("".into());
    ui.set_primary_label(
        if text.contains("WinFsp") {
            "Open WinFsp download page"
        } else {
            "Close"
        }
        .into(),
    );
    ui.set_secondary_label("".into());
}
fn show_overlay(ui: &AppWindow, title: &str, detail: &str, label: &str) {
    ui.set_overlay_title(title.into());
    ui.set_overlay_detail(detail.into());
    ui.set_overlay_confirm_label(label.into());
    ui.set_overlay_visible(true);
}
fn phase_text(p: crate::protocol::Phase) -> &'static str {
    match p {
        crate::protocol::Phase::Scan => "Scanning...",
        crate::protocol::Phase::KeyDerivation => "Deriving key...",
        crate::protocol::Phase::Encrypt => "Encrypting...",
        crate::protocol::Phase::SelfVerify => "Verifying new container...",
        crate::protocol::Phase::Extract => "Extracting...",
        crate::protocol::Phase::Verify => "Verifying...",
        crate::protocol::Phase::Commit => "Committing...",
    }
}
fn progress_text(p: crate::protocol::Phase, c: u64, t: u64) -> String {
    if t == 0 {
        phase_text(p).into()
    } else {
        format!(
            "{}: {} / {} MiB",
            phase_text(p).trim_end_matches("..."),
            c / (1024 * 1024),
            t / (1024 * 1024)
        )
    }
}
fn default_pack_output(source: &Path) -> Result<PathBuf> {
    let name = source
        .file_name()
        .context("Pack source directory has no name")?
        .to_string_lossy();
    Ok(source.with_file_name(format!("{name}.cfs")))
}

fn validate_new_password(
    password: &str,
    confirmation: &str,
    duress: Option<(&str, &str)>,
) -> Result<()> {
    anyhow::ensure!(!password.is_empty(), "Password must not be empty");
    anyhow::ensure!(password == confirmation, "Passwords do not match");
    if let Some((duress, confirmation)) = duress {
        anyhow::ensure!(duress == confirmation, "Duress passwords do not match");
        anyhow::ensure!(
            duress != password,
            "The Duress Password must differ from the master password"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn new_password_validation_rejects_mismatches_and_equal_duress() {
        assert!(validate_new_password("master", "different", None).is_err());
        assert!(validate_new_password("master", "master", Some(("duress", "different"))).is_err());
        assert!(validate_new_password("master", "master", Some(("master", "master"))).is_err());
        assert!(validate_new_password("master", "master", Some(("duress", "duress"))).is_ok());
    }

    #[test]
    fn clearing_secrets_removes_every_slint_password_value() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().unwrap();
        ui.set_password("master".into());
        ui.set_password_confirm("master".into());
        ui.set_old_password("old".into());
        ui.set_duress_password("duress".into());
        ui.set_duress_confirm("duress".into());

        clear_secrets(&ui);

        assert!(ui.get_password().is_empty());
        assert!(ui.get_password_confirm().is_empty());
        assert!(ui.get_old_password().is_empty());
        assert!(ui.get_duress_password().is_empty());
        assert!(ui.get_duress_confirm().is_empty());
    }

    #[test]
    fn accessible_button_action_dispatches_the_slint_callback() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().unwrap();
        ui.set_page(ACTIONS);
        ui.set_primary_label("Mount".into());
        ui.set_secondary_label("Extract".into());
        ui.set_tertiary_label("Verify".into());
        ui.set_quaternary_label("Change password".into());
        let invoked = Rc::new(Cell::new(false));
        let observed = Rc::clone(&invoked);
        ui.on_secondary_action(move || observed.set(true));
        let buttons = i_slint_backend_testing::ElementHandle::find_by_element_id(
            &ui,
            "AppWindow::secondary-action-button",
        )
        .collect::<Vec<_>>();
        assert_eq!(buttons.len(), 1);
        assert_eq!(buttons[0].accessible_label().as_deref(), Some("Extract"));
        buttons[0].invoke_accessible_default_action();
        assert!(invoked.get());
    }
}
