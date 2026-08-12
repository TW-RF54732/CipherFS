use crate::protocol::{
    ErrorKindDto, PROTOCOL_VERSION, ParentCommand, Phase, WorkerEvent, WorkerOperation,
    WorkerRequest, read_frame, write_frame,
};
use anyhow::{Context, Result};
use rand::Rng;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TDE_CONTENT, TDF_ALLOW_DIALOG_CANCELLATION,
    TDF_CALLBACK_TIMER, TDF_SHOW_PROGRESS_BAR, TDM_CLICK_BUTTON, TDM_SET_PROGRESS_BAR_POS,
    TDM_UPDATE_ELEMENT_TEXT, TDN_BUTTON_CLICKED, TDN_TIMER, TaskDialogIndirect,
};
use windows::Win32::UI::WindowsAndMessaging::{
    IDYES, MB_ICONWARNING, MB_YESNO, MessageBoxW, PostMessageW, SendMessageW,
};
use windows::core::{HRESULT, HSTRING, PCWSTR};

const CANCEL_BUTTON: i32 = 100;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug)]
struct WorkerFailure {
    kind: ErrorKindDto,
    message: String,
}

struct OperationState {
    child: Mutex<Option<Child>>,
    input: Mutex<Option<ChildStdin>>,
    progress: Mutex<Option<(Phase, u64, u64)>>,
    result: Mutex<Option<std::result::Result<(), WorkerFailure>>>,
    expected_artifact: Option<PathBuf>,
    observed_artifact: Mutex<Option<PathBuf>>,
    cancelling: AtomicBool,
    protected_zone: AtomicBool,
    force_closed: AtomicBool,
    committed: AtomicBool,
}

pub fn random_sibling(final_path: &Path, directory: bool) -> Result<PathBuf> {
    let absolute: PathBuf = std::path::absolute(final_path)?.components().collect();
    let parent = absolute
        .parent()
        .context("Output path must have a parent directory")?;
    for _ in 0..32 {
        let mut random = [0u8; 16];
        rand::rng().fill_bytes(&mut random);
        let suffix = if directory { "stage" } else { "tmp" };
        let candidate = parent.join(format!(".cipherfs-{}.{suffix}", hex::encode(random)));
        if std::fs::symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("Unable to allocate a private worker artifact name")
}

pub fn run_operation(
    title: &str,
    operation: WorkerOperation,
    expected_artifact: Option<PathBuf>,
) -> Result<bool> {
    let (mut child, input, output) = spawn_worker(operation)?;
    let state = Arc::new(OperationState {
        child: Mutex::new(Some(child)),
        input: Mutex::new(Some(input)),
        progress: Mutex::new(None),
        result: Mutex::new(None),
        expected_artifact,
        observed_artifact: Mutex::new(None),
        cancelling: AtomicBool::new(false),
        protected_zone: AtomicBool::new(false),
        force_closed: AtomicBool::new(false),
        committed: AtomicBool::new(false),
    });
    let reader_state = Arc::clone(&state);
    let reader = std::thread::spawn(move || read_operation_events(output, &reader_state));

    if let Err(error) = show_progress_dialog(title, &state) {
        kill_worker(&state);
        state.input.lock().expect("worker input poisoned").take();
        let _ = reader.join();
        if let Some(mut child) = state
            .child
            .lock()
            .expect("worker child lock poisoned")
            .take()
        {
            let _ = child.wait();
        }
        cleanup_exact_artifact(&state);
        return Err(error);
    }
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("CipherFS worker event reader panicked"))?;
    child = state
        .child
        .lock()
        .expect("worker child lock poisoned")
        .take()
        .context("CipherFS worker process handle was lost")?;
    let status = child.wait().context("Unable to wait for CipherFS worker")?;
    let result = state
        .result
        .lock()
        .expect("worker result lock poisoned")
        .take()
        .unwrap_or_else(|| {
            Err(WorkerFailure {
                kind: ErrorKindDto::WorkerCrashed,
                message: format!("CipherFS worker exited without a result ({status})"),
            })
        });
    if result.is_err() {
        cleanup_exact_artifact(&state);
    }
    match result {
        Ok(()) => Ok(true),
        Err(failure) if failure.kind == ErrorKindDto::Cancelled => Ok(false),
        Err(failure) => Err(anyhow::anyhow!(failure.message)),
    }
}

pub(crate) fn spawn_worker(operation: WorkerOperation) -> Result<(Child, ChildStdin, ChildStdout)> {
    let mut child = worker_command(&std::env::current_exe()?)
        .spawn()
        .context("Unable to start isolated CipherFS operation worker")?;
    let Some(mut input) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("Worker stdin pipe is unavailable");
    };
    let Some(output) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("Worker stdout pipe is unavailable");
    };
    let request = WorkerRequest {
        version: PROTOCOL_VERSION,
        operation,
    };
    if let Err(error) = write_frame(&mut input, &request) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("Unable to send the worker operation request");
    }
    Ok((child, input, output))
}

fn worker_command(executable: &Path) -> Command {
    use std::os::windows::process::CommandExt;

    let mut command = Command::new(executable);
    command
        .arg("--operation-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    command
}

fn read_operation_events(mut output: ChildStdout, state: &OperationState) {
    loop {
        match read_frame::<_, WorkerEvent>(&mut output) {
            Ok(Some(WorkerEvent::PhaseStarted(phase))) => {
                *state.progress.lock().expect("worker progress poisoned") = Some((phase, 0, 0));
            }
            Ok(Some(WorkerEvent::Progress {
                phase,
                completed,
                total,
            })) => {
                let mut current = state.progress.lock().expect("worker progress poisoned");
                if current.is_none_or(|(old_phase, old, _)| old_phase != phase || completed >= old)
                {
                    *current = Some((phase, completed, total));
                }
            }
            Ok(Some(WorkerEvent::TemporaryArtifact { path, .. })) => {
                if state.expected_artifact.as_ref() == Some(&path) {
                    *state
                        .observed_artifact
                        .lock()
                        .expect("artifact state poisoned") = Some(path);
                } else {
                    fail_protocol(state, "Worker reported an unexpected temporary artifact");
                    kill_worker(state);
                    break;
                }
            }
            Ok(Some(WorkerEvent::CommitStarted | WorkerEvent::MutationStarted)) => {
                state.protected_zone.store(true, Ordering::SeqCst);
            }
            Ok(Some(WorkerEvent::Committed)) => {
                state.committed.store(true, Ordering::SeqCst);
            }
            Ok(Some(WorkerEvent::Warning(_))) => {}
            Ok(Some(WorkerEvent::Succeeded)) => {
                *state.result.lock().expect("worker result poisoned") = Some(Ok(()));
                break;
            }
            Ok(Some(WorkerEvent::Failed { kind, message })) => {
                *state.result.lock().expect("worker result poisoned") =
                    Some(Err(WorkerFailure { kind, message }));
                break;
            }
            Ok(Some(WorkerEvent::Mounted { .. })) => {
                fail_protocol(state, "Operation worker returned an unexpected mount event");
                kill_worker(state);
                break;
            }
            Ok(None) => {
                if state
                    .result
                    .lock()
                    .expect("worker result poisoned")
                    .is_none()
                {
                    if state.committed.load(Ordering::SeqCst) {
                        *state.result.lock().expect("worker result poisoned") = Some(Ok(()));
                        break;
                    }
                    let message = if state.force_closed.load(Ordering::SeqCst) {
                        "CipherFS operation worker was force-closed; its recorded temporary artifact was removed"
                    } else {
                        "CipherFS worker pipe closed before completion"
                    };
                    *state.result.lock().expect("worker result poisoned") =
                        Some(Err(WorkerFailure {
                            kind: ErrorKindDto::WorkerCrashed,
                            message: message.to_string(),
                        }));
                }
                break;
            }
            Err(error) => {
                *state.result.lock().expect("worker result poisoned") = Some(Err(WorkerFailure {
                    kind: ErrorKindDto::WorkerProtocol,
                    message: format!("Invalid CipherFS worker response: {error:#}"),
                }));
                kill_worker(state);
                break;
            }
        }
    }
}

fn show_progress_dialog(title: &str, state: &Arc<OperationState>) -> Result<()> {
    let title = HSTRING::from(title);
    let instruction = HSTRING::from("CipherFS is working");
    let content = HSTRING::from("Starting isolated operation...");
    let cancel = HSTRING::from("Cancel");
    let button = TASKDIALOG_BUTTON {
        nButtonID: CANCEL_BUTTON,
        pszButtonText: PCWSTR::from_raw(cancel.as_ptr()),
    };
    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: HWND::default(),
        hInstance: Default::default(),
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER | TDF_SHOW_PROGRESS_BAR,
        dwCommonButtons: Default::default(),
        pszWindowTitle: PCWSTR::from_raw(title.as_ptr()),
        Anonymous1: Default::default(),
        pszMainInstruction: PCWSTR::from_raw(instruction.as_ptr()),
        pszContent: PCWSTR::from_raw(content.as_ptr()),
        cButtons: 1,
        pButtons: &button,
        nDefaultButton: CANCEL_BUTTON,
        pfCallback: Some(dialog_callback),
        lpCallbackData: Arc::as_ptr(state) as isize,
        ..Default::default()
    };
    unsafe { TaskDialogIndirect(&config, None, None, None) }
        .context("Unable to show CipherFS progress dialog")?;
    Ok(())
}

unsafe extern "system" fn dialog_callback(
    hwnd: HWND,
    message: windows::Win32::UI::Controls::TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    _lparam: LPARAM,
    callback_data: isize,
) -> HRESULT {
    let state = unsafe { &*(callback_data as *const OperationState) };
    if message == TDN_BUTTON_CLICKED {
        if state
            .result
            .lock()
            .expect("worker result poisoned")
            .is_some()
        {
            return HRESULT(0);
        }
        if state.protected_zone.load(Ordering::SeqCst) {
            update_text(
                hwnd,
                "CipherFS is committing the completed result. This short step cannot be cancelled safely.",
            );
            return HRESULT(1);
        }
        if state.cancelling.load(Ordering::SeqCst) {
            let title = HSTRING::from("Force close operation worker?");
            let warning = HSTRING::from(
                "The isolated worker is still waiting for a safe cancellation boundary. Force closing terminates only that worker; CipherFS will then remove the one recorded temporary artifact.\n\nForce close the worker now?",
            );
            if unsafe { MessageBoxW(Some(hwnd), &warning, &title, MB_YESNO | MB_ICONWARNING) }
                == IDYES
            {
                state.force_closed.store(true, Ordering::SeqCst);
                kill_worker(state);
            }
            return HRESULT(1);
        }
        let send_result = state
            .input
            .lock()
            .expect("worker input poisoned")
            .as_mut()
            .context("Worker input pipe is closed")
            .and_then(|input| write_frame(input, &ParentCommand::Cancel));
        if let Err(error) = send_result {
            *state.result.lock().expect("worker result poisoned") = Some(Err(WorkerFailure {
                kind: ErrorKindDto::WorkerProtocol,
                message: format!("Unable to request cancellation: {error:#}"),
            }));
            kill_worker(state);
        } else {
            state.cancelling.store(true, Ordering::SeqCst);
            update_text(
                hwnd,
                "Cancelling safely... Password derivation and the current chunk may need to finish. Click Cancel again to force close only the worker.",
            );
        }
        return HRESULT(1);
    }
    if message == TDN_TIMER {
        if state
            .result
            .lock()
            .expect("worker result poisoned")
            .is_some()
        {
            let _ = unsafe {
                PostMessageW(
                    Some(hwnd),
                    TDM_CLICK_BUTTON.0 as u32,
                    WPARAM(CANCEL_BUTTON as usize),
                    LPARAM(0),
                )
            };
        } else if !state.cancelling.load(Ordering::SeqCst)
            && let Some((phase, completed, total)) =
                *state.progress.lock().expect("worker progress poisoned")
        {
            let percent = if total == 0 {
                0
            } else {
                completed.saturating_mul(100) / total
            };
            unsafe {
                SendMessageW(
                    hwnd,
                    TDM_SET_PROGRESS_BAR_POS.0 as u32,
                    Some(WPARAM(percent.min(100) as usize)),
                    None,
                )
            };
            update_text(hwnd, &progress_text(phase, completed, total));
        }
    }
    HRESULT(0)
}

fn progress_text(phase: Phase, completed: u64, total: u64) -> String {
    let phase = match phase {
        Phase::Scan => "Scanning",
        Phase::KeyDerivation => "Deriving key",
        Phase::Encrypt => "Encrypting",
        Phase::SelfVerify => "Verifying new container",
        Phase::Extract => "Extracting",
        Phase::Verify => "Verifying",
        Phase::Commit => "Committing",
    };
    if total == 0 {
        format!("{phase}...")
    } else {
        format!(
            "{phase}: {} / {} MiB",
            completed / (1024 * 1024),
            total / (1024 * 1024)
        )
    }
}

fn update_text(hwnd: HWND, text: &str) {
    let text = HSTRING::from(text);
    unsafe {
        SendMessageW(
            hwnd,
            TDM_UPDATE_ELEMENT_TEXT.0 as u32,
            Some(WPARAM(TDE_CONTENT.0 as usize)),
            Some(LPARAM(text.as_ptr() as isize)),
        )
    };
}

fn fail_protocol(state: &OperationState, message: &str) {
    *state.result.lock().expect("worker result poisoned") = Some(Err(WorkerFailure {
        kind: ErrorKindDto::WorkerProtocol,
        message: message.to_string(),
    }));
}

fn kill_worker(state: &OperationState) {
    if let Some(child) = state.child.lock().expect("worker child poisoned").as_mut() {
        let _ = child.kill();
    }
}

fn cleanup_exact_artifact(state: &OperationState) {
    // The random sibling path came from the serialized request. It is the only
    // path cleanup may touch, including the race where the worker created it
    // but was killed before its TemporaryArtifact event reached the parent.
    let Some(path) = state.expected_artifact.clone() else {
        return;
    };
    cleanup_path(&path);
}

fn cleanup_path(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            let _ = std::fs::remove_file(path);
        }
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let _ = std::fs::remove_dir_all(path);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_only_the_exact_recorded_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let exact = temp.path().join("exact.tmp");
        let unrelated = temp.path().join("unrelated.tmp");
        std::fs::write(&exact, b"partial").unwrap();
        std::fs::write(&unrelated, b"keep").unwrap();
        cleanup_path(&exact);
        assert!(!exact.exists());
        assert!(unrelated.is_file());
    }

    #[test]
    fn generated_artifact_is_a_128_bit_random_sibling() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("vault.cfs");
        let first = random_sibling(&final_path, false).unwrap();
        let second = random_sibling(&final_path, false).unwrap();
        assert_eq!(first.parent(), final_path.parent());
        assert_ne!(first, second);
        let encoded = first.file_name().unwrap().to_string_lossy();
        assert_eq!(
            encoded
                .trim_start_matches(".cipherfs-")
                .trim_end_matches(".tmp")
                .len(),
            32
        );
    }

    #[test]
    fn worker_command_line_contains_only_the_hidden_mode() {
        let command = worker_command(Path::new("cipherfs-shell.exe"));
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(arguments, [std::ffi::OsStr::new("--operation-worker")]);
        assert!(command.get_envs().next().is_none());
    }
}
