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

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug)]
pub enum ControllerEvent {
    Phase(Phase),
    Progress {
        phase: Phase,
        completed: u64,
        total: u64,
    },
    Warning(String),
    Protected,
    Finished(Result<(), String>),
}

pub struct OperationHandle {
    child: Mutex<Option<Child>>,
    input: Mutex<Option<ChildStdin>>,
    expected_artifact: Option<PathBuf>,
    cancelling: AtomicBool,
    protected: AtomicBool,
}

impl OperationHandle {
    pub fn start(
        operation: WorkerOperation,
        expected_artifact: Option<PathBuf>,
        emit: impl Fn(ControllerEvent) + Send + 'static,
    ) -> Result<Arc<Self>> {
        let (child, input, output) = spawn_worker(operation)?;
        let handle = Arc::new(Self {
            child: Mutex::new(Some(child)),
            input: Mutex::new(Some(input)),
            expected_artifact,
            cancelling: AtomicBool::new(false),
            protected: AtomicBool::new(false),
        });
        let thread_handle = Arc::clone(&handle);
        std::thread::spawn(move || run_events(output, &thread_handle, emit));
        Ok(handle)
    }

    pub fn request_cancel(&self) -> Result<bool> {
        if self.protected.load(Ordering::SeqCst) {
            return Ok(false);
        }
        if self.cancelling.swap(true, Ordering::SeqCst) {
            return Ok(true);
        }
        let mut input = self.input.lock().expect("worker input poisoned");
        write_frame(
            input.as_mut().context("Worker input pipe is closed")?,
            &ParentCommand::Cancel,
        )?;
        Ok(false)
    }

    pub fn force_close(&self) {
        if let Some(child) = self.child.lock().expect("worker child poisoned").as_mut() {
            let _ = child.kill();
        }
    }

    pub fn is_protected(&self) -> bool {
        self.protected.load(Ordering::SeqCst)
    }
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

fn run_events(mut output: ChildStdout, state: &OperationHandle, emit: impl Fn(ControllerEvent)) {
    let mut committed = false;
    let result = loop {
        match read_frame::<_, WorkerEvent>(&mut output) {
            Ok(Some(WorkerEvent::PhaseStarted(phase))) => emit(ControllerEvent::Phase(phase)),
            Ok(Some(WorkerEvent::Progress {
                phase,
                completed,
                total,
            })) => emit(ControllerEvent::Progress {
                phase,
                completed,
                total,
            }),
            Ok(Some(WorkerEvent::TemporaryArtifact { path, .. }))
                if state.expected_artifact.as_ref() == Some(&path) => {}
            Ok(Some(WorkerEvent::TemporaryArtifact { .. })) => {
                break Err("Worker reported an unexpected temporary artifact".into());
            }
            Ok(Some(WorkerEvent::CommitStarted | WorkerEvent::MutationStarted)) => {
                state.protected.store(true, Ordering::SeqCst);
                emit(ControllerEvent::Protected);
            }
            Ok(Some(WorkerEvent::Committed)) => committed = true,
            Ok(Some(WorkerEvent::Warning(message))) => emit(ControllerEvent::Warning(message)),
            Ok(Some(WorkerEvent::Succeeded)) => break Ok(()),
            Ok(Some(WorkerEvent::Failed {
                kind: ErrorKindDto::Cancelled,
                ..
            })) => break Err("Operation cancelled".into()),
            Ok(Some(WorkerEvent::Failed { message, .. })) => break Err(message),
            Ok(Some(WorkerEvent::Mounted { .. })) => {
                break Err("Operation worker returned an unexpected mount event".into());
            }
            Ok(None) if committed => break Ok(()),
            Ok(None) => break Err("CipherFS worker pipe closed before completion".into()),
            Err(error) => break Err(format!("Invalid CipherFS worker response: {error:#}")),
        }
    };
    if result.is_err() {
        if let Some(child) = state.child.lock().expect("worker child poisoned").as_mut() {
            let _ = child.kill();
        }
        cleanup_expected(state);
    }
    state.input.lock().expect("worker input poisoned").take();
    if let Some(mut child) = state.child.lock().expect("worker child poisoned").take() {
        let _ = child.wait();
    }
    emit(ControllerEvent::Finished(result));
}

pub(crate) fn spawn_worker(operation: WorkerOperation) -> Result<(Child, ChildStdin, ChildStdout)> {
    let mut child = worker_command(&std::env::current_exe()?)
        .spawn()
        .context("Unable to start isolated CipherFS operation worker")?;
    let mut input = child
        .stdin
        .take()
        .context("Worker stdin pipe is unavailable")?;
    let output = child
        .stdout
        .take()
        .context("Worker stdout pipe is unavailable")?;
    let request = WorkerRequest {
        version: PROTOCOL_VERSION,
        operation,
    };
    if let Err(error) = write_frame(&mut input, &request) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
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

fn cleanup_expected(state: &OperationHandle) {
    if let Some(path) = &state.expected_artifact {
        cleanup_path(path);
    }
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
    fn cleanup_removes_only_exact_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let exact = temp.path().join("exact.tmp");
        let other = temp.path().join("other.tmp");
        std::fs::write(&exact, b"x").unwrap();
        std::fs::write(&other, b"y").unwrap();
        cleanup_path(&exact);
        assert!(!exact.exists());
        assert!(other.exists());
    }
    #[test]
    fn generated_artifact_is_random_sibling() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("vault.cfs");
        let a = random_sibling(&final_path, false).unwrap();
        let b = random_sibling(&final_path, false).unwrap();
        assert_eq!(a.parent(), final_path.parent());
        assert_ne!(a, b);
    }
    #[test]
    fn worker_command_line_contains_only_hidden_mode() {
        let command = worker_command(Path::new("cipherfs-shell.exe"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [std::ffi::OsStr::new("--operation-worker")]
        );
    }
}
