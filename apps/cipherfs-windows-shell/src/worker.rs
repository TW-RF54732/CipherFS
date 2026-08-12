use crate::protocol::{
    ArtifactKind, ErrorKindDto, PROTOCOL_VERSION, ParentCommand, Phase, WorkerEvent,
    WorkerOperation, WorkerRequest, read_frame, write_frame,
};
use anyhow::{Context, Result};
use cipherfs_core::operation::{
    CancellationToken, CoreErrorKind, OperationControl, OperationEvent, OperationPhase,
    OperationProgress, ProgressReporter, TemporaryArtifactKind,
};
use cipherfs_core::{ExtractOptions, ExtractRequest, PackOptions, PackRequest};
use cipherfs_core::{VerifyOptions, VerifyRequest};
use std::io::Stdout;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};

struct PipeReporter {
    output: Arc<Mutex<Stdout>>,
}

impl PipeReporter {
    fn send(&self, event: &WorkerEvent) {
        let _ = write_frame(
            &mut *self.output.lock().expect("worker stdout lock poisoned"),
            event,
        );
    }
}

impl ProgressReporter for PipeReporter {
    fn report(&self, progress: OperationProgress) {
        self.send(&WorkerEvent::Progress {
            phase: phase(progress.phase),
            completed: progress.completed,
            total: progress.total,
        });
    }

    fn event(&self, event: OperationEvent) {
        match event {
            OperationEvent::PhaseStarted(value) => {
                self.send(&WorkerEvent::PhaseStarted(phase(value)))
            }
            OperationEvent::Progress(value) => self.report(value),
            OperationEvent::Warning(value) => self.send(&WorkerEvent::Warning(value)),
            OperationEvent::TemporaryArtifact { kind, path } => {
                self.send(&WorkerEvent::TemporaryArtifact {
                    kind: match kind {
                        TemporaryArtifactKind::PackContainer => ArtifactKind::PackContainer,
                        TemporaryArtifactKind::ExtractionTree => ArtifactKind::ExtractionTree,
                    },
                    path,
                })
            }
            OperationEvent::CommitStarted => self.send(&WorkerEvent::CommitStarted),
            OperationEvent::Committed => self.send(&WorkerEvent::Committed),
            OperationEvent::MutationStarted => self.send(&WorkerEvent::MutationStarted),
            OperationEvent::ScanCompleted { .. } => {}
        }
    }
}

pub fn run_stdio() -> Result<()> {
    let request: WorkerRequest = read_frame(&mut std::io::stdin())?
        .context("Worker stdin closed before the operation request")?;
    anyhow::ensure!(
        request.version == PROTOCOL_VERSION,
        "Unsupported CipherFS worker protocol version {}",
        request.version
    );

    let output = Arc::new(Mutex::new(std::io::stdout()));
    let reporter = PipeReporter {
        output: Arc::clone(&output),
    };
    let cancellation = CancellationToken::default();
    let command_cancellation = cancellation.clone();
    let (command_sender, commands) = mpsc::channel();
    std::thread::spawn(move || {
        let mut input = std::io::stdin();
        loop {
            match read_frame::<_, ParentCommand>(&mut input) {
                Ok(Some(ParentCommand::Cancel)) => command_cancellation.cancel(),
                Ok(Some(command @ ParentCommand::Unmount)) => {
                    if command_sender.send(command).is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => {
                    command_cancellation.cancel();
                    let _ = command_sender.send(ParentCommand::Unmount);
                    break;
                }
            }
        }
    });

    let result = execute(request.operation, &cancellation, &reporter, &commands);
    let terminal = match result {
        Ok(()) => WorkerEvent::Succeeded,
        Err(error) => WorkerEvent::Failed {
            kind: error_kind(cipherfs_core::operation::error_kind(&error)),
            message: format!("{error:#}"),
        },
    };
    write_frame(
        &mut *output.lock().expect("worker stdout lock poisoned"),
        &terminal,
    )?;
    Ok(())
}

fn execute(
    operation: WorkerOperation,
    cancellation: &CancellationToken,
    reporter: &PipeReporter,
    commands: &mpsc::Receiver<ParentCommand>,
) -> Result<()> {
    match operation {
        WorkerOperation::Pack {
            source,
            output,
            temporary,
            password,
            duress_password,
        } => cipherfs_core::pack(
            PackRequest {
                source: &source,
                output: &output,
                password: password.expose(),
                duress_password: duress_password.as_ref().map(|secret| secret.expose()),
                options: PackOptions {
                    temporary_path: Some(temporary),
                    ..PackOptions::default()
                },
            },
            OperationControl::new(cancellation, reporter),
        ),
        WorkerOperation::Extract {
            container,
            output,
            staging,
            password,
        } => cipherfs_core::extract(
            ExtractRequest {
                container: &container,
                output: &output,
                password: password.expose(),
                options: ExtractOptions {
                    threads: 0,
                    staging_path: Some(staging),
                },
            },
            OperationControl::new(cancellation, reporter),
        ),
        WorkerOperation::Verify {
            container,
            password,
        } => cipherfs_core::verify(
            VerifyRequest {
                container: &container,
                password: password.expose(),
                options: VerifyOptions::default(),
            },
            OperationControl::new(cancellation, reporter),
        ),
        WorkerOperation::Mount {
            container,
            password,
        } => {
            let mut session = cipherfs_winfsp::WinFspMountSession::start(
                &container,
                Path::new("auto"),
                password.expose(),
                64,
            )?;
            let path = session.mount_path().to_path_buf();
            reporter.send(&WorkerEvent::Mounted { path });
            loop {
                match commands.recv() {
                    Ok(ParentCommand::Unmount) | Err(_) => break,
                    Ok(ParentCommand::Cancel) => {}
                }
            }
            session.unmount();
            Ok(())
        }
        WorkerOperation::ChangePassword {
            container,
            old_password,
            new_password,
        } => cipherfs_core::change_password_with_control(
            &container,
            old_password.expose(),
            new_password.expose(),
            cancellation,
            reporter,
        ),
    }
}

fn phase(value: OperationPhase) -> Phase {
    match value {
        OperationPhase::Scan => Phase::Scan,
        OperationPhase::KeyDerivation => Phase::KeyDerivation,
        OperationPhase::Encrypt => Phase::Encrypt,
        OperationPhase::SelfVerify => Phase::SelfVerify,
        OperationPhase::Extract => Phase::Extract,
        OperationPhase::Verify => Phase::Verify,
        OperationPhase::Commit => Phase::Commit,
    }
}

fn error_kind(value: CoreErrorKind) -> ErrorKindDto {
    match value {
        CoreErrorKind::Cancelled => ErrorKindDto::Cancelled,
        CoreErrorKind::Authentication => ErrorKindDto::Authentication,
        CoreErrorKind::Integrity => ErrorKindDto::Integrity,
        CoreErrorKind::InvalidFormat => ErrorKindDto::InvalidFormat,
        CoreErrorKind::UnsafePath => ErrorKindDto::UnsafePath,
        CoreErrorKind::DestinationExists => ErrorKindDto::DestinationExists,
        CoreErrorKind::SourceChanged => ErrorKindDto::SourceChanged,
        CoreErrorKind::Io => ErrorKindDto::Io,
        CoreErrorKind::Internal => ErrorKindDto::Internal,
    }
}
