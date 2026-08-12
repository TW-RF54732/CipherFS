//! Presentation-neutral operation lifecycle shared by every frontend.

use anyhow::Result;
use std::fmt;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPhase {
    Scan,
    KeyDerivation,
    Encrypt,
    SelfVerify,
    Extract,
    Verify,
    Commit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationProgress {
    pub phase: OperationPhase,
    pub completed: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporaryArtifactKind {
    PackContainer,
    ExtractionTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationEvent {
    PhaseStarted(OperationPhase),
    ScanCompleted {
        entries: usize,
        bytes: u64,
    },
    Progress(OperationProgress),
    Warning(String),
    TemporaryArtifact {
        kind: TemporaryArtifactKind,
        path: PathBuf,
    },
    CommitStarted,
    Committed,
    MutationStarted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreErrorKind {
    Cancelled,
    Authentication,
    Integrity,
    InvalidFormat,
    UnsafePath,
    DestinationExists,
    SourceChanged,
    Io,
    Internal,
}

#[derive(Debug)]
pub struct CoreError {
    kind: CoreErrorKind,
    message: String,
}

impl CoreError {
    pub fn kind(&self) -> CoreErrorKind {
        self.kind
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CoreError {}

#[derive(Debug)]
pub struct OperationCancelled;

impl fmt::Display for OperationCancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CipherFS operation cancelled")
    }
}

impl std::error::Error for OperationCancelled {}

pub fn error_kind(error: &anyhow::Error) -> CoreErrorKind {
    if let Some(error) = error.downcast_ref::<CoreError>() {
        return error.kind();
    }
    if error.downcast_ref::<OperationCancelled>().is_some() {
        return CoreErrorKind::Cancelled;
    }
    if error.chain().any(|cause| cause.is::<std::io::Error>()) {
        return CoreErrorKind::Io;
    }
    CoreErrorKind::Internal
}

pub(crate) fn typed(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<CoreError>().is_some() {
        return error;
    }
    CoreError {
        kind: infer_kind(&error),
        message: format!("{error:#}"),
    }
    .into()
}

fn infer_kind(error: &anyhow::Error) -> CoreErrorKind {
    if error.downcast_ref::<OperationCancelled>().is_some() {
        return CoreErrorKind::Cancelled;
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("password") || message.contains("key slot") {
        CoreErrorKind::Authentication
    } else if message.contains("authentication") || message.contains("integrity") {
        CoreErrorKind::Integrity
    } else if message.contains("destination") && message.contains("exist") {
        CoreErrorKind::DestinationExists
    } else if message.contains("source file changed") {
        CoreErrorKind::SourceChanged
    } else if message.contains("unsafe")
        || message.contains("link")
        || message.contains("reparse")
        || message.contains("escape")
    {
        CoreErrorKind::UnsafePath
    } else if message.contains("format")
        || message.contains("header")
        || message.contains("container version")
    {
        CoreErrorKind::InvalidFormat
    } else if error.chain().any(|cause| cause.is::<std::io::Error>()) {
        CoreErrorKind::Io
    } else {
        CoreErrorKind::Internal
    }
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(OperationCancelled.into());
        }
        Ok(())
    }
}

pub trait ProgressReporter: Send + Sync {
    fn report(&self, progress: OperationProgress);

    fn event(&self, event: OperationEvent) {
        if let OperationEvent::Progress(progress) = event {
            self.report(progress);
        }
    }
}

#[derive(Default)]
pub struct NoProgress;

impl ProgressReporter for NoProgress {
    fn report(&self, _progress: OperationProgress) {}
}

#[derive(Clone, Copy)]
pub struct OperationControl<'a> {
    pub cancellation: &'a CancellationToken,
    pub reporter: &'a dyn ProgressReporter,
}

impl<'a> OperationControl<'a> {
    pub fn new(cancellation: &'a CancellationToken, reporter: &'a dyn ProgressReporter) -> Self {
        Self {
            cancellation,
            reporter,
        }
    }
}

/// Serializes parallel progress callbacks and guarantees non-decreasing byte
/// counts within one phase.
pub struct ProgressTracker<'a> {
    phase: OperationPhase,
    total: u64,
    completed: Mutex<u64>,
    reporter: &'a dyn ProgressReporter,
}

impl<'a> ProgressTracker<'a> {
    pub fn new(phase: OperationPhase, total: u64, reporter: &'a dyn ProgressReporter) -> Self {
        reporter.event(OperationEvent::PhaseStarted(phase));
        reporter.event(OperationEvent::Progress(OperationProgress {
            phase,
            completed: 0,
            total,
        }));
        Self {
            phase,
            total,
            completed: Mutex::new(0),
            reporter,
        }
    }

    pub fn advance(&self, amount: u64) -> u64 {
        let mut completed = self.completed.lock().expect("progress tracker poisoned");
        *completed = completed.saturating_add(amount).min(self.total);
        self.reporter
            .event(OperationEvent::Progress(OperationProgress {
                phase: self.phase,
                completed: *completed,
                total: self.total,
            }));
        *completed
    }

    pub fn position(&self) -> u64 {
        *self.completed.lock().expect("progress tracker poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingReporter(Mutex<Vec<OperationProgress>>);

    impl ProgressReporter for RecordingReporter {
        fn report(&self, progress: OperationProgress) {
            self.0.lock().unwrap().push(progress);
        }
    }

    #[test]
    fn parallel_progress_is_serialized_and_monotonic() {
        let reporter = RecordingReporter::default();
        let tracker = ProgressTracker::new(OperationPhase::Encrypt, 1_000, &reporter);
        std::thread::scope(|scope| {
            for _ in 0..10 {
                scope.spawn(|| {
                    for _ in 0..10 {
                        tracker.advance(10);
                    }
                });
            }
        });
        let events = reporter.0.lock().unwrap();
        assert_eq!(events.first().unwrap().completed, 0);
        assert_eq!(events.last().unwrap().completed, 1_000);
        assert!(
            events
                .windows(2)
                .all(|pair| pair[0].completed <= pair[1].completed)
        );
    }

    #[test]
    fn cancellation_has_a_typed_public_kind() {
        let token = CancellationToken::default();
        token.cancel();
        let error = typed(token.check().unwrap_err());
        assert_eq!(error_kind(&error), CoreErrorKind::Cancelled);
    }
}
