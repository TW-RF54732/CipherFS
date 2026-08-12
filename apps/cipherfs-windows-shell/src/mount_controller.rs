//! Parent-side lifetime controller for the isolated WinFsp mount worker.

use crate::operation_controller::spawn_worker;
use crate::protocol::{ParentCommand, WorkerEvent, WorkerOperation, read_frame, write_frame};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout};

pub struct MountWorker {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    path: PathBuf,
    active: bool,
}

impl MountWorker {
    pub fn start(operation: WorkerOperation) -> Result<Self> {
        let (mut child, input, mut output) = spawn_worker(operation)?;
        loop {
            match read_frame::<_, WorkerEvent>(&mut output)? {
                Some(WorkerEvent::Mounted { path }) => {
                    return Ok(Self {
                        child,
                        input,
                        output,
                        path,
                        active: true,
                    });
                }
                Some(WorkerEvent::Failed { message, .. }) => {
                    let _ = child.wait();
                    return Err(anyhow::anyhow!(message));
                }
                Some(
                    WorkerEvent::Warning(_)
                    | WorkerEvent::PhaseStarted(_)
                    | WorkerEvent::Progress { .. },
                ) => {}
                Some(_) => anyhow::bail!("Mount worker returned an unexpected event"),
                None => anyhow::bail!("Mount worker exited before returning a mount path"),
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn unmount(mut self) -> Result<()> {
        write_frame(&mut self.input, &ParentCommand::Unmount)?;
        loop {
            match read_frame::<_, WorkerEvent>(&mut self.output)? {
                Some(WorkerEvent::Succeeded) => break,
                Some(WorkerEvent::Failed { message, .. }) => return Err(anyhow::anyhow!(message)),
                Some(_) => {}
                None => anyhow::bail!("Mount worker pipe closed during unmount"),
            }
        }
        let status = self.child.wait()?;
        self.active = false;
        anyhow::ensure!(status.success(), "Mount worker exited with {status}");
        Ok(())
    }
}

impl Drop for MountWorker {
    fn drop(&mut self) {
        if self.active {
            let _ = write_frame(&mut self.input, &ParentCommand::Unmount);
            for _ in 0..20 {
                if self.child.try_wait().ok().flatten().is_some() {
                    self.active = false;
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
