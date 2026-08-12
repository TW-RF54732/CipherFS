#![cfg(windows)]

use cipherfs_windows_shell::protocol::{
    ErrorKindDto, PROTOCOL_VERSION, ParentCommand, Phase, Secret, WorkerEvent, WorkerOperation,
    WorkerRequest, read_frame, write_frame,
};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

fn spawn() -> (Child, ChildStdin, ChildStdout) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cipherfs-shell"))
        .arg("--operation-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    (child, input, output)
}

fn pack_request(source: &Path, output: &Path, temporary: &Path) -> WorkerRequest {
    WorkerRequest {
        version: PROTOCOL_VERSION,
        operation: WorkerOperation::Pack {
            source: source.to_path_buf(),
            output: output.to_path_buf(),
            temporary: temporary.to_path_buf(),
            password: Secret::new("worker-test-password"),
            duress_password: None,
        },
    }
}

fn pack_fixture(source: &Path, container: &Path, password: &str) {
    let cancellation = cipherfs_core::operation::CancellationToken::default();
    let reporter = cipherfs_core::operation::NoProgress;
    cipherfs_core::pack(
        cipherfs_core::PackRequest {
            source,
            output: container,
            password,
            duress_password: None,
            options: cipherfs_core::PackOptions {
                argon2_m_cost: cipherfs_core::MIN_ARGON_MEMORY_KIB,
                argon2_t_cost: 1,
                argon2_p_cost: 1,
                threads: 1,
                ..Default::default()
            },
        },
        cipherfs_core::operation::OperationControl::new(&cancellation, &reporter),
    )
    .unwrap();
}

fn run_request(request: WorkerRequest) -> (Vec<WorkerEvent>, std::process::ExitStatus) {
    let (mut child, mut input, mut output) = spawn();
    write_frame(&mut input, &request).unwrap();
    let mut events = Vec::new();
    while let Some(event) = read_frame::<_, WorkerEvent>(&mut output).unwrap() {
        let terminal = matches!(event, WorkerEvent::Succeeded | WorkerEvent::Failed { .. });
        events.push(event);
        if terminal {
            break;
        }
    }
    drop(input);
    let status = child.wait().unwrap();
    (events, status)
}

fn read_terminal(output: &mut ChildStdout) -> (Vec<(Phase, u64)>, WorkerEvent) {
    let mut progress = Vec::new();
    loop {
        match read_frame(output).unwrap().unwrap() {
            WorkerEvent::Progress {
                phase, completed, ..
            } => progress.push((phase, completed)),
            terminal @ (WorkerEvent::Succeeded | WorkerEvent::Failed { .. }) => {
                return (progress, terminal);
            }
            _ => {}
        }
    }
}

#[test]
fn worker_pack_reports_monotonic_progress_and_commits() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let output = temp.path().join("vault.cfs");
    let temporary = temp.path().join(".exact-worker.tmp");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("data.bin"), vec![0x5a; 1024 * 1024 + 17]).unwrap();

    let (mut child, mut input, mut worker_output) = spawn();
    write_frame(&mut input, &pack_request(&source, &output, &temporary)).unwrap();
    let (progress, terminal) = read_terminal(&mut worker_output);
    drop(input);
    assert!(matches!(terminal, WorkerEvent::Succeeded));
    assert!(child.wait().unwrap().success());
    assert!(output.is_file());
    assert!(!temporary.exists());
    assert!(
        progress
            .windows(2)
            .all(|pair| { pair[0].0 != pair[1].0 || pair[0].1 <= pair[1].1 })
    );
    assert!(progress.iter().any(|(phase, _)| *phase == Phase::Encrypt));
    assert!(
        progress
            .iter()
            .any(|(phase, _)| *phase == Phase::SelfVerify)
    );
    assert!(!progress.iter().any(|(phase, _)| *phase == Phase::Verify));
}

#[test]
fn worker_extract_round_trip_reports_commit_and_cleans_staging() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let container = temp.path().join("vault.cfs");
    let output = temp.path().join("output");
    let staging = temp.path().join(".extract.stage");
    std::fs::create_dir_all(source.join("empty")).unwrap();
    std::fs::write(source.join("data.bin"), vec![0x5a; 1024 * 1024 + 17]).unwrap();
    pack_fixture(&source, &container, "extract-password");
    let (events, status) = run_request(WorkerRequest {
        version: PROTOCOL_VERSION,
        operation: WorkerOperation::Extract {
            container,
            output: output.clone(),
            staging: staging.clone(),
            password: Secret::new("extract-password"),
        },
    });
    assert!(status.success());
    assert!(matches!(events.last(), Some(WorkerEvent::Succeeded)));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, WorkerEvent::CommitStarted))
    );
    assert_eq!(
        std::fs::read(output.join("data.bin")).unwrap(),
        vec![0x5a; 1024 * 1024 + 17]
    );
    assert!(output.join("empty").is_dir());
    assert!(!staging.exists());
}

#[test]
fn worker_extract_rejects_wrong_password_corruption_and_existing_destination() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let container = temp.path().join("vault.cfs");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("data.bin"), b"secret").unwrap();
    pack_fixture(&source, &container, "right-password");

    for (name, password, precreate, corrupt) in [
        ("wrong", "wrong-password", false, false),
        ("existing", "right-password", true, false),
        ("corrupt", "right-password", false, true),
    ] {
        let case_container = temp.path().join(format!("{name}.cfs"));
        std::fs::copy(&container, &case_container).unwrap();
        if corrupt {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&case_container)
                .unwrap();
            file.seek(SeekFrom::End(-1)).unwrap();
            file.write_all(&[0]).unwrap();
        }
        let output = temp.path().join(format!("{name}-output"));
        let staging = temp.path().join(format!(".{name}.stage"));
        if precreate {
            std::fs::create_dir(&output).unwrap();
        }
        let (events, _) = run_request(WorkerRequest {
            version: PROTOCOL_VERSION,
            operation: WorkerOperation::Extract {
                container: case_container,
                output: output.clone(),
                staging: staging.clone(),
                password: Secret::new(password),
            },
        });
        assert!(
            matches!(events.last(), Some(WorkerEvent::Failed { .. })),
            "{name}"
        );
        assert_eq!(output.exists(), precreate, "{name}");
        assert!(!staging.exists(), "{name}");
    }
}

#[test]
fn worker_verify_and_password_change_cover_success_and_failure() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let container = temp.path().join("vault.cfs");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("data.bin"), b"secret").unwrap();
    pack_fixture(&source, &container, "old-password");

    for password in ["old-password", "wrong-password"] {
        let (events, _) = run_request(WorkerRequest {
            version: PROTOCOL_VERSION,
            operation: WorkerOperation::Verify {
                container: container.clone(),
                password: Secret::new(password),
            },
        });
        assert_eq!(
            matches!(events.last(), Some(WorkerEvent::Succeeded)),
            password == "old-password"
        );
    }

    let (events, status) = run_request(WorkerRequest {
        version: PROTOCOL_VERSION,
        operation: WorkerOperation::ChangePassword {
            container: container.clone(),
            old_password: Secret::new("old-password"),
            new_password: Secret::new("new-password"),
        },
    });
    assert!(status.success());
    assert!(
        events
            .iter()
            .any(|event| matches!(event, WorkerEvent::MutationStarted))
    );
    assert!(matches!(events.last(), Some(WorkerEvent::Succeeded)));
    for (password, succeeds) in [("old-password", false), ("new-password", true)] {
        let (events, _) = run_request(WorkerRequest {
            version: PROTOCOL_VERSION,
            operation: WorkerOperation::Verify {
                container: container.clone(),
                password: Secret::new(password),
            },
        });
        assert_eq!(
            matches!(events.last(), Some(WorkerEvent::Succeeded)),
            succeeds
        );
    }
}

#[test]
fn worker_cancel_and_parent_pipe_close_are_safe() {
    for close_pipe in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("vault.cfs");
        let temporary = temp.path().join(".exact-worker.tmp");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("data.bin"), vec![0x41; 1024 * 1024]).unwrap();

        let (mut child, mut input, mut worker_output) = spawn();
        write_frame(&mut input, &pack_request(&source, &output, &temporary)).unwrap();
        if close_pipe {
            drop(input);
        } else {
            write_frame(&mut input, &ParentCommand::Cancel).unwrap();
        }
        let (_, terminal) = read_terminal(&mut worker_output);
        assert!(matches!(
            terminal,
            WorkerEvent::Failed {
                kind: ErrorKindDto::Cancelled,
                ..
            }
        ));
        assert!(child.wait().unwrap().success());
        assert!(!output.exists());
        assert!(!temporary.exists());
    }
}

#[test]
fn force_killed_worker_leaves_no_success_and_cleanup_is_exact() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let output = temp.path().join("vault.cfs");
    let temporary = temp.path().join(".exact-worker.tmp");
    let unrelated = temp.path().join("keep.tmp");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("data.bin"), vec![0x41; 16 * 1024 * 1024]).unwrap();
    std::fs::write(&unrelated, b"keep").unwrap();

    let (mut child, mut input, mut worker_output) = spawn();
    write_frame(&mut input, &pack_request(&source, &output, &temporary)).unwrap();
    loop {
        match read_frame::<_, WorkerEvent>(&mut worker_output)
            .unwrap()
            .unwrap()
        {
            WorkerEvent::TemporaryArtifact { path, .. } => {
                assert_eq!(path, temporary);
                break;
            }
            WorkerEvent::Failed { message, .. } => panic!("worker failed before kill: {message}"),
            _ => {}
        }
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    if temporary.is_file() {
        std::fs::remove_file(&temporary).unwrap();
    }
    assert!(!output.exists());
    assert!(!temporary.exists());
    assert!(unrelated.is_file());
}

#[test]
fn oversized_worker_request_is_rejected_before_payload_allocation() {
    use std::io::Write;

    let (mut child, mut input, _output) = spawn();
    input
        .write_all(&((cipherfs_windows_shell::protocol::MAX_FRAME_SIZE as u32) + 1).to_le_bytes())
        .unwrap();
    input.flush().unwrap();
    drop(input);
    assert!(!child.wait().unwrap().success());
}

#[test]
fn unknown_protocol_version_exits_without_echoing_password() {
    let (mut child, mut input, mut output) = spawn();
    let secret = "never-echo-this-password";
    let request = WorkerRequest {
        version: PROTOCOL_VERSION + 1,
        operation: WorkerOperation::Verify {
            container: PathBuf::from("missing.cfs"),
            password: Secret::new(secret),
        },
    };
    write_frame(&mut input, &request).unwrap();
    drop(input);
    let mut captured = Vec::new();
    while let Some(event) = read_frame::<_, WorkerEvent>(&mut output).unwrap_or(None) {
        captured.push(format!("{event:?}"));
    }
    let status = child.wait().unwrap();
    let stderr = child.stderr.take().map(|mut value| {
        use std::io::Read;
        let mut bytes = Vec::new();
        value.read_to_end(&mut bytes).unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    });
    assert!(!status.success());
    assert!(!captured.join("\n").contains(secret));
    assert!(!stderr.unwrap_or_default().contains(secret));
}

#[test]
#[ignore = "requires the pinned WinFsp runtime and a free drive letter"]
fn worker_mount_session_auto_drive_and_unmount() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let container = temp.path().join("vault.cfs");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("read-only.txt"), b"mounted through worker").unwrap();
    let cancellation = cipherfs_core::operation::CancellationToken::default();
    let reporter = cipherfs_core::operation::NoProgress;
    cipherfs_core::pack(
        cipherfs_core::PackRequest {
            source: &source,
            output: &container,
            password: "worker-mount-password",
            duress_password: None,
            options: cipherfs_core::PackOptions {
                argon2_m_cost: cipherfs_core::MIN_ARGON_MEMORY_KIB,
                argon2_t_cost: 1,
                argon2_p_cost: 1,
                max_index_size: cipherfs_core::MAX_INDEX_SIZE,
                threads: 1,
                temporary_path: None,
            },
        },
        cipherfs_core::operation::OperationControl::new(&cancellation, &reporter),
    )
    .unwrap();

    let (mut child, mut input, mut output) = spawn();
    write_frame(
        &mut input,
        &WorkerRequest {
            version: PROTOCOL_VERSION,
            operation: WorkerOperation::Mount {
                container,
                password: Secret::new("worker-mount-password"),
            },
        },
    )
    .unwrap();
    let mounted = loop {
        match read_frame::<_, WorkerEvent>(&mut output).unwrap().unwrap() {
            WorkerEvent::Mounted { path } => break path,
            WorkerEvent::Failed { message, .. } => panic!("mount worker failed: {message}"),
            _ => {}
        }
    };
    assert_eq!(mounted.as_os_str().to_string_lossy().len(), 2);
    assert_eq!(
        mounted.as_os_str().to_string_lossy().chars().nth(1),
        Some(':')
    );
    assert_eq!(
        std::fs::read(mounted.join("read-only.txt")).unwrap(),
        b"mounted through worker"
    );
    assert!(std::fs::write(mounted.join("new.txt"), b"denied").is_err());

    write_frame(&mut input, &ParentCommand::Unmount).unwrap();
    loop {
        match read_frame::<_, WorkerEvent>(&mut output).unwrap().unwrap() {
            WorkerEvent::Succeeded => break,
            WorkerEvent::Failed { message, .. } => panic!("unmount failed: {message}"),
            _ => {}
        }
    }
    assert!(child.wait().unwrap().success());
    assert!(std::fs::read(mounted.join("read-only.txt")).is_err());
}
