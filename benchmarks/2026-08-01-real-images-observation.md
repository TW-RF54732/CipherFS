# 26.7 GiB Real-Image Extraction Observation

Date: 2026-08-01

Status: exploratory field report based on user-observed timings. The commands
were not instrumented in a controlled harness, so this document records the
observation without treating it as a benchmark conclusion.

## Reported Runs

| Run | Binary/profile | Working and data paths | Command shape | Elapsed |
| --- | --- | --- | --- | ---: |
| Reference | Optimized release binary | Windows-mounted path under `/mnt/c` | `cipherfs extract myvault.fs .` | about 8 minutes |
| Exploratory | Default `cargo run` development build | launched from the WSL ext4 repository, with container and output under `/mnt/c` | `cargo run -- extract /mnt/c/.../myvault.fs /mnt/c/...` | about 3 hours |

Dataset: approximately 26.7 GiB of real image files.

## What This Does and Does Not Show

The 3-hour run is a valid usability observation, but it is not evidence that
multithreading alone caused a 22.5x regression. The two runs changed at least
the following variables:

- optimized release binary versus the default unoptimized Cargo development
  profile;
- binary revision;
- thread behavior;
- command invocation and output directory;
- potentially Windows filesystem cache and real-time malware-scanner state.

The process working directory (`~/Project/CipherFS` versus `/mnt/c/...`) is not
expected to dominate runtime when the container and output paths are absolute.
The build profile and the actual data paths are the more important variables.

The result also highlights a workload characteristic missing from the initial
synthetic benchmark: real image collections contain many files and a broad size
distribution. Files at or below 4 MiB contain one CipherFS chunk, so they cannot
benefit from within-file chunk parallelism during the current extraction path.

## Controlled Follow-up

Use the downloaded v2.1.0-beta.1 release asset for every run, new empty output
directories, and the same container:

```bash
cipherfs extract /mnt/c/.../myvault.fs /mnt/c/.../output-1 --threads 1
cipherfs extract /mnt/c/.../myvault.fs /mnt/c/.../output-4 --threads 4
cipherfs extract /mnt/c/.../myvault.fs /mnt/c/.../output-auto --threads 0
```

Then repeat a representative subset across the path matrix in
[`PARALLEL_BETA_TEST_PLAN.md`](PARALLEL_BETA_TEST_PLAN.md). Until those results
exist, both build-profile slowdown and WSL-to-NTFS filesystem behavior remain
live hypotheses.
