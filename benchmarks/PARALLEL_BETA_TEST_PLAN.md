# v2.1 Parallel Chunk Beta Test Plan

This plan is for the v2.1.0 beta series. Its purpose is to identify where CPU
parallelism helps, where filesystem behavior dominates, and where defaults need
to change before a stable release.

## Test Invariants

- Use a downloaded and verified release asset, or `cargo build --release`.
- Never compare the default `cargo run` development profile with release data.
- Use the same container, password, machine power mode, and foreground workload
  within a comparison series.
- Use a new empty extraction directory for every run.
- Record every sample, including slow results and outliers.
- Record progress-bar ETA separately from actual wall-clock elapsed time; ETA is
  an observed-throughput estimate, not a completed benchmark.
- Verify extracted content after timing.
- Keep the existing corruption requirement: authentication failure must not
  commit output files under their final names.

## Dataset Classes

Test at least three shapes because equal byte totals can exercise very different
code and filesystem paths:

| Class | Suggested shape | What it exercises |
| --- | --- | --- |
| Large sequential | One 2-10 GiB file | many chunks in one file; best case for chunk parallelism |
| Real images | Existing 26.7 GiB image collection | representative file sizes and metadata operations |
| Small-file stress | 10,000+ files below 4 MiB | one chunk per file; per-file filesystem overhead |

Record total bytes, file count, median size, 90th-percentile size, and the number
of files above 4 MiB.

## Filesystem Path Matrix

Run a smaller representative subset through all four combinations before a
full 26.7 GiB sweep:

| Source/container | Destination | Interpretation |
| --- | --- | --- |
| WSL ext4 | WSL ext4 | native Linux baseline |
| `/mnt/c` NTFS | WSL ext4 | isolates cross-filesystem input reads |
| WSL ext4 | `/mnt/c` NTFS | isolates cross-filesystem output writes and metadata |
| `/mnt/c` NTFS | `/mnt/c` NTFS | actual Windows-folder workflow |

For pack, treat source and container as the two endpoints. For extract, treat
container and output directory as the two endpoints.

## Thread Sweep

Start with `--threads 1`, then test `2`, `4`, `8`, and `0` (automatic). Stop a
series early if elapsed time exceeds twice the one-thread result and the process
is otherwise healthy. Record logical CPU count so `0` can be interpreted.

## Cache and Windows Observations

- Label the first run after boot or copy as cold-ish; do not silently average it
  with later warm-cache runs.
- Record Windows Task Manager or Resource Monitor observations for `VmmemWSL`,
  `System`, and `MsMpEng.exe`.
- Low SSD throughput does not rule out an I/O bottleneck: also note active time,
  response time, queue length, CPU system time, and whether worker CPU usage is
  low while elapsed time rises.
- Do not disable Defender globally. If scanner impact needs testing, use a
  narrowly scoped temporary test directory and record the exact policy change.

## Commands

```bash
/usr/bin/time -v cipherfs extract container.cfs output-1 --threads 1
/usr/bin/time -v cipherfs extract container.cfs output-4 --threads 4
/usr/bin/time -v cipherfs extract container.cfs output-auto --threads 0
```

Capture release manifest version and SHA-256 before starting. For correctness,
compare the extracted tree to the source using an appropriate byte-level tool.

## Beta Decision Criteria

The parallel implementation is a stable-release candidate only when:

- round-trip, corruption, and no-partial-commit tests pass;
- `--threads 1` has no material regression from v2.0.0 on the same release
  workload and filesystem;
- the recommended thread setting improves at least one representative large
  workload without catastrophic regression on `/mnt/c` or small-file data;
- peak memory remains bounded and acceptable at the documented worker count;
- any environment-specific defaults or limitations are backed by recorded raw
  samples rather than a single timing.

## Report Template

```text
CipherFS version/tag:
Release asset SHA-256:
OS and WSL version:
CPU / logical CPUs / memory:
Power mode:
Source or container filesystem:
Destination filesystem:
Dataset bytes / files / median size / files above 4 MiB:
Operation:
--threads:
Run number:
Elapsed / user CPU / system CPU:
Displayed ETA and when it was observed:
Windows disk active time / response time / queue:
MsMpEng.exe activity:
Cache note:
Correctness result:
Other observations:
```
