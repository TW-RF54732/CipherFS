# CipherFS Engineering Experiment Archive

This directory contains machine-specific engineering evidence and test plans.
It is intentionally more detailed than the README. Results are not performance
or security guarantees and should only be compared when the binary, build
profile, dataset, filesystem path, cache state, and thread count are controlled.

## Reports and Data

- [`2026-07-25-wsl2.md`](2026-07-25-wsl2.md): v1/v2 pack, extract, random-read,
  FUSE sequential-read, small-file, and corruption observations from the v2
  hardening work.
- [`2026-08-01-wsl2-parallel.md`](2026-08-01-wsl2-parallel.md): summarized
  release-build parallel chunk benchmark on native WSL2 ext4 storage.
- [`2026-08-01-parallel-raw.csv`](2026-08-01-parallel-raw.csv): raw elapsed,
  user CPU, and system CPU samples from the parallel implementation work,
  including exploratory intermediate runs and the final 2 GiB comparison.
- [`2026-08-01-real-images-observation.md`](2026-08-01-real-images-observation.md):
  field observation from a 26.7 GiB image container and why the initial 8-minute
  versus 3-hour timings are not yet a controlled comparison.
- [`PARALLEL_BETA_TEST_PLAN.md`](PARALLEL_BETA_TEST_PLAN.md): test matrix and
  reporting template for the v2.1.0 beta series.
- [`run_parallel_bench.sh`](run_parallel_bench.sh): reproducible synthetic
  release-build pack, verify, extract, and byte-comparison harness.

## Interpretation Rules

1. Do not compare `cargo run` with an optimized release binary.
2. Treat WSL ext4 and Windows-mounted `/mnt/c` as different storage systems.
3. Record file count and size distribution, not only total bytes.
4. Separate pack, verify, and extract timings.
5. Preserve raw samples and label intermediate implementation revisions.
6. Verify extracted bytes and corruption-failure behavior before considering a
   performance sample valid.
