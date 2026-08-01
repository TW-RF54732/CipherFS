# CipherFS v2 Parallel Chunk Benchmark (WSL2, 2026-08-01)

This is a machine-specific engineering sample, not a performance guarantee.
Real results depend heavily on storage, CPU, file count, cache state, and other
workloads.

## Environment

- WSL2 Linux 6.18.33.2, ext4 `/tmp`
- AMD Ryzen 9 5900HS, 8 cores / 16 logical CPUs
- 7.5 GiB memory
- Rust 1.95.0
- Release build (`cargo build --locked --release`)
- One 2,048 MiB file containing zero bytes
- Argon2 test settings: 8 MiB memory, one iteration, one lane. These settings
  isolate chunk throughput and are not recommended password settings.
- Each configuration ran twice. Pack includes CipherFS's full self-verification.
- Harness: `benchmarks/run_parallel_bench.sh`

## Results

| Operation | Threads | Elapsed samples | Mean | Change from 1 thread |
| --- | ---: | ---: | ---: | ---: |
| Pack + self-verify | 1 | 8.91 s, 8.93 s | 8.92 s | baseline |
| Pack + self-verify | 4 | 5.11 s, 5.11 s | 5.11 s | 42.7% less elapsed time |
| Pack + self-verify | 16 | 5.72 s, 5.82 s | 5.77 s | 35.3% less elapsed time |
| Verify | 1 | 3.72 s, 2.98 s | 3.35 s | baseline |
| Verify | 4 | 2.20 s, 2.18 s | 2.19 s | 34.6% less elapsed time |
| Verify | 16 | 2.30 s, 2.36 s | 2.33 s | 30.4% less elapsed time |
| Extract | 1 | 5.55 s, 6.43 s | 5.99 s | baseline |
| Extract | 4 | 4.39 s, 3.34 s | 3.87 s | 35.5% less elapsed time |
| Extract | 16 | 4.20 s, 4.31 s | 4.26 s | 29.0% less elapsed time |

The 4-thread and 16-thread elapsed times are close while 16 threads consume
substantially more aggregate CPU time. On this setup, storage and concurrent
positional-I/O overhead become limiting factors before every logical CPU can be
used efficiently. `--threads 0` still uses all available logical CPUs by
default; users can benchmark values such as 4 or 8 for their own storage.

## Reproduction

```bash
cargo build --locked --release
CIPHERFS_BENCH_THREADS="1 4 16" \
  bash benchmarks/run_parallel_bench.sh 2048 2
```

The harness compares extracted bytes with the original input and confines its
temporary data to a checked `/tmp/cipherfs-parallel-bench.*` directory.
