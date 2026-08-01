# 26.7 GiB Real-Image ETA Observation

Date: 2026-08-01

Status: corrected exploratory field note. An earlier revision incorrectly
described a displayed three-hour ETA as an actual three-hour elapsed run. No
three-hour extraction was completed. The values below were CipherFS progress-bar
predictions, not controlled wall-clock measurements.

## Reported ETA Readings

Dataset: approximately 26.7 GiB of real image files.

| Scenario | Storage path | Execution detail | Displayed ETA |
| --- | --- | --- | ---: |
| Older single-thread release | native WSL filesystem | optimized release binary | about 3 minutes |
| Older single-thread release | Windows-mounted path under `/mnt/c` | optimized release binary | about 8 minutes |
| Later development invocation | container and output under `/mnt/c`, launched with `cargo run` from the WSL repository | default Cargo development profile; the process did not run for three hours | approximately 3 hours at the observed moment |

No final elapsed time was recorded for the three-hour prediction. These values
must not be treated as a release-versus-development or single-versus-multithread
benchmark.

## How CipherFS Produces ETA

CipherFS sets the progress length to total plaintext bytes and increments the
position after plaintext chunks have authenticated and been written. The
`{eta}` field is provided by `indicatif` 0.18.4.

The estimator observes each progress update:

```text
sample rate = delta completed bytes / delta time
ETA = remaining plaintext bytes / double-smoothed sample rate
```

`indicatif` uses a double-smoothed exponentially weighted, time-based estimate.
At its current constants, data older than 15 seconds collectively retains about
10% weight; data older than 30 seconds retains about 1%. If progress stops, the
time since the last update is treated like a zero-progress sample so the
estimated rate falls instead of remaining frozen.

This is measured effective throughput, not a prediction from CPU model, core
count, SSD specifications, or the theoretical ChaCha20-Poly1305 rate.

If an ETA is observed near the beginning of a 26.7 GiB run, its approximate
implied rates are:

| ETA | Approximate effective rate |
| ---: | ---: |
| 3 minutes | 152 MiB/s |
| 8 minutes | 57 MiB/s |
| 3 hours | 2.5 MiB/s |

The exact rate depends on how many bytes remained when the display was read.

## Why It Can Be Accurate or Misleading

Large, steady workloads give the estimator enough samples to converge, which
can make the displayed ETA surprisingly close to the eventual duration. Early
samples, filesystem stalls, file synchronization, cache changes, `/mnt/c`
translation, and unoptimized development builds can temporarily produce very
large predictions.

The extraction position advances per decrypted chunk. Per-file `sync_all`
pauses occur between progress updates and therefore influence later rate
samples. The final delayed-commit loop happens after all plaintext bytes have
been processed, so a zero ETA near the end does not necessarily mean every final
rename has completed.

For pack, the displayed encryption ETA does not include the subsequent complete
self-verification pass, so it is not a prediction of total command wall time.

## Controlled Follow-up

Record both the displayed ETA and actual wall-clock elapsed time separately:

```bash
/usr/bin/time -v cipherfs extract /mnt/c/.../myvault.fs /mnt/c/.../output-1 --threads 1
/usr/bin/time -v cipherfs extract /mnt/c/.../myvault.fs /mnt/c/.../output-4 --threads 4
/usr/bin/time -v cipherfs extract /mnt/c/.../myvault.fs /mnt/c/.../output-auto --threads 0
```

Use the same downloaded release binary and a new empty output directory for
each run. The broader comparison matrix is in
[`PARALLEL_BETA_TEST_PLAN.md`](PARALLEL_BETA_TEST_PLAN.md).
