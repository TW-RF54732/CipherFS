use anyhow::{Context, Result};

pub const AUTO_THREADS: usize = 0;

pub fn install<T, F>(threads: usize, operation: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
{
    let mut builder =
        rayon::ThreadPoolBuilder::new().thread_name(|index| format!("cipherfs-{index}"));
    if threads != AUTO_THREADS {
        builder = builder.num_threads(threads);
    }
    let pool = builder
        .build()
        .context("Unable to create worker thread pool")?;
    pool.install(operation)
}

pub fn ordered_batch_size() -> usize {
    rayon::current_num_threads().max(1)
}
