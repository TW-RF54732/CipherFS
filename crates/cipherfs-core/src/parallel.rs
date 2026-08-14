use anyhow::{Context, Result};

pub const AUTO_THREADS: usize = 0;
const MAX_DEFAULT_THREADS: usize = 6;

pub fn default_threads() -> usize {
    let available = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    balanced_threads(available)
}

fn balanced_threads(available: usize) -> usize {
    (available / 2).clamp(1, MAX_DEFAULT_THREADS)
}

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

#[cfg(test)]
mod tests {
    use super::balanced_threads;

    #[test]
    fn balanced_default_uses_half_the_available_threads_up_to_six() {
        assert_eq!(balanced_threads(1), 1);
        assert_eq!(balanced_threads(2), 1);
        assert_eq!(balanced_threads(5), 2);
        assert_eq!(balanced_threads(12), 6);
        assert_eq!(balanced_threads(32), 6);
    }
}
