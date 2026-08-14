mod extract;
mod format;
mod layout;
pub mod operation;
mod pack;
mod parallel;
mod platform_io;
mod platform_metadata;
mod readonly_fs;
mod safe_fs;
mod v2;
#[cfg(windows)]
mod windows_fs;
#[cfg(windows)]
mod windows_names;

pub use extract::{ExtractOptions, ExtractRequest, execute as extract};
pub use format::require_v2;
pub use pack::{PackOptions, PackRequest, execute as pack};
pub use parallel::default_threads;
pub use platform_io::PlatformFileExt;
pub use readonly_fs::{FsError, FsErrorKind, Node, NodeKind, ReadOnlyFs};
pub use v2::{
    CHUNK_SIZE, MAX_INDEX_SIZE, MIN_ARGON_MEMORY_KIB, VerifyOptions, VerifyRequest,
    change_password, change_password_with_control, verify,
};
#[cfg(windows)]
pub use windows_names::{WindowsNameMap, compare_display_names, equivalent};
