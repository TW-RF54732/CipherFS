use std::env;
use std::fs;
use std::path::PathBuf;

// Modified by CipherFS contributors on 2026-08-11: reuse the crate's
// pregenerated bindings instead of regenerating them with libclang.
#[cfg(feature = "system")]
use windows_registry::LOCAL_MACHINE;

#[cfg(not(feature = "system"))]
fn local() -> String {
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!(
        "cargo:rustc-link-search={}",
        project_dir.join("winfsp/lib").to_string_lossy()
    );

    "--include-directory=winfsp/inc".into()
}

#[cfg(feature = "system")]
fn system() -> String {
    if !cfg!(windows) {
        panic!("'system' feature not supported for cross-platform compilation.");
    }

    let directory = LOCAL_MACHINE
        .open("SOFTWARE\\WOW6432Node\\WinFsp")
        .ok()
        .and_then(|u| u.get_string("InstallDir").ok())
        .expect("WinFsp installation directory not found.");

    println!("cargo:rustc-link-search={}/lib", directory);

    format!("--include-directory={}/inc", directory)
}

fn copy_winfsp_dll(winfsp_lib: &str) {
    println!("cargo:rerun-if-env-changed=WINFSP_DLL_OUTPUT_PATH");

    // Get the output path from environment variable
    let dll_out_path = match env::var("WINFSP_DLL_OUTPUT_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            return;
        }
    };

    if let Err(e) = fs::create_dir_all(&dll_out_path) {
        panic!(
            "Failed to create WinFSP DLL output directory {}: {}",
            dll_out_path.display(),
            e
        );
    }

    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dll_path = project_dir
        .join("winfsp/bin")
        .join(format!("{}.dll", winfsp_lib));
    if !dll_path.exists() {
        panic!(
            "WinFSP DLL source file does not exist: {}",
            dll_path.display()
        );
    }

    let dll_dest = dll_out_path.join(format!("{}.dll", winfsp_lib));
    if let Err(e) = fs::copy(&dll_path, &dll_dest) {
        panic!(
            "Failed to copy {} to {}: {}",
            dll_path.display(),
            dll_dest.display(),
            e
        );
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // host needs to be windows
    if cfg!(feature = "docsrs") {
        println!("cargo:warning=WinFSP does not build on any operating system but Windows. This feature is meant for docs.rs only. It will not link when compiled into a binary.");
        std::fs::File::create(out_dir.join("bindings.rs")).unwrap();
        return;
    }

    // Use the target OS configuration instead of the host OS configuration to enable cross-platform compilation
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_else(|_| "unknown".to_string());

    if target_os != "windows" {
        panic!("WinFSP is only supported on Windows.");
    }

    #[cfg(feature = "system")]
    let link_include = system();
    #[cfg(not(feature = "system"))]
    let link_include = local();

    println!("cargo:rustc-link-lib=dylib=delayimp");

    // Architecture-specific configuration
    let (winfsp_lib, clang_target) = match (target_arch.as_str(), target_env.as_str()) {
        ("x86_64", "msvc") => ("winfsp-x64", "x86_64-pc-windows-msvc"),
        ("x86", "msvc") => ("winfsp-x86", "x86-pc-windows-msvc"),
        ("aarch64", "msvc") => ("winfsp-a64", "aarch64-pc-windows-msvc"),
        _ => panic!("unsupported triple {}", env::var("TARGET").unwrap()),
    };

    println!("cargo:rustc-link-lib=dylib={}", winfsp_lib);
    println!("cargo:rustc-link-arg=/DELAYLOAD:{}.dll", winfsp_lib);

    let bindings_path_str = out_dir.join("bindings.rs");

    let _ = (link_include, clang_target);
    fs::copy(
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/bindings.rs"),
        &bindings_path_str,
    )
    .expect("could not copy pregenerated WinFsp bindings");

    #[cfg(not(feature = "system"))]
    copy_winfsp_dll(winfsp_lib);
}
