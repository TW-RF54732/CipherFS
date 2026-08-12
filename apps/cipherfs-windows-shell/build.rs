fn main() {
    #[cfg(windows)]
    {
        let debug_info = std::env::var("PROFILE").is_ok_and(|profile| profile != "release");
        let config = slint_build::CompilerConfiguration::new().with_debug_info(debug_info);
        slint_build::compile_with_config("ui/app-window.slint", config)
            .expect("Unable to compile CipherFS Slint UI");
        winfsp::build::winfsp_link_delayload();
        let manifest = std::path::Path::new("windows/cipherfs-shell.manifest")
            .canonicalize()
            .expect("CipherFS shell manifest is missing");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!(
            "cargo:rustc-link-arg-bin=cipherfs-shell=/MANIFESTINPUT:{}",
            manifest.display()
        );
        println!("cargo:rustc-link-arg-bin=cipherfs-shell=/MANIFEST:EMBED");
    }
}
