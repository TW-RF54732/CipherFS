fn main() {
    #[cfg(windows)]
    {
        let debug_info = std::env::var("PROFILE").is_ok_and(|profile| profile != "release");
        let config = slint_build::CompilerConfiguration::new().with_debug_info(debug_info);
        slint_build::compile_with_config("ui/app-window.slint", config)
            .expect("Unable to compile CipherFS Slint UI");
        println!("cargo:rerun-if-changed=cipherfs-shell.rc");
        println!("cargo:rerun-if-changed=../../assets/windows/cipherfs-app.ico");
        embed_resource::compile("cipherfs-shell.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("Unable to embed the CipherFS application icon");
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
