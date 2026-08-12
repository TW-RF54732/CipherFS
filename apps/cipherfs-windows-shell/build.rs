fn main() {
    #[cfg(windows)]
    {
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
