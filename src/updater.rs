use anyhow::{Context, Result};
use minisign_verify::{PublicKey, Signature};
use reqwest::blocking::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

const OWNER: &str = "TW-RF54732";
const REPOSITORY: &str = "CipherFS";
#[cfg(unix)]
const MANIFEST_ASSET: &str = "cipherfs-linux-amd64.manifest";
#[cfg(windows)]
const MANIFEST_ASSET: &str = "cipherfs-windows-amd64.manifest";
#[cfg(unix)]
const SIGNATURE_ASSET: &str = "cipherfs-linux-amd64.manifest.minisig";
#[cfg(windows)]
const SIGNATURE_ASSET: &str = "cipherfs-windows-amd64.manifest.minisig";
#[cfg(unix)]
const TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(windows)]
const TARGET: &str = "x86_64-pc-windows-msvc";
#[cfg(unix)]
const BINARY_ASSET: &str = "cipherfs";
#[cfg(windows)]
const BINARY_ASSET: &str = "cipherfs.exe";

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    body: Option<String>,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Manifest {
    version: Version,
    target: String,
    asset: String,
    size: u64,
    sha256: String,
}

struct TempDownload(PathBuf);

impl Drop for TempDownload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn update_interactive() -> Result<()> {
    let public_key_b64 = option_env!("CIPHERFS_MINISIGN_PUBLIC_KEY").unwrap_or("");
    if public_key_b64.is_empty() {
        anyhow::bail!(
            "This build has no trusted update signing key; download releases manually from GitHub"
        );
    }
    let client = Client::builder()
        .user_agent(format!("cipherfs/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()?;
    let release: GithubRelease = client
        .get(format!(
            "https://api.github.com/repos/{OWNER}/{REPOSITORY}/releases/latest"
        ))
        .send()?
        .error_for_status()?
        .json()?;
    let latest = Version::parse(release.tag_name.trim_start_matches('v'))
        .context("Latest release tag is not a semantic version")?;
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    if latest <= current {
        println!("[Info] Already up to date (Version: {current}).");
        return Ok(());
    }

    let manifest_url = asset_url(&release, MANIFEST_ASSET)?;
    let signature_url = asset_url(&release, SIGNATURE_ASSET)?;
    let manifest_bytes = download(&client, manifest_url)?;
    let signature_text = String::from_utf8(download(&client, signature_url)?)
        .context("Update signature is not UTF-8")?;
    verify_manifest_signature(public_key_b64, &manifest_bytes, &signature_text)?;
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).context("Update manifest is not UTF-8")?;
    let manifest = parse_manifest(manifest_text)?;
    validate_manifest_for_update(&manifest, &latest, &current, TARGET, BINARY_ASSET)?;

    println!(
        "[Info] Signed update available: {} (Current: {})",
        latest, current
    );
    if let Some(body) = release.body.as_deref() {
        println!(
            "--- Release Notes ---\n{}\n---------------------",
            terminal_safe(body)
        );
    }
    print!("Install verified update {latest}? [y/N]: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("[Info] Update cancelled.");
        return Ok(());
    }

    let binary_url = asset_url(&release, &manifest.asset)?;
    let binary = download(&client, binary_url)?;
    validate_downloaded_binary(&binary, &manifest)?;

    let current_exe = std::env::current_exe()?;
    let parent = current_exe
        .parent()
        .context("Current executable has no parent directory")?;
    let mut random = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut random);
    let temp_path = parent.join(format!(
        ".cipherfs-update-{}{}",
        hex::encode(random),
        std::env::consts::EXE_SUFFIX
    ));
    let temp = TempDownload(temp_path.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    file.write_all(&binary)?;
    file.sync_all()?;
    drop(file);
    set_executable(&temp_path)?;
    std::fs::File::open(&temp_path)?.sync_all()?;
    self_replace::self_replace(&temp_path)?;
    sync_parent(parent)?;
    drop(temp);
    println!("[Success] Updated to {latest}.");
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(windows)]
fn set_executable(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &std::path::Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn verify_manifest_signature(trusted_keys: &str, manifest: &[u8], signature: &str) -> Result<()> {
    let signature = Signature::decode(signature).context("Malformed update signature")?;
    for encoded in trusted_keys
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Ok(public_key) = PublicKey::from_base64(encoded)
            && public_key.verify(manifest, &signature, false).is_ok()
        {
            return Ok(());
        }
    }
    anyhow::bail!("Update manifest signature verification failed")
}

fn terminal_safe(text: &str) -> String {
    text.chars()
        .filter(|character| *character == '\n' || *character == '\t' || !character.is_control())
        .collect()
}

fn asset_url<'a>(release: &'a GithubRelease, name: &str) -> Result<&'a str> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .map(|asset| asset.browser_download_url.as_str())
        .with_context(|| format!("Release is missing required signed asset {name}"))
}

fn download(client: &Client, url: &str) -> Result<Vec<u8>> {
    let response = client.get(url).send()?.error_for_status()?;
    let length = response.content_length();
    if length.is_some_and(|length| length > 512 * 1024 * 1024) {
        anyhow::bail!("Update asset exceeds download safety limit");
    }
    let mut bytes = Vec::with_capacity(
        length
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
    );
    response
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 512 * 1024 * 1024 {
        anyhow::bail!("Update asset exceeds download safety limit");
    }
    Ok(bytes)
}

fn parse_manifest(text: &str) -> Result<Manifest> {
    let mut values = std::collections::HashMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .context("Malformed signed update manifest")?;
        if values.insert(key, value).is_some() {
            anyhow::bail!("Duplicate field in signed update manifest");
        }
    }
    if values.len() != 5 {
        anyhow::bail!("Unexpected fields in signed update manifest");
    }
    let sha256 = values
        .remove("sha256")
        .context("Manifest has no sha256")?
        .to_string();
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("Manifest sha256 is invalid");
    }
    Ok(Manifest {
        version: Version::parse(
            values
                .remove("version")
                .context("Manifest has no version")?,
        )?,
        target: values
            .remove("target")
            .context("Manifest has no target")?
            .to_string(),
        asset: values
            .remove("asset")
            .context("Manifest has no asset")?
            .to_string(),
        size: values
            .remove("size")
            .context("Manifest has no size")?
            .parse()?,
        sha256,
    })
}

fn validate_manifest_for_update(
    manifest: &Manifest,
    latest: &Version,
    current: &Version,
    target: &str,
    binary_asset: &str,
) -> Result<()> {
    if latest <= current {
        anyhow::bail!("Refusing a non-upgrade release");
    }
    if &manifest.version != latest
        || manifest.target != target
        || manifest.asset != binary_asset
        || manifest.size == 0
    {
        anyhow::bail!("Signed update manifest does not match this release/target");
    }
    Ok(())
}

fn validate_downloaded_binary(binary: &[u8], manifest: &Manifest) -> Result<()> {
    if binary.len() as u64 != manifest.size {
        anyhow::bail!("Downloaded binary size does not match signed manifest");
    }
    let digest = hex::encode(Sha256::digest(binary));
    if !digest.eq_ignore_ascii_case(&manifest.sha256) {
        anyhow::bail!("Downloaded binary hash does not match signed manifest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_manifest_parses() {
        let manifest = parse_manifest(
            "version=2.0.0\ntarget=x86_64-unknown-linux-musl\nasset=cipherfs\nsize=12\nsha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        assert_eq!(manifest.version, Version::new(2, 0, 0));
        assert_eq!(manifest.size, 12);
    }

    #[test]
    fn duplicate_or_extra_fields_are_rejected() {
        assert!(parse_manifest("version=2.0.0\nversion=2.0.1\n").is_err());
    }

    #[test]
    fn wrong_target_downgrade_and_empty_asset_are_rejected() {
        let mut manifest = Manifest {
            version: Version::new(2, 2, 0),
            target: "x86_64-pc-windows-msvc".to_string(),
            asset: "cipherfs.exe".to_string(),
            size: 12,
            sha256: "a".repeat(64),
        };
        let latest = Version::new(2, 2, 0);
        let current = Version::new(2, 1, 0);
        assert!(
            validate_manifest_for_update(
                &manifest,
                &latest,
                &current,
                "x86_64-pc-windows-msvc",
                "cipherfs.exe"
            )
            .is_ok()
        );
        assert!(
            validate_manifest_for_update(
                &manifest,
                &latest,
                &latest,
                "x86_64-pc-windows-msvc",
                "cipherfs.exe"
            )
            .is_err()
        );
        assert!(
            validate_manifest_for_update(
                &manifest,
                &latest,
                &current,
                "x86_64-unknown-linux-musl",
                "cipherfs"
            )
            .is_err()
        );
        manifest.size = 0;
        assert!(
            validate_manifest_for_update(
                &manifest,
                &latest,
                &current,
                "x86_64-pc-windows-msvc",
                "cipherfs.exe"
            )
            .is_err()
        );
    }

    #[test]
    fn release_notes_cannot_emit_terminal_control_sequences() {
        assert_eq!(terminal_safe("safe\u{1b}[31m\nnext"), "safe[31m\nnext");
    }

    #[test]
    fn truncated_and_modified_downloads_are_rejected() {
        let complete = b"complete release binary";
        let manifest = Manifest {
            version: Version::new(2, 2, 0),
            target: TARGET.to_string(),
            asset: BINARY_ASSET.to_string(),
            size: complete.len() as u64,
            sha256: hex::encode(Sha256::digest(complete)),
        };
        assert!(validate_downloaded_binary(complete, &manifest).is_ok());
        assert!(validate_downloaded_binary(&complete[..complete.len() - 1], &manifest).is_err());
        let mut modified = complete.to_vec();
        modified[0] ^= 1;
        assert!(validate_downloaded_binary(&modified, &manifest).is_err());
    }

    #[test]
    fn signed_content_accepts_trusted_key_and_rejects_tampering() {
        let key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        let signature = concat!(
            "untrusted comment: signature from minisign secret key\n",
            "RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/",
            "z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n",
            "trusted comment: timestamp:1633700835\tfile:test\tprehashed\n",
            "wLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJ",
            "pIidRJnp94ABQkJAgAooBQ=="
        );
        assert!(verify_manifest_signature(key, b"test", signature).is_ok());
        assert!(verify_manifest_signature(&format!("invalid,{key}"), b"test", signature).is_ok());
        assert!(verify_manifest_signature(key, b"Test", signature).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_self_replace_child() {
        let Some(replacement) = std::env::var_os("CIPHERFS_SELF_REPLACE_SOURCE") else {
            return;
        };
        let marker = std::env::var_os("CIPHERFS_SELF_REPLACE_MARKER")
            .expect("replacement child marker is required");
        self_replace::self_replace(replacement).expect("running executable replacement failed");
        std::fs::write(marker, b"replaced").expect("unable to write replacement child marker");
    }

    #[cfg(windows)]
    #[test]
    fn windows_running_executable_is_replaced_by_child_process() {
        let temp = tempfile::tempdir().unwrap();
        let runner = temp.path().join("updater-child.exe");
        let replacement = temp.path().join("replacement.exe");
        let marker = temp.path().join("replacement.marker");
        std::fs::copy(std::env::current_exe().unwrap(), &runner).unwrap();
        let replacement_bytes = b"MZ\x90\0cipherfs replacement test payload";
        std::fs::write(&replacement, replacement_bytes).unwrap();

        let status = std::process::Command::new(&runner)
            .args([
                "--exact",
                "updater::tests::windows_self_replace_child",
                "--nocapture",
            ])
            .env("CIPHERFS_SELF_REPLACE_SOURCE", &replacement)
            .env("CIPHERFS_SELF_REPLACE_MARKER", &marker)
            .env("TEMP", temp.path())
            .env("TMP", temp.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read(&runner).unwrap(), replacement_bytes);
        assert_eq!(std::fs::read(&marker).unwrap(), b"replaced");
        assert!(
            replacement.exists(),
            "source replacement should remain available"
        );
    }
}
