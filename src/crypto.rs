use anyhow::Result;
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use blake3;
use crate::layout::Argon2Params;

pub fn derive_kek(password: &str, salt: &[u8], params: &Argon2Params) -> Result<[u8; 32]> {
    // Power User Limits: Allow up to 32GB RAM and 1000 iterations for maximum security
    if params.m_cost > 32 * 1024 * 1024 || params.t_cost > 1000 || params.p_cost > 256 {
        anyhow::bail!("Argon2 parameters exceed extreme limits (m: {}KB, t: {}, p: {}).", params.m_cost, params.t_cost, params.p_cost);
    }

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?,
    );
    
    let mut kek = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut kek)
        .map_err(|e| anyhow::anyhow!("KDF failed: {}", e))?;
    
    Ok(kek)
}

pub fn derive_chunk_nonce(master_nonce: &[u8; 32], chunk_index: u64) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(master_nonce);
    hasher.update(&chunk_index.to_le_bytes());
    let hash = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash.as_bytes()[0..12]);
    nonce
}

pub fn encrypt_data(key: &[u8; 32], nonce_bytes: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
}

pub fn decrypt_data(key: &[u8; 32], nonce_bytes: &[u8; 12], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, encrypted_data)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

pub fn hash_duress_password(password: &str) -> [u8; 32] {
    blake3::hash(password.as_bytes()).into()
}
