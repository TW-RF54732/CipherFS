use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

pub const MAGIC_BYTES: [u8; 4] = [0x43, 0x46, 0x53, 0x01];
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const HEADER_SIZE: usize = 512;

#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    pub magic: [u8; 4],
    pub salt: [u8; 16],
    pub argon2_params: Argon2Params,
    pub master_nonce: [u8; 32],
    pub dek_nonce: [u8; 12],
    pub index_nonce: [u8; 12],
    pub duress_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub encrypted_dek: [u8; 48], // 32B DEK + 16B Tag
    pub index_size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}
