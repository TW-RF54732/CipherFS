use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Inode {
    File {
        ino: u64,
        parent_ino: u64,
        size: u64,
        offset: u64, // 這是虛擬的平坦偏移量
    },
    Directory {
        ino: u64,
        parent_ino: u64,
        entries: HashMap<String, Inode>,
    },
}

impl Inode {
    pub fn is_file(&self) -> bool {
        matches!(self, Inode::File { .. })
    }

    pub fn ino(&self) -> u64 {
        match self {
            Inode::File { ino, .. } => *ino,
            Inode::Directory { ino, .. } => *ino,
        }
    }

    pub fn parent_ino(&self) -> u64 {
        match self {
            Inode::File { parent_ino, .. } => *parent_ino,
            Inode::Directory { parent_ino, .. } => *parent_ino,
        }
    }
}
