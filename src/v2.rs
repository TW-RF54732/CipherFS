use anyhow::{Context, Result};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::Rng;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: [u8; 4] = [0x43, 0x46, 0x53, 0x02];
pub const VERSION: u16 = 2;
pub const HEADER_SIZE: usize = 4096;
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const TAG_SIZE: u64 = 16;
pub const MAX_INDEX_SIZE: u64 = 512 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 5_000_000;
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_DEPTH: u32 = 1024;
pub const MIN_ARGON_MEMORY_KIB: u32 = 8 * 1024;
pub const MAX_ARGON_MEMORY_KIB: u32 = 1024 * 1024;
pub const MAX_ARGON_TIME: u32 = 10;
pub const MAX_ARGON_LANES: u32 = 16;

const DURESS_MARKER_CONTEXT: &[u8] = b"cipherfs-v2/duress-marker";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    pub generation: u64,
    pub salt: [u8; 16],
    pub params: Argon2Params,
    pub nonce: [u8; 12],
    #[serde(with = "BigArray")]
    pub encrypted_dek: [u8; 48],
}

impl KeySlot {
    pub fn random_disabled() -> Self {
        let mut slot = Self {
            generation: 0,
            salt: [0; 16],
            params: Argon2Params::default(),
            nonce: [0; 12],
            encrypted_dek: [0; 48],
        };
        let mut rng = rand::rng();
        rng.fill_bytes(&mut slot.salt);
        rng.fill_bytes(&mut slot.nonce);
        rng.fill_bytes(&mut slot.encrypted_dek);
        slot
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressSlot {
    pub enabled: bool,
    pub salt: [u8; 16],
    pub params: Argon2Params,
    pub nonce: [u8; 12],
    #[serde(with = "BigArray")]
    pub encrypted_marker: [u8; 48],
}

impl DuressSlot {
    pub fn random_disabled() -> Self {
        let mut slot = Self {
            enabled: false,
            salt: [0; 16],
            params: Argon2Params::default(),
            nonce: [0; 12],
            encrypted_marker: [0; 48],
        };
        let mut rng = rand::rng();
        rng.fill_bytes(&mut slot.salt);
        rng.fill_bytes(&mut slot.nonce);
        rng.fill_bytes(&mut slot.encrypted_marker);
        slot
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u16,
    pub header_size: u32,
    pub container_id: [u8; 16],
    pub chunk_size: u32,
    pub index_size: u64,
    pub data_size: u64,
    pub entry_count: u64,
    pub index_nonce: [u8; 12],
    pub slots: [KeySlot; 2],
    pub duress: DuressSlot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: u64,
    pub parent_id: u64,
    pub name: String,
    pub depth: u32,
    pub kind: EntryKind,
    pub file_id: [u8; 16],
    pub size: u64,
    pub data_offset: u64,
    pub encrypted_size: u64,
    pub chunk_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Index {
    pub entries: Vec<Entry>,
}

impl<'de> Deserialize<'de> for Index {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IndexVisitor;

        impl<'de> Visitor<'de> for IndexVisitor {
            type Value = Index;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a CipherFS v2 index tuple")
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let entries = sequence
                    .next_element::<BoundedEntries>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(Index { entries: entries.0 })
            }
        }

        deserializer.deserialize_tuple(1, IndexVisitor)
    }
}

struct BoundedEntries(Vec<Entry>);

impl<'de> Deserialize<'de> for BoundedEntries {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = BoundedEntries;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded CipherFS v2 entry array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|count| count > MAX_ENTRIES)
                {
                    return Err(serde::de::Error::custom(
                        "Index entry count exceeds local safety limits",
                    ));
                }
                let mut entries =
                    Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_ENTRIES));
                while let Some(entry) = sequence.next_element()? {
                    if entries.len() >= MAX_ENTRIES {
                        return Err(serde::de::Error::custom(
                            "Index entry count exceeds local safety limits",
                        ));
                    }
                    entries.push(entry);
                }
                Ok(BoundedEntries(entries))
            }
        }

        deserializer.deserialize_seq(EntriesVisitor)
    }
}

#[derive(Debug)]
pub struct ValidatedIndex {
    pub entries: HashMap<u64, Entry>,
    pub children: HashMap<u64, Vec<u64>>,
}

pub struct OpenedContainer {
    pub file: File,
    pub header: Header,
    pub index: ValidatedIndex,
    pub dek: Zeroizing<[u8; 32]>,
    pub data_start: u64,
}

pub enum UnlockResult {
    Unlocked(Zeroizing<[u8; 32]>),
    Duress,
    Failed,
}

pub fn validate_argon2(params: &Argon2Params) -> Result<()> {
    if !(MIN_ARGON_MEMORY_KIB..=MAX_ARGON_MEMORY_KIB).contains(&params.m_cost)
        || !(1..=MAX_ARGON_TIME).contains(&params.t_cost)
        || !(1..=MAX_ARGON_LANES).contains(&params.p_cost)
    {
        anyhow::bail!(
            "Argon2 parameters exceed local safety limits (m={}, t={}, p={})",
            params.m_cost,
            params.t_cost,
            params.p_cost
        );
    }
    Ok(())
}

pub fn derive_kek(
    password: &str,
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    validate_argon2(params)?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {e}"))?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2 failed: {e}"))?;
    Ok(key)
}

fn hkdf_key(dek: &[u8; 32], container_id: &[u8; 16], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(container_id), dek);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|_| anyhow::anyhow!("HKDF output length is invalid"))?;
    Ok(output)
}

pub fn derive_index_key(dek: &[u8; 32], container_id: &[u8; 16]) -> Result<[u8; 32]> {
    hkdf_key(dek, container_id, b"cipherfs-v2/index-key")
}

pub fn derive_file_key(
    dek: &[u8; 32],
    container_id: &[u8; 16],
    file_id: &[u8; 16],
) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(21 + file_id.len());
    info.extend_from_slice(b"cipherfs-v2/file-key");
    info.extend_from_slice(file_id);
    hkdf_key(dek, container_id, &info)
}

fn push_argon(out: &mut Vec<u8>, params: &Argon2Params) {
    out.extend_from_slice(&params.m_cost.to_le_bytes());
    out.extend_from_slice(&params.t_cost.to_le_bytes());
    out.extend_from_slice(&params.p_cost.to_le_bytes());
}

pub fn immutable_aad(header: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&header.magic);
    out.extend_from_slice(&header.version.to_le_bytes());
    out.extend_from_slice(&header.header_size.to_le_bytes());
    out.extend_from_slice(&header.container_id);
    out.extend_from_slice(&header.chunk_size.to_le_bytes());
    out.extend_from_slice(&header.index_size.to_le_bytes());
    out.extend_from_slice(&header.data_size.to_le_bytes());
    out.extend_from_slice(&header.entry_count.to_le_bytes());
    out.extend_from_slice(&header.index_nonce);
    out.push(u8::from(header.duress.enabled));
    out.extend_from_slice(&header.duress.salt);
    push_argon(&mut out, &header.duress.params);
    out.extend_from_slice(&header.duress.nonce);
    out.extend_from_slice(blake3::hash(&header.duress.encrypted_marker).as_bytes());
    out
}

fn slot_aad(header: &Header, slot: &KeySlot) -> Vec<u8> {
    let mut out = immutable_aad(header);
    out.extend_from_slice(b"/key-slot");
    out.extend_from_slice(&slot.generation.to_le_bytes());
    out.extend_from_slice(&slot.salt);
    push_argon(&mut out, &slot.params);
    out.extend_from_slice(&slot.nonce);
    out
}

fn duress_aad(header: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&header.magic);
    out.extend_from_slice(&header.version.to_le_bytes());
    out.extend_from_slice(&header.header_size.to_le_bytes());
    out.extend_from_slice(&header.container_id);
    out.extend_from_slice(&header.chunk_size.to_le_bytes());
    out.extend_from_slice(&header.index_size.to_le_bytes());
    out.extend_from_slice(&header.data_size.to_le_bytes());
    out.extend_from_slice(&header.entry_count.to_le_bytes());
    out.extend_from_slice(b"/duress-slot");
    out.extend_from_slice(&header.duress.salt);
    push_argon(&mut out, &header.duress.params);
    out.extend_from_slice(&header.duress.nonce);
    out
}

pub fn index_aad(header: &Header) -> Vec<u8> {
    let mut out = immutable_aad(header);
    out.extend_from_slice(b"/index");
    out
}

pub fn chunk_nonce(chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(b"C2CH");
    nonce[4..12].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

pub fn chunk_aad(header: &Header, entry: &Entry, chunk_index: u64, plaintext_len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&header.magic);
    out.extend_from_slice(&header.version.to_le_bytes());
    out.extend_from_slice(&header.container_id);
    out.extend_from_slice(&entry.file_id);
    out.extend_from_slice(&entry.id.to_le_bytes());
    out.extend_from_slice(&entry.size.to_le_bytes());
    out.extend_from_slice(&chunk_index.to_le_bytes());
    out.extend_from_slice(&plaintext_len.to_le_bytes());
    out
}

pub fn encrypt_aead(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| anyhow::anyhow!("Encryption failed"))
}

pub fn decrypt_aead(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| anyhow::anyhow!("Authentication failed"))
}

pub fn configure_duress(
    header: &mut Header,
    password: Option<&str>,
    params: Argon2Params,
) -> Result<()> {
    header.duress = DuressSlot::random_disabled();
    header.duress.params = params;
    let Some(password) = password else {
        return Ok(());
    };
    header.duress.enabled = true;
    let kek = derive_kek(password, &header.duress.salt, &header.duress.params)?;
    let mut marker_input = Vec::from(DURESS_MARKER_CONTEXT);
    marker_input.extend_from_slice(&header.container_id);
    let marker = blake3::hash(&marker_input);
    let encrypted = encrypt_aead(
        &kek,
        &header.duress.nonce,
        &duress_aad(header),
        marker.as_bytes(),
    )?;
    header.duress.encrypted_marker.copy_from_slice(&encrypted);
    Ok(())
}

pub fn make_key_slot(
    header: &Header,
    password: &str,
    dek: &[u8; 32],
    generation: u64,
    params: Argon2Params,
) -> Result<KeySlot> {
    let mut slot = KeySlot::random_disabled();
    slot.generation = generation;
    slot.params = params;
    let kek = derive_kek(password, &slot.salt, &slot.params)?;
    let encrypted = encrypt_aead(&kek, &slot.nonce, &slot_aad(header, &slot), dek)?;
    slot.encrypted_dek.copy_from_slice(&encrypted);
    Ok(slot)
}

pub fn unlock(header: &Header, password: &str) -> Result<UnlockResult> {
    validate_header_basic(header, None)?;
    let mut candidates: Vec<&KeySlot> = header
        .slots
        .iter()
        .filter(|slot| slot.generation > 0)
        .collect();
    candidates.sort_by_key(|slot| std::cmp::Reverse(slot.generation));
    for slot in candidates {
        let kek = derive_kek(password, &slot.salt, &slot.params)?;
        if let Ok(mut dek) = decrypt_aead(
            &kek,
            &slot.nonce,
            &slot_aad(header, slot),
            &slot.encrypted_dek,
        ) {
            if dek.len() == 32 {
                let mut value = Zeroizing::new([0u8; 32]);
                value.copy_from_slice(&dek);
                dek.zeroize();
                return Ok(UnlockResult::Unlocked(value));
            }
            dek.zeroize();
        }
    }

    if header.duress.enabled {
        let kek = derive_kek(password, &header.duress.salt, &header.duress.params)?;
        if let Ok(mut marker) = decrypt_aead(
            &kek,
            &header.duress.nonce,
            &duress_aad(header),
            &header.duress.encrypted_marker,
        ) {
            let mut marker_input = Vec::from(DURESS_MARKER_CONTEXT);
            marker_input.extend_from_slice(&header.container_id);
            let expected = blake3::hash(&marker_input);
            let matches = marker.as_slice() == expected.as_bytes();
            marker.zeroize();
            if matches {
                return Ok(UnlockResult::Duress);
            }
        }
    }

    Ok(UnlockResult::Failed)
}

pub fn serialize_header(header: &Header) -> Result<[u8; HEADER_SIZE]> {
    let bytes = rmp_serde::to_vec(header)?;
    if bytes.len() > HEADER_SIZE {
        anyhow::bail!("v2 header exceeds fixed header size");
    }
    let mut output = [0u8; HEADER_SIZE];
    output[..bytes.len()].copy_from_slice(&bytes);
    Ok(output)
}

pub fn read_header(file: &File) -> Result<Header> {
    let mut bytes = [0u8; HEADER_SIZE];
    file.read_exact_at(&mut bytes, 0)
        .context("Unable to read v2 header")?;
    let header: Header =
        rmp_serde::from_read(Cursor::new(bytes)).context("Invalid v2 header encoding")?;
    validate_header_basic(&header, Some(file.metadata()?.len()))?;
    Ok(header)
}

pub fn write_header(file: &mut File, header: &Header) -> Result<()> {
    let bytes = serialize_header(header)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn validate_header_basic(header: &Header, file_len: Option<u64>) -> Result<()> {
    if header.magic != MAGIC
        || header.version != VERSION
        || header.header_size as usize != HEADER_SIZE
        || header.chunk_size as usize != CHUNK_SIZE
    {
        anyhow::bail!("Unsupported or invalid CipherFS v2 header");
    }
    if header.index_size < TAG_SIZE || header.index_size > MAX_INDEX_SIZE {
        anyhow::bail!("Index size exceeds local safety limits");
    }
    if usize::try_from(header.entry_count)
        .map(|count| count > MAX_ENTRIES)
        .unwrap_or(true)
    {
        anyhow::bail!("Entry count exceeds local safety limits");
    }
    for slot in &header.slots {
        if slot.generation > 0 {
            validate_argon2(&slot.params)?;
        }
    }
    if header.duress.enabled {
        validate_argon2(&header.duress.params)?;
    }
    if let Some(file_len) = file_len {
        let expected = (HEADER_SIZE as u64)
            .checked_add(header.index_size)
            .and_then(|v| v.checked_add(header.data_size))
            .context("Container length overflow")?;
        if expected != file_len {
            anyhow::bail!("Container length does not match authenticated layout");
        }
    }
    Ok(())
}

pub fn encrypted_file_size(size: u64) -> Result<(u64, u64)> {
    if size == 0 {
        return Ok((0, 0));
    }
    let chunks = size
        .checked_add(CHUNK_SIZE as u64 - 1)
        .context("File size overflow")?
        / CHUNK_SIZE as u64;
    let encrypted = size
        .checked_add(
            chunks
                .checked_mul(TAG_SIZE)
                .context("Chunk overhead overflow")?,
        )
        .context("Encrypted file size overflow")?;
    Ok((chunks, encrypted))
}

pub fn validate_index(header: &Header, index: Index) -> Result<ValidatedIndex> {
    if u64::try_from(index.entries.len()) != Ok(header.entry_count)
        || index.entries.len() > MAX_ENTRIES
    {
        anyhow::bail!("Index entry count mismatch");
    }
    let mut ids = HashSet::with_capacity(index.entries.len());
    let mut file_ids = HashSet::new();
    let mut entries = HashMap::with_capacity(index.entries.len());
    let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut files = Vec::new();

    for entry in index.entries {
        if entry.id == 0 {
            anyhow::bail!("Entry id zero is reserved");
        }
        if !ids.insert(entry.id) {
            anyhow::bail!("Duplicate entry id {}", entry.id);
        }
        if entry.depth > MAX_DEPTH {
            anyhow::bail!("Directory depth exceeds local safety limits");
        }
        if entry.id == 1 {
            if entry.parent_id != 1
                || entry.depth != 0
                || entry.kind != EntryKind::Directory
                || !entry.name.is_empty()
            {
                anyhow::bail!("Invalid root entry");
            }
        } else {
            validate_name(&entry.name)?;
        }

        match entry.kind {
            EntryKind::Directory => {
                if entry.size != 0
                    || entry.data_offset != 0
                    || entry.encrypted_size != 0
                    || entry.chunk_count != 0
                    || entry.file_id != [0; 16]
                {
                    anyhow::bail!("Directory entry contains file data");
                }
            }
            EntryKind::File => {
                if entry.file_id == [0; 16] || !file_ids.insert(entry.file_id) {
                    anyhow::bail!("Invalid or duplicate file id");
                }
                let (chunks, encrypted) = encrypted_file_size(entry.size)?;
                if chunks != entry.chunk_count || encrypted != entry.encrypted_size {
                    anyhow::bail!("File chunk layout mismatch");
                }
                files.push((entry.data_offset, entry.encrypted_size, entry.id));
            }
        }
        if entry.id != 1 {
            children.entry(entry.parent_id).or_default().push(entry.id);
        }
        entries.insert(entry.id, entry);
    }

    let root = entries.get(&1).context("Index has no root entry")?;
    if root.kind != EntryKind::Directory {
        anyhow::bail!("Root is not a directory");
    }

    let mut sibling_names: HashMap<u64, HashSet<&str>> = HashMap::new();
    for entry in entries.values() {
        if entry.id == 1 {
            continue;
        }
        let parent = entries
            .get(&entry.parent_id)
            .context("Entry references a missing parent")?;
        if parent.kind != EntryKind::Directory || parent.depth.checked_add(1) != Some(entry.depth) {
            anyhow::bail!("Invalid parent or depth for entry {}", entry.id);
        }
        if !sibling_names
            .entry(entry.parent_id)
            .or_default()
            .insert(entry.name.as_str())
        {
            anyhow::bail!("Duplicate name within directory");
        }
    }

    files.sort_by_key(|item| item.0);
    let mut expected_offset = 0u64;
    for (offset, encrypted_size, _) in files {
        if offset != expected_offset {
            anyhow::bail!("File data must be contiguous and non-overlapping");
        }
        expected_offset = expected_offset
            .checked_add(encrypted_size)
            .context("Data layout overflow")?;
    }
    if expected_offset != header.data_size {
        anyhow::bail!("Data size does not match index");
    }

    Ok(ValidatedIndex { entries, children })
}

pub fn validate_name(name: &str) -> Result<()> {
    use std::path::{Component, Path};
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        anyhow::bail!("Invalid filename length");
    }
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        anyhow::bail!("Unsafe filename component");
    }
    Ok(())
}

pub fn open(path: &Path, password: &str) -> Result<OpenedContainer> {
    let file = File::open(path)?;
    let header = read_header(&file)?;
    let dek = match unlock(&header, password)? {
        UnlockResult::Unlocked(dek) => dek,
        UnlockResult::Duress => {
            drop(file);
            wipe_for_duress(path, header)?;
            anyhow::bail!("Unable to unlock container (wrong password or damage)");
        }
        UnlockResult::Failed => {
            anyhow::bail!("Unable to unlock container (wrong password or damage)")
        }
    };
    let mut encrypted_index = vec![0u8; header.index_size as usize];
    file.read_exact_at(&mut encrypted_index, HEADER_SIZE as u64)?;
    let index_key = Zeroizing::new(derive_index_key(&dek, &header.container_id)?);
    let mut serialized = decrypt_aead(
        &index_key,
        &header.index_nonce,
        &index_aad(&header),
        &encrypted_index,
    )
    .context("Index authentication failed")?;
    let index: Index = rmp_serde::from_slice(&serialized).context("Invalid v2 index encoding")?;
    serialized.zeroize();
    let index = validate_index(&header, index)?;
    let data_start = (HEADER_SIZE as u64)
        .checked_add(header.index_size)
        .context("Data offset overflow")?;
    Ok(OpenedContainer {
        file,
        header,
        index,
        dek,
        data_start,
    })
}

pub fn change_password(path: &Path, old_password: &str, new_password: &str) -> Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut header = read_header(&file)?;
    if matches!(unlock(&header, new_password)?, UnlockResult::Duress) {
        anyhow::bail!("New master password must differ from the configured Duress password");
    }
    let dek = match unlock(&header, old_password)? {
        UnlockResult::Unlocked(dek) => dek,
        UnlockResult::Duress => {
            drop(file);
            wipe_for_duress(path, header)?;
            anyhow::bail!("Unable to unlock container (wrong password or damage)");
        }
        UnlockResult::Failed => {
            anyhow::bail!("Unable to unlock container (wrong password or damage)")
        }
    };
    let highest_generation = header
        .slots
        .iter()
        .map(|slot| slot.generation)
        .max()
        .unwrap_or(0);
    let inactive = if header.slots[0].generation <= header.slots[1].generation {
        0
    } else {
        1
    };
    let previous = 1 - inactive;
    let params = header.slots[previous].params;
    header.slots[inactive] = make_key_slot(
        &header,
        new_password,
        &dek,
        highest_generation
            .checked_add(1)
            .context("Keyslot generation overflow")?,
        params,
    )?;
    write_header(&mut file, &header)?;

    header.slots[previous] = KeySlot::random_disabled();
    write_header(&mut file, &header)?;
    Ok(())
}

pub fn wipe_for_duress(path: &Path, mut header: Header) -> Result<()> {
    let mut rng = rand::rng();
    for slot in &mut header.slots {
        slot.generation = 0;
        rng.fill_bytes(&mut slot.salt);
        rng.fill_bytes(&mut slot.nonce);
        rng.fill_bytes(&mut slot.encrypted_dek);
    }
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    write_header(&mut file, &header)
}

pub fn decrypt_chunk(
    opened: &OpenedContainer,
    entry: &Entry,
    chunk_index: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    if entry.kind != EntryKind::File || chunk_index >= entry.chunk_count {
        anyhow::bail!("Invalid chunk request");
    }
    let plain_start = chunk_index
        .checked_mul(CHUNK_SIZE as u64)
        .context("Chunk offset overflow")?;
    let plain_len = std::cmp::min(CHUNK_SIZE as u64, entry.size - plain_start);
    let cipher_len = plain_len
        .checked_add(TAG_SIZE)
        .context("Ciphertext length overflow")?;
    let relative = chunk_index
        .checked_mul(CHUNK_SIZE as u64 + TAG_SIZE)
        .context("Chunk position overflow")?;
    let position = opened
        .data_start
        .checked_add(entry.data_offset)
        .and_then(|v| v.checked_add(relative))
        .context("Chunk file position overflow")?;
    let mut encrypted = vec![0u8; cipher_len as usize];
    opened.file.read_exact_at(&mut encrypted, position)?;
    let key = Zeroizing::new(derive_file_key(
        &opened.dek,
        &opened.header.container_id,
        &entry.file_id,
    )?);
    let mut plaintext = decrypt_aead(
        &key,
        &chunk_nonce(chunk_index),
        &chunk_aad(&opened.header, entry, chunk_index, plain_len),
        &encrypted,
    )?;
    encrypted.zeroize();
    if plaintext.len() as u64 != plain_len {
        plaintext.zeroize();
        anyhow::bail!("Chunk plaintext length mismatch");
    }
    Ok(Zeroizing::new(plaintext))
}

pub fn verify_all(opened: &OpenedContainer) -> Result<()> {
    let mut files: Vec<&Entry> = opened
        .index
        .entries
        .values()
        .filter(|entry| entry.kind == EntryKind::File)
        .collect();
    files.sort_by_key(|entry| entry.data_offset);
    for entry in files {
        for chunk_index in 0..entry.chunk_count {
            let _plaintext = decrypt_chunk(opened, entry, chunk_index)
                .with_context(|| format!("File entry {} chunk {} failed", entry.id, chunk_index))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_sizes_cover_boundaries() {
        assert_eq!(encrypted_file_size(0).unwrap(), (0, 0));
        assert_eq!(encrypted_file_size(1).unwrap(), (1, 17));
        assert_eq!(
            encrypted_file_size(CHUNK_SIZE as u64 - 1).unwrap(),
            (1, CHUNK_SIZE as u64 - 1 + TAG_SIZE)
        );
        assert_eq!(
            encrypted_file_size(CHUNK_SIZE as u64).unwrap(),
            (1, CHUNK_SIZE as u64 + TAG_SIZE)
        );
        assert_eq!(
            encrypted_file_size(CHUNK_SIZE as u64 + 1).unwrap(),
            (2, CHUNK_SIZE as u64 + 1 + TAG_SIZE * 2)
        );
    }

    #[test]
    fn filenames_are_single_safe_components() {
        assert!(validate_name("hello.txt").is_ok());
        assert!(validate_name("../escape").is_err());
        assert!(validate_name("/absolute").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name("..").is_err());
    }

    #[test]
    fn invalid_flat_index_layout_is_rejected() {
        let mut header = test_header();
        header.entry_count = 2;
        header.data_size = 17;
        let index = Index {
            entries: vec![
                Entry {
                    id: 1,
                    parent_id: 1,
                    name: String::new(),
                    depth: 0,
                    kind: EntryKind::Directory,
                    file_id: [0; 16],
                    size: 0,
                    data_offset: 0,
                    encrypted_size: 0,
                    chunk_count: 0,
                },
                Entry {
                    id: 2,
                    parent_id: 1,
                    name: "file".to_string(),
                    depth: 1,
                    kind: EntryKind::File,
                    file_id: [1; 16],
                    size: 1,
                    data_offset: 1,
                    encrypted_size: 17,
                    chunk_count: 1,
                },
            ],
        };
        assert!(validate_index(&header, index).is_err());
    }

    #[test]
    fn declared_index_array_above_limit_is_rejected_before_allocation() {
        let encoded = [0x91, 0xdd, 0xff, 0xff, 0xff, 0xff];
        assert!(rmp_serde::from_slice::<Index>(&encoded).is_err());
    }

    #[test]
    fn independent_file_keys_differ() {
        let dek = [7u8; 32];
        let container = [8u8; 16];
        let first = derive_file_key(&dek, &container, &[1u8; 16]).unwrap();
        let second = derive_file_key(&dek, &container, &[2u8; 16]).unwrap();
        assert_ne!(first, second);
    }

    fn test_header() -> Header {
        Header {
            magic: MAGIC,
            version: VERSION,
            header_size: HEADER_SIZE as u32,
            container_id: [3; 16],
            chunk_size: CHUNK_SIZE as u32,
            index_size: TAG_SIZE,
            data_size: 0,
            entry_count: 1,
            index_nonce: [4; 12],
            slots: [KeySlot::random_disabled(), KeySlot::random_disabled()],
            duress: DuressSlot::random_disabled(),
        }
    }

    #[test]
    fn main_and_duress_passwords_are_separate_slow_verifiers() {
        let params = Argon2Params {
            m_cost: MIN_ARGON_MEMORY_KIB,
            t_cost: 1,
            p_cost: 1,
        };
        let mut header = test_header();
        configure_duress(&mut header, Some("duress"), params).unwrap();
        let dek = [9u8; 32];
        header.slots[0] = make_key_slot(&header, "master", &dek, 1, params).unwrap();
        assert!(matches!(
            unlock(&header, "master").unwrap(),
            UnlockResult::Unlocked(_)
        ));
        assert!(matches!(
            unlock(&header, "duress").unwrap(),
            UnlockResult::Duress
        ));
        assert!(matches!(
            unlock(&header, "wrong").unwrap(),
            UnlockResult::Failed
        ));
    }

    #[test]
    fn dual_slots_survive_interrupted_password_change() {
        let params = Argon2Params {
            m_cost: MIN_ARGON_MEMORY_KIB,
            t_cost: 1,
            p_cost: 1,
        };
        let mut header = test_header();
        let dek = [9u8; 32];
        header.slots[0] = make_key_slot(&header, "old", &dek, 1, params).unwrap();
        header.slots[1] = make_key_slot(&header, "new", &dek, 2, params).unwrap();

        assert!(matches!(
            unlock(&header, "old").unwrap(),
            UnlockResult::Unlocked(_)
        ));
        assert!(matches!(
            unlock(&header, "new").unwrap(),
            UnlockResult::Unlocked(_)
        ));

        header.slots[0] = KeySlot::random_disabled();
        assert!(matches!(
            unlock(&header, "old").unwrap(),
            UnlockResult::Failed
        ));
        assert!(matches!(
            unlock(&header, "new").unwrap(),
            UnlockResult::Unlocked(_)
        ));
    }
}
