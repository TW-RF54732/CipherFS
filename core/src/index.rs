use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Inode {
    File {
        size: u64,
        offset: u64,
    },
    Directory {
        #[serde(with = "serde_arc_map")]
        entries: Arc<HashMap<String, Inode>>,
    },
}

impl Inode {
    pub fn is_file(&self) -> bool {
        matches!(self, Inode::File { .. })
    }
}

// Custom serialization for Arc<HashMap>
mod serde_arc_map {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(data: &Arc<HashMap<String, Inode>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        data.as_ref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<HashMap<String, Inode>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = HashMap::deserialize(deserializer)?;
        Ok(Arc::new(map))
    }
}
