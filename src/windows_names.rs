use std::collections::{HashMap, HashSet};

use crate::readonly_fs::Node;

pub struct WindowsNameMap {
    names: HashMap<u64, String>,
    lookup: HashMap<(u64, String), u64>,
    changes: Vec<(String, String)>,
}

impl WindowsNameMap {
    pub fn new(nodes: &[Node]) -> Self {
        let mut by_parent: HashMap<u64, Vec<&Node>> = HashMap::new();
        for node in nodes.iter().filter(|node| node.id != node.parent_id) {
            by_parent.entry(node.parent_id).or_default().push(node);
        }
        let mut names = HashMap::new();
        let mut lookup = HashMap::new();
        for (parent, mut children) in by_parent {
            children.sort_by_key(|node| node.id);
            let mut base_counts: HashMap<String, usize> = HashMap::new();
            for child in &children {
                *base_counts.entry(child.name.to_lowercase()).or_default() += 1;
            }
            let mut used = HashSet::new();
            for child in children {
                let invalid = needs_mapping(&child.name);
                let collision = base_counts
                    .get(&child.name.to_lowercase())
                    .copied()
                    .unwrap_or(0)
                    > 1;
                let mut display = if invalid || collision {
                    mapped_name(&child.name, child.id)
                } else {
                    child.name.clone()
                };
                while !used.insert(display.to_lowercase()) {
                    display = mapped_name(&display, child.id);
                }
                lookup.insert((parent, display.to_lowercase()), child.id);
                names.insert(child.id, display);
            }
        }
        let by_id: HashMap<u64, &Node> = nodes.iter().map(|node| (node.id, node)).collect();
        let mut changed_nodes: Vec<&Node> = nodes
            .iter()
            .filter(|node| names.get(&node.id).is_some_and(|name| name != &node.name))
            .collect();
        changed_nodes.sort_by_key(|node| node.id);
        let changes = changed_nodes
            .into_iter()
            .map(|node| {
                (
                    node_path(node.id, &by_id, &HashMap::new()),
                    node_path(node.id, &by_id, &names),
                )
            })
            .collect();
        Self {
            names,
            lookup,
            changes,
        }
    }

    pub fn name<'a>(&'a self, node: &'a Node) -> &'a str {
        self.name_for(node.id, &node.name)
    }

    pub fn name_for<'a>(&'a self, id: u64, original: &'a str) -> &'a str {
        self.names.get(&id).map_or(original, String::as_str)
    }

    pub fn lookup(&self, parent: u64, display_name: &str) -> Option<u64> {
        self.lookup
            .get(&(parent, display_name.to_lowercase()))
            .copied()
    }

    pub fn warn(&self) {
        for (original, display) in &self.changes {
            eprintln!("[Warning] Windows name mapping: {original:?} -> {display:?}");
        }
        if !self.changes.is_empty() {
            eprintln!(
                "[Warning] {} name(s) were mapped for Windows compatibility.",
                self.changes.len()
            );
        }
    }
}

fn node_path(id: u64, nodes: &HashMap<u64, &Node>, names: &HashMap<u64, String>) -> String {
    let mut components = Vec::new();
    let mut current = id;
    while let Some(node) = nodes.get(&current) {
        if node.id == node.parent_id {
            break;
        }
        components.push(
            names
                .get(&node.id)
                .map_or_else(|| node.name.as_str(), String::as_str),
        );
        current = node.parent_id;
    }
    components.reverse();
    components.join("\\")
}

fn needs_mapping(name: &str) -> bool {
    if name.is_empty()
        || name.ends_with([' ', '.'])
        || name.chars().any(|ch| {
            ch <= '\u{1f}' || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
        || name.encode_utf16().count() > 255
    {
        return true;
    }
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn mapped_name(name: &str, id: u64) -> String {
    let suffix = format!("~cfs-{id:016x}");
    let mut cleaned: String = name
        .chars()
        .map(|ch| {
            if ch <= '\u{1f}' || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            {
                '_'
            } else {
                ch
            }
        })
        .collect();
    cleaned = cleaned.trim_end_matches([' ', '.']).to_string();
    if cleaned.is_empty() {
        cleaned.push_str("entry");
    }
    while cleaned.encode_utf16().count() + suffix.encode_utf16().count() > 255 {
        cleaned.pop();
    }
    cleaned.push_str(&suffix);
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readonly_fs::NodeKind;

    fn node(id: u64, name: &str) -> Node {
        Node {
            id,
            parent_id: 1,
            name: name.to_string(),
            kind: NodeKind::File,
            size: 0,
        }
    }

    #[test]
    fn maps_reserved_invalid_and_case_collisions_deterministically() {
        let secondary = format!("bad_~cfs-{:016x}", 3);
        let overlong = "😀".repeat(128);
        let nodes = vec![
            node(2, "CON"),
            node(3, "bad?.txt"),
            node(4, "A.txt"),
            node(5, "a.txt"),
            node(6, "trailing. "),
            node(7, &overlong),
            node(8, &secondary),
        ];
        let map = WindowsNameMap::new(&nodes);
        for item in &nodes[..6] {
            assert!(map.name(item).contains("~cfs-"));
            assert_eq!(map.lookup(1, map.name(item)), Some(item.id));
            assert!(map.name(item).encode_utf16().count() <= 255);
        }
        assert_ne!(map.name(&nodes[1]), map.name(&nodes[6]));
        assert_eq!(map.lookup(1, map.name(&nodes[5])), Some(7));
        assert_eq!(map.lookup(1, map.name(&nodes[6])), Some(8));
    }
}
