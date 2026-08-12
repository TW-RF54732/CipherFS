use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use windows::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
};

use crate::readonly_fs::Node;

#[derive(Clone, Debug)]
struct OrdinalName {
    uppercase: Vec<u16>,
}

impl OrdinalName {
    fn new(value: String) -> Self {
        let uppercase = windows_uppercase(&value);
        Self { uppercase }
    }
}

impl PartialEq for OrdinalName {
    fn eq(&self, other: &Self) -> bool {
        compare_wide(&self.uppercase, &other.uppercase) == Ordering::Equal
    }
}

impl Eq for OrdinalName {}

impl PartialOrd for OrdinalName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdinalName {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_wide(&self.uppercase, &other.uppercase)
    }
}

pub struct WindowsNameMap {
    names: HashMap<u64, String>,
    lookup: BTreeMap<(u64, OrdinalName), u64>,
    changes: Vec<(String, String)>,
}

impl WindowsNameMap {
    pub fn new(nodes: &[Node]) -> Self {
        let mut by_parent: HashMap<u64, Vec<&Node>> = HashMap::new();
        for node in nodes.iter().filter(|node| node.id != node.parent_id) {
            by_parent.entry(node.parent_id).or_default().push(node);
        }

        let mut names = HashMap::new();
        let mut lookup = BTreeMap::new();
        for (parent, mut children) in by_parent {
            children.sort_by_key(|node| node.id);
            let mut groups: BTreeMap<OrdinalName, Vec<&Node>> = BTreeMap::new();
            for child in &children {
                groups
                    .entry(OrdinalName::new(child.name.clone()))
                    .or_default()
                    .push(child);
            }
            let collisions: HashSet<u64> = groups
                .values()
                .filter(|group| group.len() > 1)
                .flatten()
                .map(|node| node.id)
                .collect();

            let mut used = BTreeSet::new();
            for child in &children {
                if !needs_mapping(&child.name) && !collisions.contains(&child.id) {
                    used.insert(OrdinalName::new(child.name.clone()));
                    names.insert(child.id, child.name.clone());
                }
            }
            for child in &children {
                if names.contains_key(&child.id) {
                    continue;
                }
                let mut attempt = 0u64;
                let display = loop {
                    let candidate = mapped_name(&child.name, child.id, attempt);
                    if used.insert(OrdinalName::new(candidate.clone())) {
                        break candidate;
                    }
                    attempt = attempt.saturating_add(1);
                };
                names.insert(child.id, display);
            }
            for child in children {
                let display = names
                    .get(&child.id)
                    .expect("every child has a display name");
                lookup.insert((parent, OrdinalName::new(display.clone())), child.id);
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
            .get(&(parent, OrdinalName::new(display_name.to_string())))
            .copied()
    }

    pub fn changes(&self) -> &[(String, String)] {
        &self.changes
    }
}

pub fn compare_display_names(left: &str, right: &str) -> Ordering {
    ordinal_compare(left, right)
}

pub fn equivalent(left: &str, right: &str) -> bool {
    ordinal_compare(left, right) == Ordering::Equal
}

fn ordinal_compare(left: &str, right: &str) -> Ordering {
    compare_wide(&windows_uppercase(left), &windows_uppercase(right))
}

fn compare_wide(left: &[u16], right: &[u16]) -> Ordering {
    let result = unsafe { CompareStringOrdinal(left, right, true) };
    if result == CSTR_LESS_THAN {
        Ordering::Less
    } else if result == CSTR_EQUAL {
        Ordering::Equal
    } else if result == CSTR_GREATER_THAN {
        Ordering::Greater
    } else {
        left.cmp(right)
    }
}

fn windows_uppercase(value: &str) -> Vec<u16> {
    // CompareStringOrdinal(ignoreCase=true) does not collapse every pair in
    // the NTFS upcase table (notably Greek sigma/final-sigma). Normalize to a
    // conservative filesystem key first, then keep ordering and equality in
    // the Windows ordinal API.
    value.to_uppercase().encode_utf16().collect()
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
                matches!(
                    number,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
}

fn mapped_name(name: &str, id: u64, attempt: u64) -> String {
    let suffix = if attempt == 0 {
        format!("~cfs-{id:016x}")
    } else {
        format!("~cfs-{id:016x}-{attempt}")
    };
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
    fn maps_reserved_invalid_and_windows_ordinal_collisions() {
        let generated_collision = format!("bad_.txt~cfs-{:016x}", 3);
        let overlong = "??".repeat(128);
        let nodes = vec![
            node(2, "CON"),
            node(3, "bad?.txt"),
            node(4, "A.txt"),
            node(5, "a.txt"),
            node(6, "trailing. "),
            node(7, &overlong),
            node(8, &generated_collision),
            node(9, "COM¹.txt"),
            node(10, "LPT³"),
            node(11, "σ.txt"),
            node(12, "ς.txt"),
            node(13, "µ.txt"),
            node(14, "μ.txt"),
        ];
        let map = WindowsNameMap::new(&nodes);
        for item in &nodes {
            assert_eq!(map.lookup(1, map.name(item)), Some(item.id));
            assert!(map.name(item).encode_utf16().count() <= 255);
        }
        for id in [2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14] {
            let item = nodes.iter().find(|node| node.id == id).unwrap();
            assert!(
                map.name(item).contains("~cfs-"),
                "entry {id} was not mapped: {:?}",
                map.name(item)
            );
        }
        assert_ne!(map.name(&nodes[1]), map.name(&nodes[6]));
        assert!(equivalent("σ.txt", "ς.txt"));
        assert!(equivalent("µ.txt", "μ.txt"));
    }
}
