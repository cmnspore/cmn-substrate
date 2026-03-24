//! `blob_tree_blake3_nfc` tree hashing algorithm.
//!
//! This algorithm uses Git-like blob/tree object construction, BLAKE3 hashing,
//! and NFC filename normalization for cross-platform stability.

use anyhow::{anyhow, Result};
use unicode_normalization::UnicodeNormalization;

use crate::crypto::{format_hash, HashAlgorithm};

pub const ALGORITHM: &str = "blob_tree_blake3_nfc";

/// Hash output size in bytes (BLAKE3 = 32).
const HASH_SIZE: usize = 32;

/// Git file modes.
const MODE_FILE: &str = "100644";
const MODE_EXECUTABLE: &str = "100755";
const MODE_DIRECTORY: &str = "40000";

/// In-memory representation of a filesystem entry for tree hashing.
pub enum TreeEntry {
    File {
        name: String,
        content: Vec<u8>,
        executable: bool,
    },
    Directory {
        name: String,
        children: Vec<TreeEntry>,
    },
}

fn hash_data(data: &[u8]) -> [u8; HASH_SIZE] {
    *blake3::hash(data).as_bytes()
}

fn normalize_filename(name: &str) -> String {
    name.nfc().collect::<String>()
}

fn hash_blob(content: &[u8]) -> [u8; HASH_SIZE] {
    let header = format!("blob {}\0", content.len());
    let mut data = Vec::new();
    data.extend_from_slice(header.as_bytes());
    data.extend_from_slice(content);
    hash_data(&data)
}

fn hash_tree(entries: &[(String, String, [u8; HASH_SIZE])]) -> [u8; HASH_SIZE] {
    let mut entry_bytes = Vec::new();

    for (mode, name, hash) in entries {
        entry_bytes.extend_from_slice(mode.as_bytes());
        entry_bytes.push(b' ');
        entry_bytes.extend_from_slice(name.as_bytes());
        entry_bytes.push(b'\0');
        entry_bytes.extend_from_slice(hash);
    }

    let header = format!("tree {}\0", entry_bytes.len());
    let mut tree_data = Vec::new();
    tree_data.extend_from_slice(header.as_bytes());
    tree_data.extend_from_slice(&entry_bytes);

    hash_data(&tree_data)
}

fn should_exclude(name: &str, exclude_names: &[String]) -> bool {
    exclude_names.iter().any(|pattern| name == pattern)
}

/// Compute a tree hash from in-memory entries (no filesystem I/O).
pub fn compute_hash_from_entries(
    entries: &[TreeEntry],
    exclude_names: &[String],
) -> Result<String> {
    let (hash, _size) = hash_entries(entries, exclude_names)?;
    Ok(format_hash(HashAlgorithm::B3, &hash))
}

/// Compute tree hash and total uncompressed source size (sum of all blob content bytes).
pub fn compute_hash_and_size_from_entries(
    entries: &[TreeEntry],
    exclude_names: &[String],
) -> Result<(String, u64)> {
    let (hash, size) = hash_entries(entries, exclude_names)?;
    Ok((format_hash(HashAlgorithm::B3, &hash), size))
}

fn hash_entries(entries: &[TreeEntry], exclude_names: &[String]) -> Result<([u8; HASH_SIZE], u64)> {
    let mut tree_entries = Vec::new();
    let mut total_size: u64 = 0;

    for entry in entries {
        let (raw_name, mode, hash) = match entry {
            TreeEntry::File {
                name,
                content,
                executable,
            } => {
                if should_exclude(name, exclude_names) {
                    continue;
                }
                total_size += content.len() as u64;
                let mode = if *executable {
                    MODE_EXECUTABLE
                } else {
                    MODE_FILE
                };
                (name.as_str(), mode.to_string(), hash_blob(content))
            }
            TreeEntry::Directory { name, children } => {
                if should_exclude(name, exclude_names) {
                    continue;
                }
                let (dir_hash, dir_size) = hash_entries(children, exclude_names)?;
                total_size += dir_size;
                (name.as_str(), MODE_DIRECTORY.to_string(), dir_hash)
            }
        };

        let normalized_name = normalize_filename(raw_name);
        if tree_entries.iter().any(
            |(_, existing_name, _): &(String, String, [u8; HASH_SIZE])| {
                existing_name == &normalized_name
            },
        ) {
            return Err(anyhow!(
                "Filename conflict after NFC normalization: {} (multiple files normalize to same name)",
                raw_name
            ));
        }

        tree_entries.push((mode, normalized_name, hash));
    }

    tree_entries.sort_by(|a, b| a.1.cmp(&b.1));
    Ok((hash_tree(&tree_entries), total_size))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_hash_empty_blob() {
        let content = b"";
        let hash = hash_blob(content);
        assert_eq!(hash.len(), 32);

        let expected_data = b"blob 0\0";
        let expected_hash = blake3::hash(expected_data);
        assert_eq!(hash, *expected_hash.as_bytes());
    }

    #[test]
    fn test_hash_simple_blob() {
        let content = b"hello";
        let hash = hash_blob(content);
        let hash2 = hash_blob(content);
        assert_eq!(hash, hash2);

        let expected_data = b"blob 5\0hello";
        let expected_hash = blake3::hash(expected_data);
        assert_eq!(hash, *expected_hash.as_bytes());
    }

    #[test]
    fn test_normalize_filename() {
        let nfd = "cafe\u{0301}";
        let normalized = normalize_filename(nfd);
        let nfc = "caf\u{00e9}";
        assert_eq!(normalized, nfc);
    }

    #[test]
    fn test_hash_tree_empty() {
        let entries: Vec<(String, String, [u8; 32])> = vec![];
        let hash = hash_tree(&entries);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_tree_single_entry() {
        let file_hash = [0u8; 32];
        let entries = vec![(MODE_FILE.to_string(), "test.txt".to_string(), file_hash)];
        let hash = hash_tree(&entries);
        let hash2 = hash_tree(&entries);
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_hash_from_entries_format() {
        let entries = vec![TreeEntry::File {
            name: "test.txt".to_string(),
            content: b"hello".to_vec(),
            executable: false,
        }];

        let hash = compute_hash_from_entries(&entries, &[]).unwrap();
        assert!(hash.starts_with("b3."));
        let b58_part = &hash[3..];
        assert!(b58_part.len() >= 40 && b58_part.len() <= 48);
    }

    #[test]
    fn test_exclusion() {
        let entries = vec![
            TreeEntry::File {
                name: "excluded.tmp".to_string(),
                content: b"{}".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "test.txt".to_string(),
                content: b"hello".to_vec(),
                executable: false,
            },
        ];

        let hash_all = compute_hash_from_entries(&entries, &[]).unwrap();
        let hash_excluded =
            compute_hash_from_entries(&entries, &["excluded.tmp".to_string()]).unwrap();
        assert_ne!(hash_all, hash_excluded);
    }

    #[test]
    fn test_deterministic_hash() {
        let entries = vec![
            TreeEntry::File {
                name: "a.txt".to_string(),
                content: b"content a".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "b.txt".to_string(),
                content: b"content b".to_vec(),
                executable: false,
            },
        ];

        let hash1 = compute_hash_from_entries(&entries, &[]).unwrap();
        let hash2 = compute_hash_from_entries(&entries, &[]).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_should_exclude() {
        assert!(!should_exclude("test.json", &[]));
        assert!(!should_exclude("other.json", &[]));

        let excludes = vec!["node_modules".to_string(), ".git".to_string()];
        assert!(should_exclude("node_modules", &excludes));
        assert!(should_exclude(".git", &excludes));
        assert!(!should_exclude("src", &excludes));
    }

    #[test]
    fn test_nested_directory() {
        let entries = vec![
            TreeEntry::File {
                name: "main.rs".to_string(),
                content: b"fn main() {}".to_vec(),
                executable: false,
            },
            TreeEntry::Directory {
                name: "src".to_string(),
                children: vec![TreeEntry::File {
                    name: "lib.rs".to_string(),
                    content: b"pub fn foo() {}".to_vec(),
                    executable: false,
                }],
            },
        ];

        let hash = compute_hash_from_entries(&entries, &[]).unwrap();
        assert!(hash.starts_with("b3."));
    }

    #[test]
    fn test_executable_flag() {
        let entries_normal = vec![TreeEntry::File {
            name: "script.sh".to_string(),
            content: b"#!/bin/sh".to_vec(),
            executable: false,
        }];
        let entries_exec = vec![TreeEntry::File {
            name: "script.sh".to_string(),
            content: b"#!/bin/sh".to_vec(),
            executable: true,
        }];

        let hash_normal = compute_hash_from_entries(&entries_normal, &[]).unwrap();
        let hash_exec = compute_hash_from_entries(&entries_exec, &[]).unwrap();
        assert_ne!(hash_normal, hash_exec);
    }
}
