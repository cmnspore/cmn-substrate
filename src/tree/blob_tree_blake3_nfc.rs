//! `blob_tree_blake3_nfc` tree hashing algorithm.
//!
//! This algorithm uses Git-like blob/tree object construction, BLAKE3 hashing,
//! and NFC filename normalization for cross-platform stability.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use unicase::UniCase;
use unicode_normalization::UnicodeNormalization;

use crate::crypto::{format_hash, HashAlgorithm};

pub const ALGORITHM: &str = "blob_tree_blake3_nfc";

/// Hash output size in bytes (BLAKE3 = 32).
const HASH_SIZE: usize = 32;

/// Git-compatible file modes.
const MODE_FILE: &str = "100644";
const MODE_EXECUTABLE: &str = "100755";
const MODE_DIRECTORY: &str = "40000";

/// In-memory representation of a filesystem entry for tree hashing.
///
/// Symlinks are not supported — implementations MUST reject them at walk time.
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

/// Return CMN's deterministic key for portable sibling filename matching.
///
/// This intentionally uses canonical decomposition plus Unicode case folding,
/// not compatibility folding, so compatibility glyphs are not over-rejected.
pub fn portable_filename_key(name: &str) -> String {
    let decomposed = name.nfd().collect::<String>();
    UniCase::unicode(decomposed.as_str())
        .to_folded_case()
        .nfd()
        .collect()
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
    let mut seen_names = HashSet::new();
    let mut seen_portable_names = HashSet::new();
    let mut total_size: u64 = 0;

    for entry in entries {
        let raw_name = match entry {
            TreeEntry::File { name, .. } | TreeEntry::Directory { name, .. } => name.as_str(),
        };

        if should_exclude(raw_name, exclude_names) {
            continue;
        }

        let normalized_name = normalize_filename(raw_name);
        if !seen_names.insert(normalized_name.clone()) {
            return Err(anyhow!(
                "filename_nfc_conflict: Filename conflict after NFC normalization: {} (multiple sibling entries normalize to same name)",
                raw_name
            ));
        }

        let portable_name = portable_filename_key(raw_name);
        if !seen_portable_names.insert(portable_name) {
            return Err(anyhow!(
                "filename_portable_conflict: Filename conflict under CMN portable filename matching: {} (multiple sibling entries fold to same portable name)",
                raw_name
            ));
        }

        let (mode, hash) = match entry {
            TreeEntry::File {
                content,
                executable,
                ..
            } => {
                total_size += content.len() as u64;
                let mode = if *executable {
                    MODE_EXECUTABLE
                } else {
                    MODE_FILE
                };
                (mode.to_string(), hash_blob(content))
            }
            TreeEntry::Directory { children, .. } => {
                let (dir_hash, dir_size) = hash_entries(children, exclude_names)?;
                total_size += dir_size;
                (MODE_DIRECTORY.to_string(), dir_hash)
            }
        };

        tree_entries.push((mode, normalized_name, hash));
    }

    tree_entries.sort_by(|a, b| a.1.cmp(&b.1));
    Ok((hash_tree(&tree_entries), total_size))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

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
    fn test_portable_filename_key() {
        assert_eq!(
            portable_filename_key("File.txt"),
            portable_filename_key("file.txt")
        );
        assert_eq!(
            portable_filename_key("cafe\u{0301}.txt"),
            portable_filename_key("caf\u{00e9}.txt")
        );
        assert_eq!(
            portable_filename_key("Maße.txt"),
            portable_filename_key("MASSE.txt")
        );
        assert_eq!(
            portable_filename_key("Σ.txt"),
            portable_filename_key("ς.txt")
        );
        assert_eq!(
            portable_filename_key("ﬂour.txt"),
            portable_filename_key("flour.txt")
        );
        assert_eq!(
            portable_filename_key("K.txt"),
            portable_filename_key("k.txt")
        );
        assert_ne!(
            portable_filename_key("Ａ.txt"),
            portable_filename_key("A.txt")
        );
        assert_ne!(
            portable_filename_key("①.txt"),
            portable_filename_key("1.txt")
        );
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

    #[test]
    fn rejects_sibling_case_collision() {
        let entries = vec![
            TreeEntry::File {
                name: "File.txt".to_string(),
                content: b"upper".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "file.txt".to_string(),
                content: b"lower".to_vec(),
                executable: false,
            },
        ];
        let err = compute_hash_from_entries(&entries, &[]).unwrap_err();
        assert!(err.to_string().contains("filename_portable_conflict"));
    }

    #[test]
    fn rejects_sibling_canonical_unicode_collision() {
        let entries = vec![
            TreeEntry::File {
                name: "caf\u{00e9}.txt".to_string(),
                content: b"nfc".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "cafe\u{0301}.txt".to_string(),
                content: b"nfd".to_vec(),
                executable: false,
            },
        ];
        let err = compute_hash_from_entries(&entries, &[]).unwrap_err();
        assert!(err.to_string().contains("filename_nfc_conflict"));
    }

    #[test]
    fn rejects_sibling_full_case_fold_collision() {
        let entries = vec![
            TreeEntry::File {
                name: "Maße.txt".to_string(),
                content: b"one".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "MASSE.txt".to_string(),
                content: b"two".to_vec(),
                executable: false,
            },
        ];
        let err = compute_hash_from_entries(&entries, &[]).unwrap_err();
        assert!(err.to_string().contains("filename_portable_conflict"));
    }

    #[test]
    fn rejects_file_vs_directory_portable_collision() {
        let entries = vec![
            TreeEntry::File {
                name: "foo".to_string(),
                content: b"file".to_vec(),
                executable: false,
            },
            TreeEntry::Directory {
                name: "FOO".to_string(),
                children: vec![TreeEntry::File {
                    name: "bar".to_string(),
                    content: b"child".to_vec(),
                    executable: false,
                }],
            },
        ];
        let err = compute_hash_from_entries(&entries, &[]).unwrap_err();
        assert!(err.to_string().contains("filename_portable_conflict"));
    }
}
