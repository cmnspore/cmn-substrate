//! In-memory archive extraction with security validation.
//!
//! Provides tar unpacking and zstd decompression that operate entirely in memory,
//! returning `Vec<ArchiveEntry>` instead of writing to the filesystem.
//! This makes the core extraction logic usable in WASM environments.

mod zstd_codec;

pub use zstd_codec::*;

use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use crate::tree::TreeEntry;

/// Limits for archive extraction to prevent resource exhaustion.
pub struct ExtractLimits {
    pub max_bytes: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
}

/// Kind of entry in a tar archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

/// A single entry extracted from a tar archive.
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: EntryKind,
    pub data: Vec<u8>,
}

/// Error type for archive extraction operations.
#[derive(Debug)]
pub enum ExtractError {
    /// Content is actively dangerous (symlinks, hardlinks, path traversal, zip bombs).
    Malicious(String),
    /// Non-malicious failure (I/O error, unsupported format, etc.).
    Failed(String),
}

impl ExtractError {
    pub fn is_malicious(&self) -> bool {
        matches!(self, Self::Malicious(_))
    }
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malicious(msg) => write!(f, "MALICIOUS: {}", msg),
            Self::Failed(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<String> for ExtractError {
    fn from(s: String) -> Self {
        Self::Failed(s)
    }
}

/// Unpack tar from raw bytes with security validation.
///
/// Rejects symlinks, hardlinks, absolute paths, and path traversal (`..`).
/// Enforces limits on total bytes, file count, and individual file size.
pub fn extract_tar(
    tar_bytes: &[u8],
    limits: &ExtractLimits,
) -> Result<Vec<ArchiveEntry>, ExtractError> {
    let cursor = Cursor::new(tar_bytes);
    let mut archive = tar::Archive::new(cursor);
    let entries = archive
        .entries()
        .map_err(|e| ExtractError::Failed(format!("Failed to read tar entries: {}", e)))?;

    let mut result = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut total_files: u64 = 0;

    for entry_result in entries {
        let mut entry = entry_result
            .map_err(|e| ExtractError::Failed(format!("Failed to read tar entry: {}", e)))?;
        let entry_type = entry.header().entry_type();

        // Reject symlinks and hardlinks
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let path = entry
                .path()
                .map_err(|e| ExtractError::Failed(format!("Bad entry path: {}", e)))?;
            return Err(ExtractError::Malicious(format!(
                "tar contains disallowed entry type ({:?}): {}",
                entry_type,
                path.display()
            )));
        }
        if !(entry_type.is_file() || entry_type.is_dir()) {
            continue; // skip other special types silently
        }

        let path = entry
            .path()
            .map_err(|e| ExtractError::Failed(format!("Bad entry path: {}", e)))?
            .into_owned();

        // Reject absolute paths and path traversal
        if path.is_absolute()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(ExtractError::Malicious(format!(
                "path traversal in tar: {}",
                path.display()
            )));
        }

        let path_str = path.to_string_lossy().into_owned();

        if entry_type.is_dir() {
            result.push(ArchiveEntry {
                path: path_str,
                kind: EntryKind::Directory,
                data: Vec::new(),
            });
        } else {
            total_files += 1;
            if total_files > limits.max_files {
                return Err(ExtractError::Malicious(format!(
                    "archive exceeds max file count ({})",
                    limits.max_files
                )));
            }

            let mut data = Vec::new();
            let mut chunk = [0u8; 65536];
            let mut file_bytes: u64 = 0;
            loop {
                let n = entry.read(&mut chunk).map_err(|e| {
                    ExtractError::Failed(format!("Failed to read entry {}: {}", path_str, e))
                })?;
                if n == 0 {
                    break;
                }
                file_bytes += n as u64;
                total_bytes += n as u64;
                if file_bytes > limits.max_file_bytes {
                    return Err(ExtractError::Malicious(format!(
                        "single file exceeds max size ({} bytes): {}",
                        limits.max_file_bytes, path_str
                    )));
                }
                if total_bytes > limits.max_bytes {
                    return Err(ExtractError::Malicious(format!(
                        "archive exceeds max extract size ({} bytes)",
                        limits.max_bytes
                    )));
                }
                data.extend_from_slice(&chunk[..n]);
            }

            result.push(ArchiveEntry {
                path: path_str,
                kind: EntryKind::File,
                data,
            });
        }
    }

    Ok(result)
}

/// Decompress zstd then unpack tar — all in memory.
pub fn extract_tar_zstd(
    compressed: &[u8],
    limits: &ExtractLimits,
) -> Result<Vec<ArchiveEntry>, ExtractError> {
    let tar_bytes = decode_zstd(compressed, limits.max_bytes)?;
    extract_tar(&tar_bytes, limits)
}

// ---------------------------------------------------------------------------
// Archive → TreeEntry conversion
// ---------------------------------------------------------------------------

/// Convert flat `ArchiveEntry` list into a nested `TreeEntry` tree.
///
/// Only file entries are included (directories are inferred from paths).
/// Leading `./` and `/` are stripped. All files are marked non-executable.
pub fn archive_entries_to_tree(entries: &[ArchiveEntry]) -> Vec<TreeEntry> {
    entries_to_tree_inner(
        entries
            .iter()
            .filter_map(|e| {
                if e.kind != EntryKind::File {
                    return None;
                }
                let path = e.path.trim_start_matches("./").trim_start_matches('/');
                if path.is_empty() {
                    return None;
                }
                Some((path, e.data.as_slice()))
            })
            .collect(),
    )
}

fn entries_to_tree_inner(files: Vec<(&str, &[u8])>) -> Vec<TreeEntry> {
    let mut root_files: Vec<TreeEntry> = Vec::new();
    let mut subdirs: BTreeMap<&str, Vec<(&str, &[u8])>> = BTreeMap::new();

    for (path, data) in files {
        if let Some(idx) = path.find('/') {
            let dir_name = &path[..idx];
            let rest = &path[idx + 1..];
            if !rest.is_empty() {
                subdirs.entry(dir_name).or_default().push((rest, data));
            }
        } else {
            root_files.push(TreeEntry::File {
                name: path.to_string(),
                content: data.to_vec(),
                executable: false,
            });
        }
    }

    let mut result: Vec<TreeEntry> = subdirs
        .into_iter()
        .map(|(dir_name, children)| TreeEntry::Directory {
            name: dir_name.to_string(),
            children: entries_to_tree_inner(children),
        })
        .collect();

    result.extend(root_files);
    result
}

/// Consuming variant — moves file data into `TreeEntry` without cloning.
///
/// Use this when archive entries are not needed after tree construction.
pub fn archive_entries_into_tree(entries: Vec<ArchiveEntry>) -> Vec<TreeEntry> {
    entries_into_tree_inner(
        entries
            .into_iter()
            .filter_map(|e| {
                if e.kind != EntryKind::File {
                    return None;
                }
                let path = e
                    .path
                    .trim_start_matches("./")
                    .trim_start_matches('/')
                    .to_string();
                if path.is_empty() {
                    return None;
                }
                Some((path, e.data))
            })
            .collect(),
    )
}

fn entries_into_tree_inner(files: Vec<(String, Vec<u8>)>) -> Vec<TreeEntry> {
    let mut root_files: Vec<TreeEntry> = Vec::new();
    let mut subdirs: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();

    for (path, data) in files {
        if let Some(idx) = path.find('/') {
            let dir_name = path[..idx].to_string();
            let rest = path[idx + 1..].to_string();
            if !rest.is_empty() {
                subdirs.entry(dir_name).or_default().push((rest, data));
            }
        } else {
            root_files.push(TreeEntry::File {
                name: path,
                content: data,
                executable: false,
            });
        }
    }

    let mut result: Vec<TreeEntry> = subdirs
        .into_iter()
        .map(|(dir_name, children)| TreeEntry::Directory {
            name: dir_name,
            children: entries_into_tree_inner(children),
        })
        .collect();

    result.extend(root_files);
    result
}

// ---------------------------------------------------------------------------
// Extract + verify pipeline
// ---------------------------------------------------------------------------

/// Extract a tar.zst archive, verify content hash against a spore, and return
/// the verified entries.
///
/// This is the standard pipeline for consuming a spore archive:
/// 1. Decompress zstd + unpack tar (with security checks)
/// 2. Build in-memory tree from extracted files
/// 3. Verify tree hash matches the spore's content hash
///
/// The spore's declared `size_bytes` is used as an additional decompression limit
/// to prevent malicious archives from expanding beyond the expected size.
///
/// Returns the raw `ArchiveEntry` list on success (caller decides how to store).
/// Returns `ExtractError` if extraction, security checks, or hash verification fails.
pub fn extract_and_verify_tar_zstd(
    archive_bytes: &[u8],
    spore: &crate::Spore,
    expected_hash: &str,
    limits: &ExtractLimits,
) -> Result<Vec<ArchiveEntry>, ExtractError> {
    // Use the spore's declared size as an additional decompression limit.
    // Add 10% headroom for tar headers and metadata overhead.
    let spore_size = spore.capsule.core.size_bytes;
    let spore_limit = if spore_size > 0 {
        spore_size
            .saturating_add(spore_size / 10)
            .saturating_add(4096)
    } else {
        limits.max_bytes
    };
    let effective_limits = ExtractLimits {
        max_bytes: limits.max_bytes.min(spore_limit),
        max_files: limits.max_files,
        max_file_bytes: limits.max_file_bytes,
    };

    let entries = extract_tar_zstd(archive_bytes, &effective_limits)?;
    let tree = archive_entries_to_tree(&entries);
    spore
        .verify_content_hash(&tree, expected_hash)
        .map_err(|e| ExtractError::Failed(format!("content hash mismatch: {e}")))?;
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_to_tree_single_file() {
        let entries = vec![ArchiveEntry {
            path: "README.md".to_string(),
            kind: EntryKind::File,
            data: b"# hello".to_vec(),
        }];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        match &tree[0] {
            TreeEntry::File { name, content, .. } => {
                assert_eq!(name, "README.md");
                assert_eq!(content, b"# hello");
            }
            _ => panic!("expected file"),
        }
    }

    #[test]
    fn entries_to_tree_nested() {
        let entries = vec![
            ArchiveEntry {
                path: "src/main.rs".into(),
                kind: EntryKind::File,
                data: b"fn main(){}".to_vec(),
            },
            ArchiveEntry {
                path: "src/lib.rs".into(),
                kind: EntryKind::File,
                data: b"//lib".to_vec(),
            },
            ArchiveEntry {
                path: "README.md".into(),
                kind: EntryKind::File,
                data: b"hi".to_vec(),
            },
        ];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 2); // src/ dir + README.md
        match &tree[0] {
            TreeEntry::Directory { name, children } => {
                assert_eq!(name, "src");
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected directory"),
        }
    }

    #[test]
    fn entries_to_tree_skips_directories() {
        let entries = vec![
            ArchiveEntry {
                path: "src/".into(),
                kind: EntryKind::Directory,
                data: vec![],
            },
            ArchiveEntry {
                path: "src/main.rs".into(),
                kind: EntryKind::File,
                data: b"fn main(){}".to_vec(),
            },
        ];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        match &tree[0] {
            TreeEntry::Directory { name, children } => {
                assert_eq!(name, "src");
                assert_eq!(children.len(), 1);
            }
            _ => panic!("expected directory"),
        }
    }

    #[test]
    fn entries_to_tree_strips_dot_slash() {
        let entries = vec![ArchiveEntry {
            path: "./README.md".into(),
            kind: EntryKind::File,
            data: b"hi".to_vec(),
        }];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        match &tree[0] {
            TreeEntry::File { name, .. } => assert_eq!(name, "README.md"),
            _ => panic!("expected file"),
        }
    }

    #[test]
    fn entries_to_tree_deeply_nested() {
        let entries = vec![ArchiveEntry {
            path: "a/b/c/d.txt".into(),
            kind: EntryKind::File,
            data: b"deep".to_vec(),
        }];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        match &tree[0] {
            TreeEntry::Directory { name, children } => {
                assert_eq!(name, "a");
                assert_eq!(children.len(), 1);
                match &children[0] {
                    TreeEntry::Directory { name, children } => {
                        assert_eq!(name, "b");
                        match &children[0] {
                            TreeEntry::Directory { name, children } => {
                                assert_eq!(name, "c");
                                match &children[0] {
                                    TreeEntry::File { name, content, .. } => {
                                        assert_eq!(name, "d.txt");
                                        assert_eq!(content, b"deep");
                                    }
                                    _ => panic!("expected file"),
                                }
                            }
                            _ => panic!("expected directory"),
                        }
                    }
                    _ => panic!("expected directory"),
                }
            }
            _ => panic!("expected directory"),
        }
    }
}
