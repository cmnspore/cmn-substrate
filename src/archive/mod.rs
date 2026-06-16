//! In-memory archive extraction with security validation.
//!
//! Provides tar unpacking and zstd decompression that operate entirely in memory,
//! returning `Vec<ArchiveEntry>` instead of writing to the filesystem.
//! This makes the core extraction logic usable in WASM environments.

mod zstd_codec;

pub use zstd_codec::*;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path};

use crate::tree::{portable_filename_key, TreeEntry};

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
    /// Executable bit from the tar header (`mode & 0o111`). Always `false` for directories.
    ///
    /// Must survive the round trip: tree hashes encode git-style modes
    /// (`100755`/`100644`), so dropping this bit makes archive verification
    /// diverge from the publisher's filesystem-derived hash.
    pub executable: bool,
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
    let mut seen_paths = BTreeSet::new();
    let mut seen_components = PortableComponentTracker::default();
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

        let Some(path_str) = normalize_archive_path(&path)? else {
            continue;
        };
        if !seen_paths.insert(path_str.clone()) {
            return Err(ExtractError::Malicious(format!(
                "duplicate path in tar after normalization: {}",
                path_str
            )));
        }
        seen_components.validate_path(&path_str)?;

        if entry_type.is_dir() {
            result.push(ArchiveEntry {
                path: path_str,
                kind: EntryKind::Directory,
                data: Vec::new(),
                executable: false,
            });
        } else {
            let executable = entry
                .header()
                .mode()
                .map(|m| m & 0o111 != 0)
                .unwrap_or(false);
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
                executable,
            });
        }
    }

    Ok(result)
}

fn normalize_archive_path(path: &Path) -> Result<Option<String>, ExtractError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ExtractError::Malicious(format!(
                    "path traversal in tar: {}",
                    path.display()
                )));
            }
        }
    }

    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parts.join("/")))
    }
}

#[derive(Default)]
struct PortableComponentTracker {
    by_parent: BTreeMap<String, BTreeMap<String, String>>,
}

impl PortableComponentTracker {
    fn validate_path(&mut self, path: &str) -> Result<(), ExtractError> {
        let mut parent = String::new();

        for component in path.split('/') {
            let portable_key = portable_filename_key(component);
            let siblings = self.by_parent.entry(parent.clone()).or_default();
            match siblings.get(&portable_key) {
                Some(existing) if existing != component => {
                    return Err(ExtractError::Malicious(format!(
                        "filename_portable_conflict: archive path component '{}' conflicts with sibling '{}' under CMN portable filename matching",
                        component, existing
                    )));
                }
                Some(_) => {}
                None => {
                    siblings.insert(portable_key, component.to_string());
                }
            }

            if parent.is_empty() {
                parent.push_str(component);
            } else {
                parent.push('/');
                parent.push_str(component);
            }
        }

        Ok(())
    }
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
/// Leading `./` and `/` are stripped. The executable bit is carried over
/// so tree hashes match the publisher's filesystem-derived hash.
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
                Some((path, e.data.as_slice(), e.executable))
            })
            .collect(),
    )
}

/// `(path, content, executable)` borrowed from an `ArchiveEntry`.
type FileRef<'a> = (&'a str, &'a [u8], bool);

fn entries_to_tree_inner(files: Vec<FileRef<'_>>) -> Vec<TreeEntry> {
    let mut root_files: Vec<TreeEntry> = Vec::new();
    let mut subdirs: BTreeMap<&str, Vec<FileRef<'_>>> = BTreeMap::new();

    for (path, data, executable) in files {
        if let Some(idx) = path.find('/') {
            let dir_name = &path[..idx];
            let rest = &path[idx + 1..];
            if !rest.is_empty() {
                subdirs
                    .entry(dir_name)
                    .or_default()
                    .push((rest, data, executable));
            }
        } else {
            root_files.push(TreeEntry::File {
                name: path.to_string(),
                content: data.to_vec(),
                executable,
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
                Some((path, e.data, e.executable))
            })
            .collect(),
    )
}

/// `(path, content, executable)` moved out of an `ArchiveEntry`.
type FileOwned = (String, Vec<u8>, bool);

fn entries_into_tree_inner(files: Vec<FileOwned>) -> Vec<TreeEntry> {
    let mut root_files: Vec<TreeEntry> = Vec::new();
    let mut subdirs: BTreeMap<String, Vec<FileOwned>> = BTreeMap::new();

    for (path, data, executable) in files {
        if let Some(idx) = path.find('/') {
            let dir_name = path[..idx].to_string();
            let rest = path[idx + 1..].to_string();
            if !rest.is_empty() {
                subdirs
                    .entry(dir_name)
                    .or_default()
                    .push((rest, data, executable));
            }
        } else {
            root_files.push(TreeEntry::File {
                name: path,
                content: data,
                executable,
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
    use anyhow::{anyhow, Result as TestResult};

    fn tree_file(entry: &TreeEntry) -> TestResult<(&str, &[u8], bool)> {
        match entry {
            TreeEntry::File {
                name,
                content,
                executable,
            } => Ok((name.as_str(), content.as_slice(), *executable)),
            TreeEntry::Directory { name, .. } => {
                Err(anyhow!("expected file, got directory {name}"))
            }
        }
    }

    fn tree_dir(entry: &TreeEntry) -> TestResult<(&str, &[TreeEntry])> {
        match entry {
            TreeEntry::Directory { name, children } => Ok((name.as_str(), children.as_slice())),
            TreeEntry::File { name, .. } => Err(anyhow!("expected directory, got file {name}")),
        }
    }

    fn expect_malicious<T>(
        result: std::result::Result<T, ExtractError>,
        expected_message: &str,
    ) -> TestResult<()> {
        match result {
            Err(ExtractError::Malicious(message)) => {
                assert!(
                    message.contains(expected_message),
                    "expected error to contain {expected_message:?}, got {message:?}"
                );
                Ok(())
            }
            Err(error) => Err(anyhow!("expected malicious error, got {error:?}")),
            Ok(_) => Err(anyhow!("expected malicious error, got Ok")),
        }
    }

    #[test]
    fn entries_to_tree_single_file() -> TestResult<()> {
        let entries = vec![ArchiveEntry {
            path: "README.md".to_string(),
            kind: EntryKind::File,
            data: b"# hello".to_vec(),
            executable: false,
        }];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        let (name, content, _) = tree_file(&tree[0])?;
        assert_eq!(name, "README.md");
        assert_eq!(content, b"# hello");
        Ok(())
    }

    #[test]
    fn entries_to_tree_nested() -> TestResult<()> {
        let entries = vec![
            ArchiveEntry {
                path: "src/main.rs".into(),
                kind: EntryKind::File,
                data: b"fn main(){}".to_vec(),
                executable: false,
            },
            ArchiveEntry {
                path: "src/lib.rs".into(),
                kind: EntryKind::File,
                data: b"//lib".to_vec(),
                executable: false,
            },
            ArchiveEntry {
                path: "README.md".into(),
                kind: EntryKind::File,
                data: b"hi".to_vec(),
                executable: false,
            },
        ];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 2); // src/ dir + README.md
        let (name, children) = tree_dir(&tree[0])?;
        assert_eq!(name, "src");
        assert_eq!(children.len(), 2);
        Ok(())
    }

    #[test]
    fn entries_to_tree_skips_directories() -> TestResult<()> {
        let entries = vec![
            ArchiveEntry {
                path: "src/".into(),
                kind: EntryKind::Directory,
                data: vec![],
                executable: false,
            },
            ArchiveEntry {
                path: "src/main.rs".into(),
                kind: EntryKind::File,
                data: b"fn main(){}".to_vec(),
                executable: false,
            },
        ];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        let (name, children) = tree_dir(&tree[0])?;
        assert_eq!(name, "src");
        assert_eq!(children.len(), 1);
        Ok(())
    }

    #[test]
    fn entries_to_tree_strips_dot_slash() -> TestResult<()> {
        let entries = vec![ArchiveEntry {
            path: "./README.md".into(),
            kind: EntryKind::File,
            data: b"hi".to_vec(),
            executable: false,
        }];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        let (name, _, _) = tree_file(&tree[0])?;
        assert_eq!(name, "README.md");
        Ok(())
    }

    #[test]
    fn entries_to_tree_deeply_nested() -> TestResult<()> {
        let entries = vec![ArchiveEntry {
            path: "a/b/c/d.txt".into(),
            kind: EntryKind::File,
            data: b"deep".to_vec(),
            executable: false,
        }];
        let tree = archive_entries_to_tree(&entries);
        assert_eq!(tree.len(), 1);
        let (name, children) = tree_dir(&tree[0])?;
        assert_eq!(name, "a");
        assert_eq!(children.len(), 1);
        let (name, children) = tree_dir(&children[0])?;
        assert_eq!(name, "b");
        let (name, children) = tree_dir(&children[0])?;
        assert_eq!(name, "c");
        let (name, content, _) = tree_file(&children[0])?;
        assert_eq!(name, "d.txt");
        assert_eq!(content, b"deep");
        Ok(())
    }

    fn build_tar(files: &[(&str, &[u8], u32)]) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut buf);
            for (path, content, mode) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(*mode);
                header.set_cksum();
                tar.append_data(&mut header, path, *content)?;
            }
            tar.finish()?;
        }
        Ok(buf)
    }

    fn build_tar_with_dirs(
        dirs: &[&str],
        files: &[(&str, &[u8], u32)],
    ) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut buf);
            for path in dirs {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                header.set_cksum();
                tar.append_data(&mut header, path, std::io::empty())?;
            }
            for (path, content, mode) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(*mode);
                header.set_cksum();
                tar.append_data(&mut header, path, *content)?;
            }
            tar.finish()?;
        }
        Ok(buf)
    }

    const TEST_LIMITS: ExtractLimits = ExtractLimits {
        max_bytes: 1 << 20,
        max_files: 100,
        max_file_bytes: 1 << 20,
    };

    #[test]
    fn extract_preserves_executable_bit() -> TestResult<()> {
        let tar_bytes = build_tar(&[
            ("run.sh", b"#!/bin/sh\n".as_slice(), 0o755),
            ("README.md", b"hi".as_slice(), 0o644),
        ])?;
        let entries = extract_tar(&tar_bytes, &TEST_LIMITS)?;
        let flags: Vec<(&str, bool)> = entries
            .iter()
            .map(|e| (e.path.as_str(), e.executable))
            .collect();
        assert_eq!(flags, vec![("run.sh", true), ("README.md", false)]);
        Ok(())
    }

    #[test]
    fn executable_bit_round_trips_into_tree_hash() -> TestResult<()> {
        // The archive-derived tree hash must equal the hash a publisher
        // computes from a filesystem where run.sh has the executable bit set.
        let tar_bytes = build_tar(&[
            ("run.sh", b"#!/bin/sh\n".as_slice(), 0o755),
            ("README.md", b"hi".as_slice(), 0o644),
        ])?;
        let entries = extract_tar(&tar_bytes, &TEST_LIMITS)?;
        let archive_tree = archive_entries_to_tree(&entries);

        let publisher_tree = vec![
            TreeEntry::File {
                name: "run.sh".into(),
                content: b"#!/bin/sh\n".to_vec(),
                executable: true,
            },
            TreeEntry::File {
                name: "README.md".into(),
                content: b"hi".to_vec(),
                executable: false,
            },
        ];
        let archive_hash = crate::tree::compute_hash_from_entries(&archive_tree, &[])?;
        let publisher_hash = crate::tree::compute_hash_from_entries(&publisher_tree, &[])?;
        assert_eq!(archive_hash, publisher_hash);

        // Flipping the bit must change the hash (mode is hashed: 100755 vs 100644).
        let mut flipped = publisher_tree;
        if let TreeEntry::File { executable, .. } = &mut flipped[0] {
            *executable = false;
        }
        let flipped_hash = crate::tree::compute_hash_from_entries(&flipped, &[])?;
        assert_ne!(archive_hash, flipped_hash);
        Ok(())
    }

    #[test]
    fn extract_rejects_duplicate_normalized_paths() -> TestResult<()> {
        let tar_bytes = build_tar(&[
            ("./README.md", b"first".as_slice(), 0o644),
            ("README.md", b"second".as_slice(), 0o644),
        ])?;
        expect_malicious(extract_tar(&tar_bytes, &TEST_LIMITS), "duplicate path")?;
        Ok(())
    }

    #[test]
    fn extract_rejects_portable_sibling_collision() -> TestResult<()> {
        let tar_bytes = build_tar(&[
            ("File.txt", b"upper".as_slice(), 0o644),
            ("file.txt", b"lower".as_slice(), 0o644),
        ])?;
        expect_malicious(
            extract_tar(&tar_bytes, &TEST_LIMITS),
            "filename_portable_conflict",
        )?;
        Ok(())
    }

    #[test]
    fn extract_rejects_portable_file_vs_directory_collision() -> TestResult<()> {
        let tar_bytes =
            build_tar_with_dirs(&["FOO"], &[("foo/bar.txt", b"child".as_slice(), 0o644)])?;
        expect_malicious(
            extract_tar(&tar_bytes, &TEST_LIMITS),
            "filename_portable_conflict",
        )?;
        Ok(())
    }
}
