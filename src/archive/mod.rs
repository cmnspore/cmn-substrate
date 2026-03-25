//! In-memory archive extraction with security validation.
//!
//! Provides tar unpacking and zstd decompression that operate entirely in memory,
//! returning `Vec<ArchiveEntry>` instead of writing to the filesystem.
//! This makes the core extraction logic usable in WASM environments.

mod zstd_codec;

pub use zstd_codec::*;

use std::io::{Cursor, Read};

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
