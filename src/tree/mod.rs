//! Tree hashing for spores.

use anyhow::{anyhow, Result};

pub mod blob_tree_blake3_nfc;

pub use blob_tree_blake3_nfc::{compute_hash_from_entries, TreeEntry};

pub fn compute_tree_hash_from_entries(
    entries: &[TreeEntry],
    tree: &crate::model::SporeTree,
) -> Result<String> {
    match tree.algorithm.as_str() {
        blob_tree_blake3_nfc::ALGORITHM => {
            blob_tree_blake3_nfc::compute_hash_from_entries(entries, &tree.exclude_names)
        }
        other => Err(anyhow!("Unsupported tree algorithm: '{}'", other)),
    }
}

/// Compute tree hash and total uncompressed source size in bytes.
pub fn compute_tree_hash_and_size_from_entries(
    entries: &[TreeEntry],
    tree: &crate::model::SporeTree,
) -> Result<(String, u64)> {
    match tree.algorithm.as_str() {
        blob_tree_blake3_nfc::ALGORITHM => {
            blob_tree_blake3_nfc::compute_hash_and_size_from_entries(entries, &tree.exclude_names)
        }
        other => Err(anyhow!("Unsupported tree algorithm: '{}'", other)),
    }
}
