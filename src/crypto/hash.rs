use anyhow::{anyhow, Result};
use serde::Serialize;

use super::AlgorithmBytes;

const HASH_SEPARATOR: char = '.';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    B3,
}

pub fn parse_hash(value: &str) -> Result<AlgorithmBytes<HashAlgorithm>> {
    let (algorithm_str, value_b58) = value
        .split_once(HASH_SEPARATOR)
        .ok_or_else(|| anyhow!("Hash must use '{{algorithm}}.{{base58}}' format"))?;
    let algorithm = match algorithm_str {
        "b3" => HashAlgorithm::B3,
        other => return Err(anyhow!("Unsupported hash algorithm: '{}'", other)),
    };
    if value_b58.is_empty() {
        return Err(anyhow!("Hash payload must not be empty"));
    }

    let bytes = bs58::decode(value_b58)
        .into_vec()
        .map_err(|e| anyhow!("Invalid hash base58 payload: {}", e))?;
    if bytes.is_empty() {
        return Err(anyhow!("Hash payload must not decode to empty bytes"));
    }

    Ok(AlgorithmBytes { algorithm, bytes })
}

pub fn format_hash(algorithm: HashAlgorithm, bytes: &[u8]) -> String {
    format!(
        "{}.{}",
        algorithm.prefix(),
        bs58::encode(bytes).into_string()
    )
}

/// Compute a raw BLAKE3 hash using CMN hash formatting.
pub fn compute_blake3_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    format_hash(HashAlgorithm::B3, hash.as_bytes())
}

pub(crate) fn compute_signed_core_hash<T: Serialize>(
    core: &T,
    core_signature: &str,
) -> Result<String> {
    let hash_input = serde_json::json!({
        "core": core,
        "core_signature": core_signature,
    });
    let canonical = serde_jcs::to_string(&hash_input)
        .map_err(|e| anyhow!("JCS serialization failed: {}", e))?;
    Ok(compute_blake3_hash(canonical.as_bytes()))
}

pub(crate) fn compute_tree_signed_core_hash<T: Serialize>(
    tree_hash: &str,
    core: &T,
    core_signature: &str,
) -> Result<String> {
    let hash_input = serde_json::json!({
        "tree_hash": tree_hash,
        "core": core,
        "core_signature": core_signature,
    });
    let canonical = serde_jcs::to_string(&hash_input)
        .map_err(|e| anyhow!("JCS serialization failed: {}", e))?;
    Ok(compute_blake3_hash(canonical.as_bytes()))
}

impl HashAlgorithm {
    fn prefix(self) -> &'static str {
        match self {
            Self::B3 => "b3",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_parse_hash_roundtrip() {
        let parsed = parse_hash("b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2").unwrap();
        assert_eq!(parsed.algorithm, HashAlgorithm::B3);
        let normalized = format_hash(parsed.algorithm, &parsed.bytes);
        assert_eq!(normalized, "b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2");
    }

    #[test]
    fn test_parse_hash_rejects_unknown_algorithm() {
        assert!(parse_hash("sha256.abc").is_err());
    }

    #[test]
    fn test_compute_blake3_hash() {
        let hash = compute_blake3_hash(b"hello");
        assert!(hash.starts_with("b3."));
        assert!(hash.len() > 10);
        assert_eq!(hash, compute_blake3_hash(b"hello"));
        assert_ne!(hash, compute_blake3_hash(b"world"));
    }

    #[test]
    fn test_blake3_hash_for_content_addressing() {
        let content = r#"{"name":"test","version":"1.0"}"#;
        let hash1 = compute_blake3_hash(content.as_bytes());
        let hash2 = compute_blake3_hash(content.as_bytes());
        assert_eq!(hash1, hash2);

        let different_content = r#"{"name":"test","version":"1.1"}"#;
        let hash3 = compute_blake3_hash(different_content.as_bytes());
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_compute_signed_core_hash_is_deterministic() {
        let core = serde_json::json!({"name": "cmn.dev", "updated_at_epoch_ms": 1});
        let signature = "ed25519.test-signature";

        let hash1 = compute_signed_core_hash(&core, signature).unwrap();
        let hash2 = compute_signed_core_hash(&core, signature).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_tree_signed_core_hash_changes_with_tree_hash() {
        let core = serde_json::json!({"name": "cmn-spec"});
        let signature = "ed25519.test-signature";

        let hash1 = compute_tree_signed_core_hash("b3.tree-a", &core, signature).unwrap();
        let hash2 = compute_tree_signed_core_hash("b3.tree-b", &core, signature).unwrap();

        assert_ne!(hash1, hash2);
    }
}
