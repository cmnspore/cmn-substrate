//! CMN hub subdomain helpers.
//!
//! These helpers encode a CMN public key into a DNS-safe subdomain and recover
//! the public key from that subdomain without a database lookup.

use anyhow::{anyhow, Result};

use super::{format_key, parse_key, KeyAlgorithm};

/// Compute a DNS-safe cmnhub subdomain from a public key string.
///
/// Input: `"ed25519.<base58>"` (the standard CMN public key format).
/// Output: `"ed-<base32-lowercase-nopad>"` (55 chars, fits DNS 63-char label limit).
///
/// The subdomain is the raw pubkey bytes encoded directly as base32 lowercase
/// without padding, prefixed with `ed-` (ed25519). No hashing — the subdomain
/// IS the public key in a DNS-safe encoding. Base32 is used because DNS labels
/// are case-insensitive (RFC 4343), ruling out base58/base64.
///
/// The pubkey can be recovered from the subdomain by stripping the `ed-` prefix
/// and base32-decoding, enabling signature verification without a database lookup.
///
/// # Examples
/// ```
/// use substrate::crypto::hub::compute_hub_subdomain;
///
/// let sub = compute_hub_subdomain("ed25519.2p3NPZceQ6njbPg8aMFsEynX3Cmv6uCt1XMGHhPcL4AT").unwrap();
/// assert!(sub.starts_with("ed-"));
/// assert_eq!(sub.len(), 55);
/// assert!(sub.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
/// ```
pub fn compute_hub_subdomain(public_key: &str) -> Result<String> {
    let key = parse_key(public_key)?;

    let b32 = data_encoding::BASE32_NOPAD
        .encode(&key.bytes)
        .to_ascii_lowercase();

    Ok(format!("ed-{}", b32))
}

/// Recover the ed25519 public key from a hub subdomain.
///
/// Input: `"ed-<base32-lowercase-nopad>"` (as produced by `compute_hub_subdomain`).
/// Output: `"ed25519.<base58>"` (standard CMN public key format).
///
/// # Examples
/// ```
/// use substrate::crypto::hub::{compute_hub_subdomain, recover_pubkey_from_subdomain};
///
/// let key = "ed25519.2p3NPZceQ6njbPg8aMFsEynX3Cmv6uCt1XMGHhPcL4AT";
/// let sub = compute_hub_subdomain(key).unwrap();
/// let recovered = recover_pubkey_from_subdomain(&sub).unwrap();
/// assert_eq!(recovered, key);
/// ```
pub fn recover_pubkey_from_subdomain(subdomain: &str) -> Result<String> {
    let b32 = subdomain
        .strip_prefix("ed-")
        .ok_or_else(|| anyhow!("Subdomain must start with 'ed-'"))?;

    let key_bytes = data_encoding::BASE32_NOPAD
        .decode(b32.to_ascii_uppercase().as_bytes())
        .map_err(|e| anyhow!("Invalid base32 in subdomain: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid ed25519 public key length in subdomain: expected 32 bytes, got {}",
            key_bytes.len()
        ));
    }

    Ok(format_key(KeyAlgorithm::Ed25519, &key_bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_compute_hub_subdomain_shape() {
        let sub =
            compute_hub_subdomain("ed25519.2p3NPZceQ6njbPg8aMFsEynX3Cmv6uCt1XMGHhPcL4AT").unwrap();
        assert!(sub.starts_with("ed-"));
        assert_eq!(sub.len(), 55);
        assert!(sub
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn test_recover_pubkey_from_subdomain_roundtrip() {
        let key = "ed25519.2p3NPZceQ6njbPg8aMFsEynX3Cmv6uCt1XMGHhPcL4AT";
        let sub = compute_hub_subdomain(key).unwrap();
        let recovered = recover_pubkey_from_subdomain(&sub).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_recover_pubkey_from_subdomain_rejects_invalid_prefix() {
        assert!(recover_pubkey_from_subdomain("xx-invalid").is_err());
    }
}
