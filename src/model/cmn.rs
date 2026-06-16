use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const CMN_SCHEMA: &str = "https://cmn.dev/schemas/v1/cmn.json";
pub const KEY_ROTATION_PURPOSE: &str = "cmn-key-rotation-v1";

/// CMN Entry - the cmn.json file at /.well-known/cmn.json
///
/// Contains an array of capsules, each with a URI, public key, and typed
/// endpoints for resolving all resource types.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CmnEntry {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub capsules: Vec<CmnCapsuleEntry>,
    pub capsule_signature: String,
}

/// A single capsule entry in cmn.json
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CmnCapsuleEntry {
    pub uri: String,
    pub serial: u64,
    pub key: String,
    pub history: Vec<KeyHistoryEntry>,
    pub endpoints: Vec<CmnEndpoint>,
}

/// A historical public key entry, kept for verified rotations/revocations.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyHistoryEntry {
    pub key: String,
    #[serde(default)]
    pub status: KeyHistoryStatus,
    pub retired_at_epoch_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_serial: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_epoch_ms: Option<u64>,
}

/// Lifecycle state for a historical key.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyHistoryStatus {
    /// Normal rotation: old signatures remain valid.
    #[default]
    Retired,
    /// Compromise: clients must not trust signatures by this key.
    Revoked,
}

/// Confirmation details for a key accepted by `cmn.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyConfirmation {
    Current,
    Retired { retired_at_epoch_ms: u64 },
}

impl KeyConfirmation {
    pub fn retired_at_epoch_ms(self) -> Option<u64> {
        match self {
            Self::Current => None,
            Self::Retired {
                retired_at_epoch_ms,
            } => Some(retired_at_epoch_ms),
        }
    }
}

/// Statement signed by an old domain key to authorize its successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationStatement {
    pub purpose: String,
    pub domain: String,
    pub from: String,
    pub to: String,
    pub effective_serial: u64,
    pub retired_at_epoch_ms: u64,
}

/// A single typed endpoint entry in cmn.json.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CmnEndpoint {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    /// Primary mycelium content hash (authoritative metadata and featured spores).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
    /// Optional overflow shard hashes for large domains (spore lists merged, metadata ignored).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_url: Option<String>,
}

pub fn build_key_rotation_statement(
    domain: &str,
    from: &str,
    to: &str,
    effective_serial: u64,
    retired_at_epoch_ms: u64,
) -> KeyRotationStatement {
    KeyRotationStatement {
        purpose: KEY_ROTATION_PURPOSE.to_string(),
        domain: domain.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        effective_serial,
        retired_at_epoch_ms,
    }
}

pub fn verify_key_rotation_statement(
    domain: &str,
    from: &str,
    to: &str,
    effective_serial: u64,
    retired_at_epoch_ms: u64,
    rotation_signature: &str,
) -> anyhow::Result<()> {
    let statement =
        build_key_rotation_statement(domain, from, to, effective_serial, retired_at_epoch_ms);
    crate::verify_json_signature(&statement, rotation_signature, from)
}

impl KeyHistoryEntry {
    pub fn verify_rotation(&self, domain: &str, current_serial: u64) -> anyhow::Result<()> {
        if self.status != KeyHistoryStatus::Retired {
            bail!("Only retired history entries can authorize key rotation");
        }
        let effective_serial = self.effective_serial.unwrap_or(current_serial);
        let to = self
            .replaced_by
            .as_deref()
            .ok_or_else(|| anyhow!("Missing replaced_by for retired key history entry"))?;
        let rotation_signature = self
            .rotation_signature
            .as_deref()
            .ok_or_else(|| anyhow!("Missing rotation_signature for retired key history entry"))?;
        verify_key_rotation_statement(
            domain,
            &self.key,
            to,
            effective_serial,
            self.retired_at_epoch_ms,
            rotation_signature,
        )
    }
}

impl CmnCapsuleEntry {
    fn rotation_domain(&self) -> anyhow::Result<&str> {
        self.uri
            .strip_prefix("cmn://")
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| anyhow!("Invalid cmn.json capsule uri: {}", self.uri))
    }

    pub fn confirms_key(&self, key: &str) -> bool {
        self.key == key
            || self
                .history
                .iter()
                .any(|entry| self.confirms_history_key(entry, key))
    }

    fn confirms_history_key(&self, entry: &KeyHistoryEntry, key: &str) -> bool {
        if entry.key != key || entry.status != KeyHistoryStatus::Retired {
            return false;
        }
        let Ok(domain) = self.rotation_domain() else {
            return false;
        };
        entry.verify_rotation(domain, self.serial).is_ok()
    }

    pub fn key_confirmation_at(
        &self,
        key: &str,
        signed_at_epoch_ms: u64,
    ) -> Option<KeyConfirmation> {
        if self.key == key {
            return Some(KeyConfirmation::Current);
        }

        let domain = self.rotation_domain().ok()?;
        self.history.iter().find_map(|entry| {
            if entry.key != key {
                return None;
            }
            match entry.status {
                KeyHistoryStatus::Retired
                    if signed_at_epoch_ms <= entry.retired_at_epoch_ms
                        && entry.verify_rotation(domain, self.serial).is_ok() =>
                {
                    Some(KeyConfirmation::Retired {
                        retired_at_epoch_ms: entry.retired_at_epoch_ms,
                    })
                }
                KeyHistoryStatus::Retired | KeyHistoryStatus::Revoked => None,
            }
        })
    }

    pub fn confirms_key_at(&self, key: &str, signed_at_epoch_ms: u64) -> bool {
        self.key_confirmation_at(key, signed_at_epoch_ms).is_some()
    }

    pub fn find_endpoint(&self, kind: &str) -> Option<&CmnEndpoint> {
        self.endpoints.iter().find(|endpoint| endpoint.kind == kind)
    }

    pub fn find_endpoints(&self, kind: &str) -> Vec<&CmnEndpoint> {
        self.endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == kind)
            .collect()
    }

    pub fn find_archive_endpoint(&self, format: Option<&str>) -> Option<&CmnEndpoint> {
        match format {
            Some(expected) => self.endpoints.iter().find(|endpoint| {
                endpoint.kind == "archive" && endpoint.format.as_deref() == Some(expected)
            }),
            None => self.find_endpoint("archive"),
        }
    }

    /// Primary mycelium content hash (authoritative metadata).
    pub fn mycelium_hash(&self) -> Option<&str> {
        self.find_endpoint("mycelium")
            .map(|endpoint| endpoint.hash.as_str())
            .filter(|h| !h.is_empty())
    }

    /// Overflow shard hashes for large domains (spore lists only, metadata ignored).
    pub fn mycelium_hashes(&self) -> &[String] {
        self.find_endpoint("mycelium")
            .map(|endpoint| endpoint.hashes.as_slice())
            .unwrap_or(&[])
    }

    fn require_endpoint(&self, kind: &str) -> anyhow::Result<&CmnEndpoint> {
        self.find_endpoint(kind)
            .ok_or_else(|| anyhow!("No '{}' endpoint configured", kind))
    }

    fn require_archive_endpoint(&self, format: Option<&str>) -> anyhow::Result<&CmnEndpoint> {
        match format {
            Some(expected) => self
                .find_archive_endpoint(Some(expected))
                .ok_or_else(|| anyhow!("No archive endpoint configured for format '{}'", expected)),
            None => self
                .find_archive_endpoint(None)
                .ok_or_else(|| anyhow!("No 'archive' endpoint configured")),
        }
    }

    pub fn mycelium_url(&self, hash: &str) -> anyhow::Result<String> {
        self.require_endpoint("mycelium")?.resolve_url(hash)
    }

    pub fn spore_url(&self, hash: &str) -> anyhow::Result<String> {
        self.require_endpoint("spore")?.resolve_url(hash)
    }

    pub fn archive_url(&self, hash: &str) -> anyhow::Result<String> {
        self.require_archive_endpoint(None)?.resolve_url(hash)
    }

    pub fn archive_url_for_format(&self, hash: &str, format: &str) -> anyhow::Result<String> {
        self.require_archive_endpoint(Some(format))?
            .resolve_url(hash)
    }

    pub fn archive_delta_url(
        &self,
        hash: &str,
        old_hash: &str,
        format: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        self.require_archive_endpoint(format)?
            .resolve_delta_url(hash, old_hash)
    }

    pub fn taste_url(&self, hash: &str) -> anyhow::Result<String> {
        self.require_endpoint("taste")?.resolve_url(hash)
    }

    pub fn verify_rotation_chain_from(&self, pinned_key: &str) -> anyhow::Result<()> {
        if pinned_key == self.key {
            return Ok(());
        }

        let domain = self.rotation_domain()?;
        let mut current = pinned_key.to_string();
        let mut seen = HashSet::new();

        for _ in 0..self.history.len() {
            if !seen.insert(current.clone()) {
                bail!("Key rotation history contains a cycle at {}", current);
            }
            let entry = self
                .history
                .iter()
                .find(|entry| entry.key == current && entry.status == KeyHistoryStatus::Retired)
                .ok_or_else(|| anyhow!("No retired history entry for key {}", current))?;
            entry.verify_rotation(domain, self.serial)?;
            let next = entry
                .replaced_by
                .as_deref()
                .ok_or_else(|| anyhow!("Missing replaced_by for key {}", current))?;
            if next == self.key {
                return Ok(());
            }
            current = next.to_string();
        }

        bail!(
            "No verified key rotation chain from pinned key {} to current key {}",
            pinned_key,
            self.key
        )
    }
}

impl CmnEntry {
    pub fn new(capsules: Vec<CmnCapsuleEntry>) -> Self {
        Self {
            schema: CMN_SCHEMA.to_string(),
            capsules,
            capsule_signature: String::new(),
        }
    }

    pub fn primary_capsule(&self) -> anyhow::Result<&CmnCapsuleEntry> {
        self.capsules
            .first()
            .ok_or_else(|| anyhow!("Invalid cmn.json: capsules must contain at least one entry"))
    }

    pub fn uri(&self) -> anyhow::Result<&str> {
        self.primary_capsule().map(|capsule| capsule.uri.as_str())
    }

    pub fn primary_key(&self) -> anyhow::Result<&str> {
        self.primary_capsule().map(|capsule| capsule.key.as_str())
    }

    pub fn primary_confirms_key(&self, key: &str) -> anyhow::Result<bool> {
        self.primary_capsule()
            .map(|capsule| capsule.confirms_key(key))
    }

    pub fn primary_key_confirmation_at(
        &self,
        key: &str,
        signed_at_epoch_ms: u64,
    ) -> anyhow::Result<Option<KeyConfirmation>> {
        self.primary_capsule()
            .map(|capsule| capsule.key_confirmation_at(key, signed_at_epoch_ms))
    }

    pub fn primary_confirms_key_at(
        &self,
        key: &str,
        signed_at_epoch_ms: u64,
    ) -> anyhow::Result<bool> {
        self.primary_key_confirmation_at(key, signed_at_epoch_ms)
            .map(|confirmation| confirmation.is_some())
    }

    pub fn verify_signature(&self, host_key: &str) -> anyhow::Result<()> {
        crate::verify_json_signature(&self.capsules, &self.capsule_signature, host_key)
    }

    pub fn capsules_digest(&self) -> anyhow::Result<String> {
        let canonical = serde_jcs::to_string(&self.capsules)
            .map_err(|e| anyhow!("JCS serialization failed: {}", e))?;
        Ok(crate::compute_blake3_hash(canonical.as_bytes()))
    }
}

impl CmnEndpoint {
    pub fn resolve_url(&self, hash: &str) -> anyhow::Result<String> {
        let url = self.url.replace("{hash}", hash);
        crate::uri::normalize_and_validate_url(&url)
            .map_err(|e| anyhow!("Invalid {} endpoint: {}", self.kind, e))
    }

    pub fn resolve_delta_url(&self, hash: &str, old_hash: &str) -> anyhow::Result<Option<String>> {
        let Some(template) = &self.delta_url else {
            return Ok(None);
        };

        let url = template
            .replace("{hash}", hash)
            .replace("{old_hash}", old_hash);
        crate::uri::normalize_and_validate_url(&url)
            .map_err(|e| anyhow!("Invalid {} delta endpoint: {}", self.kind, e))
            .map(Some)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> ([u8; 32], String) {
        let private_key = [seed; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key);
        let public_key = crate::format_key(
            crate::KeyAlgorithm::Ed25519,
            &signing_key.verifying_key().to_bytes(),
        );
        (private_key, public_key)
    }

    fn rotation_entry(
        from_private: &[u8; 32],
        from_key: &str,
        to_key: &str,
        serial: u64,
        retired_at_epoch_ms: u64,
    ) -> KeyHistoryEntry {
        let statement = build_key_rotation_statement(
            "example.com",
            from_key,
            to_key,
            serial,
            retired_at_epoch_ms,
        );
        let rotation_signature =
            crate::compute_signature(&statement, crate::SignatureAlgorithm::Ed25519, from_private)
                .unwrap();
        KeyHistoryEntry {
            key: from_key.to_string(),
            status: KeyHistoryStatus::Retired,
            retired_at_epoch_ms,
            replaced_by: Some(to_key.to_string()),
            effective_serial: Some(serial),
            rotation_signature: Some(rotation_signature),
            revoked_at_epoch_ms: None,
        }
    }

    fn sample_cmn_endpoints() -> Vec<CmnEndpoint> {
        vec![
            CmnEndpoint {
                kind: "mycelium".to_string(),
                url: "https://example.com/cmn/mycelium/{hash}.json".to_string(),
                hash: "b3.abc123def456".to_string(),
                hashes: vec![],
                format: None,
                delta_url: None,
            },
            CmnEndpoint {
                kind: "spore".to_string(),
                url: "https://example.com/cmn/spore/{hash}.json".to_string(),
                hash: String::new(),
                hashes: vec![],
                format: None,
                delta_url: None,
            },
            CmnEndpoint {
                kind: "archive".to_string(),
                url: "https://example.com/cmn/archive/{hash}.tar.zst".to_string(),
                hash: String::new(),
                hashes: vec![],
                format: Some("tar+zstd".to_string()),
                delta_url: Some(
                    "https://example.com/cmn/archive/{hash}.from.{old_hash}.tar.zst".to_string(),
                ),
            },
        ]
    }

    fn sample_capsule() -> CmnCapsuleEntry {
        CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial: 1,
            key: "host-key".to_string(),
            history: vec![],
            endpoints: sample_cmn_endpoints(),
        }
    }

    #[test]
    fn test_cmn_entry_serialization() {
        let entry = CmnEntry::new(vec![CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial: 1,
            key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            history: vec![],
            endpoints: sample_cmn_endpoints(),
        }]);

        let json = serde_json::to_string(&entry).unwrap_or_default();
        assert!(json.contains("\"$schema\""));
        assert!(json.contains(CMN_SCHEMA));
        assert!(json.contains("b3.abc123def456"));
        assert!(json.contains("\"serial\""));
        assert!(json.contains("\"history\""));
        assert!(json.contains("\"endpoints\""));
        assert!(json.contains("\"key\""));
        assert!(!json.contains("protocol_versions"));

        let parsed: CmnEntry = serde_json::from_str(&json).unwrap();
        let capsule = parsed.primary_capsule().unwrap();
        assert_eq!(parsed.schema, CMN_SCHEMA);
        assert_eq!(capsule.serial, 1);
        assert_eq!(capsule.mycelium_hash(), Some("b3.abc123def456"));
        assert_eq!(
            capsule.key,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_capsule_build_mycelium_url() {
        let capsule = sample_capsule();
        let url = capsule.mycelium_url("b3.abc123").unwrap();
        assert_eq!(url, "https://example.com/cmn/mycelium/b3.abc123.json");
    }

    #[test]
    fn test_capsule_build_spore_url() {
        let capsule = sample_capsule();
        let url = capsule.spore_url("b3.abc123").unwrap();
        assert_eq!(url, "https://example.com/cmn/spore/b3.abc123.json");
    }

    #[test]
    fn test_capsule_build_archive_url() {
        let capsule = sample_capsule();
        let url = capsule.archive_url("b3.abc123").unwrap();
        assert_eq!(url, "https://example.com/cmn/archive/b3.abc123.tar.zst");
    }

    #[test]
    fn test_capsule_build_archive_url_for_format() {
        let capsule = sample_capsule();
        let url = capsule
            .archive_url_for_format("b3.abc123", "tar+zstd")
            .unwrap();
        assert_eq!(url, "https://example.com/cmn/archive/b3.abc123.tar.zst");
    }

    #[test]
    fn test_capsule_build_archive_delta_url() {
        let capsule = sample_capsule();
        let url = capsule
            .archive_delta_url("b3.new", "b3.old", Some("tar+zstd"))
            .unwrap()
            .unwrap();
        assert_eq!(
            url,
            "https://example.com/cmn/archive/b3.new.from.b3.old.tar.zst"
        );
    }

    #[test]
    fn test_capsule_build_taste_url() {
        let mut endpoints = sample_cmn_endpoints();
        endpoints.push(CmnEndpoint {
            kind: "taste".to_string(),
            url: "https://example.com/cmn/taste/{hash}.json".to_string(),
            hash: String::new(),
            hashes: vec![],
            format: None,
            delta_url: None,
        });
        let capsule = CmnCapsuleEntry {
            endpoints,
            ..sample_capsule()
        };
        let url = capsule.taste_url("b3.7tRkW2x").unwrap();
        assert_eq!(url, "https://example.com/cmn/taste/b3.7tRkW2x.json");
    }

    #[test]
    fn test_capsule_build_taste_url_not_configured() {
        let capsule = sample_capsule();
        assert!(capsule.taste_url("b3.7tRkW2x").is_err());
    }

    #[test]
    fn test_capsule_build_url_rejects_malicious_template() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial: 1,
            key: "host-key".to_string(),
            history: vec![],
            endpoints: vec![
                CmnEndpoint {
                    kind: "mycelium".to_string(),
                    url: "file:///etc/passwd?{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                },
                CmnEndpoint {
                    kind: "spore".to_string(),
                    url: "gopher://internal/{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                },
                CmnEndpoint {
                    kind: "archive".to_string(),
                    url: "http://localhost:9090/{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: Some("tar+zstd".to_string()),
                    delta_url: None,
                },
            ],
        };
        assert!(capsule.mycelium_url("b3.abc").is_err());
        assert!(capsule.spore_url("b3.abc").is_err());
        assert!(capsule.archive_url("b3.abc").is_err());
    }

    #[test]
    fn test_capsule_build_url_rejects_ssrf_template() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial: 1,
            key: "host-key".to_string(),
            history: vec![],
            endpoints: vec![
                CmnEndpoint {
                    kind: "mycelium".to_string(),
                    url: "https://10.0.0.1/cmn/{hash}.json".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                },
                CmnEndpoint {
                    kind: "spore".to_string(),
                    url: "https://192.168.1.1/cmn/{hash}.json".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                },
                CmnEndpoint {
                    kind: "archive".to_string(),
                    url: "https://169.254.169.254/cmn/{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: Some("tar+zstd".to_string()),
                    delta_url: None,
                },
            ],
        };
        assert!(capsule.mycelium_url("b3.abc").is_err());
        assert!(capsule.spore_url("b3.abc").is_err());
        assert!(capsule.archive_url("b3.abc").is_err());
    }

    #[test]
    fn test_capsule_confirms_retired_history_key_with_rotation_proof() {
        let serial = 2;
        let retired_at_epoch_ms = 1_710_000_000_000;
        let (previous_private, previous_key) = keypair(3);
        let (_, current_key) = keypair(4);
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial,
            key: current_key.clone(),
            history: vec![rotation_entry(
                &previous_private,
                &previous_key,
                &current_key,
                serial,
                retired_at_epoch_ms,
            )],
            endpoints: vec![],
        };

        assert!(capsule.confirms_key(&current_key));
        assert!(capsule.confirms_key(&previous_key));
        assert!(!capsule.confirms_key("ed25519.other"));
    }

    #[test]
    fn test_capsule_confirms_retired_history_key_only_before_retirement() {
        let serial = 2;
        let retired_at_epoch_ms = 1_710_000_000_000;
        let (previous_private, previous_key) = keypair(5);
        let (_, current_key) = keypair(6);
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial,
            key: current_key.clone(),
            history: vec![rotation_entry(
                &previous_private,
                &previous_key,
                &current_key,
                serial,
                retired_at_epoch_ms,
            )],
            endpoints: vec![],
        };

        assert_eq!(
            capsule.key_confirmation_at(&current_key, retired_at_epoch_ms + 1),
            Some(KeyConfirmation::Current)
        );
        assert_eq!(
            capsule.key_confirmation_at(&previous_key, retired_at_epoch_ms),
            Some(KeyConfirmation::Retired {
                retired_at_epoch_ms
            })
        );
        assert!(capsule.confirms_key_at(&previous_key, retired_at_epoch_ms - 1));
        assert!(!capsule.confirms_key_at(&previous_key, retired_at_epoch_ms + 1));
    }

    #[test]
    fn test_retired_history_uses_entry_effective_serial_after_later_cmn_updates() {
        let rotation_serial = 2;
        let current_serial = 3;
        let retired_at_epoch_ms = 1_710_000_000_000;
        let (previous_private, previous_key) = keypair(13);
        let (_, current_key) = keypair(14);
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial: current_serial,
            key: current_key.clone(),
            history: vec![rotation_entry(
                &previous_private,
                &previous_key,
                &current_key,
                rotation_serial,
                retired_at_epoch_ms,
            )],
            endpoints: vec![],
        };

        assert!(capsule.confirms_key_at(&previous_key, retired_at_epoch_ms));
        capsule.verify_rotation_chain_from(&previous_key).unwrap();
    }

    #[test]
    fn test_capsule_rejects_revoked_history_key() {
        let (_, current_key) = keypair(7);
        let (_, compromised_key) = keypair(8);
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial: 2,
            key: current_key,
            history: vec![KeyHistoryEntry {
                key: compromised_key.clone(),
                retired_at_epoch_ms: 1_710_000_000_000,
                status: KeyHistoryStatus::Revoked,
                replaced_by: None,
                effective_serial: None,
                rotation_signature: None,
                revoked_at_epoch_ms: Some(1_710_000_000_000),
            }],
            endpoints: vec![],
        };

        assert!(!capsule.confirms_key(&compromised_key));
    }

    #[test]
    fn test_rotation_statement_verification_rejects_wrong_fields() {
        let serial = 2;
        let retired_at_epoch_ms = 1_710_000_000_000;
        let (previous_private, previous_key) = keypair(9);
        let (_, current_key) = keypair(10);
        let entry = rotation_entry(
            &previous_private,
            &previous_key,
            &current_key,
            serial,
            retired_at_epoch_ms,
        );
        let signature = entry.rotation_signature.as_deref().unwrap();

        verify_key_rotation_statement(
            "example.com",
            &previous_key,
            &current_key,
            serial,
            retired_at_epoch_ms,
            signature,
        )
        .unwrap();
        assert!(verify_key_rotation_statement(
            "evil.example",
            &previous_key,
            &current_key,
            serial,
            retired_at_epoch_ms,
            signature,
        )
        .is_err());
        assert!(verify_key_rotation_statement(
            "example.com",
            &current_key,
            &previous_key,
            serial,
            retired_at_epoch_ms,
            signature,
        )
        .is_err());
        assert!(verify_key_rotation_statement(
            "example.com",
            &previous_key,
            &current_key,
            serial + 1,
            retired_at_epoch_ms,
            signature,
        )
        .is_err());
    }

    #[test]
    fn test_verify_rotation_chain_from_pinned_key() {
        let serial = 3;
        let retired_at_epoch_ms = 1_710_000_000_000;
        let (old_private, old_key) = keypair(11);
        let (_, current_key) = keypair(12);
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            serial,
            key: current_key.clone(),
            history: vec![rotation_entry(
                &old_private,
                &old_key,
                &current_key,
                serial,
                retired_at_epoch_ms,
            )],
            endpoints: vec![],
        };

        capsule.verify_rotation_chain_from(&old_key).unwrap();
        assert!(capsule
            .verify_rotation_chain_from("ed25519.unknown")
            .is_err());
    }

    #[test]
    fn test_capsules_digest_changes_with_serial_endpoint_or_history() {
        let mut entry = CmnEntry::new(vec![sample_capsule()]);
        let original = entry.capsules_digest().unwrap();
        entry.capsules[0].serial += 1;
        assert_ne!(entry.capsules_digest().unwrap(), original);

        let mut entry = CmnEntry::new(vec![sample_capsule()]);
        entry.capsules[0].endpoints[0].url = "https://example.com/other/{hash}.json".to_string();
        assert_ne!(entry.capsules_digest().unwrap(), original);

        let mut entry = CmnEntry::new(vec![sample_capsule()]);
        entry.capsules[0].history.push(KeyHistoryEntry {
            key: "ed25519.history".to_string(),
            status: KeyHistoryStatus::Revoked,
            retired_at_epoch_ms: 1,
            replaced_by: None,
            effective_serial: None,
            rotation_signature: None,
            revoked_at_epoch_ms: Some(1),
        });
        assert_ne!(entry.capsules_digest().unwrap(), original);
    }
}
