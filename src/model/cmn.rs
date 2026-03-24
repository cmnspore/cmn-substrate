use anyhow::anyhow;
use serde::{Deserialize, Serialize};

pub const CMN_SCHEMA: &str = "https://cmn.dev/schemas/v1/cmn.json";

/// CMN Entry - the cmn.json file at /.well-known/cmn.json
///
/// Contains an array of capsules, each with a URI, public key, and typed
/// endpoints for resolving all resource types.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CmnEntry {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub protocol_versions: Vec<String>,
    pub capsules: Vec<CmnCapsuleEntry>,
    pub capsule_signature: String,
}

/// A single capsule entry in cmn.json
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CmnCapsuleEntry {
    pub uri: String,
    pub key: String,
    pub previous_keys: Vec<PreviousKey>,
    pub endpoints: Vec<CmnEndpoint>,
}

/// A retired public key, kept for verifying historical content
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreviousKey {
    pub key: String,
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
    /// Protocol version this endpoint serves (e.g. "v1"). Defaults to "v1" when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
}

impl CmnCapsuleEntry {
    pub fn confirms_key(&self, key: &str) -> bool {
        self.key == key
            || self
                .previous_keys
                .iter()
                .any(|previous| previous.key == key)
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
}

impl CmnEntry {
    pub fn new(capsules: Vec<CmnCapsuleEntry>) -> Self {
        Self {
            schema: CMN_SCHEMA.to_string(),
            protocol_versions: vec!["v1".to_string()],
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

    pub fn effective_protocol_versions(&self) -> Vec<&str> {
        if self.protocol_versions.is_empty() {
            vec!["v1"]
        } else {
            self.protocol_versions.iter().map(String::as_str).collect()
        }
    }

    pub fn supports_protocol_version(&self, version: &str) -> bool {
        if self.protocol_versions.is_empty() {
            version == "v1"
        } else {
            self.protocol_versions
                .iter()
                .any(|candidate| candidate == version)
        }
    }

    pub fn verify_signature(&self, host_key: &str) -> anyhow::Result<()> {
        crate::verify_json_signature(&self.capsules, &self.capsule_signature, host_key)
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
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    fn sample_cmn_endpoints() -> Vec<CmnEndpoint> {
        vec![
            CmnEndpoint {
                kind: "mycelium".to_string(),
                url: "https://example.com/cmn/mycelium/{hash}.json".to_string(),
                hash: "b3.abc123def456".to_string(),
                hashes: vec![],
                format: None,
                delta_url: None,
                protocol_version: None,
            },
            CmnEndpoint {
                kind: "spore".to_string(),
                url: "https://example.com/cmn/spore/{hash}.json".to_string(),
                hash: String::new(),
                hashes: vec![],
                format: None,
                delta_url: None,
                protocol_version: None,
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
                protocol_version: None,
            },
        ]
    }

    #[test]
    fn test_cmn_entry_serialization() {
        let entry = CmnEntry::new(vec![CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        }]);

        let json = serde_json::to_string(&entry).unwrap_or_default();
        assert!(json.contains("\"$schema\""));
        assert!(json.contains(CMN_SCHEMA));
        assert!(json.contains("b3.abc123def456"));
        assert!(json.contains("\"endpoints\""));
        assert!(json.contains("\"key\""));

        let parsed: CmnEntry = serde_json::from_str(&json).unwrap();
        let capsule = parsed.primary_capsule().unwrap();
        assert_eq!(parsed.schema, CMN_SCHEMA);
        assert_eq!(capsule.mycelium_hash(), Some("b3.abc123def456"));
        assert_eq!(
            capsule.key,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(parsed.effective_protocol_versions(), vec!["v1"]);
    }

    #[test]
    fn test_capsule_build_mycelium_url() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        };
        let url = capsule.mycelium_url("b3.abc123").unwrap();
        assert_eq!(url, "https://example.com/cmn/mycelium/b3.abc123.json");
    }

    #[test]
    fn test_capsule_build_spore_url() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        };
        let url = capsule.spore_url("b3.abc123").unwrap();
        assert_eq!(url, "https://example.com/cmn/spore/b3.abc123.json");
    }

    #[test]
    fn test_capsule_build_archive_url() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        };
        let url = capsule.archive_url("b3.abc123").unwrap();
        assert_eq!(url, "https://example.com/cmn/archive/b3.abc123.tar.zst");
    }

    #[test]
    fn test_capsule_build_archive_url_for_format() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        };
        let url = capsule
            .archive_url_for_format("b3.abc123", "tar+zstd")
            .unwrap();
        assert_eq!(url, "https://example.com/cmn/archive/b3.abc123.tar.zst");
    }

    #[test]
    fn test_capsule_build_archive_delta_url() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        };
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
            protocol_version: None,
        });
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints,
        };
        let url = capsule.taste_url("b3.7tRkW2x").unwrap();
        assert_eq!(url, "https://example.com/cmn/taste/b3.7tRkW2x.json");
    }

    #[test]
    fn test_capsule_build_taste_url_not_configured() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: sample_cmn_endpoints(),
        };
        assert!(capsule.taste_url("b3.7tRkW2x").is_err());
    }

    #[test]
    fn test_capsule_build_url_rejects_malicious_template() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: vec![
                CmnEndpoint {
                    kind: "mycelium".to_string(),
                    url: "file:///etc/passwd?{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                    protocol_version: None,
                },
                CmnEndpoint {
                    kind: "spore".to_string(),
                    url: "gopher://internal/{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                    protocol_version: None,
                },
                CmnEndpoint {
                    kind: "archive".to_string(),
                    url: "http://localhost:9090/{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: Some("tar+zstd".to_string()),
                    delta_url: None,
                    protocol_version: None,
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
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: vec![
                CmnEndpoint {
                    kind: "mycelium".to_string(),
                    url: "https://10.0.0.1/cmn/{hash}.json".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                    protocol_version: None,
                },
                CmnEndpoint {
                    kind: "spore".to_string(),
                    url: "https://192.168.1.1/cmn/{hash}.json".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: None,
                    delta_url: None,
                    protocol_version: None,
                },
                CmnEndpoint {
                    kind: "archive".to_string(),
                    url: "https://169.254.169.254/cmn/{hash}".to_string(),
                    hash: String::new(),
                    hashes: vec![],
                    format: Some("tar+zstd".to_string()),
                    delta_url: None,
                    protocol_version: None,
                },
            ],
        };
        assert!(capsule.mycelium_url("b3.abc").is_err());
        assert!(capsule.spore_url("b3.abc").is_err());
        assert!(capsule.archive_url("b3.abc").is_err());
    }

    #[test]
    fn test_capsule_confirms_previous_key() {
        let capsule = CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "ed25519.current".to_string(),
            previous_keys: vec![PreviousKey {
                key: "ed25519.previous".to_string(),
                retired_at_epoch_ms: 1710000000000,
            }],
            endpoints: vec![],
        };

        assert!(capsule.confirms_key("ed25519.current"));
        assert!(capsule.confirms_key("ed25519.previous"));
        assert!(!capsule.confirms_key("ed25519.other"));
    }

    #[test]
    fn test_effective_protocol_versions_default_to_v1() {
        let entry = CmnEntry::new(vec![CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: vec![],
        }]);

        assert_eq!(entry.effective_protocol_versions(), vec!["v1"]);
        assert!(entry.supports_protocol_version("v1"));
        assert!(!entry.supports_protocol_version("v2"));
    }

    #[test]
    fn test_effective_protocol_versions_use_advertised_versions() {
        let mut entry = CmnEntry::new(vec![CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "host-key".to_string(),
            previous_keys: vec![],
            endpoints: vec![],
        }]);
        entry.protocol_versions = vec!["v1".to_string(), "v2".to_string()];

        assert_eq!(entry.effective_protocol_versions(), vec!["v1", "v2"]);
        assert!(entry.supports_protocol_version("v2"));
        assert!(!entry.supports_protocol_version("v3"));
    }
}
