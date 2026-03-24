use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const MYCELIUM_SCHEMA: &str = "https://cmn.dev/schemas/v1/mycelium.json";

/// Full Mycelium manifest (content-addressed)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mycelium {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub capsule: MyceliumCapsule,
    pub capsule_signature: String,
}

/// Mycelium capsule containing uri, core, and core_signature
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyceliumCapsule {
    pub uri: String,
    pub core: MyceliumCore,
    pub core_signature: String,
}

/// Core mycelium data (part of hash)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyceliumCore {
    pub name: String,
    pub domain: String,
    pub key: String,
    pub synopsis: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bio: String,
    #[serde(default)]
    pub nutrients: Vec<Nutrient>,
    pub updated_at_epoch_ms: u64,
    #[serde(default)]
    pub spores: Vec<MyceliumCoreSpore>,
    #[serde(default)]
    pub tastes: Vec<MyceliumCoreTaste>,
}

/// Spore entry in mycelium's spores list
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyceliumCoreSpore {
    pub id: String,
    pub hash: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synopsis: Option<String>,
}

/// Taste entry in mycelium's tastes list
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyceliumCoreTaste {
    pub hash: String,
    pub target_uri: String,
}

/// Single nutrient method entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Nutrient {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

impl Mycelium {
    pub fn new(domain: &str, name: &str, synopsis: &str, updated_at_epoch_ms: u64) -> Self {
        Self {
            schema: MYCELIUM_SCHEMA.to_string(),
            capsule: MyceliumCapsule {
                uri: String::new(),
                core: MyceliumCore {
                    name: name.to_string(),
                    domain: domain.to_string(),
                    key: String::new(),
                    synopsis: synopsis.to_string(),
                    bio: String::new(),
                    nutrients: vec![],
                    updated_at_epoch_ms,
                    spores: vec![],
                    tastes: vec![],
                },
                core_signature: String::new(),
            },
            capsule_signature: String::new(),
        }
    }

    pub fn add_spore(
        &mut self,
        id: &str,
        hash: &str,
        name: &str,
        synopsis: Option<&str>,
        updated_at_epoch_ms: u64,
    ) {
        self.capsule.core.spores.retain(|entry| {
            if entry.id.is_empty() {
                entry.name != name
            } else {
                entry.id != id
            }
        });

        self.capsule.core.spores.push(MyceliumCoreSpore {
            id: id.to_string(),
            hash: hash.to_string(),
            name: name.to_string(),
            synopsis: synopsis.map(str::to_string),
        });
        self.capsule.core.updated_at_epoch_ms = updated_at_epoch_ms;
    }

    pub fn uri(&self) -> &str {
        &self.capsule.uri
    }

    pub fn author_domain(&self) -> &str {
        &self.capsule.core.domain
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.capsule.core.updated_at_epoch_ms
    }

    pub fn embedded_core_key(&self) -> Option<&str> {
        let key = self.capsule.core.key.as_str();
        (!key.is_empty()).then_some(key)
    }

    pub fn spore_hashes(&self) -> impl Iterator<Item = &str> {
        self.capsule
            .core
            .spores
            .iter()
            .map(|spore| spore.hash.as_str())
    }

    pub fn verify_core_signature(&self, author_key: &str) -> Result<()> {
        crate::verify_json_signature(&self.capsule.core, &self.capsule.core_signature, author_key)
    }

    pub fn verify_capsule_signature(&self, host_key: &str) -> Result<()> {
        crate::verify_json_signature(&self.capsule, &self.capsule_signature, host_key)
    }

    pub fn verify_signatures(&self, host_key: &str, author_key: &str) -> Result<()> {
        self.verify_core_signature(author_key)?;
        self.verify_capsule_signature(host_key)
    }

    pub fn computed_uri_hash(&self) -> Result<String> {
        crate::crypto::hash::compute_signed_core_hash(
            &self.capsule.core,
            &self.capsule.core_signature,
        )
    }

    pub fn verify_uri_hash(&self, expected_hash: &str) -> Result<()> {
        let actual_hash = self.computed_uri_hash()?;
        super::verify_expected_uri_hash(&actual_hash, expected_hash)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;

    #[test]
    fn test_mycelium_new() {
        let mycelium = Mycelium::new("example.com", "Example", "A test mycelium", 123);
        assert_eq!(mycelium.schema, MYCELIUM_SCHEMA);
        assert_eq!(mycelium.capsule.core.name, "Example");
        assert_eq!(mycelium.capsule.core.synopsis, "A test mycelium");
        assert_eq!(mycelium.capsule.core.domain, "example.com");
        assert_eq!(mycelium.capsule.core.updated_at_epoch_ms, 123);
        assert!(mycelium.capsule.core.spores.is_empty());
        assert!(mycelium.capsule.core.tastes.is_empty());
    }

    #[test]
    fn test_mycelium_add_spore() {
        let mut mycelium = Mycelium::new("example.com", "Example", "", 10);
        mycelium.add_spore("test", "b3.abc123", "test-spore", Some("A test spore"), 20);

        assert_eq!(mycelium.capsule.core.spores.len(), 1);
        assert_eq!(mycelium.capsule.core.spores[0].id, "test");
        assert_eq!(mycelium.capsule.core.spores[0].hash, "b3.abc123");
        assert_eq!(mycelium.capsule.core.spores[0].name, "test-spore");
        assert_eq!(
            mycelium.capsule.core.spores[0].synopsis,
            Some("A test spore".to_string())
        );
        assert_eq!(mycelium.capsule.core.updated_at_epoch_ms, 20);
    }

    #[test]
    fn test_mycelium_add_spore_replaces_existing() {
        let mut mycelium = Mycelium::new("example.com", "Example", "", 10);
        mycelium.add_spore(
            "my-spore",
            "b3.abc123",
            "old-name",
            Some("Old synopsis"),
            20,
        );
        mycelium.add_spore(
            "my-spore",
            "b3.def456",
            "new-name",
            Some("New synopsis"),
            30,
        );

        assert_eq!(mycelium.capsule.core.spores.len(), 1);
        assert_eq!(mycelium.capsule.core.spores[0].id, "my-spore");
        assert_eq!(mycelium.capsule.core.spores[0].hash, "b3.def456");
        assert_eq!(mycelium.capsule.core.spores[0].name, "new-name");
        assert_eq!(
            mycelium.capsule.core.spores[0].synopsis,
            Some("New synopsis".to_string())
        );
        assert_eq!(mycelium.capsule.core.updated_at_epoch_ms, 30);
    }

    #[test]
    fn test_mycelium_full_serialization() {
        let mut mycelium = Mycelium::new("dev.example", "Developer", "A Rust developer", 10);
        mycelium.add_spore("my-lib", "b3.spore1", "my-lib", Some("A library"), 20);
        mycelium.add_spore("my-app", "b3.spore2", "my-app", None, 30);
        mycelium.capsule.core_signature = "ed25519.core123".to_string();
        mycelium.capsule_signature = "ed25519.capsule123".to_string();
        mycelium.capsule.uri = "cmn://dev.example".to_string();

        let json = serde_json::to_string_pretty(&mycelium).unwrap_or_default();
        assert!(json.contains("\"$schema\""));
        assert!(json.contains(MYCELIUM_SCHEMA));
        assert!(json.contains("Developer"));
        assert!(json.contains("my-lib"));
        assert!(json.contains("my-app"));
    }

    #[test]
    fn test_mycelium_bio_field() {
        let mut mycelium = Mycelium::new("example.com", "Example", "A test mycelium", 10);
        mycelium.capsule.core.bio = "Longer biography of this mycelium".to_string();

        let json = serde_json::to_string(&mycelium).unwrap_or_default();
        assert!(json.contains("\"bio\""));
        assert!(json.contains("Longer biography of this mycelium"));

        let parsed: Mycelium = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capsule.core.bio, "Longer biography of this mycelium");
    }

    #[test]
    fn test_mycelium_nutrients_field() {
        let mut mycelium = Mycelium::new("example.com", "Example", "A test mycelium", 10);
        mycelium.capsule.core.nutrients = vec![
            Nutrient {
                kind: "web".to_string(),
                address: None,
                recipient: None,
                url: Some("https://example.com/sponsor".to_string()),
                label: Some("Sponsor".to_string()),
                chain_id: None,
                token: None,
                asset_id: None,
            },
            Nutrient {
                kind: "evm".to_string(),
                address: Some("0x1234567890abcdef1234567890abcdef12345678".to_string()),
                recipient: None,
                url: None,
                label: Some("ETH".to_string()),
                chain_id: Some(1),
                token: Some("ETH".to_string()),
                asset_id: None,
            },
        ];

        let json = serde_json::to_string(&mycelium).unwrap_or_default();
        assert!(json.contains("\"nutrients\""));
        assert!(json.contains("https://example.com/sponsor"));
        assert!(json.contains("0x1234567890abcdef1234567890abcdef12345678"));

        let parsed: Mycelium = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capsule.core.nutrients.len(), 2);
        assert_eq!(parsed.capsule.core.nutrients[0].kind, "web");
        assert_eq!(parsed.capsule.core.nutrients[1].kind, "evm");
        assert_eq!(parsed.capsule.core.nutrients[1].chain_id, Some(1));
    }

    #[test]
    fn test_mycelium_nutrients_serialization() {
        let nutrient = Nutrient {
            kind: "bitcoin".to_string(),
            address: Some("bc1qexampleaddress".to_string()),
            recipient: Some("donations@example.com".to_string()),
            url: Some("https://example.com/donate".to_string()),
            label: Some("Bitcoin".to_string()),
            chain_id: None,
            token: None,
            asset_id: None,
        };

        let json = serde_json::to_string(&nutrient).unwrap_or_default();
        assert!(json.contains("\"type\":\"bitcoin\""));
        assert!(json.contains("bc1qexampleaddress"));
        assert!(json.contains("donations@example.com"));
        assert!(json.contains("https://example.com/donate"));

        let parsed: Nutrient = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind, "bitcoin");
        assert_eq!(parsed.address, Some("bc1qexampleaddress".to_string()));
        assert_eq!(parsed.recipient, Some("donations@example.com".to_string()));
        assert_eq!(parsed.url, Some("https://example.com/donate".to_string()));
    }
}
