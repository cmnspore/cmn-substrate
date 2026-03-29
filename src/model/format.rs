use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{Map, Value};

/// Trait for canonical pretty-printing of CMN protocol types.
pub trait PrettyJson {
    fn to_pretty_json(&self) -> Result<String>;
}

/// Reorder keys in a JSON object map according to a priority list.
/// Keys in `key_order` appear first (in that order), followed by any
/// remaining keys in their existing (JCS-alphabetical) order.
fn order_keys(map: &Map<String, Value>, key_order: &[&str]) -> Map<String, Value> {
    let mut ordered = Map::with_capacity(map.len());
    for &key in key_order {
        if let Some(v) = map.get(key) {
            ordered.insert(key.to_string(), v.clone());
        }
    }
    for (k, v) in map {
        if !ordered.contains_key(k) {
            ordered.insert(k.clone(), v.clone());
        }
    }
    ordered
}

/// Apply key ordering to a specific JSON pointer path within a value.
fn order_keys_at(value: &mut Value, pointer: &str, key_order: &[&str]) {
    if let Some(obj) = value.pointer(pointer).and_then(|v| v.as_object().cloned()) {
        let ordered = order_keys(&obj, key_order);
        // Navigate to parent and replace
        if let Some(last_slash) = pointer.rfind('/') {
            let parent_path = &pointer[..last_slash];
            let child_key = &pointer[last_slash + 1..];
            let parent = if parent_path.is_empty() {
                Some(value as &mut Value)
            } else {
                value.pointer_mut(parent_path)
            };
            if let Some(Value::Object(parent_map)) = parent {
                parent_map.insert(child_key.to_string(), Value::Object(ordered));
            }
        } else if pointer.is_empty() {
            *value = Value::Object(ordered);
        }
    }
}

/// Apply key ordering to each element of a JSON array at the given pointer.
fn order_array_elements_at(value: &mut Value, pointer: &str, key_order: &[&str]) {
    if let Some(Value::Array(arr)) = value.pointer_mut(pointer) {
        for item in arr.iter_mut() {
            if let Value::Object(map) = item {
                *map = order_keys(map, key_order);
            }
        }
    }
}

/// JCS-canonicalize then pretty-print with custom key ordering.
///
/// Strategy: serialize to JCS (deterministic nested sorting), re-parse,
/// then apply manual top-level + known nested object reordering.
fn format_value(value: &Value, orderings: &[(&str, &[&str])]) -> Result<String> {
    let canonical =
        serde_jcs::to_string(value).map_err(|e| anyhow!("JCS serialization failed: {}", e))?;
    let mut sorted: Value =
        serde_json::from_str(&canonical).map_err(|e| anyhow!("JCS re-parse failed: {}", e))?;

    for &(pointer, key_order) in orderings {
        if let Some(array_pointer) = pointer.strip_suffix("[]") {
            order_array_elements_at(&mut sorted, array_pointer, key_order);
        } else {
            order_keys_at(&mut sorted, pointer, key_order);
        }
    }

    let pretty =
        serde_json::to_string_pretty(&sorted).map_err(|e| anyhow!("Pretty-print failed: {}", e))?;
    Ok(format!("{}\n", pretty))
}

fn serialize_to_value<T: Serialize>(value: &T, label: &str) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| anyhow!("{} serialization failed: {}", label, e))
}

// -- Spore key orders --

const SPORE_TOP_KEY_ORDER: &[&str] = &["$schema", "capsule", "capsule_signature"];
const SPORE_CAPSULE_KEY_ORDER: &[&str] = &["uri", "core", "core_signature", "dist"];
/// Shared key order for SporeCore — works for both `capsule.core` (inside
/// spore.json) and the top-level `spore.core.json` document.  `order_keys`
/// silently skips keys that aren't present, so `$schema` is a no-op inside
/// a capsule core and `updated_at_epoch_ms` is a no-op in draft files.
const SPORE_CORE_KEY_ORDER: &[&str] = &[
    "$schema",
    "id",
    "name",
    "version",
    "domain",
    "key",
    "synopsis",
    "intent",
    "license",
    "mutations",
    "updated_at_epoch_ms",
    "bonds",
    "tree",
];
const BOND_KEY_ORDER: &[&str] = &["relation", "uri", "id", "reason", "with"];
const SPORE_TREE_KEY_ORDER: &[&str] = &["algorithm", "exclude_names", "follow_rules"];

// -- Mycelium key orders --

const MYCELIUM_TOP_KEY_ORDER: &[&str] = &["$schema", "capsule", "capsule_signature"];
const MYCELIUM_CAPSULE_KEY_ORDER: &[&str] = &["uri", "core", "core_signature"];
const MYCELIUM_CORE_KEY_ORDER: &[&str] = &[
    "domain",
    "key",
    "name",
    "synopsis",
    "bio",
    "nutrients",
    "updated_at_epoch_ms",
    "spores",
    "tastes",
];
const NUTRIENT_KEY_ORDER: &[&str] = &[
    "type",
    "address",
    "recipient",
    "url",
    "label",
    "chain_id",
    "token",
    "asset_id",
];
const MYCELIUM_SPORE_KEY_ORDER: &[&str] = &["id", "hash", "name", "synopsis"];
const MYCELIUM_TASTE_KEY_ORDER: &[&str] = &["hash", "target_uri"];

// -- Taste key orders --

const TASTE_TOP_KEY_ORDER: &[&str] = &["$schema", "capsule", "capsule_signature"];
const TASTE_CAPSULE_KEY_ORDER: &[&str] = &["uri", "core", "core_signature"];
const TASTE_CORE_KEY_ORDER: &[&str] = &[
    "domain",
    "key",
    "target_uri",
    "verdict",
    "notes",
    "tasted_at_epoch_ms",
];

// -- CMN key orders --

const CMN_TOP_KEY_ORDER: &[&str] = &[
    "$schema",
    "protocol_versions",
    "capsules",
    "capsule_signature",
];
const CMN_CAPSULE_ENTRY_KEY_ORDER: &[&str] = &["uri", "key", "previous_keys", "endpoints"];
const CMN_ENDPOINT_KEY_ORDER: &[&str] = &["type", "url", "hashes", "format", "delta_url"];
const PREVIOUS_KEY_ORDER: &[&str] = &["key", "retired_at_epoch_ms"];

// -- PrettyJson implementations --

impl PrettyJson for super::Spore {
    fn to_pretty_json(&self) -> Result<String> {
        let value = serialize_to_value(self, "Spore")?;
        format_value(
            &value,
            &[
                ("", SPORE_TOP_KEY_ORDER),
                ("/capsule", SPORE_CAPSULE_KEY_ORDER),
                ("/capsule/core", SPORE_CORE_KEY_ORDER),
                ("/capsule/core/bonds[]", BOND_KEY_ORDER),
                ("/capsule/core/tree", SPORE_TREE_KEY_ORDER),
            ],
        )
    }
}

impl PrettyJson for super::SporeCoreDocument {
    fn to_pretty_json(&self) -> Result<String> {
        let value = serialize_to_value(self, "SporeCoreDocument")?;
        format_value(
            &value,
            &[
                ("", SPORE_CORE_KEY_ORDER),
                ("/bonds[]", BOND_KEY_ORDER),
                ("/tree", SPORE_TREE_KEY_ORDER),
            ],
        )
    }
}

/// Format a spore core draft value for writing to spore.core.json.
/// Strips `updated_at_epoch_ms` and applies canonical key ordering.
pub fn format_spore_core_draft(value: &Value) -> Result<String> {
    let mut clean = value.clone();
    if let Some(obj) = clean.as_object_mut() {
        obj.remove("updated_at_epoch_ms");
    }
    format_value(
        &clean,
        &[
            ("", SPORE_CORE_KEY_ORDER),
            ("/bonds[]", BOND_KEY_ORDER),
            ("/tree", SPORE_TREE_KEY_ORDER),
        ],
    )
}

impl PrettyJson for super::Mycelium {
    fn to_pretty_json(&self) -> Result<String> {
        let value = serialize_to_value(self, "Mycelium")?;
        format_value(
            &value,
            &[
                ("", MYCELIUM_TOP_KEY_ORDER),
                ("/capsule", MYCELIUM_CAPSULE_KEY_ORDER),
                ("/capsule/core", MYCELIUM_CORE_KEY_ORDER),
                ("/capsule/core/nutrients[]", NUTRIENT_KEY_ORDER),
                ("/capsule/core/spores[]", MYCELIUM_SPORE_KEY_ORDER),
                ("/capsule/core/tastes[]", MYCELIUM_TASTE_KEY_ORDER),
            ],
        )
    }
}

impl PrettyJson for super::Taste {
    fn to_pretty_json(&self) -> Result<String> {
        let value = serialize_to_value(self, "Taste")?;
        format_value(
            &value,
            &[
                ("", TASTE_TOP_KEY_ORDER),
                ("/capsule", TASTE_CAPSULE_KEY_ORDER),
                ("/capsule/core", TASTE_CORE_KEY_ORDER),
            ],
        )
    }
}

impl PrettyJson for super::CmnEntry {
    fn to_pretty_json(&self) -> Result<String> {
        let value = serialize_to_value(self, "CmnEntry")?;
        format_value(
            &value,
            &[
                ("", CMN_TOP_KEY_ORDER),
                ("/capsules[]", CMN_CAPSULE_ENTRY_KEY_ORDER),
            ],
        )
    }
}

/// Apply key ordering to CmnEntry after it's already a Value.
/// Useful when the CmnEntry has already been serialized/validated.
pub fn format_cmn_entry(value: &Value) -> Result<String> {
    format_value(
        value,
        &[
            ("", CMN_TOP_KEY_ORDER),
            ("/capsules[]", CMN_CAPSULE_ENTRY_KEY_ORDER),
        ],
    )
}

impl super::CmnEntry {
    /// Pretty-print with full deep key ordering including nested endpoints.
    pub fn to_pretty_json_deep(&self) -> Result<String> {
        let canonical =
            serde_jcs::to_string(self).map_err(|e| anyhow!("JCS serialization failed: {}", e))?;
        let mut sorted: Value =
            serde_json::from_str(&canonical).map_err(|e| anyhow!("JCS re-parse failed: {}", e))?;

        // Top-level
        if let Value::Object(ref map) = sorted.clone() {
            sorted = Value::Object(order_keys(map, CMN_TOP_KEY_ORDER));
        }

        // Each capsule entry
        if let Some(Value::Array(capsules)) = sorted.pointer_mut("/capsules") {
            for capsule in capsules.iter_mut() {
                if let Value::Object(map) = capsule {
                    *map = order_keys(map, CMN_CAPSULE_ENTRY_KEY_ORDER);

                    // Endpoints inside each capsule
                    if let Some(Value::Array(endpoints)) = map.get_mut("endpoints") {
                        for ep in endpoints.iter_mut() {
                            if let Value::Object(ep_map) = ep {
                                *ep_map = order_keys(ep_map, CMN_ENDPOINT_KEY_ORDER);
                            }
                        }
                    }

                    // Previous keys inside each capsule
                    if let Some(Value::Array(prev_keys)) = map.get_mut("previous_keys") {
                        for pk in prev_keys.iter_mut() {
                            if let Value::Object(pk_map) = pk {
                                *pk_map = order_keys(pk_map, PREVIOUS_KEY_ORDER);
                            }
                        }
                    }
                }
            }
        }

        let pretty = serde_json::to_string_pretty(&sorted)
            .map_err(|e| anyhow!("Pretty-print failed: {}", e))?;
        Ok(format!("{}\n", pretty))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;
    use crate::model::*;

    #[test]
    fn test_order_keys() {
        let mut map = Map::new();
        map.insert("z".to_string(), Value::Null);
        map.insert("a".to_string(), Value::Null);
        map.insert("m".to_string(), Value::Null);

        let ordered = order_keys(&map, &["m", "a"]);
        let keys: Vec<&String> = ordered.keys().collect();
        assert_eq!(keys, vec!["m", "a", "z"]);
    }

    #[test]
    fn test_spore_to_pretty_json_key_order() {
        let spore = Spore::new(
            "example.com",
            "test",
            "A test",
            vec!["v1".to_string()],
            "MIT",
        );
        let json = spore.to_pretty_json().unwrap();

        // Verify top-level key order: $schema before capsule before capsule_signature
        let schema_pos = json.find("\"$schema\"").unwrap();
        let capsule_pos = json.find("\"capsule\"").unwrap();
        let capsule_sig_pos = json.find("\"capsule_signature\"").unwrap();
        assert!(schema_pos < capsule_pos);
        assert!(capsule_pos < capsule_sig_pos);

        // Verify core key order: name before domain before synopsis
        let name_pos = json.find("\"name\"").unwrap();
        let domain_pos = json.find("\"domain\"").unwrap();
        let synopsis_pos = json.find("\"synopsis\"").unwrap();
        assert!(name_pos < domain_pos);
        assert!(domain_pos < synopsis_pos);
    }

    #[test]
    fn test_spore_core_document_key_order() {
        let doc = SporeCoreDocument {
            schema: SPORE_CORE_SCHEMA.to_string(),
            core: SporeCore {
                id: String::new(),
                name: "test".to_string(),
                version: String::new(),
                domain: "example.com".to_string(),
                key: String::new(),
                synopsis: "A test".to_string(),
                intent: vec![],
                license: "MIT".to_string(),
                mutations: vec![],
                size_bytes: 0,
                updated_at_epoch_ms: 0,
                bonds: vec![],
                tree: SporeTree::default(),
            },
        };
        let json = doc.to_pretty_json().unwrap();

        let schema_pos = json.find("\"$schema\"").unwrap();
        let name_pos = json.find("\"name\"").unwrap();
        let domain_pos = json.find("\"domain\"").unwrap();
        assert!(schema_pos < name_pos);
        assert!(name_pos < domain_pos);
    }

    #[test]
    fn test_format_spore_core_draft_strips_updated_at() {
        let value = serde_json::json!({
            "$schema": SPORE_CORE_SCHEMA,
            "name": "test",
            "domain": "example.com",
            "synopsis": "A test",
            "intent": [],
            "license": "MIT",
            "updated_at_epoch_ms": 12345,
            "tree": {
                "algorithm": "blob_tree_blake3_nfc",
                "exclude_names": [],
                "follow_rules": []
            }
        });
        let json = format_spore_core_draft(&value).unwrap();
        assert!(!json.contains("updated_at_epoch_ms"));
    }

    #[test]
    fn test_mycelium_to_pretty_json_core_key_order() {
        let mycelium = Mycelium::new("example.com", "Example", "A test", 123);
        let json = mycelium.to_pretty_json().unwrap();

        // Verify core key order: domain before name before synopsis
        let domain_pos = json.find("\"domain\"").unwrap();
        let name_pos = json.find("\"name\"").unwrap();
        let synopsis_pos = json.find("\"synopsis\"").unwrap();
        assert!(domain_pos < name_pos);
        assert!(name_pos < synopsis_pos);
    }

    #[test]
    fn test_cmn_entry_to_pretty_json_deep() {
        let entry = CmnEntry::new(vec![CmnCapsuleEntry {
            uri: "cmn://example.com".to_string(),
            key: "ed25519.abc".to_string(),
            previous_keys: vec![],
            endpoints: vec![CmnEndpoint {
                kind: "mycelium".to_string(),
                url: "https://example.com/cmn/mycelium/{hash}.json".to_string(),
                hash: "b3.abc".to_string(),
                hashes: vec![],
                format: None,
                delta_url: None,
                protocol_version: None,
            }],
        }]);
        let json = entry.to_pretty_json_deep().unwrap();

        let schema_pos = json.find("\"$schema\"").unwrap();
        let capsules_pos = json.find("\"capsules\"").unwrap();
        let sig_pos = json.find("\"capsule_signature\"").unwrap();
        assert!(schema_pos < capsules_pos);
        assert!(capsules_pos < sig_pos);
    }

    #[test]
    fn test_taste_to_pretty_json_key_order() {
        let taste = Taste {
            schema: TASTE_SCHEMA.to_string(),
            capsule: TasteCapsule {
                uri: "cmn://example.com/taste/b3.abc".to_string(),
                core: TasteCore {
                    target_uri: "cmn://other.com/b3.xyz".to_string(),
                    domain: "example.com".to_string(),
                    key: "ed25519.abc".to_string(),
                    verdict: TasteVerdict::Safe,
                    notes: vec![],
                    tasted_at_epoch_ms: 123,
                },
                core_signature: "ed25519.sig".to_string(),
            },
            capsule_signature: "ed25519.capsig".to_string(),
        };
        let json = taste.to_pretty_json().unwrap();

        let schema_pos = json.find("\"$schema\"").unwrap();
        let capsule_pos = json.find("\"capsule\"").unwrap();
        assert!(schema_pos < capsule_pos);
    }
}
