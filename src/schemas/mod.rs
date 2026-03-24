//! JSON Schema validation for CMN documents
//!
//! Uses embedded schemas for fast, offline validation.
//! See docs/09_SCHEMA.md for specification.

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::model::{CMN_SCHEMA, MYCELIUM_SCHEMA, SPORE_CORE_SCHEMA, SPORE_SCHEMA, TASTE_SCHEMA};

// Embedded schemas - compiled into the binary
pub const SPORE_SCHEMA_JSON: &str = include_str!("spore.json");
pub const MYCELIUM_SCHEMA_JSON: &str = include_str!("mycelium.json");
pub const CMN_SCHEMA_JSON: &str = include_str!("cmn.json");
pub const SPORE_CORE_SCHEMA_JSON: &str = include_str!("spore-core.json");
pub const TASTE_SCHEMA_JSON: &str = include_str!("taste.json");

/// CMN document type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaType {
    Spore,
    SporeCore,
    Mycelium,
    Cmn,
    Taste,
}

#[derive(Clone, Copy)]
struct SchemaDescriptor {
    schema_type: SchemaType,
    schema_json: &'static str,
}

/// Validation error details
#[derive(Debug)]
pub struct ValidationError {
    pub message: String,
    pub path: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.message, self.path)
    }
}

fn extract_schema_url(doc: &Value) -> Result<&str> {
    doc.get("$schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing $schema field"))
}

fn describe_schema(schema_url: &str) -> Option<SchemaDescriptor> {
    match schema_url {
        s if s == SPORE_SCHEMA || s.ends_with("/spore.json") => Some(SchemaDescriptor {
            schema_type: SchemaType::Spore,
            schema_json: SPORE_SCHEMA_JSON,
        }),
        s if s == SPORE_CORE_SCHEMA || s.ends_with("/spore-core.json") => Some(SchemaDescriptor {
            schema_type: SchemaType::SporeCore,
            schema_json: SPORE_CORE_SCHEMA_JSON,
        }),
        s if s == MYCELIUM_SCHEMA || s.ends_with("/mycelium.json") => Some(SchemaDescriptor {
            schema_type: SchemaType::Mycelium,
            schema_json: MYCELIUM_SCHEMA_JSON,
        }),
        s if s == CMN_SCHEMA || s.ends_with("/cmn.json") => Some(SchemaDescriptor {
            schema_type: SchemaType::Cmn,
            schema_json: CMN_SCHEMA_JSON,
        }),
        s if s == TASTE_SCHEMA || s.ends_with("/taste.json") => Some(SchemaDescriptor {
            schema_type: SchemaType::Taste,
            schema_json: TASTE_SCHEMA_JSON,
        }),
        _ => None,
    }
}

/// Get embedded schema by URL
///
/// Returns the embedded schema JSON string for a given schema URL.
/// Uses suffix matching to handle different schema URL formats.
///
/// # Examples
/// ```
/// use substrate::schemas::get_schema;
///
/// let schema = get_schema("https://cmn.dev/schemas/v1/spore.json");
/// assert!(schema.is_some());
/// ```
pub fn get_schema(schema_url: &str) -> Option<&'static str> {
    describe_schema(schema_url).map(|descriptor| descriptor.schema_json)
}

/// Detect document type from $schema field
///
/// # Examples
/// ```
/// use substrate::schemas::detect_schema_type;
/// use serde_json::json;
///
/// let doc = json!({
///     "$schema": "https://cmn.dev/schemas/v1/spore.json",
///     "capsule": {},
///     "capsule_signature": ""
/// });
/// let schema_type = detect_schema_type(&doc).unwrap();
/// assert!(matches!(schema_type, substrate::schemas::SchemaType::Spore));
/// ```
pub fn detect_schema_type(doc: &Value) -> Result<SchemaType> {
    let schema_url = extract_schema_url(doc)?;
    describe_schema(schema_url)
        .map(|descriptor| descriptor.schema_type)
        .ok_or_else(|| anyhow!("Unknown schema: {}", schema_url))
}

/// Validate a CMN document against its schema
///
/// Automatically detects the document type from `$schema` and validates
/// against the embedded schema.
///
/// # Examples
/// ```
/// use substrate::schemas::validate;
/// use serde_json::json;
///
/// let doc = json!({
///     "$schema": "https://cmn.dev/schemas/v1/spore.json",
///     "capsule": {
///         "uri": "cmn://example.com/b3.3yMR7vZQ9hL",
///         "core": {
///             "id": "test",
///             "name": "test",
///             "domain": "example.com",
///             "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
///             "synopsis": "A test",
///             "intent": ["Testing"],
///             "license": "MIT",
///             "mutations": [],
///             "bonds": [],
///             "size_bytes": 0,
///             "tree": { "algorithm": "blob_tree_blake3_nfc", "exclude_names": [], "follow_rules": [] },
///             "updated_at_epoch_ms": 1700000000000_u64
///         },
///         "core_signature": "ed25519.5XmkQ9vZP8nL",
///         "dist": [{"type":"archive"}]
///     },
///     "capsule_signature": "ed25519.3yMR7vZQ9hL"
/// });
///
/// assert!(validate(&doc).is_ok());
/// ```
pub fn validate(doc: &Value) -> Result<SchemaType> {
    // 1. Extract schema URL and schema metadata
    let schema_url = extract_schema_url(doc)?;
    let descriptor =
        describe_schema(schema_url).ok_or_else(|| anyhow!("Unknown schema: {}", schema_url))?;

    // 2. Get schema
    let schema: Value = serde_json::from_str(descriptor.schema_json)
        .map_err(|e| anyhow!("Failed to parse schema: {}", e))?;

    // 3. Compile schema
    let compiled = jsonschema::validator_for(&schema)
        .map_err(|e| anyhow!("Failed to compile schema: {}", e))?;

    // 4. Validate
    if let Err(e) = compiled.validate(doc) {
        let errors: Vec<String> = compiled
            .iter_errors(doc)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        if errors.is_empty() {
            return Err(anyhow!("Validation failed: {}", e));
        }
        return Err(anyhow!("Validation failed: {}", errors.join("; ")));
    }

    Ok(descriptor.schema_type)
}

/// Validate a document and return detailed errors
///
/// Unlike `validate()`, this returns a list of all validation errors
/// instead of failing on the first one.
pub fn validate_detailed(doc: &Value) -> Result<(SchemaType, Vec<ValidationError>)> {
    // 1. Extract schema URL and schema metadata
    let schema_url = extract_schema_url(doc)?;
    let descriptor =
        describe_schema(schema_url).ok_or_else(|| anyhow!("Unknown schema: {}", schema_url))?;

    // 2. Get schema
    let schema: Value = serde_json::from_str(descriptor.schema_json)
        .map_err(|e| anyhow!("Failed to parse schema: {}", e))?;

    // 3. Compile schema
    let compiled = jsonschema::validator_for(&schema)
        .map_err(|e| anyhow!("Failed to compile schema: {}", e))?;

    // 4. Validate and collect errors
    let errors: Vec<ValidationError> = compiled
        .iter_errors(doc)
        .map(|e| ValidationError {
            message: e.to_string(),
            path: e.instance_path().to_string(),
        })
        .collect();

    Ok((descriptor.schema_type, errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_get_schema_spore() {
        let schema = get_schema(SPORE_SCHEMA);
        assert!(schema.is_some());
        assert!(schema.map(|s| s.contains("spore_core")).unwrap_or(false));
    }

    #[test]
    fn test_get_schema_mycelium() {
        let schema = get_schema(MYCELIUM_SCHEMA);
        assert!(schema.is_some());
        assert!(schema.map(|s| s.contains("mycelium_core")).unwrap_or(false));
    }

    #[test]
    fn test_get_schema_cmn() {
        let schema = get_schema(CMN_SCHEMA);
        assert!(schema.is_some());
        assert!(schema.map(|s| s.contains("endpoints")).unwrap_or(false));
    }

    #[test]
    fn test_get_schema_unknown() {
        let schema = get_schema("https://example.com/unknown.json");
        assert!(schema.is_none());
    }

    #[test]
    fn test_detect_schema_type_spore() {
        let doc = json!({
            "$schema": SPORE_SCHEMA
        });
        assert_eq!(detect_schema_type(&doc).ok(), Some(SchemaType::Spore));
    }

    #[test]
    fn test_detect_schema_type_mycelium() {
        let doc = json!({
            "$schema": MYCELIUM_SCHEMA
        });
        assert_eq!(detect_schema_type(&doc).ok(), Some(SchemaType::Mycelium));
    }

    #[test]
    fn test_detect_schema_type_cmn() {
        let doc = json!({
            "$schema": CMN_SCHEMA
        });
        assert_eq!(detect_schema_type(&doc).ok(), Some(SchemaType::Cmn));
    }

    #[test]
    fn test_validate_valid_spore() {
        let doc = json!({
            "$schema": SPORE_SCHEMA,
            "capsule": {
                "uri": "cmn://example.com/b3.3yMR7vZQ9hL",
                "core": {
                    "id": "test-spore",
                    "name": "test-spore",
                    "domain": "example.com",
                    "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                    "synopsis": "A test spore",
                    "intent": ["Testing"],
                    "license": "MIT",
                    "mutations": [],
                    "bonds": [],
                    "size_bytes": 0,
                    "tree": { "algorithm": "blob_tree_blake3_nfc", "exclude_names": [], "follow_rules": [] },
                    "updated_at_epoch_ms": 1700000000000_u64
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL",
                "dist": [{"type":"archive"}]
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
        assert_eq!(result.ok(), Some(SchemaType::Spore));
    }

    #[test]
    fn test_validate_valid_mycelium() {
        let doc = json!({
            "$schema": MYCELIUM_SCHEMA,
            "capsule": {
                "uri": "cmn://example.com/mycelium/b3.3yMR7vZQ9hL",
                "core": {
                    "name": "Test User",
                    "domain": "example.com",
                    "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                    "synopsis": "A test user",
                    "updated_at_epoch_ms": 1234567890000_u64,
                    "spores": [],
                    "nutrients": [],
                    "tastes": []
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL"
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
        assert_eq!(result.ok(), Some(SchemaType::Mycelium));
    }

    #[test]
    fn test_validate_valid_cmn() {
        let doc = json!({
            "$schema": CMN_SCHEMA,
            "protocol_versions": ["v1"],
            "capsules": [{
                "uri": "cmn://example.com",
                "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                "previous_keys": [],
                "endpoints": [
                    {
                        "type": "mycelium",
                        "url": "https://example.com/cmn/mycelium/{hash}.json",
                        "hash": "b3.3yMR7vZQ9hL"
                    },
                    {
                        "type": "spore",
                        "url": "https://example.com/cmn/spore/{hash}.json"
                    },
                    {
                        "type": "archive",
                        "url": "https://example.com/cmn/archive/{hash}.tar.zst",
                        "format": "tar+zstd"
                    }
                ]
            }],
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
        assert_eq!(result.ok(), Some(SchemaType::Cmn));
    }

    #[test]
    fn test_validate_valid_cmn_taste_only() {
        // Taste-only domain: uri + key + taste endpoint only
        let doc = json!({
            "$schema": CMN_SCHEMA,
            "protocol_versions": ["v1"],
            "capsules": [{
                "uri": "cmn://taster.example.com",
                "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                "previous_keys": [],
                "endpoints": [{
                    "type": "taste",
                    "url": "https://taster.example.com/cmn/taste/{hash}.json"
                }]
            }],
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_valid_cmn_no_endpoints() {
        // Minimal domain: uri + key + empty endpoints
        let doc = json!({
            "$schema": CMN_SCHEMA,
            "protocol_versions": ["v1"],
            "capsules": [{
                "uri": "cmn://minimal.example.com",
                "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                "previous_keys": [],
                "endpoints": []
            }],
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_cmn_missing_key() {
        let doc = json!({
            "$schema": CMN_SCHEMA,
            "protocol_versions": ["v1"],
            "capsules": [{
                "uri": "cmn://example.com",
                "previous_keys": [],
                "endpoints": []
            }],
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_err(), "Expected validation to fail without key");
    }

    #[test]
    fn test_validate_missing_schema() {
        let doc = json!({
            "capsule": {}
        });

        let result = validate(&doc);
        assert!(result.is_err());
        assert!(result
            .err()
            .map(|e| e.to_string().contains("Missing $schema"))
            .unwrap_or(false));
    }

    #[test]
    fn test_validate_invalid_spore_missing_required() {
        let doc = json!({
            "$schema": SPORE_SCHEMA,
            "capsule": {
                "uri": "cmn://example.com/b3.3yMR7vZQ9hL",
                "core": {
                    "name": "test"
                    // missing domain, synopsis, intent, license
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL",
                "dist": [{"type":"archive","filename":"test.tar.zst"}]
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_detailed_returns_all_errors() {
        let doc = json!({
            "$schema": SPORE_SCHEMA,
            "capsule": {
                "uri": "invalid-uri",  // Invalid format
                "core": {
                    "name": ""  // Empty name (minLength: 1)
                    // missing required fields
                },
                "core_signature": "invalid",  // Invalid format
                "dist": [{"type":"archive","filename":"test.tar.zst"}]
            },
            "capsule_signature": "invalid"  // Invalid format
        });

        let result = validate_detailed(&doc);
        assert!(result.is_ok());
        let (_, errors) = result.ok().unwrap_or((SchemaType::Spore, vec![]));
        assert!(!errors.is_empty(), "Expected validation errors");
    }

    #[test]
    fn test_get_schema_spore_core() {
        let schema = get_schema(SPORE_CORE_SCHEMA);
        assert!(schema.is_some());
        assert!(schema.map(|s| s.contains("bonds")).unwrap_or(false));
    }

    #[test]
    fn test_detect_schema_type_spore_core() {
        let doc = json!({
            "$schema": SPORE_CORE_SCHEMA
        });
        assert_eq!(detect_schema_type(&doc).ok(), Some(SchemaType::SporeCore));
    }

    #[test]
    fn test_validate_valid_spore_core() {
        // This is the format of spore.core.json
        let doc = json!({
            "$schema": SPORE_CORE_SCHEMA,
            "id": "my-tool",
            "name": "my-tool",
            "domain": "example.com",
            "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
            "synopsis": "A useful tool",
            "intent": ["v1.0.0"],
            "license": "MIT",
            "mutations": [],
            "bonds": [],
            "tree": { "algorithm": "blob_tree_blake3_nfc", "exclude_names": [], "follow_rules": [] }
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
        assert_eq!(result.ok(), Some(SchemaType::SporeCore));
    }

    #[test]
    fn test_validate_spore_core_with_optional_fields() {
        let doc = json!({
            "$schema": SPORE_CORE_SCHEMA,
            "id": "my-tool",
            "name": "my-tool",
            "domain": "example.com",
            "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
            "synopsis": "A useful tool",
            "intent": ["v1.0.0"],
            "license": "MIT",
            "mutations": [],
            "bonds": [
                { "uri": "cmn://other.com/b3.3yMR7vZQ9hL", "relation": "depends_on" }
            ],
            "tree": {
                "algorithm": "blob_tree_blake3_nfc",
                "exclude_names": [".git"],
                "follow_rules": [".gitignore"]
            }
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
        assert_eq!(result.ok(), Some(SchemaType::SporeCore));
    }

    #[test]
    fn test_get_schema_taste() {
        let schema = get_schema(TASTE_SCHEMA);
        assert!(schema.is_some());
        assert!(schema.map(|s| s.contains("taste_core")).unwrap_or(false));
    }

    #[test]
    fn test_detect_schema_type_taste() {
        let doc = json!({
            "$schema": TASTE_SCHEMA
        });
        assert_eq!(detect_schema_type(&doc).ok(), Some(SchemaType::Taste));
    }

    #[test]
    fn test_validate_valid_taste() {
        let doc = json!({
            "$schema": TASTE_SCHEMA,
            "capsule": {
                "uri": "cmn://reviewer.com/taste/b3.7tRkW2xPqL9nH",
                "core": {
                    "target_uri": "cmn://example.com/b3.3yMR7vZQ9hL",
                    "domain": "reviewer.com",
                    "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                    "verdict": "safe",
                    "tasted_at_epoch_ms": 1234567890000_u64
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL"
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
        assert_eq!(result.ok(), Some(SchemaType::Taste));
    }

    #[test]
    fn test_validate_taste_invalid_verdict() {
        let doc = json!({
            "$schema": TASTE_SCHEMA,
            "capsule": {
                "uri": "cmn://reviewer.com/taste/b3.7tRkW2xPqL9nH",
                "core": {
                    "target_uri": "cmn://example.com/b3.3yMR7vZQ9hL",
                    "domain": "reviewer.com",
                    "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                    "verdict": "unknown_taste",
                    "tasted_at_epoch_ms": 1234567890000_u64
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL"
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(
            result.is_err(),
            "Expected validation to fail with invalid taste"
        );
    }

    #[test]
    fn test_validate_taste_mycelium_target_uri() {
        let doc = json!({
            "$schema": TASTE_SCHEMA,
            "capsule": {
                "uri": "cmn://reviewer.com/taste/b3.7tRkW2xPqL9nH",
                "core": {
                    "target_uri": "cmn://example.com/mycelium/b3.3yMR7vZQ9hL",
                    "domain": "reviewer.com",
                    "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                    "verdict": "safe",
                    "tasted_at_epoch_ms": 1234567890000_u64
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL"
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_taste_rejects_taste_target_uri() {
        let doc = json!({
            "$schema": TASTE_SCHEMA,
            "capsule": {
                "uri": "cmn://reviewer.com/taste/b3.7tRkW2xPqL9nH",
                "core": {
                    "target_uri": "cmn://someone.dev/taste/b3.3yMR7vZQ9hL",
                    "domain": "reviewer.com",
                    "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
                    "verdict": "safe",
                    "tasted_at_epoch_ms": 1234567890000_u64
                },
                "core_signature": "ed25519.5XmkQ9vZP8nL"
            },
            "capsule_signature": "ed25519.3yMR7vZQ9hL"
        });

        let result = validate(&doc);
        assert!(result.is_err(), "Expected taste target_uri to be rejected");
    }

    #[test]
    fn test_validate_invalid_spore_core_missing_required() {
        let doc = json!({
            "$schema": SPORE_CORE_SCHEMA,
            "name": "my-tool"
            // missing domain, synopsis, intent, license
        });

        let result = validate(&doc);
        assert!(result.is_err());
    }
}
