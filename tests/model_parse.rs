#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use substrate::*;

#[test]
fn test_decode_spore_metadata() {
    let payload = serde_json::json!({
        "$schema": "https://cmn.dev/schemas/v1/spore.json",
        "capsule": {
            "uri": "cmn://example.com/b3.3yMR7vZQ9hL",
            "core": {
                "name": "test",
                "domain": "example.com",
                "key": "ed25519.5XmkQ9vZP8nL",
                "synopsis": "Test",
                "intent": ["Testing"],
                "license": "MIT",
                "mutations": [],
                "size_bytes": 1024,
                "updated_at_epoch_ms": 1234567890000_u64,
                "bonds": [],
                "tree": { "algorithm": "blob_tree_blake3_nfc", "exclude_names": [], "follow_rules": [] }
            },
            "core_signature": "ed25519.5XmkQ9vZP8nL",
            "dist": []
        },
        "capsule_signature": "ed25519.5XmkQ9vZP8nL"
    });

    let spore = decode_spore(&payload).unwrap();
    assert_eq!(spore.capsule.core.name, "test");
    assert_eq!(spore.capsule.core.domain, "example.com");
    assert_eq!(spore.timestamp_ms(), 1234567890000_u64);
}

#[test]
fn test_decode_spore_spawned_from_hash() {
    let payload = serde_json::json!({
        "$schema": "https://cmn.dev/schemas/v1/spore.json",
        "capsule": {
            "uri": "cmn://example.com/b3.childhash",
            "core": {
                "name": "child",
                "domain": "example.com",
                "key": "ed25519.5XmkQ9vZP8nL",
                "synopsis": "Child",
                "intent": ["Testing"],
                "license": "MIT",
                "mutations": [],
                "size_bytes": 2048,
                "updated_at_epoch_ms": 1234567890000_u64,
                "bonds": [{
                    "relation": "spawned_from",
                    "uri": "cmn://parent.com/b3.parenthash"
                }],
                "tree": { "algorithm": "blob_tree_blake3_nfc", "exclude_names": [], "follow_rules": [] }
            },
            "core_signature": "ed25519.5XmkQ9vZP8nL",
            "dist": []
        },
        "capsule_signature": "ed25519.5XmkQ9vZP8nL"
    });

    let spore = decode_spore(&payload).unwrap();
    assert_eq!(spore.spawned_from_hash(), Some("b3.parenthash".to_string()));
}

#[test]
fn test_decode_cmn_entry() {
    let payload = serde_json::json!({
        "$schema": "https://cmn.dev/schemas/v1/cmn.json",
        "protocol_versions": ["v1"],
        "capsules": [{
            "uri": "cmn://example.com",
            "key": "ed25519.5XmkQ9vZP8nL",
            "previous_keys": [],
            "endpoints": [{
                "type": "mycelium",
                "url": "https://example.com/cmn/mycelium/{hash}.json",
                "hashes": ["b3.abc123"]
            }]
        }],
        "capsule_signature": "ed25519.5XmkQ9vZP8nL"
    });

    let entry = decode_cmn_entry(&payload).unwrap();
    let capsule = entry.primary_capsule().unwrap();
    assert_eq!(capsule.uri, "cmn://example.com");
    assert_eq!(capsule.mycelium_hashes(), &["b3.abc123"]);
}

#[test]
fn test_decode_taste_metadata() {
    let payload = serde_json::json!({
        "$schema": "https://cmn.dev/schemas/v1/taste.json",
        "capsule": {
            "uri": "cmn://example.com/taste/b3.123",
            "core": {
                "target_uri": "cmn://target.com/b3.456",
                "domain": "example.com",
                "key": "ed25519.5XmkQ9vZP8nL",
                "verdict": "safe",
                "notes": ["Looks good"],
                "tasted_at_epoch_ms": 1234567890000_u64
            },
            "core_signature": "ed25519.5XmkQ9vZP8nL"
        },
        "capsule_signature": "ed25519.5XmkQ9vZP8nL"
    });

    let taste = decode_taste(&payload).unwrap();
    assert_eq!(taste.target_uri(), "cmn://target.com/b3.456");
    assert_eq!(taste.author_domain(), "example.com");
    assert_eq!(taste.timestamp_ms(), 1234567890000_u64);
}
