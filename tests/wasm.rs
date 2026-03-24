//! WASM integration tests — verify core algorithms run correctly in a WASM runtime.

#![cfg(target_arch = "wasm32")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use wasm_bindgen_test::*;

use substrate::{compute_tree_hash_from_entries, SporeTree, TreeEntry};

#[wasm_bindgen_test]
fn wasm_tree_hash_single_file() {
    let entries = vec![TreeEntry::File {
        name: "hello.txt".to_string(),
        content: b"hello world".to_vec(),
        executable: false,
    }];
    let tree = SporeTree {
        algorithm: "blob_tree_blake3_nfc".to_string(),
        exclude_names: vec![],
        follow_rules: vec![],
    };
    let hash = compute_tree_hash_from_entries(&entries, &tree).expect("hash should succeed");
    assert!(hash.starts_with("b3."), "hash should start with b3. prefix");
}

#[wasm_bindgen_test]
fn wasm_tree_hash_nested_directory() {
    let entries = vec![
        TreeEntry::File {
            name: "README.md".to_string(),
            content: b"# hello\n".to_vec(),
            executable: false,
        },
        TreeEntry::Directory {
            name: "src".to_string(),
            children: vec![TreeEntry::File {
                name: "main.rs".to_string(),
                content: b"fn main() {}".to_vec(),
                executable: false,
            }],
        },
    ];
    let tree = SporeTree::default();
    let hash = compute_tree_hash_from_entries(&entries, &tree).expect("hash should succeed");
    assert!(hash.starts_with("b3."));
}

#[wasm_bindgen_test]
fn wasm_tree_hash_deterministic() {
    let make_entries = || {
        vec![
            TreeEntry::File {
                name: "a.txt".to_string(),
                content: b"aaa".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "b.txt".to_string(),
                content: b"bbb".to_vec(),
                executable: false,
            },
        ]
    };
    let tree = SporeTree::default();
    let h1 = compute_tree_hash_from_entries(&make_entries(), &tree).unwrap();
    let h2 = compute_tree_hash_from_entries(&make_entries(), &tree).unwrap();
    assert_eq!(h1, h2, "hash must be deterministic");
}

#[wasm_bindgen_test]
fn wasm_tree_hash_exclusion() {
    let entries = vec![
        TreeEntry::File {
            name: "keep.txt".to_string(),
            content: b"keep".to_vec(),
            executable: false,
        },
        TreeEntry::File {
            name: "drop.log".to_string(),
            content: b"drop".to_vec(),
            executable: false,
        },
    ];
    let tree_all = SporeTree::default();
    let tree_exclude = SporeTree {
        exclude_names: vec!["drop.log".to_string()],
        ..SporeTree::default()
    };
    let h_all = compute_tree_hash_from_entries(&entries, &tree_all).unwrap();
    let h_excl = compute_tree_hash_from_entries(&entries, &tree_exclude).unwrap();
    assert_ne!(h_all, h_excl, "excluding a file should change the hash");
}

#[wasm_bindgen_test]
fn wasm_blake3_hash() {
    let hash = substrate::compute_blake3_hash(b"test data");
    assert!(hash.starts_with("b3."));
}

#[wasm_bindgen_test]
fn wasm_crypto_roundtrip() {
    // Key format/parse roundtrip
    let key_bytes = [42u8; 32];
    let formatted = substrate::format_key(substrate::KeyAlgorithm::Ed25519, &key_bytes);
    assert!(formatted.starts_with("ed25519."));
    let parsed = substrate::parse_key(&formatted).expect("parse key");
    assert_eq!(parsed.algorithm, substrate::KeyAlgorithm::Ed25519);
    assert_eq!(parsed.bytes, key_bytes);

    // Hash format/parse roundtrip
    let hash = substrate::compute_blake3_hash(b"wasm crypto test");
    let parsed = substrate::parse_hash(&hash).expect("parse hash");
    assert_eq!(parsed.algorithm, substrate::HashAlgorithm::B3);
    assert_eq!(parsed.bytes.len(), 32);
}
