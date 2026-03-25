//! Substrate - Shared library for CMN (Code Mycelial Network)
//!
//! This library provides common data structures and utilities shared between
//! hypha (client) and synapse (indexer).
//!
//! **Zero I/O, WASM-compatible.** All algorithms (tree hashing, signatures,
//! schema validation) operate on in-memory data only. Filesystem traversal
//! lives in downstream crates (e.g. cmn-hypha).

#[cfg(any(feature = "archive-ruzstd", feature = "archive-zstd"))]
pub mod archive;
#[cfg(feature = "client")]
pub mod client;
pub mod crypto;
pub mod model;
pub mod schemas;
pub mod tree;
pub mod uri;
pub mod util;

pub use crypto::{
    compute_blake3_hash, compute_signature, format_hash, format_key, format_signature, parse_hash,
    parse_key, parse_signature, verify_json_signature, verify_signature, HashAlgorithm,
    KeyAlgorithm, SignatureAlgorithm,
};
pub use model::*;
pub use schemas::{detect_schema_type, validate as validate_schema, SchemaType};
pub use tree::{
    compute_tree_hash_from_entries, flatten_entries, max_mtime, walk_dir, DirEntry, DirReader,
    TreeEntry,
};
pub use uri::{
    build_domain_uri, build_mycelium_uri, build_spore_uri, build_taste_uri, cmn_entry_url,
    normalize_and_validate_url, normalize_taste_target_uri, parse_uri, validate_domain, CmnUri,
    CmnUriKind,
};
pub use util::{local_dir_name, validate_timestamp_not_future};
