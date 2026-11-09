# cmn-substrate

The shared Rust library for CMN — data models, cryptographic verification, tree hashing, URI parsing, and JSON-schema validation used by Hypha and Synapse.

Core library for the [Code Mycelial Network](https://cmn.dev) protocol. The default
build performs no I/O and supports WASM; HTTP and archive support are opt-in.

## What it does

- **Data models** — Spore, Mycelium, Taste, CMN entry structs with serde serialization
- **Cryptography** — Ed25519 signatures and BLAKE3 content hashing with JCS canonicalization
- **Tree hashing** — Git-like Merkle tree (blob_tree_blake3_nfc) with Unicode NFC normalization
- **URI parsing** — `cmn://domain/b3.hash` with domain and URL validation;
  use `client-safe-dns` for HTTP clients that also filter resolved addresses
- **Schema validation** — Embedded JSON Schema (draft 2020-12) for all protocol artifacts
- **HTTP client** — Optional async client for fetching manifests, mycelium, taste reports (feature-gated)
- **Archive extraction** — Optional tar+zstd extraction with security hardening (feature-gated)

## Features

| Feature | Description |
|---------|-------------|
| `client` | HTTP client via reqwest |
| `client-safe-dns` | Client with DNS filtering (adds tokio) |
| `archive-ruzstd` | Tar extraction with ruzstd (WASM-compatible) |
| `archive-zstd` | Tar extraction with zstd (native, faster) |

## Usage

```toml
[dependencies]
cmn-substrate = "0.4"
```

With the HTTP client and DNS filtering:

```toml
[dependencies]
cmn-substrate = { version = "0.4", features = ["client-safe-dns"] }
```

```rust
use substrate::{parse_uri, validate_schema, compute_blake3_hash};

// Parse a CMN URI
let hash = compute_blake3_hash(b"example");
let uri = parse_uri(&format!("cmn://example.com/{hash}"))?;

// Validate a document against its schema
let doc: serde_json::Value = serde_json::from_str(&json_str)?;
validate_schema(&doc)?;
```

## License

MIT
