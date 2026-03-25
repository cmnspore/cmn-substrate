# Conformance vectors — copies from cmn-spec, DO NOT EDIT HERE
#
# Authoritative source: cmn-spec/conformance/v1/
# To sync: cp -r cmn-spec/conformance/v1/* cmn-substrate/tests/conformance/

# CMN Conformance Vectors (v1)

This directory provides implementation-neutral conformance vectors for every
normative core spec chapter plus supporting protocol behaviors:

- `substrate`: `01-substrate` domain entry, endpoint resolution, protocol versions
- `mycelium`: `02-mycelium` manifest inventory, nutrients, taste catalog
- `spore`: `03-spore` manifest semantics, distributions, lineage helpers
- `taste`: `04-taste` base verdict-to-action safety rules
- `strain`: `05-strain` extends semantics, root-lineage classification, explicit declaration
- `uri`: `06-uri` parse/normalization behavior
- `algorithm_registry`: `07-algorithm-registry` prefix parsing and tree algorithm handling
- `signature`: Ed25519 verification over canonical JSON bytes
- `capsule`: Two-layer signature verification for authored vs hosted capsules
- `key_rotation`: Domain key rollover trust behavior
- `blob_tree_blake3_nfc`: Tree-root behavior from a virtual file tree
- `bond_traversal`: BFS/DFS graph traversal over spore bonds
- `taste_gating`: Operation-specific gating for spawn/grow/absorb/bond

`overview.md`, `glossary.md`, and `example.md` are non-normative/supporting
documents, so they are not represented as standalone vector files.

The authoritative machine-readable entry point is [`manifest.json`](./manifest.json). Every JSON file in [`vectors/`](./vectors/) MUST be listed there.

Run the manifest integrity check before release or CI:

```bash
python3 check_manifest.py
```

Passing all manifest-listed vectors indicates baseline protocol compatibility for these areas.

## Vector Schema

Each vector file is JSON:

```json
{
  "version": "cmn-conformance-v1",
  "cases": [ ... ]
}
```

### `signature` case

```json
{
  "id": "valid_signature",
  "canonical_json": "{\"k\":\"v\"}",
  "public_key": "ed25519....",
  "signature": "ed25519....",
  "valid": true
}
```

### `uri` case

```json
{
  "id": "valid_spore",
  "uri": "cmn://example.com/b3....",
  "parse_ok": true,
  "normalized_uri": "cmn://example.com/b3...."
}
```

For invalid input:

```json
{
  "id": "invalid_hash",
  "uri": "cmn://example.com/not-a-hash",
  "parse_ok": false,
  "error_code": "invalid_hash"
}
```

### `blob_tree_blake3_nfc` case

```json
{
  "id": "basic_tree",
  "entries": [
    { "path": "README.md", "content": "hello\n" }
  ],
  "exclude_names": [],
  "follow_rules": [],
  "expect_ok": true,
  "root_hash": "b3...."
}
```

For invalid input:

```json
{
  "id": "nfc_conflict",
  "entries": [ ... ],
  "exclude_names": [],
  "follow_rules": [],
  "expect_ok": false,
  "error_code": "filename_nfc_conflict"
}
```
