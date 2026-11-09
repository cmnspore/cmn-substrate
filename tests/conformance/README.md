# CMN Conformance Vectors (v1)

This directory provides implementation-neutral conformance vectors for every
normative core spec chapter plus supporting protocol behaviors:

- `substrate`: `01-substrate` domain entry, endpoint resolution, serial/history semantics
- `mycelium`: `02-mycelium` manifest inventory, nutrients, taste catalog
- `spore`: `03-spore` manifest semantics, distributions, lineage helpers
- `taste`: `04-taste` base verdict-to-action safety rules
- `strain`: `05-strain` extends semantics, root-lineage classification, explicit declaration
- `uri`: `06-uri` parse/normalization behavior
- `algorithm_registry`: `07-algorithm-registry` prefix parsing and tree algorithm handling
- `signature`: Ed25519 verification over canonical JSON bytes
- `capsule`: Two-layer signature verification for authored vs hosted capsules
- `capsule_signed`: Five actual Ed25519 capsules covering hosting, swapped keys and tampering
- `key_rotation`: Domain key rollover trust behavior
- `key_rotation_signed`: Four signed content cases at the retired-key time boundary
- `blob_tree_blake3_nfc`: Tree-root behavior from a virtual file tree
- `bond_traversal`: BFS/DFS graph traversal over spore bonds
- `taste_gating`: Operation-specific gating for spawn/grow/absorb/bond

`glossary.md` and `example.md` are non-normative/supporting documents, so they
are not represented as standalone vector files.

The authoritative machine-readable entry point is [`manifest.json`](./manifest.json). Every JSON file in [`vectors/`](./vectors/) MUST be listed there.

Run the manifest integrity check before release or CI:

```bash
python3 check_manifest.py
```

Passing all manifest-listed vectors indicates baseline protocol compatibility for these areas.

The signed fixtures publish their deterministic Ed25519 test seeds in `test_keys`.
They are public test data and MUST NOT be used for real identities. Regenerate them
with `node generate_signed_vectors.mjs` (Node.js built-ins only). Each signature
uses JCS canonical JSON; the Rust runner also recomputes signatures from the seeds.
The URI hashes in these signed fixtures are structural placeholders. These cases
exercise signatures and key lifecycle policy, not archive/tree content addressing.
Retirement cases use the signed core's `updated_at_epoch_ms`, a timestamp declared
by the signer. They verify the inclusive policy boundary, not protection against
backdating by someone who holds a retired private key. Missing signing time is
rejected as required by 01-substrate §1.2.3.

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
