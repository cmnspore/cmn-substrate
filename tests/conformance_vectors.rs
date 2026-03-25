use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

use substrate::TreeEntry;
use substrate::{
    build_domain_uri, build_mycelium_uri, build_spore_uri, build_taste_uri,
    classify_capsule_hosting, decide_key_trust, decode_cmn_entry, decode_mycelium, decode_spore,
    evaluate_signed_capsule_validity, format_hash, format_key, format_signature, parse_hash,
    parse_key, parse_signature, parse_uri, traverse_bond_graph, validate_schema, verify_signature,
    BondGraphNode, BondRelation, BondTraversalDirection, BondTraversalQuery, CapsuleHostingKind,
    CmnCapsuleEntry, CmnUriKind, DomainKeyConfirmation, GateAction, GateOperation, KeyTrustClass,
    KeyTrustDecision, KeyTrustWitnessPolicy, PreviousKey, SchemaType, Spore, SporeBond, SporeTree,
    TasteVerdict,
};

#[derive(Debug, Deserialize)]
struct VectorFile<T> {
    version: String,
    cases: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct SignatureCase {
    id: String,
    canonical_json: String,
    public_key: String,
    signature: String,
    valid: bool,
}

#[derive(Debug, Deserialize)]
struct UriCase {
    id: String,
    uri: String,
    parse_ok: bool,
    normalized_uri: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlobTreeBlake3NfcEntry {
    path: String,
    content: String,
    executable: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct BlobTreeBlake3NfcCase {
    id: String,
    entries: Vec<BlobTreeBlake3NfcEntry>,
    exclude_names: Vec<String>,
    follow_rules: Vec<String>,
    expect_ok: bool,
    root_hash: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CapsuleCase {
    id: String,
    uri_domain: String,
    core_domain: String,
    core_key: String,
    capsule_key: String,
    core_signature_valid: bool,
    capsule_signature_valid: bool,
    is_replicate: bool,
    expected_valid: bool,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PreviousKeyCase {
    key: String,
    retired_at_epoch_ms: u64,
}

#[derive(Debug, Deserialize)]
struct KeyRotationCmnCase {
    key: String,
    #[serde(default)]
    previous_keys: Vec<PreviousKeyCase>,
}

#[derive(Debug, Deserialize)]
struct KeyRotationCase {
    id: String,
    cmn_json: Option<KeyRotationCmnCase>,
    cmn_json_reachable: Option<bool>,
    synapse_confirms_key: Option<bool>,
    content_key: String,
    expected_trusted: bool,
    expected_trust_class: Option<KeyTrustClass>,
}

#[derive(Debug, Deserialize)]
struct TasteCase {
    id: String,
    verdict: Option<TasteVerdict>,
    expected_action: GateAction,
}

#[derive(Debug, Deserialize)]
struct TasteGatingCase {
    id: String,
    operation: GateOperation,
    verdict: Option<TasteVerdict>,
    expected_action: GateAction,
}

#[derive(Debug, Deserialize)]
struct BondTraversalVectorQuery {
    start: Option<String>,
    direction: BondTraversalDirection,
    relation: Option<BondRelation>,
    max_depth: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BondTraversalCase {
    id: String,
    spore_uri: Option<String>,
    bonds: Option<Vec<SporeBond>>,
    graph: Option<Vec<BondGraphNode>>,
    query: BondTraversalVectorQuery,
    expected_uris: Option<Vec<String>>,
    expected_uris_unordered: Option<Vec<String>>,
    expected_depth: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SubstrateCase {
    id: String,
    cmn: Value,
    expected_primary_uri: String,
    expected_primary_key: String,
    expected_mycelium_hash: Option<String>,
    #[serde(default)]
    confirm_keys: Vec<String>,
    #[serde(default)]
    reject_keys: Vec<String>,
    #[serde(default)]
    supports_versions: Vec<String>,
    #[serde(default)]
    rejects_versions: Vec<String>,
    resolve_hash: Option<String>,
    resolve_old_hash: Option<String>,
    expected_mycelium_url: Option<String>,
    expected_spore_url: Option<String>,
    expected_archive_url: Option<String>,
    expected_archive_delta_url: Option<String>,
    expected_taste_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MyceliumCase {
    id: String,
    mycelium: Value,
    expected_uri: String,
    expected_domain: String,
    expected_timestamp_ms: u64,
    expected_key: String,
    expected_spore_hashes: Vec<String>,
    expected_taste_targets: Vec<String>,
    expected_nutrient_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SporeCase {
    id: String,
    spore: Value,
    cmn: Option<Value>,
    expected_uri: String,
    expected_domain: String,
    expected_timestamp_ms: u64,
    expected_key: String,
    expected_spawned_from_uri: Option<String>,
    expected_spawned_from_hash: Option<String>,
    expected_dist_types: Vec<String>,
    expected_followed_uris: Vec<String>,
    expected_git_url: Option<String>,
    expected_git_ref: Option<String>,
    resolve_hash: Option<String>,
    resolve_old_hash: Option<String>,
    expected_archive_url: Option<String>,
    expected_archive_delta_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StrainCase {
    id: String,
    spore: Value,
    accepted_root_lineage_uris: Vec<String>,
    required_extends: Vec<String>,
    expected_extended_uris: Vec<String>,
    expected_is_strain_definition: bool,
    expected_extends_all: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AlgorithmRegistryKind {
    Hash,
    Key,
    Signature,
    Tree,
}

#[derive(Debug, Deserialize)]
struct AlgorithmRegistryCase {
    id: String,
    kind: AlgorithmRegistryKind,
    value: Option<String>,
    tree_algorithm: Option<String>,
    parse_ok: bool,
    normalized_value: Option<String>,
    error_code: Option<String>,
}

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance")
}

fn load_vector_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_slice::<T>(&bytes)
        .with_context(|| format!("Failed to parse {}", path.display()))
}

fn normalize_uri(parsed: &substrate::CmnUri) -> Result<String> {
    match parsed.kind {
        CmnUriKind::Domain => Ok(build_domain_uri(&parsed.domain)),
        CmnUriKind::Spore => {
            let hash = parsed
                .hash
                .as_deref()
                .ok_or_else(|| anyhow!("spore kind must include hash"))?;
            Ok(build_spore_uri(&parsed.domain, hash))
        }
        CmnUriKind::Mycelium => {
            let hash = parsed
                .hash
                .as_deref()
                .ok_or_else(|| anyhow!("mycelium kind must include hash"))?;
            Ok(build_mycelium_uri(&parsed.domain, hash))
        }
        CmnUriKind::Taste => {
            let hash = parsed
                .hash
                .as_deref()
                .ok_or_else(|| anyhow!("taste kind must include hash"))?;
            Ok(build_taste_uri(&parsed.domain, hash))
        }
    }
}

fn map_uri_error_code(message: &str) -> &'static str {
    if message.contains("URI must start with 'cmn://'") {
        "invalid_scheme"
    } else if message.contains("Missing domain in URI") {
        "missing_domain"
    } else if message.contains("Invalid spore hash")
        || message.contains("Invalid mycelium hash")
        || message.contains("Invalid taste hash")
    {
        "invalid_hash"
    } else if message.contains("missing hash after /mycelium/")
        || message.contains("missing hash after /taste/")
    {
        "missing_hash"
    } else if message.contains("Domain ") || message.contains("Empty domain") {
        "invalid_domain"
    } else {
        "unknown_error"
    }
}

fn map_blob_tree_error_code(message: &str) -> &'static str {
    if message.contains("Filename conflict after NFC normalization") {
        "filename_nfc_conflict"
    } else {
        "tree_error"
    }
}

fn map_algorithm_error_code(message: &str) -> &'static str {
    if message.contains("Unsupported") {
        "unsupported_algorithm"
    } else if message.contains("Invalid")
        || message.contains("must use")
        || message.contains("must not")
    {
        "invalid_encoding"
    } else {
        "unknown_error"
    }
}

fn detect_nfc_conflict(entries: &[BlobTreeBlake3NfcEntry]) -> Option<String> {
    let mut seen: HashMap<(String, String), String> = HashMap::new();
    for entry in entries {
        let path = Path::new(&entry.path);
        let parent = path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let normalized = name.nfc().collect::<String>();
        let key = (parent, normalized.clone());
        if let Some(existing) = seen.insert(key, name.clone()) {
            return Some(format!(
                "Filename conflict after NFC normalization: {} vs {}",
                existing, name
            ));
        }
    }
    None
}

fn write_virtual_tree(root: &Path, entries: &[BlobTreeBlake3NfcEntry]) -> Result<()> {
    for entry in entries {
        let file_path = root.join(&entry.path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        fs::write(&file_path, entry.content.as_bytes())
            .with_context(|| format!("Failed to write {}", file_path.display()))?;

        if entry.executable.unwrap_or(false) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = fs::metadata(&file_path)
                    .with_context(|| format!("Failed to stat {}", file_path.display()))?
                    .permissions();
                perm.set_mode(0o755);
                fs::set_permissions(&file_path, perm).with_context(|| {
                    format!("Failed to chmod executable {}", file_path.display())
                })?;
            }
        }
    }

    Ok(())
}

/// Convert flat `BlobTreeBlake3NfcEntry` list (with paths like "dir/file.txt")
/// into a nested `Vec<TreeEntry>` structure.
fn entries_to_tree_entries(entries: &[BlobTreeBlake3NfcEntry]) -> Vec<TreeEntry> {
    use std::collections::BTreeMap;

    // Group entries by top-level component
    let mut roots: BTreeMap<String, Vec<BlobTreeBlake3NfcEntry>> = BTreeMap::new();
    let mut root_files: Vec<TreeEntry> = Vec::new();

    for entry in entries {
        let path = Path::new(&entry.path);
        let components: Vec<_> = path.components().collect();

        if components.len() == 1 {
            root_files.push(TreeEntry::File {
                name: entry.path.clone(),
                content: entry.content.as_bytes().to_vec(),
                executable: entry.executable.unwrap_or(false),
            });
        } else {
            let dir_name = components[0].as_os_str().to_string_lossy().to_string();
            let rest = components[1..]
                .iter()
                .collect::<PathBuf>()
                .to_string_lossy()
                .to_string();
            roots
                .entry(dir_name)
                .or_default()
                .push(BlobTreeBlake3NfcEntry {
                    path: rest,
                    content: entry.content.clone(),
                    executable: entry.executable,
                });
        }
    }

    let mut result = root_files;
    for (dir_name, children) in roots {
        result.push(TreeEntry::Directory {
            name: dir_name,
            children: entries_to_tree_entries(&children),
        });
    }
    result
}

/// Walk a directory on disk and produce `TreeEntry` values (for follow_rules conformance tests).
fn walk_dir_for_test(
    dir_path: &Path,
    exclude_names: &[String],
    follow_rules: &[String],
) -> Result<Vec<TreeEntry>> {
    use ignore::gitignore::{Gitignore, GitignoreBuilder};

    let gitignore = if follow_rules.is_empty() {
        None
    } else {
        let mut builder = GitignoreBuilder::new(dir_path);
        let mut found_any = false;
        for rule_file in follow_rules {
            let path = dir_path.join(rule_file);
            if path.exists() && builder.add(&path).is_none() {
                found_any = true;
            }
        }
        if found_any {
            builder.build().ok()
        } else {
            None
        }
    };

    fn walk_inner(
        dir_path: &Path,
        exclude_names: &[String],
        gitignore: Option<&Gitignore>,
    ) -> Result<Vec<TreeEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if exclude_names.iter().any(|ex| ex == &name) {
                continue;
            }

            if let Some(gi) = gitignore {
                let is_dir = path.is_dir();
                if gi.matched_path_or_any_parents(&path, is_dir).is_ignore() {
                    continue;
                }
            }

            if path.is_file() {
                let content = fs::read(&path)?;
                let executable = {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::metadata(&path)?.permissions().mode() & 0o111 != 0
                    }
                    #[cfg(not(unix))]
                    {
                        false
                    }
                };
                entries.push(TreeEntry::File {
                    name,
                    content,
                    executable,
                });
            } else if path.is_dir() {
                let children = walk_inner(&path, exclude_names, gitignore)?;
                entries.push(TreeEntry::Directory { name, children });
            }
        }
        Ok(entries)
    }

    walk_inner(dir_path, exclude_names, gitignore.as_ref())
}

fn build_key_rotation_capsule(case: KeyRotationCmnCase) -> CmnCapsuleEntry {
    CmnCapsuleEntry {
        uri: "cmn://example.com".to_string(),
        key: case.key,
        previous_keys: case
            .previous_keys
            .into_iter()
            .map(|previous| PreviousKey {
                key: previous.key,
                retired_at_epoch_ms: previous.retired_at_epoch_ms,
            })
            .collect(),
        endpoints: vec![],
    }
}

fn key_trust_outcome(decision: KeyTrustDecision) -> (bool, Option<KeyTrustClass>) {
    match decision {
        KeyTrustDecision::Trusted { trust_class, .. } => (true, Some(trust_class)),
        KeyTrustDecision::Untrusted { .. } => (false, None),
    }
}

fn build_bond_graph(case: &BondTraversalCase) -> Result<Vec<BondGraphNode>> {
    if let Some(graph) = &case.graph {
        return Ok(graph.clone());
    }

    let uri = case
        .spore_uri
        .clone()
        .ok_or_else(|| anyhow!("bond traversal case {} missing spore_uri", case.id))?;
    Ok(vec![BondGraphNode {
        uri,
        bonds: case.bonds.clone().unwrap_or_default(),
    }])
}

#[test]
fn conformance_signature_vectors() -> Result<()> {
    let file: VectorFile<SignatureCase> =
        load_vector_file(&conformance_dir().join("vectors/signature.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let result = verify_signature(
            case.canonical_json.as_bytes(),
            &case.signature,
            &case.public_key,
        );
        assert_eq!(
            result.is_ok(),
            case.valid,
            "signature case {} failed: result={:?}",
            case.id,
            result
        );
    }

    Ok(())
}

#[test]
fn conformance_uri_vectors() -> Result<()> {
    let file: VectorFile<UriCase> = load_vector_file(&conformance_dir().join("vectors/uri.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let result = parse_uri(&case.uri);
        if case.parse_ok {
            let parsed = result.with_context(|| format!("uri case {} should parse", case.id))?;
            let actual = normalize_uri(&parsed)?;
            let expected = case
                .normalized_uri
                .as_deref()
                .ok_or_else(|| anyhow!("uri case {} missing normalized_uri", case.id))?;
            assert_eq!(actual, expected, "uri case {} normalized mismatch", case.id);
        } else {
            let err = result
                .err()
                .ok_or_else(|| anyhow!("uri case {} should fail parse", case.id))?;
            let actual_code = map_uri_error_code(&err.to_string());
            let expected_code = case
                .error_code
                .as_deref()
                .ok_or_else(|| anyhow!("uri case {} missing error_code", case.id))?;
            assert_eq!(
                actual_code, expected_code,
                "uri case {} wrong error code (message={})",
                case.id, err
            );
        }
    }

    Ok(())
}

#[test]
fn conformance_blob_tree_blake3_nfc_vectors() -> Result<()> {
    let file: VectorFile<BlobTreeBlake3NfcCase> =
        load_vector_file(&conformance_dir().join("vectors/blob_tree_blake3_nfc.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        if let Some(conflict_message) = detect_nfc_conflict(&case.entries) {
            if case.expect_ok {
                return Err(anyhow!(
                    "blob_tree_blake3_nfc case {} expected success but has NFC conflict: {}",
                    case.id,
                    conflict_message
                ));
            } else {
                let actual_code = map_blob_tree_error_code(&conflict_message);
                let expected_code = case.error_code.as_deref().ok_or_else(|| {
                    anyhow!("blob_tree_blake3_nfc case {} missing error_code", case.id)
                })?;
                assert_eq!(
                    actual_code, expected_code,
                    "blob_tree_blake3_nfc case {} wrong error code (message={})",
                    case.id, conflict_message
                );
                continue;
            }
        }

        let result = if case.follow_rules.is_empty() {
            // Pure in-memory path: no filesystem needed
            let tree_entries = entries_to_tree_entries(&case.entries);
            substrate::compute_tree_hash_from_entries(
                &tree_entries,
                &SporeTree {
                    algorithm: "blob_tree_blake3_nfc".to_string(),
                    exclude_names: case.exclude_names.clone(),
                    follow_rules: vec![],
                },
            )
        } else {
            // follow_rules require filesystem + gitignore walk
            let temp = tempfile::tempdir()
                .with_context(|| format!("blob_tree_blake3_nfc case {} create tempdir", case.id))?;
            write_virtual_tree(temp.path(), &case.entries).with_context(|| {
                format!("blob_tree_blake3_nfc case {} write virtual tree", case.id)
            })?;
            let tree_entries =
                walk_dir_for_test(temp.path(), &case.exclude_names, &case.follow_rules)?;
            substrate::compute_tree_hash_from_entries(
                &tree_entries,
                &SporeTree {
                    algorithm: "blob_tree_blake3_nfc".to_string(),
                    exclude_names: case.exclude_names.clone(),
                    follow_rules: vec![],
                },
            )
        };
        if case.expect_ok {
            let actual = result
                .with_context(|| format!("blob_tree_blake3_nfc case {} should succeed", case.id))?;
            let expected = case.root_hash.as_deref().ok_or_else(|| {
                anyhow!("blob_tree_blake3_nfc case {} missing root_hash", case.id)
            })?;
            assert!(
                !expected.is_empty(),
                "blob_tree_blake3_nfc case {} root_hash is empty, computed={}",
                case.id,
                actual
            );
            assert_eq!(
                actual, expected,
                "blob_tree_blake3_nfc case {} hash mismatch",
                case.id
            );
        } else {
            let err = result
                .err()
                .ok_or_else(|| anyhow!("blob_tree_blake3_nfc case {} should fail", case.id))?;
            let actual_code = map_blob_tree_error_code(&err.to_string());
            let expected_code = case.error_code.as_deref().ok_or_else(|| {
                anyhow!("blob_tree_blake3_nfc case {} missing error_code", case.id)
            })?;
            assert_eq!(
                actual_code, expected_code,
                "blob_tree_blake3_nfc case {} wrong error code (message={})",
                case.id, err
            );
        }
    }

    Ok(())
}

#[test]
fn conformance_capsule_vectors() -> Result<()> {
    let file: VectorFile<CapsuleCase> =
        load_vector_file(&conformance_dir().join("vectors/capsule.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let actual_kind = classify_capsule_hosting(&case.uri_domain, &case.core_domain);
        assert_eq!(
            matches!(actual_kind, CapsuleHostingKind::Replicate),
            case.is_replicate,
            "capsule case {} hosting classification mismatch",
            case.id
        );
        assert!(
            !case.core_key.is_empty() && !case.capsule_key.is_empty(),
            "capsule case {} must provide both keys",
            case.id
        );

        let actual_valid = evaluate_signed_capsule_validity(
            case.core_signature_valid,
            case.capsule_signature_valid,
        );
        assert_eq!(
            actual_valid, case.expected_valid,
            "capsule case {} validity mismatch",
            case.id
        );

        if let Some(error_code) = case.error_code.as_deref() {
            if !case.expected_valid {
                assert_eq!(
                    error_code, "sig_failed",
                    "capsule case {} unexpected error_code",
                    case.id
                );
            }
        }
    }

    Ok(())
}

#[test]
fn conformance_key_rotation_vectors() -> Result<()> {
    let file: VectorFile<KeyRotationCase> =
        load_vector_file(&conformance_dir().join("vectors/key_rotation.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let decision = if let Some(cmn_json) = case.cmn_json {
            let capsule = build_key_rotation_capsule(cmn_json);
            let confirmation = if capsule.confirms_key(&case.content_key) {
                DomainKeyConfirmation::Confirmed
            } else {
                DomainKeyConfirmation::Rejected
            };
            decide_key_trust(confirmation, KeyTrustWitnessPolicy::Allow, false, None)
        } else if case.cmn_json_reachable == Some(false) {
            decide_key_trust(
                DomainKeyConfirmation::Unreachable,
                KeyTrustWitnessPolicy::Allow,
                false,
                case.synapse_confirms_key,
            )
        } else {
            return Err(anyhow!(
                "key rotation case {} does not describe usable evidence",
                case.id
            ));
        };

        let (actual_trusted, actual_trust_class) = key_trust_outcome(decision);
        assert_eq!(
            actual_trusted, case.expected_trusted,
            "key rotation case {} trusted mismatch",
            case.id
        );
        if let Some(expected_class) = case.expected_trust_class {
            assert_eq!(
                actual_trust_class,
                Some(expected_class),
                "key rotation case {} trust class mismatch",
                case.id
            );
        }
    }

    Ok(())
}

#[test]
fn conformance_substrate_vectors() -> Result<()> {
    let file: VectorFile<SubstrateCase> =
        load_vector_file(&conformance_dir().join("vectors/substrate.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let schema_type = validate_schema(&case.cmn)
            .with_context(|| format!("substrate case {} schema validation failed", case.id))?;
        assert_eq!(schema_type, SchemaType::Cmn);

        let entry = decode_cmn_entry(&case.cmn)
            .with_context(|| format!("substrate case {} parse failed", case.id))?;
        let capsule = entry
            .primary_capsule()
            .map_err(|err| anyhow!("substrate case {} primary capsule: {}", case.id, err))?;

        assert_eq!(
            capsule.uri, case.expected_primary_uri,
            "substrate case {} primary URI mismatch",
            case.id
        );
        assert_eq!(
            capsule.key, case.expected_primary_key,
            "substrate case {} primary key mismatch",
            case.id
        );
        assert_eq!(
            capsule.mycelium_hash().map(|s| s.to_string()),
            case.expected_mycelium_hash,
            "substrate case {} mycelium hash mismatch",
            case.id
        );

        for key in case.confirm_keys {
            assert!(
                capsule.confirms_key(&key),
                "substrate case {} should confirm key {}",
                case.id,
                key
            );
        }
        for key in case.reject_keys {
            assert!(
                !capsule.confirms_key(&key),
                "substrate case {} should reject key {}",
                case.id,
                key
            );
        }
        for version in case.supports_versions {
            assert!(
                entry.supports_protocol_version(&version),
                "substrate case {} should support protocol version {}",
                case.id,
                version
            );
        }
        for version in case.rejects_versions {
            assert!(
                !entry.supports_protocol_version(&version),
                "substrate case {} should reject protocol version {}",
                case.id,
                version
            );
        }

        if let Some(expected_url) = case.expected_mycelium_url {
            let hash = case
                .resolve_hash
                .as_deref()
                .ok_or_else(|| anyhow!("substrate case {} missing resolve_hash", case.id))?;
            assert_eq!(
                capsule.mycelium_url(hash)?,
                expected_url,
                "substrate case {} mycelium URL mismatch",
                case.id
            );
        }
        if let Some(expected_url) = case.expected_spore_url {
            let hash = case
                .resolve_hash
                .as_deref()
                .ok_or_else(|| anyhow!("substrate case {} missing resolve_hash", case.id))?;
            assert_eq!(
                capsule.spore_url(hash)?,
                expected_url,
                "substrate case {} spore URL mismatch",
                case.id
            );
        }
        if let Some(expected_url) = case.expected_archive_url {
            let hash = case
                .resolve_hash
                .as_deref()
                .ok_or_else(|| anyhow!("substrate case {} missing resolve_hash", case.id))?;
            assert_eq!(
                capsule.archive_url(hash)?,
                expected_url,
                "substrate case {} archive URL mismatch",
                case.id
            );
        }
        if let Some(expected_url) = case.expected_archive_delta_url {
            let hash = case
                .resolve_hash
                .as_deref()
                .ok_or_else(|| anyhow!("substrate case {} missing resolve_hash", case.id))?;
            let old_hash = case
                .resolve_old_hash
                .as_deref()
                .ok_or_else(|| anyhow!("substrate case {} missing resolve_old_hash", case.id))?;
            assert_eq!(
                capsule.archive_delta_url(hash, old_hash, None)?,
                Some(expected_url),
                "substrate case {} archive delta URL mismatch",
                case.id
            );
        }
        if let Some(expected_url) = case.expected_taste_url {
            let hash = case
                .resolve_hash
                .as_deref()
                .ok_or_else(|| anyhow!("substrate case {} missing resolve_hash", case.id))?;
            assert_eq!(
                capsule.taste_url(hash)?,
                expected_url,
                "substrate case {} taste URL mismatch",
                case.id
            );
        }
    }

    Ok(())
}

#[test]
fn conformance_mycelium_vectors() -> Result<()> {
    let file: VectorFile<MyceliumCase> =
        load_vector_file(&conformance_dir().join("vectors/mycelium.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let schema_type = validate_schema(&case.mycelium)
            .with_context(|| format!("mycelium case {} schema validation failed", case.id))?;
        assert_eq!(schema_type, SchemaType::Mycelium);

        let mycelium = decode_mycelium(&case.mycelium)
            .with_context(|| format!("mycelium case {} parse failed", case.id))?;

        assert_eq!(
            mycelium.uri(),
            case.expected_uri,
            "mycelium case {} URI",
            case.id
        );
        assert_eq!(
            mycelium.author_domain(),
            case.expected_domain,
            "mycelium case {} domain",
            case.id
        );
        assert_eq!(
            mycelium.timestamp_ms(),
            case.expected_timestamp_ms,
            "mycelium case {} timestamp",
            case.id
        );
        assert_eq!(
            mycelium.embedded_core_key(),
            Some(case.expected_key.as_str()),
            "mycelium case {} key",
            case.id
        );

        let actual_hashes: Vec<String> = mycelium.spore_hashes().map(str::to_string).collect();
        let actual_taste_targets: Vec<String> = mycelium
            .capsule
            .core
            .tastes
            .iter()
            .map(|taste| taste.target_uri.clone())
            .collect();
        let actual_nutrient_types: Vec<String> = mycelium
            .capsule
            .core
            .nutrients
            .iter()
            .map(|nutrient| nutrient.kind.clone())
            .collect();

        assert_eq!(
            actual_hashes, case.expected_spore_hashes,
            "mycelium case {} spore hashes mismatch",
            case.id
        );
        assert_eq!(
            actual_taste_targets, case.expected_taste_targets,
            "mycelium case {} taste targets mismatch",
            case.id
        );
        assert_eq!(
            actual_nutrient_types, case.expected_nutrient_types,
            "mycelium case {} nutrient order mismatch",
            case.id
        );
    }

    Ok(())
}

#[test]
fn conformance_spore_vectors() -> Result<()> {
    let file: VectorFile<SporeCase> =
        load_vector_file(&conformance_dir().join("vectors/spore.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let schema_type = validate_schema(&case.spore)
            .with_context(|| format!("spore case {} schema validation failed", case.id))?;
        assert_eq!(schema_type, SchemaType::Spore);

        let spore = decode_spore(&case.spore)
            .with_context(|| format!("spore case {} parse failed", case.id))?;

        assert_eq!(spore.uri(), case.expected_uri, "spore case {} URI", case.id);
        assert_eq!(
            spore.author_domain(),
            case.expected_domain,
            "spore case {} domain",
            case.id
        );
        assert_eq!(
            spore.timestamp_ms(),
            case.expected_timestamp_ms,
            "spore case {} timestamp",
            case.id
        );
        assert_eq!(
            spore.embedded_core_key(),
            Some(case.expected_key.as_str()),
            "spore case {} key",
            case.id
        );
        assert_eq!(
            spore.spawned_from_uri(),
            case.expected_spawned_from_uri.as_deref(),
            "spore case {} spawned_from URI",
            case.id
        );
        assert_eq!(
            spore.spawned_from_hash(),
            case.expected_spawned_from_hash,
            "spore case {} spawned_from hash",
            case.id
        );

        let actual_dist_types: Vec<String> = spore
            .distributions()
            .iter()
            .map(|dist| dist.kind.to_string())
            .collect();
        assert_eq!(
            actual_dist_types, case.expected_dist_types,
            "spore case {} dist types mismatch",
            case.id
        );

        let actual_followed_uris: Vec<String> = spore
            .followed_strain_uris()
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(
            actual_followed_uris, case.expected_followed_uris,
            "spore case {} followed URIs mismatch",
            case.id
        );

        let git_dist = spore.distributions().iter().find(|dist| dist.is_git());
        let actual_git_url = git_dist.and_then(|dist| dist.git_url()).map(str::to_string);
        let actual_git_ref = git_dist.and_then(|dist| dist.git_ref()).map(str::to_string);
        assert_eq!(
            actual_git_url, case.expected_git_url,
            "spore case {} git URL mismatch",
            case.id
        );
        assert_eq!(
            actual_git_ref, case.expected_git_ref,
            "spore case {} git ref mismatch",
            case.id
        );

        if case.expected_archive_url.is_some() || case.expected_archive_delta_url.is_some() {
            let cmn = case
                .cmn
                .as_ref()
                .ok_or_else(|| anyhow!("spore case {} missing cmn entry", case.id))?;
            let schema_type = validate_schema(cmn).with_context(|| {
                format!(
                    "spore case {} associated cmn schema validation failed",
                    case.id
                )
            })?;
            assert_eq!(schema_type, SchemaType::Cmn);
            let entry = decode_cmn_entry(cmn)
                .with_context(|| format!("spore case {} associated cmn parse failed", case.id))?;
            let capsule = entry
                .primary_capsule()
                .map_err(|err| anyhow!("spore case {} primary capsule: {}", case.id, err))?;
            let hash = case
                .resolve_hash
                .as_deref()
                .ok_or_else(|| anyhow!("spore case {} missing resolve_hash", case.id))?;

            if let Some(expected_url) = case.expected_archive_url {
                assert_eq!(
                    capsule.archive_url(hash)?,
                    expected_url,
                    "spore case {} archive URL mismatch",
                    case.id
                );
            }
            if let Some(expected_url) = case.expected_archive_delta_url {
                let old_hash = case
                    .resolve_old_hash
                    .as_deref()
                    .ok_or_else(|| anyhow!("spore case {} missing resolve_old_hash", case.id))?;
                assert_eq!(
                    capsule.archive_delta_url(hash, old_hash, None)?,
                    Some(expected_url),
                    "spore case {} archive delta URL mismatch",
                    case.id
                );
            }
        }
    }

    Ok(())
}

#[test]
fn conformance_strain_vectors() -> Result<()> {
    let file: VectorFile<StrainCase> =
        load_vector_file(&conformance_dir().join("vectors/strain.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let schema_type = validate_schema(&case.spore)
            .with_context(|| format!("strain case {} schema validation failed", case.id))?;
        assert_eq!(schema_type, SchemaType::Spore);

        let spore: Spore = decode_spore(&case.spore)
            .with_context(|| format!("strain case {} parse failed", case.id))?;
        let actual_extended_uris: Vec<String> = spore
            .extended_strain_uris()
            .into_iter()
            .map(str::to_string)
            .collect();
        let accepted_roots: Vec<&str> = case
            .accepted_root_lineage_uris
            .iter()
            .map(String::as_str)
            .collect();
        let required_extends: Vec<&str> =
            case.required_extends.iter().map(String::as_str).collect();

        assert_eq!(
            actual_extended_uris, case.expected_extended_uris,
            "strain case {} extended URIs mismatch",
            case.id
        );
        assert_eq!(
            spore.is_strain_definition(&accepted_roots),
            case.expected_is_strain_definition,
            "strain case {} strain-definition mismatch",
            case.id
        );
        assert_eq!(
            spore.extends_all(&required_extends),
            case.expected_extends_all,
            "strain case {} explicit extends mismatch",
            case.id
        );
    }

    Ok(())
}

#[test]
fn conformance_algorithm_registry_vectors() -> Result<()> {
    let file: VectorFile<AlgorithmRegistryCase> =
        load_vector_file(&conformance_dir().join("vectors/algorithm_registry.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        match case.kind {
            AlgorithmRegistryKind::Hash => {
                let value = case
                    .value
                    .as_deref()
                    .ok_or_else(|| anyhow!("algorithm case {} missing value", case.id))?;
                let result =
                    parse_hash(value).map(|parsed| format_hash(parsed.algorithm, &parsed.bytes));
                if case.parse_ok {
                    assert_eq!(
                        result?,
                        case.normalized_value.ok_or_else(|| anyhow!(
                            "algorithm case {} missing normalized_value",
                            case.id
                        ))?,
                        "algorithm case {} hash normalization mismatch",
                        case.id
                    );
                } else {
                    let err = result.err().ok_or_else(|| {
                        anyhow!("algorithm case {} expected hash parse failure", case.id)
                    })?;
                    assert_eq!(
                        map_algorithm_error_code(&err.to_string()),
                        case.error_code.as_deref().ok_or_else(|| anyhow!(
                            "algorithm case {} missing error_code",
                            case.id
                        ))?,
                        "algorithm case {} hash error mismatch",
                        case.id
                    );
                }
            }
            AlgorithmRegistryKind::Key => {
                let value = case
                    .value
                    .as_deref()
                    .ok_or_else(|| anyhow!("algorithm case {} missing value", case.id))?;
                let result =
                    parse_key(value).map(|parsed| format_key(parsed.algorithm, &parsed.bytes));
                if case.parse_ok {
                    assert_eq!(
                        result?,
                        case.normalized_value.ok_or_else(|| anyhow!(
                            "algorithm case {} missing normalized_value",
                            case.id
                        ))?,
                        "algorithm case {} key normalization mismatch",
                        case.id
                    );
                } else {
                    let err = result.err().ok_or_else(|| {
                        anyhow!("algorithm case {} expected key parse failure", case.id)
                    })?;
                    assert_eq!(
                        map_algorithm_error_code(&err.to_string()),
                        case.error_code.as_deref().ok_or_else(|| anyhow!(
                            "algorithm case {} missing error_code",
                            case.id
                        ))?,
                        "algorithm case {} key error mismatch",
                        case.id
                    );
                }
            }
            AlgorithmRegistryKind::Signature => {
                let value = case
                    .value
                    .as_deref()
                    .ok_or_else(|| anyhow!("algorithm case {} missing value", case.id))?;
                let result = parse_signature(value)
                    .map(|parsed| format_signature(parsed.algorithm, &parsed.bytes));
                if case.parse_ok {
                    assert_eq!(
                        result?,
                        case.normalized_value.ok_or_else(|| anyhow!(
                            "algorithm case {} missing normalized_value",
                            case.id
                        ))?,
                        "algorithm case {} signature normalization mismatch",
                        case.id
                    );
                } else {
                    let err = result.err().ok_or_else(|| {
                        anyhow!(
                            "algorithm case {} expected signature parse failure",
                            case.id
                        )
                    })?;
                    assert_eq!(
                        map_algorithm_error_code(&err.to_string()),
                        case.error_code.as_deref().ok_or_else(|| anyhow!(
                            "algorithm case {} missing error_code",
                            case.id
                        ))?,
                        "algorithm case {} signature error mismatch",
                        case.id
                    );
                }
            }
            AlgorithmRegistryKind::Tree => {
                let algorithm = case
                    .tree_algorithm
                    .as_deref()
                    .ok_or_else(|| anyhow!("algorithm case {} missing tree_algorithm", case.id))?;
                let tree_entries = vec![TreeEntry::File {
                    name: "README.md".to_string(),
                    content: b"hello\n".to_vec(),
                    executable: false,
                }];
                let result = substrate::compute_tree_hash_from_entries(
                    &tree_entries,
                    &SporeTree {
                        algorithm: algorithm.to_string(),
                        exclude_names: vec![],
                        follow_rules: vec![],
                    },
                );
                if case.parse_ok {
                    assert!(
                        result.is_ok(),
                        "algorithm case {} tree algorithm should succeed: {:?}",
                        case.id,
                        result
                    );
                } else {
                    let err = result.err().ok_or_else(|| {
                        anyhow!("algorithm case {} expected tree failure", case.id)
                    })?;
                    assert_eq!(
                        map_algorithm_error_code(&err.to_string()),
                        case.error_code.as_deref().ok_or_else(|| anyhow!(
                            "algorithm case {} missing error_code",
                            case.id
                        ))?,
                        "algorithm case {} tree error mismatch",
                        case.id
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn conformance_taste_vectors() -> Result<()> {
    let file: VectorFile<TasteCase> =
        load_vector_file(&conformance_dir().join("vectors/taste.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let actual = TasteVerdict::base_gate_action(case.verdict);
        assert_eq!(
            actual, case.expected_action,
            "taste case {} action mismatch",
            case.id
        );
    }

    Ok(())
}

#[test]
fn conformance_taste_gating_vectors() -> Result<()> {
    let file: VectorFile<TasteGatingCase> =
        load_vector_file(&conformance_dir().join("vectors/taste_gating.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let actual = TasteVerdict::gate_action_for(case.operation, case.verdict);
        assert_eq!(
            actual, case.expected_action,
            "taste gating case {} action mismatch",
            case.id
        );
    }

    Ok(())
}

#[test]
fn conformance_bond_traversal_vectors() -> Result<()> {
    let file: VectorFile<BondTraversalCase> =
        load_vector_file(&conformance_dir().join("vectors/bond_traversal.json"))?;
    assert_eq!(file.version, "cmn-conformance-v1");

    for case in file.cases {
        let graph = build_bond_graph(&case)?;
        let start = case
            .query
            .start
            .clone()
            .or_else(|| case.spore_uri.clone())
            .ok_or_else(|| anyhow!("bond traversal case {} missing start URI", case.id))?;
        let result = traverse_bond_graph(
            &graph,
            &BondTraversalQuery {
                start,
                direction: case.query.direction,
                relation: case.query.relation.clone(),
                max_depth: case.query.max_depth.unwrap_or(1),
            },
        );

        let actual_uris: Vec<String> = result.hits.iter().map(|hit| hit.uri.clone()).collect();
        if let Some(expected) = case.expected_uris {
            assert_eq!(
                actual_uris, expected,
                "bond traversal case {} ordered URIs mismatch",
                case.id
            );
        }
        if let Some(expected_unordered) = case.expected_uris_unordered {
            let mut actual_sorted = actual_uris.clone();
            let mut expected_sorted = expected_unordered.clone();
            actual_sorted.sort();
            expected_sorted.sort();
            assert_eq!(
                actual_sorted, expected_sorted,
                "bond traversal case {} unordered URIs mismatch",
                case.id
            );
        }
        if let Some(expected_depth) = case.expected_depth {
            let actual_depth = result.hits.iter().map(|hit| hit.depth).max().unwrap_or(0);
            assert_eq!(
                actual_depth, expected_depth,
                "bond traversal case {} depth mismatch",
                case.id
            );
        }
    }

    Ok(())
}
