use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SPORE_SCHEMA: &str = "https://cmn.dev/schemas/v1/spore.json";
pub const SPORE_CORE_SCHEMA: &str = "https://cmn.dev/schemas/v1/spore-core.json";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BondRelation {
    SpawnedFrom,
    AbsorbedFrom,
    DependsOn,
    Follows,
    Extends,
    Other(String),
}

impl BondRelation {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SpawnedFrom => "spawned_from",
            Self::AbsorbedFrom => "absorbed_from",
            Self::DependsOn => "depends_on",
            Self::Follows => "follows",
            Self::Extends => "extends",
            Self::Other(value) => value.as_str(),
        }
    }

    pub fn is_historical(&self) -> bool {
        matches!(self, Self::SpawnedFrom | Self::AbsorbedFrom)
    }

    pub fn participates_in_bond_updates(&self) -> bool {
        matches!(self, Self::DependsOn | Self::Follows | Self::Extends)
    }

    pub fn is_spawned_from(&self) -> bool {
        matches!(self, Self::SpawnedFrom)
    }

    pub fn is_absorbed_from(&self) -> bool {
        matches!(self, Self::AbsorbedFrom)
    }

    pub fn is_excluded_from_bond_fetch(&self) -> bool {
        self.is_spawned_from() || self.is_absorbed_from()
    }
}

impl Display for BondRelation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BondRelation {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        if value.is_empty() {
            bail!("Bond relation must not be empty");
        }

        Ok(match value {
            "spawned_from" => Self::SpawnedFrom,
            "absorbed_from" => Self::AbsorbedFrom,
            "depends_on" => Self::DependsOn,
            "follows" => Self::Follows,
            "extends" => Self::Extends,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Serialize for BondRelation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BondRelation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Full Spore manifest (content-addressed)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Spore {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub capsule: SporeCapsule,
    pub capsule_signature: String,
}

/// Spore capsule containing uri, core, core_signature, and distribution info
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SporeCapsule {
    pub uri: String,
    pub core: SporeCore,
    pub core_signature: String,
    pub dist: Vec<SporeDist>,
}

/// Core spore data (immutable, part of hash)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SporeCore {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    pub synopsis: String,
    pub intent: Vec<String>,
    pub license: String,
    #[serde(default)]
    pub mutations: Vec<String>,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub updated_at_epoch_ms: u64,
    #[serde(default)]
    pub bonds: Vec<SporeBond>,
    pub tree: SporeTree,
}

/// Tree hash configuration: algorithm, exclusions, and ignore rules
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SporeTree {
    #[serde(default = "SporeTree::default_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub exclude_names: Vec<String>,
    #[serde(default)]
    pub follow_rules: Vec<String>,
}

/// Local `spore.core.json` document used during development.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SporeCoreDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    #[serde(flatten)]
    pub core: SporeCore,
}

/// Distribution type for a spore.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DistKind {
    Archive,
    Git,
    Ipfs,
    Other(String),
}

impl DistKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Archive => "archive",
            Self::Git => "git",
            Self::Ipfs => "ipfs",
            Self::Other(value) => value.as_str(),
        }
    }
}

impl Display for DistKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DistKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        Ok(match value {
            "archive" => Self::Archive,
            "git" => Self::Git,
            "ipfs" => Self::Ipfs,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Serialize for DistKind {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DistKind {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Distribution entry in a spore manifest.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SporeDist {
    #[serde(rename = "type")]
    pub kind: DistKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl SporeDist {
    pub fn is_archive(&self) -> bool {
        self.kind == DistKind::Archive
    }

    pub fn is_git(&self) -> bool {
        self.kind == DistKind::Git
    }

    pub fn git_url(&self) -> Option<&str> {
        self.is_git().then_some(self.url.as_deref()).flatten()
    }

    pub fn git_ref(&self) -> Option<&str> {
        self.is_git().then_some(self.git_ref.as_deref()).flatten()
    }
}

impl Default for SporeTree {
    fn default() -> Self {
        Self {
            algorithm: Self::default_algorithm(),
            exclude_names: vec![],
            follow_rules: vec![],
        }
    }
}

impl SporeTree {
    fn default_algorithm() -> String {
        "blob_tree_blake3_nfc".to_string()
    }

    pub fn compute_hash(&self, entries: &[crate::tree::TreeEntry]) -> anyhow::Result<String> {
        crate::tree::compute_tree_hash_from_entries(entries, self)
    }

    pub fn compute_hash_and_size(
        &self,
        entries: &[crate::tree::TreeEntry],
    ) -> anyhow::Result<(String, u64)> {
        crate::tree::compute_tree_hash_and_size_from_entries(entries, self)
    }
}

/// Bond to another spore
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SporeBond {
    pub relation: BondRelation,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub with: Option<Value>,
}

impl SporeBond {
    /// Check if this bond matches a (relation, uri) filter pair.
    pub fn matches_filter(&self, relation: &BondRelation, uri: &str) -> bool {
        &self.relation == relation && self.uri == uri
    }
}

/// Lightweight bond projection containing only relation and URI.
///
/// Used by indexers and storage layers that don't need the full bond metadata
/// (id, reason, with). Avoids repeated manual extraction of these two fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondProjection {
    pub uri: String,
    pub relation: BondRelation,
}

impl From<&SporeBond> for BondProjection {
    fn from(bond: &SporeBond) -> Self {
        Self {
            uri: bond.uri.clone(),
            relation: bond.relation.clone(),
        }
    }
}

/// Check if all required bond filters are satisfied by the given bonds.
///
/// Each filter is a (relation, uri) pair. Returns true only if every filter
/// matches at least one bond in the slice.
pub fn bonds_match_all(bonds: &[SporeBond], filters: &[(BondRelation, String)]) -> bool {
    filters
        .iter()
        .all(|(rel, uri)| bonds.iter().any(|b| b.matches_filter(rel, uri)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BondTraversalDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondGraphNode {
    pub uri: String,
    #[serde(default)]
    pub bonds: Vec<SporeBond>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTraversalQuery {
    pub start: String,
    pub direction: BondTraversalDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<BondRelation>,
    #[serde(default = "BondTraversalQuery::default_max_depth")]
    pub max_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTraversalHit {
    pub uri: String,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTraversalResult {
    pub hits: Vec<BondTraversalHit>,
    pub max_depth_reached: bool,
}

/// Maximum allowed bond traversal depth to prevent runaway resolution.
pub const MAX_BOND_DEPTH: u32 = 64;

impl BondTraversalQuery {
    fn default_max_depth() -> u32 {
        1
    }
}

/// Result of a generic BFS traversal.
#[derive(Debug, Clone)]
pub struct BfsResult<T> {
    pub nodes: Vec<T>,
    pub max_depth_reached: bool,
}

/// Generic synchronous BFS traversal.
///
/// Starting from `start`, calls `neighbors_fn(current_id, current_depth)` to discover
/// neighbors. Each neighbor is represented as `(neighbor_id, node_data)`.
/// The `node_data` of type `T` is collected into the result.
///
/// Handles cycle detection via `HashSet` and enforces `max_depth`.
pub fn bfs_traverse<T, F>(start: &str, max_depth: u32, mut neighbors_fn: F) -> BfsResult<T>
where
    F: FnMut(&str, u32) -> Vec<(String, T)>,
{
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut results = Vec::new();
    let mut depth_reached = false;

    visited.insert(start.to_string());
    queue.push_back((start.to_string(), 0u32));

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_depth {
            depth_reached = true;
            continue;
        }
        for (neighbor_id, node_data) in neighbors_fn(&current, depth) {
            if visited.insert(neighbor_id.clone()) {
                results.push(node_data);
                queue.push_back((neighbor_id, depth + 1));
            }
        }
    }

    BfsResult {
        nodes: results,
        max_depth_reached: depth_reached,
    }
}

pub fn traverse_bond_graph(
    graph: &[BondGraphNode],
    query: &BondTraversalQuery,
) -> BondTraversalResult {
    let mut graph_by_uri = HashMap::with_capacity(graph.len());
    for node in graph {
        graph_by_uri.insert(node.uri.as_str(), node);
    }

    let mut hits = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut max_depth_reached = false;

    visited.insert(query.start.clone());
    queue.push_back((query.start.as_str(), 0_u32));

    while let Some((current_uri, depth)) = queue.pop_front() {
        let next_edges: Vec<(&str, &BondRelation)> = match query.direction {
            BondTraversalDirection::Outbound => graph_by_uri
                .get(current_uri)
                .into_iter()
                .flat_map(|node| node.bonds.iter())
                .filter(|bond| {
                    query
                        .relation
                        .as_ref()
                        .map(|relation| bond.relation == *relation)
                        .unwrap_or(true)
                })
                .map(|bond| (bond.uri.as_str(), &bond.relation))
                .collect(),
            BondTraversalDirection::Inbound => graph
                .iter()
                .flat_map(|node| {
                    node.bonds
                        .iter()
                        .filter(move |bond| bond.uri == current_uri)
                        .map(move |bond| (node.uri.as_str(), &bond.relation))
                })
                .filter(|(_, relation)| {
                    query
                        .relation
                        .as_ref()
                        .map(|expected| *relation == expected)
                        .unwrap_or(true)
                })
                .collect(),
        };

        for (next_uri, _) in next_edges {
            let next_depth = depth.saturating_add(1);
            if next_depth > query.max_depth {
                max_depth_reached = true;
                continue;
            }
            if !visited.insert(next_uri.to_string()) {
                continue;
            }

            hits.push(BondTraversalHit {
                uri: next_uri.to_string(),
                depth: next_depth,
            });
            queue.push_back((next_uri, next_depth));
        }
    }

    BondTraversalResult {
        hits,
        max_depth_reached,
    }
}

impl Spore {
    /// Create a new spore (unsigned, uri placeholder)
    pub fn new(
        domain: &str,
        name: &str,
        synopsis: &str,
        intent: Vec<String>,
        license: &str,
    ) -> Self {
        Self {
            schema: SPORE_SCHEMA.to_string(),
            capsule: SporeCapsule {
                uri: String::new(),
                core: SporeCore {
                    id: String::new(),
                    version: String::new(),
                    name: name.to_string(),
                    domain: domain.to_string(),
                    key: String::new(),
                    synopsis: synopsis.to_string(),
                    intent,
                    license: license.to_string(),
                    mutations: vec![],
                    size_bytes: 0,
                    bonds: vec![],
                    tree: SporeTree::default(),
                    updated_at_epoch_ms: 0,
                },
                core_signature: String::new(),
                dist: vec![],
            },
            capsule_signature: String::new(),
        }
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

    /// Returns the effective author key: the embedded `core.key` if present,
    /// otherwise falls back to the given host key.
    pub fn effective_author_key<'a>(&'a self, host_key: &'a str) -> &'a str {
        self.embedded_core_key().unwrap_or(host_key)
    }

    /// Extract lightweight bond projections from this spore's bonds.
    pub fn extract_bonds(&self) -> Vec<BondProjection> {
        self.capsule
            .core
            .bonds
            .iter()
            .map(BondProjection::from)
            .collect()
    }

    pub fn tree(&self) -> &SporeTree {
        &self.capsule.core.tree
    }

    pub fn distributions(&self) -> &[SporeDist] {
        &self.capsule.dist
    }

    pub fn followed_strain_uris(&self) -> Vec<&str> {
        self.capsule
            .core
            .bonds
            .iter()
            .filter(|bond| bond.relation == BondRelation::Follows)
            .map(|bond| bond.uri.as_str())
            .collect()
    }

    pub fn follows_uri(&self, uri: &str) -> bool {
        self.capsule
            .core
            .bonds
            .iter()
            .any(|bond| bond.relation == BondRelation::Follows && bond.uri == uri)
    }

    pub fn follows_all(&self, required_uris: &[&str]) -> bool {
        required_uris.iter().all(|uri| self.follows_uri(uri))
    }

    pub fn extended_strain_uris(&self) -> Vec<&str> {
        self.capsule
            .core
            .bonds
            .iter()
            .filter(|bond| bond.relation == BondRelation::Extends)
            .map(|bond| bond.uri.as_str())
            .collect()
    }

    pub fn extends_uri(&self, uri: &str) -> bool {
        self.capsule
            .core
            .bonds
            .iter()
            .any(|bond| bond.relation == BondRelation::Extends && bond.uri == uri)
    }

    pub fn extends_all(&self, required_uris: &[&str]) -> bool {
        required_uris.iter().all(|uri| self.extends_uri(uri))
    }

    pub fn is_strain_definition(&self, accepted_root_lineage_uris: &[&str]) -> bool {
        accepted_root_lineage_uris
            .iter()
            .any(|uri| self.extends_uri(uri))
    }

    pub fn spawned_from_uri(&self) -> Option<&str> {
        self.capsule
            .core
            .bonds
            .iter()
            .find(|bond| bond.relation.is_spawned_from())
            .map(|bond| bond.uri.as_str())
    }

    pub fn spawned_from_hash(&self) -> Option<String> {
        crate::uri::parse_uri(self.spawned_from_uri()?)
            .ok()
            .and_then(|uri| uri.hash)
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

    /// Verify both signatures using the same key (self-hosted case where host == author).
    pub fn verify_self_hosted_signatures(&self, key: &str) -> Result<()> {
        self.verify_signatures(key, key)
    }

    pub fn computed_uri_hash_from_tree_hash(&self, tree_hash: &str) -> Result<String> {
        crate::crypto::hash::compute_tree_signed_core_hash(
            tree_hash,
            &self.capsule.core,
            &self.capsule.core_signature,
        )
    }

    pub fn verify_uri_hash_from_tree_hash(
        &self,
        expected_hash: &str,
        tree_hash: &str,
    ) -> Result<()> {
        let actual_hash = self.computed_uri_hash_from_tree_hash(tree_hash)?;
        super::verify_expected_uri_hash(&actual_hash, expected_hash)
    }

    pub fn verify_content_hash(
        &self,
        entries: &[crate::tree::TreeEntry],
        expected_hash: &str,
    ) -> Result<()> {
        let tree_hash = self.tree().compute_hash(entries)?;
        self.verify_uri_hash_from_tree_hash(expected_hash, &tree_hash)
    }

    /// Verify content hash and size_bytes match the manifest.
    /// Returns an error if hash or size mismatch.
    pub fn verify_content_hash_and_size(
        &self,
        entries: &[crate::tree::TreeEntry],
        expected_hash: &str,
    ) -> Result<()> {
        let (tree_hash, computed_size) = self.tree().compute_hash_and_size(entries)?;
        self.verify_uri_hash_from_tree_hash(expected_hash, &tree_hash)?;
        let declared = self.capsule.core.size_bytes;
        if declared > 0 && computed_size != declared {
            return Err(anyhow!(
                "size_bytes mismatch: declared {} but computed {}",
                declared,
                computed_size
            ));
        }
        Ok(())
    }
}

impl SporeCoreDocument {
    pub fn into_core(self) -> SporeCore {
        self.core
    }

    pub fn core(&self) -> &SporeCore {
        &self.core
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;
    #[test]
    fn test_spore_bond() {
        let reference = SporeBond {
            uri: "cmn://other.com/b3.def456".to_string(),
            relation: BondRelation::DependsOn,
            id: None,
            reason: None,
            with: None,
        };

        let json = serde_json::to_string(&reference).unwrap_or_default();
        assert!(json.contains("\"uri\""));
        assert!(json.contains("\"relation\""));
        assert!(json.contains("depends_on"));
    }

    #[test]
    fn test_spore_new() {
        let spore = Spore::new(
            "example.com",
            "my-tool",
            "A useful tool",
            vec!["Initial release".to_string()],
            "MIT",
        );
        assert_eq!(spore.schema, SPORE_SCHEMA);
        assert_eq!(spore.capsule.core.name, "my-tool");
        assert_eq!(spore.capsule.core.domain, "example.com");
        assert_eq!(spore.capsule.core.synopsis, "A useful tool");
        assert_eq!(spore.capsule.core.license, "MIT");
    }

    #[test]
    fn test_spore_with_bonds() {
        let mut spore = Spore::new(
            "example.com",
            "child-spore",
            "A child spore",
            vec!["v1.0".to_string()],
            "MIT",
        );
        spore.capsule.core.bonds = vec![
            SporeBond {
                uri: "cmn://parent.com/b3.parent1".to_string(),
                relation: BondRelation::SpawnedFrom,
                id: None,
                reason: None,
                with: None,
            },
            SporeBond {
                uri: "cmn://lib.com/b3.lib1".to_string(),
                relation: BondRelation::DependsOn,
                id: None,
                reason: None,
                with: None,
            },
        ];
        spore.capsule.core_signature = "ed25519.abc".to_string();
        spore.capsule_signature = "ed25519.def".to_string();
        spore.capsule.uri = "cmn://example.com/b3.abc123".to_string();

        let json = serde_json::to_string_pretty(&spore).unwrap_or_default();
        assert!(json.contains("\"bonds\""));
        assert!(json.contains("spawned_from"));
        assert!(json.contains("parent.com"));

        let parsed: Spore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capsule.core.bonds.len(), 2);
        assert_eq!(
            parsed.capsule.core.bonds[0].relation,
            BondRelation::SpawnedFrom
        );
        assert_eq!(
            parsed.capsule.core.bonds[1].relation,
            BondRelation::DependsOn
        );
    }

    #[test]
    fn test_spore_tree() {
        let tree = SporeTree {
            algorithm: "blob_tree_blake3_nfc".to_string(),
            exclude_names: vec!["node_modules".to_string(), ".git".to_string()],
            follow_rules: vec![".gitignore".to_string()],
        };

        let json = serde_json::to_string(&tree).unwrap_or_default();
        assert!(json.contains("blob_tree_blake3_nfc"));
        assert!(json.contains("node_modules"));
        assert!(json.contains(".gitignore"));

        let parsed: SporeTree = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.algorithm, "blob_tree_blake3_nfc");
        assert_eq!(parsed.exclude_names.len(), 2);
        assert_eq!(parsed.follow_rules.len(), 1);
    }

    #[test]
    fn test_spore_strain_helpers() {
        let mut spore = Spore::new(
            "example.com",
            "strain-child",
            "A strain child",
            vec!["Initial release".to_string()],
            "MIT",
        );
        spore.capsule.core.bonds = vec![
            SporeBond {
                uri: "cmn://service.dev/b3.service".to_string(),
                relation: BondRelation::Follows,
                id: None,
                reason: None,
                with: None,
            },
            SporeBond {
                uri: "cmn://root.dev/b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2".to_string(),
                relation: BondRelation::Extends,
                id: None,
                reason: None,
                with: None,
            },
            SporeBond {
                uri: "cmn://parent.dev/b3.BMjugPDk6SFJiCLvTTWJtbD6LxSmhw6KBbXQh7Lixv5W".to_string(),
                relation: BondRelation::Extends,
                id: None,
                reason: None,
                with: None,
            },
        ];

        assert_eq!(
            spore.followed_strain_uris(),
            vec!["cmn://service.dev/b3.service"]
        );
        assert!(spore.follows_uri("cmn://service.dev/b3.service"));
        assert!(spore.follows_all(&["cmn://service.dev/b3.service"]));
        assert_eq!(
            spore.extended_strain_uris(),
            vec![
                "cmn://root.dev/b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2",
                "cmn://parent.dev/b3.BMjugPDk6SFJiCLvTTWJtbD6LxSmhw6KBbXQh7Lixv5W"
            ]
        );
        assert!(
            spore.extends_uri("cmn://parent.dev/b3.BMjugPDk6SFJiCLvTTWJtbD6LxSmhw6KBbXQh7Lixv5W")
        );
        assert!(spore.extends_all(&[
            "cmn://root.dev/b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2",
            "cmn://parent.dev/b3.BMjugPDk6SFJiCLvTTWJtbD6LxSmhw6KBbXQh7Lixv5W"
        ]));
        assert!(spore
            .is_strain_definition(&["cmn://root.dev/b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2"]));
        assert!(!spore.is_strain_definition(&[
            "cmn://other-root.dev/b3.Bp7WKXh4Rxx2jyu5taj2aeMorH5YLT4R8DF5rWq7jZjq"
        ]));
    }

    #[test]
    fn test_traverse_bond_graph_outbound() {
        let graph = vec![
            BondGraphNode {
                uri: "cmn://a.dev/b3.parent".to_string(),
                bonds: vec![],
            },
            BondGraphNode {
                uri: "cmn://b.dev/b3.child".to_string(),
                bonds: vec![SporeBond {
                    uri: "cmn://a.dev/b3.parent".to_string(),
                    relation: BondRelation::SpawnedFrom,
                    id: None,
                    reason: None,
                    with: None,
                }],
            },
        ];

        let result = traverse_bond_graph(
            &graph,
            &BondTraversalQuery {
                start: "cmn://b.dev/b3.child".to_string(),
                direction: BondTraversalDirection::Outbound,
                relation: Some(BondRelation::SpawnedFrom),
                max_depth: 1,
            },
        );

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].uri, "cmn://a.dev/b3.parent");
        assert_eq!(result.hits[0].depth, 1);
    }

    #[test]
    fn test_traverse_bond_graph_cycle() {
        let graph = vec![
            BondGraphNode {
                uri: "cmn://a.dev/b3.alpha".to_string(),
                bonds: vec![SporeBond {
                    uri: "cmn://b.dev/b3.beta".to_string(),
                    relation: BondRelation::DependsOn,
                    id: None,
                    reason: None,
                    with: None,
                }],
            },
            BondGraphNode {
                uri: "cmn://b.dev/b3.beta".to_string(),
                bonds: vec![SporeBond {
                    uri: "cmn://a.dev/b3.alpha".to_string(),
                    relation: BondRelation::DependsOn,
                    id: None,
                    reason: None,
                    with: None,
                }],
            },
        ];

        let result = traverse_bond_graph(
            &graph,
            &BondTraversalQuery {
                start: "cmn://a.dev/b3.alpha".to_string(),
                direction: BondTraversalDirection::Outbound,
                relation: Some(BondRelation::DependsOn),
                max_depth: 10,
            },
        );

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].uri, "cmn://b.dev/b3.beta");
    }
}
