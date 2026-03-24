use anyhow::{anyhow, Result};

use super::{json_from_response, FetchOptions};
use crate::{cmn_entry_url, validate_schema, CmnCapsuleEntry, CmnEntry, SchemaType};

/// Fetch and validate cmn.json from a domain.
pub async fn fetch_cmn_entry(
    client: &reqwest::Client,
    domain: &str,
    opts: FetchOptions,
) -> Result<CmnEntry> {
    let url = cmn_entry_url(domain);
    let response = client.get(&url).send().await?;
    if response.status().as_u16() == 404 {
        return Err(anyhow!(
            "{domain} does not publish CMN manifest ({url} returned 404)"
        ));
    }
    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch {url}: HTTP {}", response.status()));
    }
    let payload: serde_json::Value = json_from_response(response, &url, opts.max_bytes).await?;
    let schema_type = validate_schema(&payload)?;
    if schema_type != SchemaType::Cmn {
        return Err(anyhow!(
            "Invalid document type from {domain}: expected cmn.json, got {schema_type:?}"
        ));
    }
    let entry: CmnEntry = serde_json::from_value(payload)?;
    entry.primary_capsule()?; // validate structure
    Ok(entry)
}

/// Fetch a mycelium manifest JSON from a capsule's endpoint.
pub async fn fetch_mycelium_manifest(
    client: &reqwest::Client,
    capsule: &CmnCapsuleEntry,
    hash: &str,
    opts: FetchOptions,
) -> Result<serde_json::Value> {
    let url = capsule.mycelium_url(hash)?;
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch {url}: HTTP {}", response.status()));
    }
    json_from_response(response, &url, opts.max_bytes).await
}

/// Fetch the primary mycelium manifest and any overflow shards, merging spore lists.
///
/// The primary `hash` field carries authoritative domain metadata (name, bio, nutrients)
/// and featured spores. The optional `hashes` array contains overflow shards whose
/// spore lists are merged for search/indexing — metadata from overflow shards is ignored.
pub async fn fetch_mycelium(
    client: &reqwest::Client,
    capsule: &CmnCapsuleEntry,
    opts: FetchOptions,
) -> Result<serde_json::Value> {
    let primary_hash = capsule
        .mycelium_hash()
        .ok_or_else(|| anyhow!("No mycelium hash in endpoint"))?;

    let mut manifest = fetch_mycelium_manifest(client, capsule, primary_hash, opts.clone()).await?;

    for hash in capsule.mycelium_hashes() {
        let shard = fetch_mycelium_manifest(client, capsule, hash, opts.clone()).await?;
        merge_mycelium_spores(&mut manifest, &shard);
    }

    Ok(manifest)
}

/// Merge spore entries from a shard into the base mycelium manifest.
pub fn merge_mycelium_spores(base: &mut serde_json::Value, shard: &serde_json::Value) {
    if let (Some(base_spores), Some(shard_spores)) = (
        base.pointer_mut("/capsule/core/spores")
            .and_then(serde_json::Value::as_array_mut),
        shard
            .pointer("/capsule/core/spores")
            .and_then(serde_json::Value::as_array),
    ) {
        base_spores.extend(shard_spores.iter().cloned());
    }
}

/// Fetch a taste document JSON from a capsule's endpoint.
pub async fn fetch_taste(
    client: &reqwest::Client,
    capsule: &CmnCapsuleEntry,
    hash: &str,
    opts: FetchOptions,
) -> Result<serde_json::Value> {
    let url = capsule.taste_url(hash)?;
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch {url}: HTTP {}", response.status()));
    }
    json_from_response(response, &url, opts.max_bytes).await
}

/// Fetch a spore manifest JSON from a capsule's endpoint.
pub async fn fetch_spore_manifest(
    client: &reqwest::Client,
    capsule: &CmnCapsuleEntry,
    hash: &str,
    opts: FetchOptions,
) -> Result<serde_json::Value> {
    let url = capsule.spore_url(hash)?;
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("Failed to fetch {url}: HTTP {}", response.status()));
    }
    json_from_response(response, &url, opts.max_bytes).await
}
