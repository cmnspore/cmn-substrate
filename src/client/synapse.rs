use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::{apply_headers, json_from_response, FetchOptions};
use crate::BondRelation;

/// Synapse search response (Agent-First Data envelope).
#[derive(Debug, Deserialize)]
pub struct SearchResponse {
    pub code: String,
    pub result: SearchResult,
}

#[derive(Debug, Deserialize)]
pub struct SearchResult {
    pub query: SearchResponseQuery,
    pub spores: Vec<SearchResultItem>,
}

#[derive(Debug, Deserialize)]
pub struct SearchResponseQuery {
    pub text: String,
    pub domain: Option<String>,
    pub license: Option<String>,
    pub limit: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SearchResultItem {
    pub uri: String,
    pub domain: String,
    pub name: String,
    pub synopsis: String,
    pub license: String,
    pub intent: Vec<String>,
    pub relevance: f32,
}

/// Synapse bonds response (Agent-First Data envelope).
#[derive(Debug, Deserialize)]
pub struct BondsResponse {
    pub code: String,
    pub result: BondsResult,
    #[serde(default)]
    pub trace: Option<BondsTrace>,
}

#[derive(Debug, Deserialize)]
pub struct BondsResult {
    pub query: BondsQuery,
    pub bonds: Vec<BondNode>,
}

#[derive(Debug, Deserialize)]
pub struct BondsQuery {
    pub hash: String,
    pub max_depth: u32,
}

#[derive(Debug, Deserialize)]
pub struct BondsTrace {
    #[serde(default)]
    pub max_depth_reached: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BondNode {
    pub uri: String,
    pub domain: String,
    pub name: String,
    pub synopsis: String,
    pub license: String,
    pub intent: Vec<String>,
    pub relation: BondRelation,
}

/// Synapse key response.
#[derive(Debug, Deserialize)]
pub struct SynapseKeyResponse {
    pub key: String,
}

/// Synapse spore response (GET /synapse/spore/{hash}).
#[derive(Debug, Deserialize)]
pub struct SynapseSporeResponse {
    pub code: String,
    pub result: SynapseSporeResult,
}

#[derive(Debug, Deserialize)]
pub struct SynapseSporeResult {
    pub query: SynapseSporeQuery,
    pub spore: serde_json::Value,
    #[serde(default)]
    pub replicates: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SynapseSporeQuery {
    pub hash: String,
}

/// Synapse mycelium response (GET /synapse/mycelium/{domain}).
#[derive(Debug, Deserialize)]
pub struct SynapseMyceliumResponse {
    pub code: String,
    pub result: SynapseMyceliumResult,
}

#[derive(Debug, Deserialize)]
pub struct SynapseMyceliumResult {
    pub query: SynapseMyceliumQuery,
    pub mycelium: serde_json::Value,
    #[serde(default)]
    pub replicates: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SynapseMyceliumQuery {
    pub domain: String,
}

/// Search spores via a synapse instance.
#[allow(clippy::too_many_arguments)]
pub async fn search(
    client: &reqwest::Client,
    synapse_url: &str,
    query: &str,
    domain: Option<&str>,
    license: Option<&str>,
    bond_filter: Option<&str>,
    limit: u32,
    opts: FetchOptions,
) -> Result<SearchResponse> {
    let mut url = reqwest::Url::parse(&format!(
        "{}/synapse/search",
        synapse_url.trim_end_matches('/')
    ))
    .map_err(|e| anyhow!("Invalid synapse URL: {e}"))?;

    url.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("limit", &limit.to_string());
    if let Some(d) = domain {
        url.query_pairs_mut().append_pair("domain", d);
    }
    if let Some(l) = license {
        url.query_pairs_mut().append_pair("license", l);
    }
    if let Some(r) = bond_filter {
        url.query_pairs_mut().append_pair("bonds", r);
    }

    let req = apply_headers(client.get(url.as_str()), &opts);
    let response = req.send().await?;

    if response.status().as_u16() == 503 {
        return Err(anyhow!(
            "Search engine not configured on this synapse instance"
        ));
    }
    if !response.status().is_success() {
        return Err(anyhow!("Synapse returned HTTP {}", response.status()));
    }

    json_from_response(response, url.as_str(), opts.max_bytes).await
}

/// Fetch bond lineage from synapse.
pub async fn fetch_lineage(
    client: &reqwest::Client,
    synapse_url: &str,
    hash: &str,
    direction: &str,
    max_depth: u32,
    opts: FetchOptions,
) -> Result<BondsResponse> {
    let url = format!(
        "{}/synapse/spore/{}/bonds?direction={}&max_depth={}",
        synapse_url.trim_end_matches('/'),
        hash,
        direction,
        max_depth
    );

    let req = apply_headers(client.get(&url), &opts);
    let response = req.send().await?;

    if response.status().as_u16() == 404 {
        return Err(anyhow!("Spore not found in synapse index"));
    }
    if !response.status().is_success() {
        return Err(anyhow!("Synapse returned HTTP {}", response.status()));
    }

    json_from_response(response, &url, opts.max_bytes).await
}

/// Fetch taste reports for a spore from synapse.
pub async fn fetch_taste_reports(
    client: &reqwest::Client,
    synapse_url: &str,
    hash: &str,
    opts: FetchOptions,
) -> Result<serde_json::Value> {
    let url = format!(
        "{}/synapse/spore/{}/tastes",
        synapse_url.trim_end_matches('/'),
        hash
    );

    let req = apply_headers(client.get(&url), &opts);
    let response = req.send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("Synapse returned HTTP {}", response.status()));
    }

    json_from_response(response, &url, opts.max_bytes).await
}

/// Fetch the public key a synapse has recorded for a domain.
///
/// GET /synapse/key/{domain} → { "key": "ed25519.xxx" }
pub async fn fetch_synapse_key(
    client: &reqwest::Client,
    synapse_url: &str,
    domain: &str,
    opts: FetchOptions,
) -> Result<SynapseKeyResponse> {
    let url = format!(
        "{}/synapse/key/{}",
        synapse_url.trim_end_matches('/'),
        domain
    );

    let req = apply_headers(client.get(&url), &opts);
    let response = req.send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("Synapse returned HTTP {}", response.status()));
    }

    json_from_response(response, &url, opts.max_bytes).await
}

/// Fetch a spore manifest from synapse.
///
/// GET /synapse/spore/{hash} → SynapseSporeResponse
pub async fn fetch_synapse_spore(
    client: &reqwest::Client,
    synapse_url: &str,
    hash: &str,
    opts: FetchOptions,
) -> Result<SynapseSporeResponse> {
    let url = format!(
        "{}/synapse/spore/{}",
        synapse_url.trim_end_matches('/'),
        hash
    );

    let req = apply_headers(client.get(&url), &opts);
    let response = req.send().await?;

    if response.status().as_u16() == 404 {
        return Err(anyhow!("Spore not found in synapse"));
    }
    if !response.status().is_success() {
        return Err(anyhow!("Synapse returned HTTP {}", response.status()));
    }

    json_from_response(response, &url, opts.max_bytes).await
}

/// Fetch a mycelium manifest from synapse.
///
/// GET /synapse/mycelium/{domain} → SynapseMyceliumResponse
pub async fn fetch_synapse_mycelium(
    client: &reqwest::Client,
    synapse_url: &str,
    domain: &str,
    opts: FetchOptions,
) -> Result<SynapseMyceliumResponse> {
    let url = format!(
        "{}/synapse/mycelium/{}",
        synapse_url.trim_end_matches('/'),
        domain
    );

    let req = apply_headers(client.get(&url), &opts);
    let response = req.send().await?;

    if response.status().as_u16() == 404 {
        return Err(anyhow!(
            "Mycelium not found in synapse for domain {}",
            domain
        ));
    }
    if !response.status().is_success() {
        return Err(anyhow!("Synapse returned HTTP {}", response.status()));
    }

    json_from_response(response, &url, opts.max_bytes).await
}

/// Post a document (spore, mycelium, taste) to a synapse pulse endpoint.
///
/// POST /synapse/pulse with JSON body.
pub async fn post_synapse_pulse(
    client: &reqwest::Client,
    synapse_url: &str,
    payload: &serde_json::Value,
    opts: FetchOptions,
) -> Result<()> {
    let url = format!("{}/synapse/pulse", synapse_url.trim_end_matches('/'));

    let req = apply_headers(client.post(&url).json(payload), &opts);
    let response = req.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Synapse returned HTTP {status}: {body}"));
    }

    Ok(())
}
