//! CMN protocol HTTP client — fetch domains, spores, synapse APIs.
//! Requires the `client` feature. WASM-compatible.

mod domain;
mod synapse;

pub use domain::{
    fetch_cmn_entry, fetch_mycelium, fetch_mycelium_manifest, fetch_spore_manifest, fetch_taste,
    merge_mycelium_spores,
};
pub use synapse::{
    fetch_lineage, fetch_synapse_cmn, fetch_synapse_mycelium_by_hash, fetch_synapse_spore,
    fetch_synapse_taste, fetch_taste_reports, post_synapse_pulse, search, BondNode, BondsQuery,
    BondsResponse, BondsResult, BondsTrace, SearchResponse, SearchResponseQuery, SearchResult,
    SearchResultItem, SynapseCmnQuery, SynapseCmnResponse, SynapseCmnResult,
    SynapseMyceliumByHashQuery, SynapseMyceliumByHashResponse, SynapseMyceliumByHashResult,
    SynapseSporeQuery, SynapseSporeResponse, SynapseSporeResult, SynapseTasteQuery,
    SynapseTasteResponse, SynapseTasteResult,
};

use anyhow::{anyhow, Result};
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;

/// Default response body limit for JSON/text client reads (64 MiB).
pub const DEFAULT_FETCH_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Options for controlling fetch behaviour.
///
/// Use `Default::default()` (or `FetchOptions::new()`) for the default 64 MiB
/// response limit with no extra headers, or build with `with_max_bytes` /
/// `with_bearer_token` / `headers`. Use `FetchOptions::unlimited()` only
/// when the caller has an explicit external size bound.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Maximum response body bytes. `None` means no limit (uses reqwest `.json()`).
    pub max_bytes: Option<usize>,
    /// Extra headers to attach to the request.
    pub headers: Option<reqwest::header::HeaderMap>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_bytes: Some(DEFAULT_FETCH_MAX_BYTES),
            headers: None,
        }
    }
}

impl FetchOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn unlimited() -> Self {
        Self {
            max_bytes: None,
            ..Default::default()
        }
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes: Some(max_bytes),
            ..Default::default()
        }
    }

    /// Convenience: set a Bearer token (adds Authorization header).
    pub fn with_bearer_token(token: &str) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(val) = format!("Bearer {token}").parse() {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
        Self {
            headers: Some(headers),
            ..Default::default()
        }
    }

    /// Merge additional headers into this FetchOptions.
    pub fn headers(mut self, extra: reqwest::header::HeaderMap) -> Self {
        match &mut self.headers {
            Some(existing) => existing.extend(extra),
            None => self.headers = Some(extra),
        }
        self
    }

    /// Set max_bytes on an existing FetchOptions (builder style).
    pub fn max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = Some(max);
        self
    }
}

/// Apply FetchOptions headers to a request builder.
pub(crate) fn apply_headers(
    mut req: reqwest::RequestBuilder,
    opts: &FetchOptions,
) -> reqwest::RequestBuilder {
    if let Some(ref headers) = opts.headers {
        for (key, value) in headers {
            req = req.header(key, value);
        }
    }
    req
}

/// Read a response body with a strict byte limit, then deserialize as JSON.
///
/// If `max_bytes` is `None`, falls back to reqwest's `.json()`.
pub async fn json_from_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    source: &str,
    max_bytes: Option<usize>,
) -> Result<T> {
    let bytes = match max_bytes {
        None => response
            .bytes()
            .await
            .map_err(|e| anyhow!("Failed to read JSON body from {source}: {e}"))?
            .to_vec(),
        Some(limit) => read_body_limited(response, source, limit).await?,
    };
    json_from_slice_reject_duplicates(&bytes, source)
}

/// Deserialize JSON while rejecting duplicate object keys.
///
/// `serde_json` keeps the last duplicate key by default. For signed protocol
/// objects that creates parser-differential risk, so client fetch boundaries
/// fail closed before typed deserialization.
pub fn json_from_slice_reject_duplicates<T: DeserializeOwned>(
    bytes: &[u8],
    source: &str,
) -> Result<T> {
    reject_duplicate_json_keys(bytes, source)?;
    serde_json::from_slice(bytes).map_err(|e| anyhow!("Failed to parse JSON from {source}: {e}"))
}

fn reject_duplicate_json_keys(bytes: &[u8], source: &str) -> Result<()> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    NoDuplicateKeys::deserialize(&mut de)
        .map_err(|e| anyhow!("Duplicate-key-safe JSON parse failed from {source}: {e}"))?;
    de.end()
        .map_err(|e| anyhow!("Failed to parse JSON from {source}: {e}"))
}

struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _v: bool) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _v: i64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _v: u64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _v: f64) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _v: &str) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_string<E>(self, _v: String) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateKeys::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object key '{key}'"
                )));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

/// Read a response body as UTF-8 text with an optional byte limit.
///
/// If `max_bytes` is `None`, falls back to reqwest's `.text()`.
pub async fn text_from_response(
    response: reqwest::Response,
    source: &str,
    max_bytes: Option<usize>,
) -> Result<String> {
    match max_bytes {
        None => response
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read text from {source}: {e}")),
        Some(limit) => {
            let bytes = read_body_limited(response, source, limit).await?;
            String::from_utf8(bytes)
                .map_err(|e| anyhow!("Response was not UTF-8 from {source}: {e}"))
        }
    }
}

/// Stream a response body into a writer with a strict byte limit.
///
/// Calls `on_progress(downloaded_bytes, total_bytes)` before reading starts and
/// after each chunk is written. Returns the total bytes written.
pub async fn download_response_to_writer<W, F>(
    response: reqwest::Response,
    source: &str,
    max_bytes: u64,
    mut writer: W,
    mut on_progress: F,
) -> Result<u64>
where
    W: std::io::Write,
    F: FnMut(u64, Option<u64>),
{
    let total_bytes = response.content_length();
    if let Some(cl) = total_bytes {
        if cl > max_bytes {
            return Err(anyhow!(
                "Remote payload too large from {source}: {cl} bytes exceeds limit {max_bytes}"
            ));
        }
    }

    on_progress(0, total_bytes);

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut response = response;
        let mut downloaded: u64 = 0;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| anyhow!("Failed reading response body from {source}: {e}"))?
        {
            downloaded = downloaded.saturating_add(chunk.len() as u64);
            if downloaded > max_bytes {
                return Err(anyhow!(
                    "Remote payload exceeded limit from {source}: >{max_bytes} bytes"
                ));
            }
            writer
                .write_all(&chunk)
                .map_err(|e| anyhow!("Failed writing response body for {source}: {e}"))?;
            on_progress(downloaded, total_bytes);
        }
        writer
            .flush()
            .map_err(|e| anyhow!("Failed flushing response body for {source}: {e}"))?;
        Ok(downloaded)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow!("Failed reading response body from {source}: {e}"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(anyhow!(
                "Remote payload exceeded limit from {source}: {} bytes exceeds limit {max_bytes}",
                bytes.len()
            ));
        }
        writer
            .write_all(&bytes)
            .map_err(|e| anyhow!("Failed writing response body for {source}: {e}"))?;
        writer
            .flush()
            .map_err(|e| anyhow!("Failed flushing response body for {source}: {e}"))?;
        on_progress(bytes.len() as u64, total_bytes);
        Ok(bytes.len() as u64)
    }
}

/// Read a response body with a strict byte limit.
///
/// On native targets, reads chunk-by-chunk for early abort on oversized payloads.
/// On WASM, falls back to full-body read then size check (streaming not available).
async fn read_body_limited(
    response: reqwest::Response,
    source: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if let Some(cl) = response.content_length() {
        if cl > max_bytes as u64 {
            return Err(anyhow!(
                "Remote payload too large from {source}: {cl} bytes exceeds limit {max_bytes}"
            ));
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut response = response;
        let mut out = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| anyhow!("Failed reading response body from {source}: {e}"))?
        {
            if out.len().saturating_add(chunk.len()) > max_bytes {
                return Err(anyhow!(
                    "Remote payload exceeded limit from {source}: >{max_bytes} bytes"
                ));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    #[cfg(target_arch = "wasm32")]
    {
        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow!("Failed reading response body from {source}: {e}"))?;
        if bytes.len() > max_bytes {
            return Err(anyhow!(
                "Remote payload exceeded limit from {source}: {} bytes exceeds limit {max_bytes}",
                bytes.len()
            ));
        }
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn json_from_slice_rejects_duplicate_keys() {
        let err = json_from_slice_reject_duplicates::<Value>(
            br#"{"capsule":{"key":"a","key":"b"}}"#,
            "test-json",
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate JSON object key 'key'"));
    }

    #[test]
    fn json_from_slice_rejects_nested_duplicate_keys() {
        let err = json_from_slice_reject_duplicates::<Value>(
            br#"[{"a":1},{"nested":{"b":2,"b":3}}]"#,
            "test-json",
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate JSON object key 'b'"));
    }

    #[test]
    fn json_from_slice_accepts_distinct_keys() {
        let value = json_from_slice_reject_duplicates::<Value>(
            br#"{"capsule":{"key":"a","history":[{"key":"old"}]}}"#,
            "test-json",
        )
        .unwrap();
        assert_eq!(value["capsule"]["key"], "a");
    }
}

/// DNS resolver that rejects private/loopback IP addresses (SSRF protection).
///
/// Prevents DNS rebinding attacks: an attacker registers a domain that initially
/// resolves to a public IP, then changes DNS to point at an internal network address.
///
/// Requires the `client-safe-dns` feature. Not available on WASM (browsers handle
/// DNS resolution and CORS policy provides equivalent protection).
#[cfg(feature = "client-safe-dns")]
pub mod safe_dns {
    use reqwest::dns::{Addrs, Name, Resolve, Resolving};
    use std::net::{SocketAddr, ToSocketAddrs};

    /// A DNS resolver that performs system DNS resolution and rejects private IPs.
    pub struct SafeResolver;

    impl SafeResolver {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for SafeResolver {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Resolve for SafeResolver {
        fn resolve(&self, name: Name) -> Resolving {
            let host = name.as_str().to_string();
            Box::pin(async move {
                let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                    (host.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|iter| iter.collect::<Vec<_>>())
                })
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

                let filtered: Vec<SocketAddr> = addrs
                    .into_iter()
                    .filter(|addr| crate::uri::is_public_ip(addr.ip()))
                    .collect();

                if filtered.is_empty() {
                    return Err("DNS resolved to private/loopback address (blocked)".into());
                }

                let addrs: Addrs = Box::new(filtered.into_iter());
                Ok(addrs)
            })
        }
    }
}

/// Build a reqwest client with SSRF protections enabled.
///
/// Requires the `client-safe-dns` feature. On WASM, use `reqwest::Client::new()`
/// directly (browsers provide CORS protection).
#[cfg(feature = "client-safe-dns")]
pub fn http_client(timeout_secs: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(safe_dns::SafeResolver::new()))
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {e}"))
}
