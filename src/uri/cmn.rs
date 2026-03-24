use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use super::validate_domain;

/// The kind of entity a CMN URI identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmnUriKind {
    /// Domain root: `cmn://domain`
    Domain,
    /// Content-addressed spore: `cmn://domain/hash`
    Spore,
    /// Content-addressed mycelium: `cmn://domain/mycelium/hash`
    Mycelium,
    /// Content-addressed taste report: `cmn://domain/taste/hash`
    Taste,
}

impl CmnUriKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Spore => "spore",
            Self::Mycelium => "mycelium",
            Self::Taste => "taste",
        }
    }
}

impl Display for CmnUriKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CmnUriKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "domain" => Ok(Self::Domain),
            "spore" => Ok(Self::Spore),
            "mycelium" => Ok(Self::Mycelium),
            "taste" => Ok(Self::Taste),
            _ => Err(anyhow!(
                "Invalid CMN URI kind '{}'. Must be one of: domain, spore, mycelium, taste",
                value
            )),
        }
    }
}

impl Serialize for CmnUriKind {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CmnUriKind {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Parsed CMN URI
#[derive(Debug, Clone, PartialEq)]
pub struct CmnUri {
    pub domain: String,
    pub hash: Option<String>,
    pub kind: CmnUriKind,
}

impl CmnUri {
    /// Parse a CMN URI string into a CmnUri struct
    ///
    /// # Examples
    /// ```
    /// use substrate::CmnUri;
    ///
    /// let uri = CmnUri::parse("cmn://example.com/b3.3yMR7vZQ9hL").unwrap();
    /// assert_eq!(uri.domain, "example.com");
    /// assert_eq!(uri.hash, Some("b3.3yMR7vZQ9hL".to_string()));
    ///
    /// let taste = CmnUri::parse("cmn://alice.dev/taste/b3.7tRkW2x").unwrap();
    /// assert_eq!(taste.domain, "alice.dev");
    /// assert_eq!(taste.hash, Some("b3.7tRkW2x".to_string()));
    /// assert!(taste.is_taste());
    /// ```
    pub fn parse(uri: &str) -> Result<Self, String> {
        parse_uri(uri).map_err(|e| e.to_string())
    }

    /// Get hash formatted for use in filenames.
    pub fn hash_filename(&self) -> Option<String> {
        self.hash.clone()
    }

    /// Returns true if this is a spore URI (has a hash, not a taste).
    pub fn is_spore(&self) -> bool {
        self.kind == CmnUriKind::Spore
    }

    /// Returns true if this is a domain root URI (no hash).
    pub fn is_domain(&self) -> bool {
        self.kind == CmnUriKind::Domain
    }

    /// Returns true if this is a taste report URI.
    pub fn is_taste(&self) -> bool {
        self.kind == CmnUriKind::Taste
    }

    /// Returns true if this is a mycelium URI.
    pub fn is_mycelium(&self) -> bool {
        self.kind == CmnUriKind::Mycelium
    }
}

/// Parse a CMN URI into its components
///
/// Four forms:
/// - `cmn://domain` → domain root
/// - `cmn://domain/hash` → content-addressed spore
/// - `cmn://domain/mycelium/hash` → content-addressed mycelium
/// - `cmn://domain/taste/hash` → content-addressed taste report
///
/// # Examples
/// ```
/// use substrate::uri::parse_uri;
///
/// let spore = parse_uri("cmn://example.com/b3.3yMR7vZQ9hL").unwrap();
/// assert_eq!(spore.domain, "example.com");
/// assert_eq!(spore.hash, Some("b3.3yMR7vZQ9hL".to_string()));
/// assert!(spore.is_spore());
///
/// let domain = parse_uri("cmn://example.com").unwrap();
/// assert_eq!(domain.domain, "example.com");
/// assert_eq!(domain.hash, None);
/// assert!(domain.is_domain());
///
/// let mycelium = parse_uri("cmn://example.com/mycelium/b3.7tRk").unwrap();
/// assert_eq!(mycelium.domain, "example.com");
/// assert_eq!(mycelium.hash, Some("b3.7tRk".to_string()));
/// assert!(mycelium.is_mycelium());
///
/// let taste = parse_uri("cmn://alice.dev/taste/b3.7tRkW2x").unwrap();
/// assert_eq!(taste.domain, "alice.dev");
/// assert_eq!(taste.hash, Some("b3.7tRkW2x".to_string()));
/// assert!(taste.is_taste());
/// ```
pub fn parse_uri(uri: &str) -> Result<CmnUri> {
    let rest = uri
        .strip_prefix("cmn://")
        .ok_or_else(|| anyhow!("URI must start with 'cmn://'"))?;

    let trimmed = rest.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(anyhow!("Missing domain in URI"));
    }

    let (domain, path) = match trimmed.split_once('/') {
        Some((domain, path)) if !path.is_empty() => (domain.to_string(), Some(path.to_string())),
        Some((domain, _)) => (domain.to_string(), None),
        None => (trimmed.to_string(), None),
    };

    validate_domain(&domain)?;

    let (kind, hash) = match path {
        None => (CmnUriKind::Domain, None),
        Some(path) => {
            if path == "taste" {
                return Err(anyhow!("Taste URI missing hash after /taste/"));
            } else if path == "mycelium" {
                return Err(anyhow!("Mycelium URI missing hash after /mycelium/"));
            } else if let Some(taste_hash) = path.strip_prefix("taste/") {
                if taste_hash.is_empty() {
                    return Err(anyhow!("Taste URI missing hash after /taste/"));
                }
                let normalized = crate::crypto::parse_hash(taste_hash)
                    .map(|hash| crate::crypto::format_hash(hash.algorithm, &hash.bytes))
                    .map_err(|e| anyhow!("Invalid taste hash '{}': {}", taste_hash, e))?;
                (CmnUriKind::Taste, Some(normalized))
            } else if let Some(mycelium_hash) = path.strip_prefix("mycelium/") {
                if mycelium_hash.is_empty() {
                    return Err(anyhow!("Mycelium URI missing hash after /mycelium/"));
                }
                let normalized = crate::crypto::parse_hash(mycelium_hash)
                    .map(|hash| crate::crypto::format_hash(hash.algorithm, &hash.bytes))
                    .map_err(|e| anyhow!("Invalid mycelium hash '{}': {}", mycelium_hash, e))?;
                (CmnUriKind::Mycelium, Some(normalized))
            } else {
                let normalized = crate::crypto::parse_hash(&path)
                    .map(|hash| crate::crypto::format_hash(hash.algorithm, &hash.bytes))
                    .map_err(|e| anyhow!("Invalid spore hash '{}': {}", path, e))?;
                (CmnUriKind::Spore, Some(normalized))
            }
        }
    };

    Ok(CmnUri { domain, hash, kind })
}

/// Normalize and validate a taste target URI.
///
/// Allowed target kinds:
/// - `cmn://{domain}`
/// - `cmn://{domain}/{hash}`
/// - `cmn://{domain}/mycelium/{hash}`
///
/// Taste report URIs (`cmn://.../taste/{hash}`) are not valid targets.
pub fn normalize_taste_target_uri(uri: &str) -> Result<String> {
    let parsed = parse_uri(uri)?;
    match parsed.kind {
        CmnUriKind::Domain => Ok(build_domain_uri(&parsed.domain)),
        CmnUriKind::Spore => {
            let hash = parsed
                .hash
                .ok_or_else(|| anyhow!("Spore target URI is missing hash"))?;
            Ok(build_spore_uri(&parsed.domain, &hash))
        }
        CmnUriKind::Mycelium => {
            let hash = parsed
                .hash
                .ok_or_else(|| anyhow!("Mycelium target URI is missing hash"))?;
            Ok(build_mycelium_uri(&parsed.domain, &hash))
        }
        CmnUriKind::Taste => {
            bail!("Taste target_uri must be one of: domain URI, spore URI, mycelium URI")
        }
    }
}

/// Build a spore URI
pub fn build_spore_uri(domain: &str, hash: &str) -> String {
    format!("cmn://{}/{}", domain, hash)
}

/// Build a domain root URI
pub fn build_domain_uri(domain: &str) -> String {
    format!("cmn://{}", domain)
}

/// Build a taste report URI
pub fn build_taste_uri(domain: &str, hash: &str) -> String {
    format!("cmn://{}/taste/{}", domain, hash)
}

/// Build a mycelium URI
pub fn build_mycelium_uri(domain: &str, hash: &str) -> String {
    format!("cmn://{}/mycelium/{}", domain, hash)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_parse_spore_uri() {
        let uri = parse_uri("cmn://example.com/b3.3yMR7vZQ9hL").unwrap();
        assert_eq!(uri.domain, "example.com");
        assert_eq!(uri.hash, Some("b3.3yMR7vZQ9hL".to_string()));
        assert!(uri.is_spore());
        assert_eq!(uri.kind, CmnUriKind::Spore);
    }

    #[test]
    fn test_parse_domain_uri() {
        let uri = parse_uri("cmn://example.com").unwrap();
        assert_eq!(uri.domain, "example.com");
        assert_eq!(uri.hash, None);
        assert!(uri.is_domain());
        assert_eq!(uri.kind, CmnUriKind::Domain);
    }

    #[test]
    fn test_parse_domain_uri_trailing_slash() {
        let uri = parse_uri("cmn://example.com/").unwrap();
        assert_eq!(uri.domain, "example.com");
        assert_eq!(uri.hash, None);
    }

    #[test]
    fn test_parse_taste_uri() {
        let uri = parse_uri("cmn://alice.dev/taste/b3.7tRkW2xPqL9nH").unwrap();
        assert_eq!(uri.domain, "alice.dev");
        assert_eq!(uri.hash, Some("b3.7tRkW2xPqL9nH".to_string()));
        assert!(uri.is_taste());
        assert_eq!(uri.kind, CmnUriKind::Taste);
    }

    #[test]
    fn test_parse_mycelium_uri() {
        let uri = parse_uri("cmn://example.com/mycelium/b3.7tRkW2xPqL9nH").unwrap();
        assert_eq!(uri.domain, "example.com");
        assert_eq!(uri.hash, Some("b3.7tRkW2xPqL9nH".to_string()));
        assert!(uri.is_mycelium());
        assert_eq!(uri.kind, CmnUriKind::Mycelium);
    }

    #[test]
    fn test_parse_mycelium_uri_missing_hash() {
        assert!(parse_uri("cmn://example.com/mycelium/").is_err());
        assert!(parse_uri("cmn://example.com/mycelium").is_err());
    }

    #[test]
    fn test_parse_taste_uri_missing_hash() {
        assert!(parse_uri("cmn://alice.dev/taste/").is_err());
        assert!(parse_uri("cmn://alice.dev/taste").is_err());
    }

    #[test]
    fn test_parse_invalid_uri() {
        assert!(parse_uri("http://example.com/spore").is_err());
        assert!(parse_uri("cmn://").is_err());
        assert!(parse_uri("cmn:///spore").is_err());
        assert!(parse_uri("cmn://example.com/not-a-hash").is_err());
    }

    #[test]
    fn test_build_spore_uri() {
        let uri = build_spore_uri("example.com", "b3.3yMR7vZQ9hL");
        assert_eq!(uri, "cmn://example.com/b3.3yMR7vZQ9hL");
    }

    #[test]
    fn test_build_domain_uri() {
        let uri = build_domain_uri("example.com");
        assert_eq!(uri, "cmn://example.com");
    }

    #[test]
    fn test_build_taste_uri() {
        let uri = build_taste_uri("alice.dev", "b3.7tRkW2xPqL9nH");
        assert_eq!(uri, "cmn://alice.dev/taste/b3.7tRkW2xPqL9nH");
    }

    #[test]
    fn test_build_mycelium_uri() {
        let uri = build_mycelium_uri("example.com", "b3.7tRkW2xPqL9nH");
        assert_eq!(uri, "cmn://example.com/mycelium/b3.7tRkW2xPqL9nH");
    }

    #[test]
    fn test_normalize_taste_target_uri_domain() {
        let uri = normalize_taste_target_uri("cmn://example.com/").unwrap();
        assert_eq!(uri, "cmn://example.com");
    }

    #[test]
    fn test_normalize_taste_target_uri_spore() {
        let uri = normalize_taste_target_uri("cmn://example.com/b3.3yMR7vZQ9hL").unwrap();
        assert_eq!(uri, "cmn://example.com/b3.3yMR7vZQ9hL");
    }

    #[test]
    fn test_normalize_taste_target_uri_mycelium() {
        let uri = normalize_taste_target_uri("cmn://example.com/mycelium/b3.3yMR7vZQ9hL").unwrap();
        assert_eq!(uri, "cmn://example.com/mycelium/b3.3yMR7vZQ9hL");
    }

    #[test]
    fn test_normalize_taste_target_uri_rejects_taste_uri() {
        assert!(normalize_taste_target_uri("cmn://example.com/taste/b3.3yMR7vZQ9hL").is_err());
    }
}
