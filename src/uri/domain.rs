use anyhow::{bail, Result};

/// Build the well-known cmn.json entry URL for a domain
///
/// Protocol is selected by domain suffix: .onion and .i2p use HTTP,
/// all others use HTTPS.
pub fn cmn_entry_url(domain: &str) -> String {
    let scheme = if domain.ends_with(".onion") || domain.ends_with(".i2p") {
        "http"
    } else {
        "https"
    };
    format!("{}://{}/.well-known/cmn.json", scheme, domain)
}

/// Validate a domain name per CMN spec (RFC 1123, lowercase only).
pub fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        bail!("Empty domain");
    }
    if domain.len() > 253 {
        bail!("Domain exceeds 253 characters");
    }
    if domain.ends_with('.') {
        bail!("Domain must not have trailing dot");
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        bail!("Domain must have at least 2 labels (e.g., 'example.com')");
    }

    for label in &labels {
        if label.is_empty() {
            bail!("Domain contains empty label");
        }
        if label.len() > 63 {
            bail!("Domain label exceeds 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("Domain label must not start or end with hyphen");
        }
        for ch in label.chars() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '-') {
                bail!(
                    "Domain contains invalid character '{}' (must be lowercase a-z, 0-9, or hyphen)",
                    ch
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::uri::parse_uri;

    #[test]
    fn test_domain_valid() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("my-project.io").is_ok());
        assert!(validate_domain("a.b.c.d.example.com").is_ok());
        assert!(validate_domain("x1.y2.com").is_ok());
    }

    #[test]
    fn test_domain_reject_uppercase() {
        assert!(validate_domain("Example.com").is_err());
        assert!(validate_domain("EXAMPLE.COM").is_err());
        assert!(validate_domain("cmn.Dev").is_err());
        assert!(parse_uri("cmn://CMN.DEV/b3.3yMR7vZQ9hL").is_err());
    }

    #[test]
    fn test_domain_reject_single_label() {
        assert!(validate_domain("localhost").is_err());
        assert!(validate_domain("example").is_err());
    }

    #[test]
    fn test_domain_reject_invalid_format() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("example.com.").is_err());
        assert!(validate_domain("-example.com").is_err());
        assert!(validate_domain("example-.com").is_err());
        assert!(validate_domain("exam ple.com").is_err());
        assert!(validate_domain("exam_ple.com").is_err());
        assert!(validate_domain(".example.com").is_err());
        assert!(validate_domain("example..com").is_err());
    }
}
