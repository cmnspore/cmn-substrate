use anyhow::{Result, anyhow, bail};

/// Normalize and validate an HTTP(S) URL against SSRF and scheme injection.
pub fn normalize_and_validate_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let parsed =
        url::Url::parse(trimmed).map_err(|e| anyhow!("Invalid URL '{}': {}", trimmed, e))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("URL must not include userinfo: {}", trimmed);
    }

    let host = parsed
        .host()
        .ok_or_else(|| anyhow!("Empty hostname in URL: {}", trimmed))?;

    match host {
        url::Host::Ipv4(v4) => {
            if parsed.scheme() != "https" {
                bail!("URL with IP address must use https://: {}", trimmed);
            }
            if !is_public_ip(std::net::IpAddr::V4(v4)) {
                bail!("URL targets private/reserved IP: {}", trimmed);
            }
        }
        url::Host::Ipv6(v6) => {
            if parsed.scheme() != "https" {
                bail!("URL with IP address must use https://: {}", trimmed);
            }
            if !is_public_ip(std::net::IpAddr::V6(v6)) {
                bail!("URL targets private/reserved IP: {}", trimmed);
            }
        }
        url::Host::Domain(domain) => {
            let d = domain.to_ascii_lowercase();
            let is_onion_or_i2p = d.ends_with(".onion") || d.ends_with(".i2p");
            match parsed.scheme() {
                "https" => {}
                "http" if is_onion_or_i2p => {}
                "http" => bail!("HTTP only allowed for .onion/.i2p domains, got: {}", d),
                _ => bail!(
                    "URL must use https:// (or http:// for .onion/.i2p): {}",
                    trimmed
                ),
            }

            let trimmed_d = d.trim_end_matches('.');
            if trimmed_d.is_empty()
                || trimmed_d == "localhost"
                || trimmed_d.ends_with(".localhost")
                || (!trimmed_d.contains('.') && !is_onion_or_i2p)
            {
                if trimmed_d == "localhost" || trimmed_d.ends_with(".localhost") {
                    bail!("URL targets localhost: {}", trimmed);
                } else {
                    bail!("URL hostname must be a fully qualified domain: {}", trimmed);
                }
            }
        }
    }

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

/// Check whether an IP address is routable on the public internet.
pub fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_documentation()
                && octets[0] != 0
                && !(octets[0] == 100 && (octets[1] & 0xC0) == 64)
                && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                && octets[0] < 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }

            let segments = v6.segments();
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !((segments[0] == 0x2001) && (segments[1] == 0x0db8))
                && (segments[0] & 0xfe00) != 0xfc00
                && (segments[0] & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;

    #[test]
    fn test_normalize_and_validate_url_valid_https() {
        assert_eq!(
            normalize_and_validate_url("https://api.example.com/svc").unwrap(),
            "https://api.example.com/svc"
        );
    }

    #[test]
    fn test_normalize_and_validate_url_strips_trailing_slash() {
        assert_eq!(
            normalize_and_validate_url("https://api.example.com/svc/").unwrap(),
            "https://api.example.com/svc"
        );
    }

    #[test]
    fn test_normalize_and_validate_url_allows_http_onion() {
        assert_eq!(
            normalize_and_validate_url("http://abc123.onion/svc").unwrap(),
            "http://abc123.onion/svc"
        );
    }

    #[test]
    fn test_normalize_and_validate_url_allows_http_i2p() {
        assert_eq!(
            normalize_and_validate_url("http://site.i2p/svc").unwrap(),
            "http://site.i2p/svc"
        );
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_http_clearnet() {
        assert!(normalize_and_validate_url("http://api.example.com/svc").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_file_scheme() {
        assert!(normalize_and_validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_javascript() {
        assert!(normalize_and_validate_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_localhost() {
        assert!(normalize_and_validate_url("https://localhost/svc").is_err());
        assert!(normalize_and_validate_url("https://127.0.0.1/svc").is_err());
        assert!(normalize_and_validate_url("https://127.1.2.3/svc").is_err());
        assert!(normalize_and_validate_url("https://[::1]/svc").is_err());
        assert!(normalize_and_validate_url("https://0.0.0.0/svc").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_private_ips() {
        assert!(normalize_and_validate_url("https://10.0.0.1/svc").is_err());
        assert!(normalize_and_validate_url("https://172.16.0.1/svc").is_err());
        assert!(normalize_and_validate_url("https://172.31.255.1/svc").is_err());
        assert!(normalize_and_validate_url("https://192.168.1.1/svc").is_err());
        assert!(normalize_and_validate_url("https://169.254.0.1/svc").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_ipv4_mapped_ipv6() {
        assert!(normalize_and_validate_url("https://[::ffff:127.0.0.1]/svc").is_err());
        assert!(normalize_and_validate_url("https://[::ffff:10.0.0.1]/svc").is_err());
        assert!(normalize_and_validate_url("https://[::ffff:192.168.1.1]/svc").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_allows_public_ips() {
        assert!(normalize_and_validate_url("https://8.8.8.8/svc").is_ok());
        assert!(normalize_and_validate_url("https://1.1.1.1/svc").is_ok());
        assert!(normalize_and_validate_url("https://[2606:4700:4700::1111]/svc").is_ok());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_localhost_variants() {
        assert!(normalize_and_validate_url("https://localhost./svc").is_err());
        assert!(normalize_and_validate_url("https://sub.localhost/svc").is_err());
        assert!(normalize_and_validate_url("https://sub.localhost./svc").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_bare_hostname() {
        assert!(normalize_and_validate_url("https://internal-service/api").is_err());
    }

    #[test]
    fn test_normalize_and_validate_url_rejects_userinfo() {
        assert!(normalize_and_validate_url("https://a.com@127.0.0.1/svc").is_err());
        assert!(normalize_and_validate_url("https://user:pass@example.com/svc").is_err());
    }

    #[test]
    fn test_is_public_ip_v4() {
        use std::net::{IpAddr, Ipv4Addr};

        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
    }

    #[test]
    fn test_is_public_ip_v6() {
        use std::net::{IpAddr, Ipv6Addr};

        assert!(is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn test_is_public_ip_v4_mapped_v6() {
        use std::net::{IpAddr, Ipv6Addr};

        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001
        ))));
        assert!(is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808
        ))));
    }
}
