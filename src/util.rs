//! Local projection helpers and timestamp utilities.

use anyhow::{anyhow, Result};

// -- Local directory naming --

fn derive_local_path_segment(value: &str) -> Option<String> {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if "/\\:*?\"<>|".contains(ch) || ch.is_whitespace() || ch.is_control() {
                '-'
            } else {
                ch
            }
        })
        .collect();

    let segment = sanitized.trim_matches('-').trim_start_matches('.');
    if segment.is_empty() || segment == "." || segment == ".." {
        None
    } else {
        Some(segment.to_string())
    }
}

/// Pick a local directory name from opaque CMN metadata.
///
/// Attempts `id`, then `name`, and finally falls back to `hash`.
pub fn local_dir_name(id: Option<&str>, name: Option<&str>, hash: &str) -> String {
    id.filter(|value| !value.is_empty())
        .and_then(derive_local_path_segment)
        .or_else(|| {
            name.filter(|value| !value.is_empty())
                .and_then(derive_local_path_segment)
        })
        .unwrap_or_else(|| hash.to_string())
}

// -- Timestamp validation --

pub fn validate_timestamp_not_future(
    epoch_ms: u64,
    now_epoch_ms: u64,
    max_skew_ms: u64,
) -> Result<()> {
    if epoch_ms > now_epoch_ms + max_skew_ms {
        return Err(anyhow!(
            "Timestamp {} is {}ms in the future (tolerance: {}ms)",
            epoch_ms,
            epoch_ms - now_epoch_ms,
            max_skew_ms
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    // -- local_dir_name tests --

    #[test]
    fn test_derive_local_path_segment_valid() {
        assert_eq!(
            derive_local_path_segment("strain-account"),
            Some("strain-account".to_string())
        );
        assert_eq!(derive_local_path_segment("a.b"), Some("a.b".to_string()));
        assert_eq!(
            derive_local_path_segment("CMN Protocol Specification"),
            Some("CMN-Protocol-Specification".to_string())
        );
        assert_eq!(
            derive_local_path_segment("CMN协议规范"),
            Some("CMN协议规范".to_string())
        );
    }

    #[test]
    fn test_derive_local_path_segment_invalid_or_fallback_cases() {
        assert_eq!(derive_local_path_segment(""), None);
        assert_eq!(
            derive_local_path_segment(".hidden"),
            Some("hidden".to_string())
        );
        assert_eq!(
            derive_local_path_segment("bad/id"),
            Some("bad-id".to_string())
        );
        assert_eq!(
            derive_local_path_segment("bad id"),
            Some("bad-id".to_string())
        );
        assert_eq!(derive_local_path_segment(".."), None);
        assert_eq!(derive_local_path_segment("---"), None);
        assert_eq!(derive_local_path_segment("\x01\x02"), None);
    }

    #[test]
    fn test_local_dir_name() {
        assert_eq!(
            local_dir_name(Some("strain-account"), Some("Friendly Name"), "b3.hash"),
            "strain-account"
        );
        assert_eq!(
            local_dir_name(Some("../etc"), Some("Friendly Name"), "b3.hash"),
            "-etc"
        );
        assert_eq!(
            local_dir_name(Some(""), Some("Friendly Name"), "b3.hash"),
            "Friendly-Name"
        );
        assert_eq!(local_dir_name(None, Some(""), "b3.hash"), "b3.hash");
        assert_eq!(local_dir_name(None, None, "b3.hash"), "b3.hash");
    }

    // -- timestamp tests --

    #[test]
    fn test_validate_timestamp_not_future_allows_within_skew() {
        assert!(validate_timestamp_not_future(105, 100, 10).is_ok());
    }

    #[test]
    fn test_validate_timestamp_not_future_rejects_far_future() {
        assert!(validate_timestamp_not_future(111, 100, 10).is_err());
    }
}
