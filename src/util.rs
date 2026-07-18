//! Local projection helpers and timestamp utilities.

use agent_first_slug::{
    slugify, validate_slug, AllowedCharacterSet, DotHandlingPolicy, EmptyOutputPolicy, SlugConfig,
    SlugValidationPolicy, TransliterationPolicy,
};
use anyhow::{anyhow, Result};

// -- Local directory naming --

fn derive_local_path_segment(value: &str) -> Option<String> {
    let config = SlugConfig {
        replacement_delimiter: '-',
        lowercase_enabled: true,
        max_slug_chars: None,
        allowed_character_set: AllowedCharacterSet::UnicodeAlphanumericCharacters,
        dot_handling_policy: DotHandlingPolicy::PreserveDotsBetweenDecimalDigits,
        transliteration_policy: TransliterationPolicy::None,
        validation_policy: SlugValidationPolicy::LocalPathSegment,
        empty_output_policy: EmptyOutputPolicy::KeepEmptySlug,
    };

    let segment = slugify(value, &config).ok()?.slug;
    if segment.is_empty() {
        None
    } else {
        Some(segment)
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

/// Return whether a value is safe to use as one local filesystem path segment.
///
/// This validates an existing value without requiring it to use the canonical
/// slug format produced by [`local_dir_name`].
pub fn is_safe_local_path_segment(value: &str) -> bool {
    validate_slug(value, SlugValidationPolicy::LocalPathSegment).is_ok()
}

// -- Version comparison --

/// Result of comparing two timestamps for version ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOrder {
    /// The incoming timestamp is strictly newer.
    Newer,
    /// Both timestamps are identical.
    Same,
    /// The incoming timestamp is older.
    Older,
}

/// Compare an incoming timestamp against an existing one for version ordering.
///
/// CMN uses strictly-newer semantics: content is only accepted when `incoming > existing`.
pub fn compare_version_timestamps(incoming_epoch_ms: u64, existing_epoch_ms: u64) -> VersionOrder {
    match incoming_epoch_ms.cmp(&existing_epoch_ms) {
        std::cmp::Ordering::Greater => VersionOrder::Newer,
        std::cmp::Ordering::Equal => VersionOrder::Same,
        std::cmp::Ordering::Less => VersionOrder::Older,
    }
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
        assert_eq!(derive_local_path_segment("a.b"), Some("a-b".to_string()));
        assert_eq!(
            derive_local_path_segment("Ubuntu 16.04"),
            Some("ubuntu-16.04".to_string())
        );
        assert_eq!(
            derive_local_path_segment("v1.2.3"),
            Some("v1.2.3".to_string())
        );
        assert_eq!(
            derive_local_path_segment("CMN Protocol Specification"),
            Some("cmn-protocol-specification".to_string())
        );
        assert_eq!(
            derive_local_path_segment("CMN协议规范"),
            Some("cmn协议规范".to_string())
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
            "etc"
        );
        assert_eq!(
            local_dir_name(Some(""), Some("Friendly Name"), "b3.hash"),
            "friendly-name"
        );
        assert_eq!(local_dir_name(None, Some(""), "b3.hash"), "b3.hash");
        assert_eq!(local_dir_name(None, None, "b3.hash"), "b3.hash");
    }

    #[test]
    fn test_is_safe_local_path_segment() {
        assert!(is_safe_local_path_segment("Foo"));
        assert!(is_safe_local_path_segment("foo_bar"));
        assert!(is_safe_local_path_segment("b3.hash"));

        assert!(!is_safe_local_path_segment(""));
        assert!(!is_safe_local_path_segment("."));
        assert!(!is_safe_local_path_segment(".."));
        assert!(!is_safe_local_path_segment("bad/name"));
        assert!(!is_safe_local_path_segment("bad\\name"));
        assert!(!is_safe_local_path_segment("bad name"));
        assert!(!is_safe_local_path_segment("bad\x01name"));
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
