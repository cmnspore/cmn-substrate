use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleHostingKind {
    SelfHosted,
    Replicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTrustRefreshPolicy {
    Expired,
    Always,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTrustWitnessPolicy {
    Allow,
    RequireDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainKeyConfirmation {
    Confirmed,
    Rejected,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTrustClass {
    FirstClass,
    SecondClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTrustWarning {
    SynapseSource,
    SynapseWitness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTrustFailure {
    OfflineCacheRequired,
    DomainRejected,
    DomainUnreachableWitnessDisabled,
    DomainUnreachableWitnessRejected,
    DomainUnreachableNoSynapse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTrustDecision {
    Trusted {
        trust_class: KeyTrustClass,
        cache_key: bool,
        warning: Option<KeyTrustWarning>,
    },
    Untrusted {
        reason: KeyTrustFailure,
    },
}

pub fn classify_capsule_hosting(uri_domain: &str, core_domain: &str) -> CapsuleHostingKind {
    if uri_domain == core_domain {
        CapsuleHostingKind::SelfHosted
    } else {
        CapsuleHostingKind::Replicate
    }
}

pub fn evaluate_signed_capsule_validity(
    core_signature_valid: bool,
    capsule_signature_valid: bool,
) -> bool {
    core_signature_valid && capsule_signature_valid
}

pub fn needs_key_trust_refresh(
    key_trusted_in_cache: bool,
    refresh_policy: KeyTrustRefreshPolicy,
) -> std::result::Result<bool, KeyTrustFailure> {
    match refresh_policy {
        KeyTrustRefreshPolicy::Expired => Ok(!key_trusted_in_cache),
        KeyTrustRefreshPolicy::Always => Ok(true),
        KeyTrustRefreshPolicy::Offline if key_trusted_in_cache => Ok(false),
        KeyTrustRefreshPolicy::Offline => Err(KeyTrustFailure::OfflineCacheRequired),
    }
}

pub fn decide_key_trust(
    domain_confirmation: DomainKeyConfirmation,
    witness_policy: KeyTrustWitnessPolicy,
    from_synapse: bool,
    synapse_confirms_key: Option<bool>,
) -> KeyTrustDecision {
    match domain_confirmation {
        DomainKeyConfirmation::Confirmed => KeyTrustDecision::Trusted {
            trust_class: KeyTrustClass::FirstClass,
            cache_key: true,
            warning: None,
        },
        DomainKeyConfirmation::Rejected => KeyTrustDecision::Untrusted {
            reason: KeyTrustFailure::DomainRejected,
        },
        DomainKeyConfirmation::Unreachable => {
            if matches!(witness_policy, KeyTrustWitnessPolicy::RequireDomain) {
                return KeyTrustDecision::Untrusted {
                    reason: KeyTrustFailure::DomainUnreachableWitnessDisabled,
                };
            }

            if from_synapse {
                return KeyTrustDecision::Trusted {
                    trust_class: KeyTrustClass::SecondClass,
                    cache_key: false,
                    warning: Some(KeyTrustWarning::SynapseSource),
                };
            }

            match synapse_confirms_key {
                Some(true) => KeyTrustDecision::Trusted {
                    trust_class: KeyTrustClass::SecondClass,
                    cache_key: false,
                    warning: Some(KeyTrustWarning::SynapseWitness),
                },
                Some(false) => KeyTrustDecision::Untrusted {
                    reason: KeyTrustFailure::DomainUnreachableWitnessRejected,
                },
                None => KeyTrustDecision::Untrusted {
                    reason: KeyTrustFailure::DomainUnreachableNoSynapse,
                },
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;

    #[test]
    fn test_classify_capsule_hosting() {
        assert_eq!(
            classify_capsule_hosting("cmn.dev", "cmn.dev"),
            CapsuleHostingKind::SelfHosted
        );
        assert_eq!(
            classify_capsule_hosting("mirror.dev", "cmn.dev"),
            CapsuleHostingKind::Replicate
        );
    }

    #[test]
    fn test_needs_key_trust_refresh() {
        assert!(!needs_key_trust_refresh(true, KeyTrustRefreshPolicy::Expired).unwrap());
        assert!(needs_key_trust_refresh(false, KeyTrustRefreshPolicy::Always).unwrap());
        assert_eq!(
            needs_key_trust_refresh(false, KeyTrustRefreshPolicy::Offline),
            Err(KeyTrustFailure::OfflineCacheRequired)
        );
    }

    #[test]
    fn test_decide_key_trust() {
        assert_eq!(
            decide_key_trust(
                DomainKeyConfirmation::Confirmed,
                KeyTrustWitnessPolicy::Allow,
                false,
                None
            ),
            KeyTrustDecision::Trusted {
                trust_class: KeyTrustClass::FirstClass,
                cache_key: true,
                warning: None,
            }
        );
        assert_eq!(
            decide_key_trust(
                DomainKeyConfirmation::Unreachable,
                KeyTrustWitnessPolicy::Allow,
                false,
                Some(true)
            ),
            KeyTrustDecision::Trusted {
                trust_class: KeyTrustClass::SecondClass,
                cache_key: false,
                warning: Some(KeyTrustWarning::SynapseWitness),
            }
        );
        assert_eq!(
            decide_key_trust(
                DomainKeyConfirmation::Rejected,
                KeyTrustWitnessPolicy::Allow,
                false,
                None
            ),
            KeyTrustDecision::Untrusted {
                reason: KeyTrustFailure::DomainRejected,
            }
        );
    }
}
