use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const TASTE_SCHEMA: &str = "https://cmn.dev/schemas/v1/taste.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    Block,
    Warn,
    Proceed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOperation {
    Spawn,
    Grow,
    Absorb,
    Bond,
    Replicate,
    Taste,
    Sense,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TasteVerdict {
    Sweet,
    Fresh,
    Safe,
    Rotten,
    Toxic,
}

impl TasteVerdict {
    pub const ALL: [Self; 5] = [
        Self::Sweet,
        Self::Fresh,
        Self::Safe,
        Self::Rotten,
        Self::Toxic,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sweet => "sweet",
            Self::Fresh => "fresh",
            Self::Safe => "safe",
            Self::Rotten => "rotten",
            Self::Toxic => "toxic",
        }
    }

    pub fn allows_use(self) -> bool {
        !matches!(self, Self::Toxic)
    }

    pub fn base_gate_action(verdict: Option<Self>) -> GateAction {
        match verdict {
            None | Some(Self::Toxic) => GateAction::Block,
            Some(Self::Rotten) => GateAction::Warn,
            Some(Self::Safe | Self::Fresh | Self::Sweet) => GateAction::Proceed,
        }
    }

    pub fn gate_action_for(operation: GateOperation, verdict: Option<Self>) -> GateAction {
        Self::gate_action_for_env(operation, verdict, false)
    }

    /// Gate action with optional sandbox override.
    /// In sandbox mode, untasted and rotten spores proceed (toxic still blocks).
    pub fn gate_action_for_env(
        operation: GateOperation,
        verdict: Option<Self>,
        sandboxed: bool,
    ) -> GateAction {
        match operation {
            GateOperation::Taste | GateOperation::Sense => GateAction::Proceed,
            GateOperation::Spawn
            | GateOperation::Grow
            | GateOperation::Absorb
            | GateOperation::Bond
            | GateOperation::Replicate => {
                if sandboxed && verdict != Some(Self::Toxic) {
                    GateAction::Proceed
                } else {
                    Self::base_gate_action(verdict)
                }
            }
        }
    }
}

impl Display for TasteVerdict {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TasteVerdict {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "sweet" => Ok(Self::Sweet),
            "fresh" => Ok(Self::Fresh),
            "safe" => Ok(Self::Safe),
            "rotten" => Ok(Self::Rotten),
            "toxic" => Ok(Self::Toxic),
            _ => Err(anyhow!(
                "Invalid verdict '{}'. Must be one of: sweet, fresh, safe, rotten, toxic",
                value
            )),
        }
    }
}

impl Serialize for TasteVerdict {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TasteVerdict {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Full Taste manifest (content-addressed)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Taste {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub capsule: TasteCapsule,
    pub capsule_signature: String,
}

/// Taste capsule containing uri, core, and core_signature
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TasteCapsule {
    pub uri: String,
    pub core: TasteCore,
    pub core_signature: String,
}

/// Core taste data (part of hash)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TasteCore {
    pub target_uri: String,
    pub domain: String,
    pub key: String,
    pub verdict: TasteVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub tasted_at_epoch_ms: u64,
}

impl Taste {
    pub fn uri(&self) -> &str {
        &self.capsule.uri
    }

    pub fn target_uri(&self) -> &str {
        &self.capsule.core.target_uri
    }

    pub fn author_domain(&self) -> &str {
        &self.capsule.core.domain
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.capsule.core.tasted_at_epoch_ms
    }

    pub fn embedded_core_key(&self) -> Option<&str> {
        let key = self.capsule.core.key.as_str();
        (!key.is_empty()).then_some(key)
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

    pub fn computed_uri_hash(&self) -> Result<String> {
        crate::crypto::hash::compute_signed_core_hash(
            &self.capsule.core,
            &self.capsule.core_signature,
        )
    }

    pub fn verify_uri_hash(&self, expected_hash: &str) -> Result<()> {
        let actual_hash = self.computed_uri_hash()?;
        super::verify_expected_uri_hash(&actual_hash, expected_hash)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_base_gate_action() {
        assert_eq!(TasteVerdict::base_gate_action(None), GateAction::Block);
        assert_eq!(
            TasteVerdict::base_gate_action(Some(TasteVerdict::Toxic)),
            GateAction::Block
        );
        assert_eq!(
            TasteVerdict::base_gate_action(Some(TasteVerdict::Rotten)),
            GateAction::Warn
        );
        assert_eq!(
            TasteVerdict::base_gate_action(Some(TasteVerdict::Safe)),
            GateAction::Proceed
        );
    }

    #[test]
    fn test_gate_action_for_operation() {
        assert_eq!(
            TasteVerdict::gate_action_for(GateOperation::Spawn, Some(TasteVerdict::Rotten)),
            GateAction::Warn
        );
        assert_eq!(
            TasteVerdict::gate_action_for(GateOperation::Taste, Some(TasteVerdict::Toxic)),
            GateAction::Proceed
        );
        assert_eq!(
            TasteVerdict::gate_action_for(GateOperation::Sense, None),
            GateAction::Proceed
        );
    }

    #[test]
    fn test_gate_action_sandbox_skips_untasted() {
        assert_eq!(
            TasteVerdict::gate_action_for_env(GateOperation::Spawn, None, true),
            GateAction::Proceed
        );
    }

    #[test]
    fn test_gate_action_sandbox_skips_rotten() {
        assert_eq!(
            TasteVerdict::gate_action_for_env(
                GateOperation::Bond,
                Some(TasteVerdict::Rotten),
                true
            ),
            GateAction::Proceed
        );
    }

    #[test]
    fn test_gate_action_sandbox_still_blocks_toxic() {
        assert_eq!(
            TasteVerdict::gate_action_for_env(
                GateOperation::Spawn,
                Some(TasteVerdict::Toxic),
                true
            ),
            GateAction::Block
        );
    }
}
