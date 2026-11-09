//! Typed protocol models for CMN.

use anyhow::{Result, anyhow};
use serde_json::Value;

mod cmn;
mod format;
mod mycelium;
mod spore;
mod taste;
mod trust;

pub use self::cmn::*;
pub use self::format::PrettyJson;
pub use self::format::format_cmn_entry;
pub use self::format::format_spore_core_draft;
pub use self::mycelium::*;
pub use self::spore::*;
pub use self::taste::*;
pub use self::trust::*;

fn verify_expected_uri_hash(actual_hash: &str, expected_hash: &str) -> Result<()> {
    let expected_hash = crate::parse_hash(expected_hash)?;
    let expected_hash_text = crate::format_hash(expected_hash.algorithm, &expected_hash.bytes);

    if actual_hash != expected_hash_text {
        return Err(anyhow!(
            "URI hash mismatch!\n  Expected: {}\n  Actual:   {}",
            expected_hash_text,
            actual_hash
        ));
    }

    Ok(())
}

pub fn decode_spore(payload: &Value) -> Result<Spore> {
    serde_json::from_value(payload.clone()).map_err(|e| anyhow!("Failed to decode spore: {}", e))
}

pub fn decode_mycelium(payload: &Value) -> Result<Mycelium> {
    serde_json::from_value(payload.clone()).map_err(|e| anyhow!("Failed to decode mycelium: {}", e))
}

pub fn decode_cmn_entry(payload: &Value) -> Result<CmnEntry> {
    serde_json::from_value(payload.clone()).map_err(|e| anyhow!("Failed to decode cmn.json: {}", e))
}

pub fn decode_taste(payload: &Value) -> Result<Taste> {
    serde_json::from_value(payload.clone())
        .map_err(|e| anyhow!("Failed to decode taste report: {}", e))
}

#[derive(Debug, Clone)]
pub enum Manifest {
    Spore(Spore),
    Mycelium(Mycelium),
}

impl Manifest {
    pub fn verify_core_signature(&self, author_key: &str) -> Result<()> {
        match self {
            Manifest::Spore(s) => s.verify_core_signature(author_key),
            Manifest::Mycelium(m) => m.verify_core_signature(author_key),
        }
    }

    pub fn verify_capsule_signature(&self, host_key: &str) -> Result<()> {
        match self {
            Manifest::Spore(s) => s.verify_capsule_signature(host_key),
            Manifest::Mycelium(m) => m.verify_capsule_signature(host_key),
        }
    }

    pub fn verify_signatures(&self, host_key: &str, author_key: &str) -> Result<()> {
        match self {
            Manifest::Spore(s) => s.verify_signatures(host_key, author_key),
            Manifest::Mycelium(m) => m.verify_signatures(host_key, author_key),
        }
    }

    pub fn verify_self_hosted_signatures(&self, key: &str) -> Result<()> {
        match self {
            Manifest::Spore(s) => s.verify_self_hosted_signatures(key),
            Manifest::Mycelium(m) => m.verify_self_hosted_signatures(key),
        }
    }
}

pub fn decode_manifest(payload: &Value) -> Result<Manifest> {
    if let Ok(schema_type) = crate::schemas::detect_schema_type(payload) {
        match schema_type {
            crate::schemas::SchemaType::Spore => return decode_spore(payload).map(Manifest::Spore),
            crate::schemas::SchemaType::Mycelium => {
                return decode_mycelium(payload).map(Manifest::Mycelium);
            }
            _ => {}
        }
    }
    if let Ok(spore) = decode_spore(payload) {
        return Ok(Manifest::Spore(spore));
    }
    decode_mycelium(payload)
        .map(Manifest::Mycelium)
        .map_err(|e| anyhow!("Failed to decode manifest as spore or mycelium: {}", e))
}
