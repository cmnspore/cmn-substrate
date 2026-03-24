//! Typed protocol models for CMN.

use anyhow::{anyhow, Result};
use serde_json::Value;

mod cmn;
mod format;
mod mycelium;
mod spore;
mod taste;
mod trust;

pub use self::cmn::*;
pub use self::format::format_cmn_entry;
pub use self::format::format_spore_core_draft;
pub use self::format::PrettyJson;
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
