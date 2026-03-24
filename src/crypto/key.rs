use anyhow::{anyhow, Result};

use super::AlgorithmBytes;

const KEY_SEPARATOR: char = '.';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
}

pub fn parse_key(value: &str) -> Result<AlgorithmBytes<KeyAlgorithm>> {
    let (algorithm_str, value_b58) = value
        .split_once(KEY_SEPARATOR)
        .ok_or_else(|| anyhow!("Key must use '{{algorithm}}.{{base58}}' format"))?;
    let algorithm = match algorithm_str {
        "ed25519" => KeyAlgorithm::Ed25519,
        other => return Err(anyhow!("Unsupported key algorithm: '{}'", other)),
    };
    if value_b58.is_empty() {
        return Err(anyhow!("Key payload must not be empty"));
    }

    let bytes = bs58::decode(value_b58)
        .into_vec()
        .map_err(|e| anyhow!("Invalid key base58 payload: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid key length for {}: expected 32 bytes, got {}",
            algorithm.prefix(),
            bytes.len()
        ));
    }

    Ok(AlgorithmBytes { algorithm, bytes })
}

pub fn format_key(algorithm: KeyAlgorithm, bytes: &[u8]) -> String {
    format!(
        "{}.{}",
        algorithm.prefix(),
        bs58::encode(bytes).into_string()
    )
}

impl KeyAlgorithm {
    fn prefix(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_key_roundtrip() {
        let input = "ed25519.2p3NPZceQ6njbPg8aMFsEynX3Cmv6uCt1XMGHhPcL4AT";
        let parsed = parse_key(input).unwrap();
        assert_eq!(parsed.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(format_key(parsed.algorithm, &parsed.bytes), input);
    }

    #[test]
    fn test_parse_key_rejects_wrong_length() {
        assert!(parse_key("ed25519.5Hue").is_err());
    }
}
