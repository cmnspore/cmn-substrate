use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;

use super::AlgorithmBytes;

const SIGNATURE_SEPARATOR: char = '.';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519,
}

pub fn parse_signature(value: &str) -> Result<AlgorithmBytes<SignatureAlgorithm>> {
    let (algorithm_str, value_b58) = value
        .split_once(SIGNATURE_SEPARATOR)
        .ok_or_else(|| anyhow!("Signature must use '{{algorithm}}.{{base58}}' format"))?;
    let algorithm = match algorithm_str {
        "ed25519" => SignatureAlgorithm::Ed25519,
        other => return Err(anyhow!("Unsupported signature algorithm: '{}'", other)),
    };
    if value_b58.is_empty() {
        return Err(anyhow!("Signature payload must not be empty"));
    }

    let bytes = bs58::decode(value_b58)
        .into_vec()
        .map_err(|e| anyhow!("Invalid signature base58 payload: {}", e))?;
    if bytes.len() != 64 {
        return Err(anyhow!(
            "Invalid signature length for {}: expected 64 bytes, got {}",
            algorithm.prefix(),
            bytes.len()
        ));
    }

    Ok(AlgorithmBytes { algorithm, bytes })
}

pub fn format_signature(algorithm: SignatureAlgorithm, bytes: &[u8]) -> String {
    format!(
        "{}.{}",
        algorithm.prefix(),
        bs58::encode(bytes).into_string()
    )
}

pub fn compute_signature<T: Serialize>(
    value: &T,
    algorithm: SignatureAlgorithm,
    private_key_bytes: &[u8],
) -> Result<String> {
    let canonical = canonicalize_json(value)?;

    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let private_key_bytes: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
                anyhow!("Invalid private key length for ed25519: expected 32 bytes")
            })?;
            let signing_key = SigningKey::from_bytes(&private_key_bytes);
            let signature = signing_key.sign(canonical.as_bytes());
            Ok(format_signature(
                SignatureAlgorithm::Ed25519,
                &signature.to_bytes(),
            ))
        }
    }
}

/// Verify a raw signature against raw data.
pub fn verify_signature(data: &[u8], signature_str: &str, public_key: &str) -> Result<()> {
    let signature = parse_signature(signature_str)?;
    let public_key = super::parse_key(public_key)?;

    match (signature.algorithm, public_key.algorithm) {
        (SignatureAlgorithm::Ed25519, super::KeyAlgorithm::Ed25519) => {
            verify_ed25519(data, &signature.bytes, &public_key.bytes)
        }
    }
}

pub fn verify_json_signature<T: Serialize>(
    value: &T,
    signature: &str,
    public_key: &str,
) -> Result<()> {
    let canonical = canonicalize_json(value)?;
    verify_signature(canonical.as_bytes(), signature, public_key)
}

impl SignatureAlgorithm {
    fn prefix(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

fn canonicalize_json<T: Serialize>(value: &T) -> Result<String> {
    serde_jcs::to_string(value).map_err(|e| anyhow!("JCS serialization failed: {}", e))
}

fn verify_ed25519(data: &[u8], signature_bytes: &[u8], public_key_bytes: &[u8]) -> Result<()> {
    let public_key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length (expected 32 bytes for ed25519)"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid signature length (expected 64 bytes for ed25519)"))?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(data, &signature)
        .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::{format_key, KeyAlgorithm};
    use serde_json::json;

    #[test]
    fn test_parse_signature_roundtrip() {
        let bytes = vec![7u8; 64];
        let encoded = format_signature(SignatureAlgorithm::Ed25519, &bytes);
        let parsed = parse_signature(&encoded).unwrap();
        assert_eq!(parsed.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(parsed.bytes, bytes);
    }

    #[test]
    fn test_parse_signature_rejects_wrong_length() {
        let encoded = format_signature(SignatureAlgorithm::Ed25519, &[1, 2, 3]);
        assert!(parse_signature(&encoded).is_err());
    }

    #[test]
    fn test_compute_and_verify_json_signature_roundtrip() {
        let private_key = [3u8; 32];
        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = format_key(
            KeyAlgorithm::Ed25519,
            &signing_key.verifying_key().to_bytes(),
        );
        let value = json!({"b": 2, "a": 1});

        let signature =
            compute_signature(&value, SignatureAlgorithm::Ed25519, &private_key).unwrap();
        verify_json_signature(&value, &signature, &public_key).unwrap();
    }

    #[test]
    fn test_verify_signature_missing_prefix() {
        let result = verify_signature(b"test", "aabbcc", "ed25519.aabbccdd");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_key_missing_prefix() {
        let result = verify_signature(b"test", "ed25519.aabbcc", "aabbccdd");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_wrong_length() {
        let result = verify_signature(b"test", "ed25519.5Hue", "ed25519.5Hue");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let secret_bytes: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let public_key = format_key(
            super::super::KeyAlgorithm::Ed25519,
            &signing_key.verifying_key().to_bytes(),
        );
        let data = json!({
            "author": "test.com",
            "intent": ["v1.0"],
            "license": "MIT",
            "name": "test-spore",
            "synopsis": "A test spore"
        });

        let signature =
            compute_signature(&data, super::SignatureAlgorithm::Ed25519, &secret_bytes).unwrap();
        let canonical = serde_jcs::to_string(&data).unwrap();

        assert!(verify_signature(canonical.as_bytes(), &signature, &public_key).is_ok());
        assert!(verify_signature(b"wrong data", &signature, &public_key).is_err());
    }
}
