//! Cryptographic utilities for CMN.

pub mod hash;
pub mod hub;
pub mod key;
pub mod signature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmBytes<A> {
    pub algorithm: A,
    pub bytes: Vec<u8>,
}

pub use hash::{compute_blake3_hash, format_hash, parse_hash, HashAlgorithm};
pub use key::{format_key, parse_key, KeyAlgorithm};
pub use signature::{
    compute_signature, format_signature, parse_signature, verify_json_signature, verify_signature,
    SignatureAlgorithm,
};
