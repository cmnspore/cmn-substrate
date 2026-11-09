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

pub use hash::{HashAlgorithm, compute_blake3_hash, format_hash, parse_hash};
pub use key::{KeyAlgorithm, format_key, parse_key};
pub use signature::{
    SignatureAlgorithm, compute_signature, format_signature, parse_signature,
    verify_json_signature, verify_signature,
};
