//! Zstd compression/decompression with cfg-based backend selection.
//!
//! - `archive-zstd`: uses C-binding `zstd` crate (native-only, faster, encode + decode)
//! - `archive-ruzstd`: uses pure-Rust `ruzstd` crate (WASM-compatible, decode only)
//!
//! If both features are enabled, `archive-zstd` takes priority for decoding.

use super::ExtractError;

/// Decompress zstd to raw bytes.
pub fn decode_zstd(compressed: &[u8], max_bytes: u64) -> Result<Vec<u8>, ExtractError> {
    decode_zstd_impl(compressed, max_bytes)
}

/// Decompress zstd with dictionary (delta archives).
pub fn decode_zstd_with_dict(
    compressed: &[u8],
    dict: &[u8],
    max_bytes: u64,
) -> Result<Vec<u8>, ExtractError> {
    decode_zstd_with_dict_impl(compressed, dict, max_bytes)
}

// --- archive-zstd backend (C bindings) ---

#[cfg(feature = "archive-zstd")]
fn decode_zstd_impl(compressed: &[u8], max_bytes: u64) -> Result<Vec<u8>, ExtractError> {
    let mut decoder = zstd::Decoder::new(std::io::Cursor::new(compressed))
        .map_err(|e| ExtractError::Failed(format!("Failed to create zstd decoder: {}", e)))?;
    read_with_limit(&mut decoder, max_bytes)
}

#[cfg(feature = "archive-zstd")]
fn decode_zstd_with_dict_impl(
    compressed: &[u8],
    dict: &[u8],
    max_bytes: u64,
) -> Result<Vec<u8>, ExtractError> {
    let mut decoder = zstd::Decoder::with_dictionary(std::io::Cursor::new(compressed), dict)
        .map_err(|e| ExtractError::Failed(format!("Failed to create dict decoder: {}", e)))?;
    read_with_limit(&mut decoder, max_bytes)
}

// --- archive-ruzstd backend (pure Rust, WASM-compatible) ---

#[cfg(all(feature = "archive-ruzstd", not(feature = "archive-zstd")))]
fn decode_zstd_impl(compressed: &[u8], max_bytes: u64) -> Result<Vec<u8>, ExtractError> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(compressed)
        .map_err(|e| ExtractError::Failed(format!("Failed to create ruzstd decoder: {}", e)))?;
    read_with_limit(&mut decoder, max_bytes)
}

#[cfg(all(feature = "archive-ruzstd", not(feature = "archive-zstd")))]
fn decode_zstd_with_dict_impl(
    _compressed: &[u8],
    _dict: &[u8],
    _max_bytes: u64,
) -> Result<Vec<u8>, ExtractError> {
    Err(ExtractError::Failed(
        "Dictionary decoding is not supported with the ruzstd backend".to_string(),
    ))
}

// --- Shared helper ---

fn read_with_limit<R: std::io::Read>(
    reader: &mut R,
    max_bytes: u64,
) -> Result<Vec<u8>, ExtractError> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 65_536];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| ExtractError::Failed(format!("zstd decompression error: {}", e)))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_bytes {
            return Err(ExtractError::Malicious(format!(
                "decompressed output exceeds limit ({} bytes)",
                max_bytes
            )));
        }
        output.extend_from_slice(&chunk[..n]);
    }
    Ok(output)
}

// --- Encode (archive-zstd only) ---

/// Compress bytes with zstd at given level.
#[cfg(feature = "archive-zstd")]
pub fn encode_zstd(data: &[u8], level: i32) -> Result<Vec<u8>, ExtractError> {
    use std::io::Write;
    let mut output = Vec::new();
    let mut encoder = zstd::Encoder::new(&mut output, level)
        .map_err(|e| ExtractError::Failed(format!("Failed to create zstd encoder: {}", e)))?;
    encoder
        .write_all(data)
        .map_err(|e| ExtractError::Failed(format!("zstd compression error: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| ExtractError::Failed(format!("zstd finish error: {}", e)))?;
    Ok(output)
}

/// Compress with zstd dictionary + long distance matching (for delta archives).
#[cfg(feature = "archive-zstd")]
pub fn encode_zstd_with_dict(
    data: &[u8],
    dict: &[u8],
    level: i32,
) -> Result<Vec<u8>, ExtractError> {
    use std::io::Write;
    let dictionary = zstd::dict::EncoderDictionary::copy(dict, level);
    let mut output = Vec::new();
    let mut encoder = zstd::Encoder::with_prepared_dictionary(&mut output, &dictionary)
        .map_err(|e| ExtractError::Failed(format!("Failed to create dict encoder: {}", e)))?;
    encoder
        .long_distance_matching(true)
        .map_err(|e| ExtractError::Failed(format!("Failed to set LDM: {}", e)))?;
    encoder
        .write_all(data)
        .map_err(|e| ExtractError::Failed(format!("zstd dict compression error: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| ExtractError::Failed(format!("zstd dict finish error: {}", e)))?;
    Ok(output)
}
