#![cfg(any(feature = "archive-ruzstd", feature = "archive-zstd"))]

use anyhow::{Result as TestResult, anyhow};
use substrate::archive::*;

fn make_tar(entries: &[(&str, &[u8])]) -> std::io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, &data[..])?;
    }
    builder.into_inner()
}

/// Build a tar with a raw path that bypasses builder validation.
fn make_tar_raw_path(path: &str, data: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    // Write path directly into the header bytes
    let path_bytes = path.as_bytes();
    let header_bytes = header.as_mut_bytes();
    header_bytes[..path_bytes.len().min(100)]
        .copy_from_slice(&path_bytes[..path_bytes.len().min(100)]);
    // Zero remaining path bytes
    for b in &mut header_bytes[path_bytes.len().min(100)..100] {
        *b = 0;
    }
    header.set_cksum();

    // Build the tar manually: header (512 bytes) + data (padded to 512) + 2 x 512 zero blocks
    let mut out = Vec::new();
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(data);
    let padding = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat_n(0u8, padding));
    out.extend(std::iter::repeat_n(0u8, 1024)); // end-of-archive marker
    out
}

fn default_limits() -> ExtractLimits {
    ExtractLimits {
        max_bytes: 10 * 1024 * 1024,
        max_files: 1000,
        max_file_bytes: 5 * 1024 * 1024,
    }
}

fn expect_malicious<T>(
    result: std::result::Result<T, ExtractError>,
    expected_message: &str,
) -> TestResult<()> {
    match result {
        Err(ExtractError::Malicious(message)) => {
            assert!(
                message.contains(expected_message),
                "expected error to contain {expected_message:?}, got {message:?}"
            );
            Ok(())
        }
        Err(error) => Err(anyhow!("expected Malicious, got: {error:?}")),
        Ok(_) => Err(anyhow!("expected Malicious, got Ok")),
    }
}

#[test]
fn test_extract_tar_basic() -> TestResult<()> {
    let tar_bytes = make_tar(&[
        ("hello.txt", b"hello world"),
        ("sub/file.rs", b"fn main() {}"),
    ])?;
    let entries = extract_tar(&tar_bytes, &default_limits())?;

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, "hello.txt");
    assert_eq!(entries[0].kind, EntryKind::File);
    assert_eq!(entries[0].data, b"hello world");
    assert_eq!(entries[1].path, "sub/file.rs");
    assert_eq!(entries[1].data, b"fn main() {}");
    Ok(())
}

#[test]
fn test_extract_tar_rejects_symlink() -> TestResult<()> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    builder.append_link(&mut header, "evil-link", "/etc/passwd")?;
    let tar_bytes = builder.into_inner()?;

    expect_malicious(
        extract_tar(&tar_bytes, &default_limits()),
        "disallowed entry type",
    )
}

#[test]
fn test_extract_tar_rejects_path_traversal() -> TestResult<()> {
    let tar_bytes = make_tar_raw_path("../../etc/passwd", b"root:x:0:0");
    expect_malicious(extract_tar(&tar_bytes, &default_limits()), "path traversal")
}

#[test]
fn test_extract_tar_rejects_absolute_path() -> TestResult<()> {
    let tar_bytes = make_tar_raw_path("/etc/passwd", b"root:x:0:0");
    expect_malicious(extract_tar(&tar_bytes, &default_limits()), "path traversal")
}

#[test]
fn test_extract_tar_file_count_limit() -> TestResult<()> {
    let entries: Vec<(String, Vec<u8>)> =
        (0..5).map(|i| (format!("f{}.txt", i), vec![0u8])).collect();
    let tar_entries: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    let tar_bytes = make_tar(&tar_entries)?;

    let limits = ExtractLimits {
        max_bytes: 10 * 1024 * 1024,
        max_files: 3,
        max_file_bytes: 5 * 1024 * 1024,
    };
    expect_malicious(extract_tar(&tar_bytes, &limits), "max file count")
}

#[test]
fn test_extract_tar_total_bytes_limit() -> TestResult<()> {
    let tar_bytes = make_tar(&[("big.bin", &[0xAA; 1024])])?;
    let limits = ExtractLimits {
        max_bytes: 512,
        max_files: 1000,
        max_file_bytes: 5 * 1024 * 1024,
    };
    expect_malicious(extract_tar(&tar_bytes, &limits), "max extract size")
}

#[test]
fn test_extract_tar_single_file_limit() -> TestResult<()> {
    let tar_bytes = make_tar(&[("big.bin", &[0xBB; 1024])])?;
    let limits = ExtractLimits {
        max_bytes: 10 * 1024 * 1024,
        max_files: 1000,
        max_file_bytes: 512,
    };
    expect_malicious(
        extract_tar(&tar_bytes, &limits),
        "single file exceeds max size",
    )
}

// USTAR hello.txt (mode 0644, mtime 0, "hello world\n"), encoded by native
// zstd 1.5.7 at level 3. The pure Rust profile must decode the same bytes.
const NATIVE_TAR_ZSTD: &[u8] = &[
    40, 181, 47, 253, 4, 88, 157, 2, 0, 36, 3, 104, 101, 108, 108, 111, 46, 116, 120, 116, 0, 48,
    48, 48, 48, 54, 52, 52, 48, 48, 48, 48, 48, 49, 55, 54, 48, 52, 0, 32, 48, 117, 115, 116, 97,
    114, 0, 48, 48, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 10, 11, 0, 20, 5, 120,
    160, 101, 27, 42, 185, 57, 10, 0, 192, 16, 7, 171, 152, 105, 67, 101, 240, 179, 24, 0, 199,
    202, 101, 110, 2, 72, 86, 171, 169, 196,
];

#[test]
fn native_zstd_fixture_decodes_and_extracts() -> TestResult<()> {
    let decoded = decode_zstd(NATIVE_TAR_ZSTD, 10_240)?;
    assert_eq!(decoded.len(), 10_240);
    let entries = extract_tar_zstd(NATIVE_TAR_ZSTD, &default_limits())?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "hello.txt");
    assert_eq!(entries[0].data, b"hello world\n");
    Ok(())
}

#[test]
fn native_zstd_fixture_rejects_truncation_and_overflow() -> TestResult<()> {
    assert!(decode_zstd(&NATIVE_TAR_ZSTD[..NATIVE_TAR_ZSTD.len() / 2], 10_240).is_err());
    expect_malicious(decode_zstd(NATIVE_TAR_ZSTD, 10_239), "exceeds limit")
}

#[cfg(all(feature = "archive-ruzstd", not(feature = "archive-zstd")))]
#[test]
fn ruzstd_dictionary_decoding_is_explicitly_unsupported() -> TestResult<()> {
    match decode_zstd_with_dict(NATIVE_TAR_ZSTD, b"dictionary", 10_240) {
        Err(ExtractError::Failed(message)) => {
            assert!(message.contains("Dictionary decoding is not supported"))
        }
        result => {
            return Err(anyhow!(
                "expected unsupported dictionary error, got {result:?}"
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "archive-zstd")]
mod zstd_tests {
    use std::io::Write;
    use substrate::archive::*;

    use super::{TestResult, default_limits, expect_malicious, make_tar};

    fn zstd_compress(data: &[u8], level: i32) -> TestResult<Vec<u8>> {
        let mut encoder = zstd::Encoder::new(Vec::new(), level)?;
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    #[test]
    fn test_decode_zstd_roundtrip() -> TestResult<()> {
        let original = b"hello zstd world! This is some test data for compression.";
        let compressed = zstd_compress(original, 3)?;

        let decoded = decode_zstd(&compressed, 1024 * 1024)?;
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_decode_zstd_limit() -> TestResult<()> {
        let data = vec![0xCC; 4096];
        let compressed = zstd_compress(&data, 1)?;

        expect_malicious(decode_zstd(&compressed, 100), "exceeds limit")
    }

    #[test]
    fn test_extract_tar_zstd() -> TestResult<()> {
        let tar_bytes = make_tar(&[("test.txt", b"compressed tar content")])?;
        let compressed = zstd_compress(&tar_bytes, 3)?;

        let entries = extract_tar_zstd(&compressed, &default_limits())?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "test.txt");
        assert_eq!(entries[0].data, b"compressed tar content");
        Ok(())
    }

    #[test]
    fn test_encode_decode_zstd_roundtrip() -> TestResult<()> {
        let original = b"encode-decode roundtrip test data for zstd compression";
        let compressed = encode_zstd(original, 3)?;
        let decoded = decode_zstd(&compressed, 1024 * 1024)?;
        assert_eq!(decoded, original.to_vec());
        Ok(())
    }

    #[test]
    fn test_encode_decode_zstd_with_dict_roundtrip() -> TestResult<()> {
        let dict_data = b"this is the dictionary data that provides context for compression";
        let original = b"this is the dictionary data with some modifications for delta";
        let compressed = encode_zstd_with_dict(original, dict_data, 3)?;
        let decoded = decode_zstd_with_dict(&compressed, dict_data, 1024 * 1024)?;
        assert_eq!(decoded, original.to_vec());
        Ok(())
    }

    #[test]
    fn test_extract_and_verify_tar_zstd_multiple_small_files() -> TestResult<()> {
        let mut entries = Vec::new();
        let mut tree_entries = Vec::new();
        let mut total_size: u64 = 0;
        for i in 0..10 {
            let name = format!("file_{i}.txt");
            let content = format!("{i}").into_bytes();
            total_size += content.len() as u64;
            tree_entries.push(substrate::tree::TreeEntry::File {
                name: name.clone(),
                content: content.clone(),
                executable: false,
            });
            entries.push((name, content));
        }

        let slice_entries: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, c)| (n.as_str(), c.as_slice()))
            .collect();
        let tar_bytes = make_tar(&slice_entries)?;
        let compressed = zstd_compress(&tar_bytes, 3)?;

        let tree_hash = substrate::tree::compute_hash_from_entries(&tree_entries, &[])?;

        let mut spore: substrate::Spore = serde_json::from_value(serde_json::json!({
            "$schema": "https://cmn.dev/schemas/v1/spore.json",
            "capsule": {
                "uri": "cmn://example.com/placeholder",
                "core": {
                    "name": "test-small-files",
                    "domain": "example.com",
                    "synopsis": "Testing multiple small files framing",
                    "intent": ["test"],
                    "license": "MIT",
                    "size_bytes": total_size,
                    "tree": {
                        "algorithm": substrate::tree::blob_tree_blake3_nfc::ALGORITHM,
                        "hash": tree_hash
                    }
                },
                "core_signature": "ed25519.fakesig",
                "dist": []
            },
            "capsule_signature": "ed25519.fakesig"
        }))?;

        let uri_hash = spore.computed_uri_hash_from_tree_hash(&tree_hash)?;
        spore.capsule.uri = format!("cmn://example.com/{uri_hash}");

        let extracted =
            extract_and_verify_tar_zstd(&compressed, &spore, &uri_hash, &default_limits())?;
        assert_eq!(extracted.len(), 10);
        Ok(())
    }
}
