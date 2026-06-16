#![cfg(any(feature = "archive-ruzstd", feature = "archive-zstd"))]

use anyhow::{anyhow, Result as TestResult};
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

#[cfg(feature = "archive-zstd")]
mod zstd_tests {
    use std::io::Write;
    use substrate::archive::*;

    use super::{default_limits, expect_malicious, make_tar, TestResult};

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
}

#[test]
fn verify_cmn_spec_archive_hash() -> TestResult<()> {
    let archive_path = "/tmp/test-archive.tar.zst";
    if !std::path::Path::new(archive_path).exists() {
        return Ok(());
    }
    let bytes = std::fs::read(archive_path)?;
    let limits = substrate::archive::ExtractLimits {
        max_bytes: 1_000_000_000,
        max_files: 100_000,
        max_file_bytes: 500_000_000,
    };
    let ae = substrate::archive::extract_tar_zstd(&bytes, &limits)?;

    fn to_tree(entries: &[substrate::archive::ArchiveEntry]) -> Vec<substrate::TreeEntry> {
        use std::collections::BTreeMap;
        let mut files = Vec::new();
        let mut dirs: BTreeMap<String, Vec<(String, &substrate::archive::ArchiveEntry)>> =
            BTreeMap::new();
        for e in entries {
            if e.kind == substrate::archive::EntryKind::Directory {
                continue;
            }
            let p = e.path.trim_start_matches("./").trim_start_matches('/');
            if p.is_empty() {
                continue;
            }
            if let Some(i) = p.find('/') {
                dirs.entry(p[..i].to_string())
                    .or_default()
                    .push((p[i + 1..].to_string(), e));
            } else {
                files.push(substrate::TreeEntry::File {
                    name: p.to_string(),
                    content: e.data.clone(),
                    executable: e.executable,
                });
            }
        }
        let mut result = Vec::new();
        for (d, ch) in dirs {
            let child_ae: Vec<substrate::archive::ArchiveEntry> = ch
                .into_iter()
                .map(|(r, e)| substrate::archive::ArchiveEntry {
                    path: r,
                    kind: e.kind.clone(),
                    data: e.data.clone(),
                    executable: e.executable,
                })
                .collect();
            result.push(substrate::TreeEntry::Directory {
                name: d,
                children: to_tree(&child_ae),
            });
        }
        result.extend(files);
        result
    }

    let tree = to_tree(&ae);
    let config = substrate::SporeTree {
        algorithm: "blob_tree_blake3_nfc".to_string(),
        exclude_names: vec![".git".to_string()],
        follow_rules: vec![".gitignore".to_string()],
    };
    let hash = substrate::compute_tree_hash_from_entries(&tree, &config)?;
    let expected = "b3.5DzAN1LM3aK9bESYV4nXRkekKgo2Q4Shx2sgsojk1bmn";
    assert_eq!(hash, expected);
    Ok(())
}
