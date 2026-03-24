#![cfg(any(feature = "archive-ruzstd", feature = "archive-zstd"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use substrate::archive::*;

fn make_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, &data[..]).unwrap();
    }
    builder.into_inner().unwrap()
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

#[test]
fn test_extract_tar_basic() {
    let tar_bytes = make_tar(&[
        ("hello.txt", b"hello world"),
        ("sub/file.rs", b"fn main() {}"),
    ]);
    let entries = extract_tar(&tar_bytes, &default_limits()).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, "hello.txt");
    assert_eq!(entries[0].kind, EntryKind::File);
    assert_eq!(entries[0].data, b"hello world");
    assert_eq!(entries[1].path, "sub/file.rs");
    assert_eq!(entries[1].data, b"fn main() {}");
}

#[test]
fn test_extract_tar_rejects_symlink() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    builder
        .append_link(&mut header, "evil-link", "/etc/passwd")
        .unwrap();
    let tar_bytes = builder.into_inner().unwrap();

    let err = extract_tar(&tar_bytes, &default_limits()).unwrap_err();
    match err {
        ExtractError::Malicious(msg) => assert!(msg.contains("disallowed entry type")),
        other => panic!("expected Malicious, got: {:?}", other),
    }
}

#[test]
fn test_extract_tar_rejects_path_traversal() {
    let tar_bytes = make_tar_raw_path("../../etc/passwd", b"root:x:0:0");
    let err = extract_tar(&tar_bytes, &default_limits()).unwrap_err();
    match err {
        ExtractError::Malicious(msg) => assert!(msg.contains("path traversal")),
        other => panic!("expected Malicious, got: {:?}", other),
    }
}

#[test]
fn test_extract_tar_rejects_absolute_path() {
    let tar_bytes = make_tar_raw_path("/etc/passwd", b"root:x:0:0");
    let err = extract_tar(&tar_bytes, &default_limits()).unwrap_err();
    match err {
        ExtractError::Malicious(msg) => assert!(msg.contains("path traversal")),
        other => panic!("expected Malicious, got: {:?}", other),
    }
}

#[test]
fn test_extract_tar_file_count_limit() {
    let entries: Vec<(String, Vec<u8>)> =
        (0..5).map(|i| (format!("f{}.txt", i), vec![0u8])).collect();
    let tar_entries: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, d)| (p.as_str(), d.as_slice()))
        .collect();
    let tar_bytes = make_tar(&tar_entries);

    let limits = ExtractLimits {
        max_bytes: 10 * 1024 * 1024,
        max_files: 3,
        max_file_bytes: 5 * 1024 * 1024,
    };
    let err = extract_tar(&tar_bytes, &limits).unwrap_err();
    match err {
        ExtractError::Malicious(msg) => assert!(msg.contains("max file count")),
        other => panic!("expected Malicious, got: {:?}", other),
    }
}

#[test]
fn test_extract_tar_total_bytes_limit() {
    let tar_bytes = make_tar(&[("big.bin", &[0xAA; 1024])]);
    let limits = ExtractLimits {
        max_bytes: 512,
        max_files: 1000,
        max_file_bytes: 5 * 1024 * 1024,
    };
    let err = extract_tar(&tar_bytes, &limits).unwrap_err();
    match err {
        ExtractError::Malicious(msg) => assert!(msg.contains("max extract size")),
        other => panic!("expected Malicious, got: {:?}", other),
    }
}

#[test]
fn test_extract_tar_single_file_limit() {
    let tar_bytes = make_tar(&[("big.bin", &[0xBB; 1024])]);
    let limits = ExtractLimits {
        max_bytes: 10 * 1024 * 1024,
        max_files: 1000,
        max_file_bytes: 512,
    };
    let err = extract_tar(&tar_bytes, &limits).unwrap_err();
    match err {
        ExtractError::Malicious(msg) => assert!(msg.contains("single file exceeds max size")),
        other => panic!("expected Malicious, got: {:?}", other),
    }
}

#[cfg(feature = "archive-zstd")]
mod zstd_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::Write;
    use substrate::archive::*;

    use super::{default_limits, make_tar};

    #[test]
    fn test_decode_zstd_roundtrip() {
        let original = b"hello zstd world! This is some test data for compression.";
        let compressed = {
            let mut encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
            encoder.write_all(original).unwrap();
            encoder.finish().unwrap()
        };

        let decoded = decode_zstd(&compressed, 1024 * 1024).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_zstd_limit() {
        let data = vec![0xCC; 4096];
        let compressed = {
            let mut encoder = zstd::Encoder::new(Vec::new(), 1).unwrap();
            encoder.write_all(&data).unwrap();
            encoder.finish().unwrap()
        };

        let err = decode_zstd(&compressed, 100).unwrap_err();
        match err {
            ExtractError::Malicious(msg) => assert!(msg.contains("exceeds limit")),
            other => panic!("expected Malicious, got: {:?}", other),
        }
    }

    #[test]
    fn test_extract_tar_zstd() {
        let tar_bytes = make_tar(&[("test.txt", b"compressed tar content")]);
        let compressed = {
            let mut encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap()
        };

        let entries = extract_tar_zstd(&compressed, &default_limits()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "test.txt");
        assert_eq!(entries[0].data, b"compressed tar content");
    }

    #[test]
    fn test_encode_decode_zstd_roundtrip() {
        let original = b"encode-decode roundtrip test data for zstd compression";
        let compressed = encode_zstd(original, 3).unwrap();
        let decoded = decode_zstd(&compressed, 1024 * 1024).unwrap();
        assert_eq!(decoded, original.to_vec());
    }

    #[test]
    fn test_encode_decode_zstd_with_dict_roundtrip() {
        let dict_data = b"this is the dictionary data that provides context for compression";
        let original = b"this is the dictionary data with some modifications for delta";
        let compressed = encode_zstd_with_dict(original, dict_data, 3).unwrap();
        let decoded = decode_zstd_with_dict(&compressed, dict_data, 1024 * 1024).unwrap();
        assert_eq!(decoded, original.to_vec());
    }
}

#[test]
fn verify_cmn_spec_archive_hash() {
    let archive_path = "/tmp/test-archive.tar.zst";
    if !std::path::Path::new(archive_path).exists() {
        eprintln!("Skipping: {archive_path} not found");
        return;
    }
    let bytes = std::fs::read(archive_path).unwrap();
    let limits = substrate::archive::ExtractLimits {
        max_bytes: 1_000_000_000,
        max_files: 100_000,
        max_file_bytes: 500_000_000,
    };
    let ae = substrate::archive::extract_tar_zstd(&bytes, &limits).unwrap();

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
                    executable: false,
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
    let hash = substrate::compute_tree_hash_from_entries(&tree, &config).unwrap();
    eprintln!("Computed: {hash}");
    eprintln!("Expected: b3.5DzAN1LM3aK9bESYV4nXRkekKgo2Q4Shx2sgsojk1bmn");
    assert_eq!(hash, "b3.5DzAN1LM3aK9bESYV4nXRkekKgo2Q4Shx2sgsojk1bmn");
}
