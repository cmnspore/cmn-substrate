//! Directory traversal with filtering for tree hashing, archive packing, and mtime computation.
//!
//! Substrate defines the traversal logic and filtering rules; callers provide I/O
//! via the [`DirReader`] trait. This keeps substrate zero-I/O and WASM-compatible
//! while ensuring consistent filtering everywhere.

use std::path::Path;

use anyhow::Result;

use super::blob_tree_blake3_nfc::TreeEntry;

// Re-use the exact same predicate the hash layer uses.
/// Check whether a filename should be excluded (exact name match).
///
/// This is the canonical predicate used by [`walk_dir`] and the hash layer.
pub fn should_exclude(name: &str, exclude_names: &[String]) -> bool {
    exclude_names.iter().any(|pattern| name == pattern)
}

/// A single entry returned by [`DirReader::read_dir`].
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_file: bool,
}

/// Filesystem abstraction so substrate can drive traversal without doing I/O itself.
pub trait DirReader {
    /// List immediate children of a directory.
    fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>>;
    /// Read the full contents of a file.
    fn read_file(&self, path: &Path) -> Result<Vec<u8>>;
    /// Check whether a file has the executable bit set.
    fn is_executable(&self, path: &Path) -> Result<bool>;
    /// Check whether a path is ignored by follow_rules (gitignore-style).
    fn is_ignored(&self, path: &Path, is_dir: bool) -> bool;
    /// Return the file's modification time as milliseconds since the Unix epoch.
    fn mtime_ms(&self, path: &Path) -> Result<Option<u64>>;
}

/// Walk a directory tree and produce [`TreeEntry`] values.
///
/// `exclude_names` filters by exact filename match (same rule as the hash layer).
/// `reader.is_ignored()` handles follow_rules / gitignore-style filtering.
pub fn walk_dir(
    reader: &dyn DirReader,
    dir_path: &Path,
    exclude_names: &[String],
) -> Result<Vec<TreeEntry>> {
    let children = reader.read_dir(dir_path)?;
    let mut entries = Vec::new();

    for child in children {
        if should_exclude(&child.name, exclude_names) {
            continue;
        }

        let child_path = dir_path.join(&child.name);

        if reader.is_ignored(&child_path, child.is_dir) {
            continue;
        }

        if child.is_file {
            let content = reader.read_file(&child_path)?;
            let executable = reader.is_executable(&child_path)?;
            entries.push(TreeEntry::File {
                name: child.name,
                content,
                executable,
            });
        } else if child.is_dir {
            let sub = walk_dir(reader, &child_path, exclude_names)?;
            entries.push(TreeEntry::Directory {
                name: child.name,
                children: sub,
            });
        }
    }

    Ok(entries)
}

/// Flatten a recursive `TreeEntry` tree into a flat list of `(path, content, executable)`.
///
/// Only files appear in the output. Paths use `/` as separator.
pub fn flatten_entries(entries: &[TreeEntry]) -> Vec<(String, Vec<u8>, bool)> {
    let mut result = Vec::new();
    flatten_inner(entries, "", &mut result);
    result
}

fn flatten_inner(entries: &[TreeEntry], prefix: &str, result: &mut Vec<(String, Vec<u8>, bool)>) {
    for entry in entries {
        match entry {
            TreeEntry::File {
                name,
                content,
                executable,
            } => {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", prefix, name)
                };
                result.push((path, content.clone(), *executable));
            }
            TreeEntry::Directory { name, children } => {
                let dir_prefix = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", prefix, name)
                };
                flatten_inner(children, &dir_prefix, result);
            }
        }
    }
}

/// Walk a directory and return the maximum file modification time (epoch ms).
///
/// Uses the same `exclude_names` + `is_ignored` filtering as [`walk_dir`].
pub fn max_mtime(reader: &dyn DirReader, dir_path: &Path, exclude_names: &[String]) -> Result<u64> {
    let children = reader.read_dir(dir_path)?;
    let mut max_ms: u64 = 0;

    for child in children {
        if should_exclude(&child.name, exclude_names) {
            continue;
        }

        let child_path = dir_path.join(&child.name);

        if reader.is_ignored(&child_path, child.is_dir) {
            continue;
        }

        if child.is_file {
            if let Some(ms) = reader.mtime_ms(&child_path)? {
                if ms > max_ms {
                    max_ms = ms;
                }
            }
        } else if child.is_dir {
            let sub = max_mtime(reader, &child_path, exclude_names)?;
            if sub > max_ms {
                max_ms = sub;
            }
        }
    }

    Ok(max_ms)
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// In-memory filesystem for testing.
    struct MockFs {
        /// path → (content, executable, mtime_ms)
        files: BTreeMap<PathBuf, (Vec<u8>, bool, u64)>,
        /// path → list of child names
        dirs: BTreeMap<PathBuf, Vec<String>>,
        /// paths that should be "ignored" (gitignore simulation)
        ignored: Vec<PathBuf>,
    }

    impl MockFs {
        fn new() -> Self {
            Self {
                files: BTreeMap::new(),
                dirs: BTreeMap::new(),
                ignored: Vec::new(),
            }
        }

        fn add_file(&mut self, path: &str, content: &[u8], executable: bool, mtime_ms: u64) {
            let p = PathBuf::from(path);
            self.files
                .insert(p.clone(), (content.to_vec(), executable, mtime_ms));
            // Register in parent dir
            if let Some(parent) = p.parent() {
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                self.dirs
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(name);
                // Ensure parent dirs exist up the chain
                self.ensure_dir(parent);
            }
        }

        fn add_dir(&mut self, path: &str) {
            let p = PathBuf::from(path);
            self.ensure_dir(&p);
        }

        fn ensure_dir(&mut self, path: &Path) {
            if !self.dirs.contains_key(path) {
                self.dirs.insert(path.to_path_buf(), Vec::new());
            }
            if let Some(parent) = path.parent() {
                if parent != path {
                    let name = path.file_name().unwrap().to_string_lossy().to_string();
                    let siblings = self.dirs.entry(parent.to_path_buf()).or_default();
                    if !siblings.contains(&name) {
                        siblings.push(name);
                    }
                    self.ensure_dir(parent);
                }
            }
        }

        fn ignore(&mut self, path: &str) {
            self.ignored.push(PathBuf::from(path));
        }
    }

    impl DirReader for MockFs {
        fn read_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
            let children = self.dirs.get(path).cloned().unwrap_or_default();
            Ok(children
                .into_iter()
                .map(|name| {
                    let child_path = path.join(&name);
                    DirEntry {
                        name,
                        is_dir: self.dirs.contains_key(&child_path),
                        is_file: self.files.contains_key(&child_path),
                    }
                })
                .collect())
        }

        fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
            self.files
                .get(path)
                .map(|(content, _, _)| content.clone())
                .ok_or_else(|| anyhow::anyhow!("file not found: {}", path.display()))
        }

        fn is_executable(&self, path: &Path) -> Result<bool> {
            Ok(self
                .files
                .get(path)
                .map(|(_, exec, _)| *exec)
                .unwrap_or(false))
        }

        fn is_ignored(&self, path: &Path, _is_dir: bool) -> bool {
            self.ignored.iter().any(|p| p == path)
        }

        fn mtime_ms(&self, path: &Path) -> Result<Option<u64>> {
            Ok(self.files.get(path).map(|(_, _, mtime)| *mtime))
        }
    }

    // ─── flatten_entries tests ───

    #[test]
    fn flatten_empty_tree() {
        let result = flatten_entries(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn flatten_single_file() {
        let entries = vec![TreeEntry::File {
            name: "hello.txt".to_string(),
            content: b"hello".to_vec(),
            executable: false,
        }];
        let flat = flatten_entries(&entries);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].0, "hello.txt");
        assert_eq!(flat[0].1, b"hello");
        assert!(!flat[0].2);
    }

    #[test]
    fn flatten_executable_flag() {
        let entries = vec![TreeEntry::File {
            name: "run.sh".to_string(),
            content: b"#!/bin/sh".to_vec(),
            executable: true,
        }];
        let flat = flatten_entries(&entries);
        assert!(flat[0].2);
    }

    #[test]
    fn flatten_multiple_files_no_dirs() {
        let entries = vec![
            TreeEntry::File {
                name: "a.txt".to_string(),
                content: b"a".to_vec(),
                executable: false,
            },
            TreeEntry::File {
                name: "b.txt".to_string(),
                content: b"b".to_vec(),
                executable: false,
            },
        ];
        let flat = flatten_entries(&entries);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].0, "a.txt");
        assert_eq!(flat[1].0, "b.txt");
    }

    #[test]
    fn flatten_nested_dir() {
        let entries = vec![TreeEntry::Directory {
            name: "src".to_string(),
            children: vec![TreeEntry::File {
                name: "lib.rs".to_string(),
                content: b"pub fn foo() {}".to_vec(),
                executable: false,
            }],
        }];
        let flat = flatten_entries(&entries);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].0, "src/lib.rs");
    }

    #[test]
    fn flatten_deep_nesting() {
        let entries = vec![TreeEntry::Directory {
            name: "a".to_string(),
            children: vec![TreeEntry::Directory {
                name: "b".to_string(),
                children: vec![TreeEntry::File {
                    name: "c.txt".to_string(),
                    content: b"deep".to_vec(),
                    executable: false,
                }],
            }],
        }];
        let flat = flatten_entries(&entries);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].0, "a/b/c.txt");
        assert_eq!(flat[0].1, b"deep");
    }

    #[test]
    fn flatten_mixed_files_and_dirs() {
        let entries = vec![
            TreeEntry::File {
                name: "README.md".to_string(),
                content: b"# Hello".to_vec(),
                executable: false,
            },
            TreeEntry::Directory {
                name: "src".to_string(),
                children: vec![
                    TreeEntry::File {
                        name: "main.rs".to_string(),
                        content: b"fn main() {}".to_vec(),
                        executable: false,
                    },
                    TreeEntry::File {
                        name: "lib.rs".to_string(),
                        content: b"pub mod foo;".to_vec(),
                        executable: false,
                    },
                ],
            },
        ];
        let flat = flatten_entries(&entries);
        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].0, "README.md");
        assert_eq!(flat[1].0, "src/main.rs");
        assert_eq!(flat[2].0, "src/lib.rs");
    }

    #[test]
    fn flatten_empty_directory_produces_nothing() {
        let entries = vec![TreeEntry::Directory {
            name: "empty".to_string(),
            children: vec![],
        }];
        let flat = flatten_entries(&entries);
        assert!(flat.is_empty());
    }

    #[test]
    fn flatten_paths_use_forward_slash() {
        let entries = vec![TreeEntry::Directory {
            name: "dir".to_string(),
            children: vec![TreeEntry::Directory {
                name: "sub".to_string(),
                children: vec![TreeEntry::File {
                    name: "f.txt".to_string(),
                    content: vec![],
                    executable: false,
                }],
            }],
        }];
        let flat = flatten_entries(&entries);
        assert_eq!(flat[0].0, "dir/sub/f.txt");
        assert!(!flat[0].0.contains('\\'));
    }

    #[test]
    fn flatten_preserves_content() {
        let content = vec![0u8, 1, 2, 255, 128, 64];
        let entries = vec![TreeEntry::File {
            name: "binary.bin".to_string(),
            content: content.clone(),
            executable: false,
        }];
        let flat = flatten_entries(&entries);
        assert_eq!(flat[0].1, content);
    }

    // ─── walk_dir tests ───

    #[test]
    fn walk_basic() {
        let mut fs = MockFs::new();
        fs.add_file("/root/a.txt", b"aaa", false, 1000);
        fs.add_file("/root/b.txt", b"bbb", false, 2000);

        let entries = walk_dir(&fs, Path::new("/root"), &[]).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn walk_exclude_names_exact_match() {
        let mut fs = MockFs::new();
        fs.add_file("/root/keep.txt", b"keep", false, 1000);
        fs.add_dir("/root/.git");
        fs.add_file("/root/.git/config", b"git", false, 1000);

        let entries = walk_dir(&fs, Path::new("/root"), &[".git".to_string()]).unwrap();
        // .git dir should be excluded
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            TreeEntry::File { name, .. } => assert_eq!(name, "keep.txt"),
            _ => panic!("expected file"),
        }
    }

    #[test]
    fn walk_exclude_names_no_substring_match() {
        // Regression test: exclude_names ".git" must NOT exclude ".gitignore"
        let mut fs = MockFs::new();
        fs.add_file("/root/.gitignore", b"*.tmp", false, 1000);
        fs.add_file("/root/file.txt", b"ok", false, 1000);

        let entries = walk_dir(&fs, Path::new("/root"), &[".git".to_string()]).unwrap();
        let names: Vec<&str> = entries
            .iter()
            .map(|e| match e {
                TreeEntry::File { name, .. } | TreeEntry::Directory { name, .. } => name.as_str(),
            })
            .collect();
        assert!(
            names.contains(&".gitignore"),
            "should NOT exclude .gitignore when excluding .git"
        );
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn walk_exclude_names_nested_dir() {
        // .git inside a subdir should also be excluded
        let mut fs = MockFs::new();
        fs.add_file("/root/src/code.rs", b"fn main(){}", false, 1000);
        fs.add_dir("/root/src/.git");
        fs.add_file("/root/src/.git/HEAD", b"ref", false, 1000);

        let entries = walk_dir(&fs, Path::new("/root"), &[".git".to_string()]).unwrap();
        let flat = flatten_entries(&entries);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].0, "src/code.rs");
    }

    #[test]
    fn walk_is_ignored_respected() {
        let mut fs = MockFs::new();
        fs.add_file("/root/keep.txt", b"keep", false, 1000);
        fs.add_file("/root/ignored.tmp", b"tmp", false, 1000);
        fs.ignore("/root/ignored.tmp");

        let entries = walk_dir(&fs, Path::new("/root"), &[]).unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            TreeEntry::File { name, .. } => assert_eq!(name, "keep.txt"),
            _ => panic!("expected file"),
        }
    }

    #[test]
    fn walk_executable_detected() {
        let mut fs = MockFs::new();
        fs.add_file("/root/script.sh", b"#!/bin/sh", true, 1000);
        fs.add_file("/root/data.txt", b"data", false, 1000);

        let entries = walk_dir(&fs, Path::new("/root"), &[]).unwrap();
        for entry in &entries {
            if let TreeEntry::File {
                name, executable, ..
            } = entry
            {
                if name == "script.sh" {
                    assert!(*executable);
                } else {
                    assert!(!*executable);
                }
            }
        }
    }

    #[test]
    fn walk_nested_structure() {
        let mut fs = MockFs::new();
        fs.add_file("/root/README.md", b"# Hi", false, 1000);
        fs.add_file("/root/src/main.rs", b"fn main(){}", false, 2000);
        fs.add_file("/root/src/util/helpers.rs", b"pub fn help(){}", false, 3000);

        let entries = walk_dir(&fs, Path::new("/root"), &[]).unwrap();
        let flat = flatten_entries(&entries);
        let paths: Vec<&str> = flat.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(paths.contains(&"README.md"));
        assert!(paths.contains(&"src/main.rs"));
        assert!(paths.contains(&"src/util/helpers.rs"));
    }

    // ─── max_mtime tests ───

    #[test]
    fn max_mtime_returns_largest() {
        let mut fs = MockFs::new();
        fs.add_file("/root/old.txt", b"old", false, 1000);
        fs.add_file("/root/new.txt", b"new", false, 5000);
        fs.add_file("/root/mid.txt", b"mid", false, 3000);

        let ms = max_mtime(&fs, Path::new("/root"), &[]).unwrap();
        assert_eq!(ms, 5000);
    }

    #[test]
    fn max_mtime_respects_exclude_names() {
        let mut fs = MockFs::new();
        fs.add_file("/root/code.rs", b"fn main(){}", false, 1000);
        fs.add_dir("/root/.git");
        fs.add_file("/root/.git/index", b"git-index", false, 9999);

        let ms = max_mtime(&fs, Path::new("/root"), &[".git".to_string()]).unwrap();
        // .git/index has mtime 9999 but should be excluded
        assert_eq!(ms, 1000);
    }

    #[test]
    fn max_mtime_respects_is_ignored() {
        let mut fs = MockFs::new();
        fs.add_file("/root/code.rs", b"fn main(){}", false, 1000);
        fs.add_file("/root/build.tmp", b"tmp", false, 9999);
        fs.ignore("/root/build.tmp");

        let ms = max_mtime(&fs, Path::new("/root"), &[]).unwrap();
        assert_eq!(ms, 1000);
    }

    #[test]
    fn max_mtime_nested() {
        let mut fs = MockFs::new();
        fs.add_file("/root/a.txt", b"a", false, 100);
        fs.add_file("/root/sub/b.txt", b"b", false, 500);

        let ms = max_mtime(&fs, Path::new("/root"), &[]).unwrap();
        assert_eq!(ms, 500);
    }

    #[test]
    fn max_mtime_empty_dir() {
        let mut fs = MockFs::new();
        fs.add_dir("/root");

        let ms = max_mtime(&fs, Path::new("/root"), &[]).unwrap();
        assert_eq!(ms, 0);
    }
}
