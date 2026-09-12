//! Parses immutable GitHub Cargo sources and inspects bounded commit archives as inert data.
//! No Git executable, checkout, hook, submodule, filter, or crate code is invoked here.

use crate::archive_inspector::{ArchiveInspection, inspect_files};
use crate::findings::Finding;
use crate::{Result, error};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

const MAX_ENTRIES: usize = 16_384;
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RELEVANT_ENTRY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubSource {
    pub owner: String,
    pub repository: String,
    pub commit: String,
}

impl GitHubSource {
    pub fn parse(source: &str) -> std::result::Result<Self, String> {
        let rest = source
            .strip_prefix("git+https://github.com/")
            .ok_or_else(|| {
                "only HTTPS GitHub sources are currently supported by the bounded no-checkout reviewer"
                    .to_owned()
            })?;
        let (location, commit) = rest
            .rsplit_once('#')
            .ok_or_else(|| "Cargo.lock does not contain an exact Git commit".to_owned())?;
        if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Cargo.lock Git identity is not a full 40-hex commit".to_owned());
        }
        let repository_path = location.split_once('?').map_or(location, |(path, _)| path);
        let repository_path = repository_path
            .trim_end_matches('/')
            .trim_end_matches(".git");
        let mut parts = repository_path.split('/');
        let owner = parts.next().unwrap_or_default();
        let repository = parts.next().unwrap_or_default();
        if owner.is_empty()
            || repository.is_empty()
            || parts.next().is_some()
            || !safe_component(owner)
            || !safe_component(repository)
        {
            return Err("GitHub source does not have a safe owner/repository path".to_owned());
        }
        Ok(Self {
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            commit: commit.to_ascii_lowercase(),
        })
    }

    pub fn archive_url(&self) -> String {
        format!(
            "https://codeload.github.com/{}/{}/tar.gz/{}",
            self.owner, self.repository, self.commit
        )
    }

    pub fn commit_url(&self) -> String {
        format!(
            "https://github.com/{}/{}/tree/{}",
            self.owner, self.repository, self.commit
        )
    }
}

fn safe_component(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug)]
pub struct GitArchiveInspection {
    pub inspection: ArchiveInspection,
    pub content_sha256: String,
}

pub fn inspect_git_archive_for_review(
    bytes: &[u8],
    artifact_name: &str,
    artifact_version: &str,
) -> Result<GitArchiveInspection> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut relevant_files = BTreeMap::<PathBuf, Vec<u8>>::new();
    let mut tree_records = Vec::<(PathBuf, u32, [u8; 32])>::new();
    let mut seen_paths = BTreeSet::new();
    let mut archive_root = None;
    let mut count = 0usize;
    let mut total = 0u64;

    for entry in archive.entries()? {
        let mut entry = entry?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(error(format!(
                "Git archive exceeds {MAX_ENTRIES} entry limit"
            )));
        }
        let kind = entry.header().entry_type();
        if kind.is_pax_global_extensions()
            || kind.is_pax_local_extensions()
            || kind.is_gnu_longname()
            || kind.is_gnu_longlink()
        {
            total = total
                .checked_add(entry.size())
                .ok_or_else(|| error("Git archive declared size overflow"))?;
            if total > MAX_DECOMPRESSED_BYTES {
                return Err(error(format!(
                    "Git archive exceeds {MAX_DECOMPRESSED_BYTES} decompressed byte limit"
                )));
            }
            continue;
        }
        let path = entry.path()?.into_owned();
        validate_path(&path)?;
        let root = path
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                _ => None,
            })
            .ok_or_else(|| error("invalid Git archive root"))?;
        if archive_root
            .as_ref()
            .is_some_and(|expected| expected != &root)
        {
            return Err(error("Git archive contains multiple top-level roots"));
        }
        archive_root.get_or_insert(root);

        if kind.is_symlink() || kind.is_hard_link() {
            return Err(error(format!(
                "Git archive contains link entry {}; link traversal is not accepted",
                path.display()
            )));
        }
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(error(format!(
                "Git archive contains unsupported entry type at {}",
                path.display()
            )));
        }

        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| error("Git archive declared size overflow"))?;
        if total > MAX_DECOMPRESSED_BYTES {
            return Err(error(format!(
                "Git archive exceeds {MAX_DECOMPRESSED_BYTES} decompressed byte limit"
            )));
        }
        let relative = strip_root(&path)?;
        if !seen_paths.insert(relative.clone()) {
            return Err(error(format!(
                "Git archive contains duplicate path {}",
                relative.display()
            )));
        }
        if relative == Path::new(".gitmodules") {
            return Err(error(
                "Git dependency declares submodules; their contents are outside the reviewed commit archive",
            ));
        }
        let mut contents = Vec::with_capacity(size.min(64 * 1024) as usize);
        entry
            .by_ref()
            .take(MAX_DECOMPRESSED_BYTES + 1)
            .read_to_end(&mut contents)?;
        if contents.len() as u64 != size {
            return Err(error("Git archive entry size did not match its header"));
        }
        if contents.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
            return Err(error(format!(
                "Git archive contains an unresolved Git LFS pointer at {}",
                relative.display()
            )));
        }
        let mode = entry.header().mode().unwrap_or(0) & 0o777;
        tree_records.push((relative.clone(), mode, Sha256::digest(&contents).into()));

        let relevant = relative
            .file_name()
            .is_some_and(|name| name == "Cargo.toml" || name == "Cargo.toml.orig")
            || relative
                .extension()
                .is_some_and(|extension| extension == "rs");
        if relevant {
            if size > MAX_RELEVANT_ENTRY_BYTES {
                return Err(error(format!(
                    "relevant Git archive entry {} exceeds {MAX_RELEVANT_ENTRY_BYTES} byte limit",
                    relative.display()
                )));
            }
            relevant_files.insert(relative, contents);
        }
    }

    if tree_records.is_empty() {
        return Err(error("Git archive contains no regular files"));
    }
    tree_records.sort_by(|left, right| left.0.cmp(&right.0));
    let mut tree_hasher = Sha256::new();
    tree_hasher.update(b"cargo-wrapper-supply-chain-guard-git-tree-v1\0");
    for (path, mode, digest) in &tree_records {
        let path = path
            .to_str()
            .ok_or_else(|| error("Git archive contains a non-UTF-8 path"))?;
        tree_hasher.update((path.len() as u64).to_be_bytes());
        tree_hasher.update(path.as_bytes());
        tree_hasher.update(mode.to_be_bytes());
        tree_hasher.update(digest);
    }
    let content_sha256 = format!("{:x}", tree_hasher.finalize());

    let package_root = find_package_root(&relevant_files, artifact_name, artifact_version)?;
    let mut package_files = BTreeMap::new();
    for (path, contents) in relevant_files {
        if let Ok(relative) = path.strip_prefix(&package_root) {
            package_files.insert(relative.to_path_buf(), contents);
        }
    }
    let mut inspection = inspect_files(&package_files)?;
    inspection.findings.insert(Finding::new(
        "git-source",
        "dependency is supplied by an immutable Git commit rather than a registry-checksummed release; explicit trust is required for this exact commit and tree digest",
    ));
    Ok(GitArchiveInspection {
        inspection,
        content_sha256,
    })
}

fn find_package_root(
    files: &BTreeMap<PathBuf, Vec<u8>>,
    expected_name: &str,
    expected_version: &str,
) -> Result<PathBuf> {
    let manifests: BTreeMap<_, toml::Value> = files
        .iter()
        .filter(|(path, _)| path.file_name().is_some_and(|name| name == "Cargo.toml"))
        .map(|(path, bytes)| {
            let text = std::str::from_utf8(bytes)?;
            Ok((path.clone(), toml::from_str(text)?))
        })
        .collect::<Result<_>>()?;
    let mut matches = Vec::new();
    for (path, manifest) in &manifests {
        let package = manifest.get("package");
        let name = package
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str);
        if name != Some(expected_name) {
            continue;
        }
        let version = package
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .or_else(|| inherited_workspace_version(path, &manifests));
        if version.as_deref() == Some(expected_version) {
            matches.push(path.parent().unwrap_or(Path::new("")).to_path_buf());
        }
    }
    match matches.as_slice() {
        [root] => Ok(root.clone()),
        [] => Err(error(format!(
            "Git commit archive has no unambiguous Cargo package {expected_name} {expected_version}"
        ))),
        _ => Err(error(format!(
            "Git commit archive contains multiple Cargo packages matching {expected_name} {expected_version}"
        ))),
    }
}

fn inherited_workspace_version(
    manifest_path: &Path,
    manifests: &BTreeMap<PathBuf, toml::Value>,
) -> Option<String> {
    let manifest = manifests.get(manifest_path)?;
    let inherits = manifest
        .get("package")?
        .get("version")?
        .get("workspace")?
        .as_bool()?;
    if !inherits {
        return None;
    }
    let mut directory = manifest_path.parent();
    while let Some(parent) = directory {
        let candidate = parent.join("Cargo.toml");
        if let Some(version) = manifests
            .get(&candidate)
            .and_then(|root| root.get("workspace"))
            .and_then(|workspace| workspace.get("package"))
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str)
        {
            return Some(version.to_owned());
        }
        directory = parent.parent();
    }
    None
}

fn validate_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(error(format!(
            "unsafe Git archive path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn strip_root(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    components.next();
    let relative: PathBuf = components.collect();
    if relative.as_os_str().is_empty() {
        return Err(error("Git archive entry has no path below its root"));
    }
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let encoder = GzEncoder::new(&mut bytes, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *contents).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        bytes
    }

    #[test]
    fn parses_exact_github_lock_source() {
        let source = GitHubSource::parse(
            "git+https://github.com/acme/demo.git?tag=v1#0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();
        assert_eq!(source.owner, "acme");
        assert_eq!(source.repository, "demo");
        assert!(source.archive_url().ends_with(&source.commit));
    }

    #[test]
    fn inspects_matching_package_and_hashes_complete_tree() {
        let bytes = archive(&[
            (
                "demo-rev/Cargo.toml",
                b"[package]\nname='demo'\nversion='1.0.0'\nbuild='build.rs'",
            ),
            (
                "demo-rev/build.rs",
                b"fn main(){std::process::Command::new(\"sh\").status();}",
            ),
            ("demo-rev/README.md", b"data"),
        ]);
        let result = inspect_git_archive_for_review(&bytes, "demo", "1.0.0").unwrap();
        assert_eq!(result.content_sha256.len(), 64);
        assert!(
            result
                .inspection
                .findings
                .iter()
                .any(|finding| finding.capability == "build-script")
        );
        assert!(
            result
                .inspection
                .findings
                .iter()
                .any(|finding| finding.capability == "process-execution")
        );
        assert!(
            result
                .inspection
                .findings
                .iter()
                .any(|finding| finding.capability == "git-source")
        );
    }

    #[test]
    fn rejects_submodules_and_lfs_pointers() {
        let manifest = (
            "demo-rev/Cargo.toml",
            b"[package]\nname='demo'\nversion='1.0.0'".as_slice(),
        );
        let submodule = archive(&[manifest, ("demo-rev/.gitmodules", b"[submodule]")]);
        assert!(inspect_git_archive_for_review(&submodule, "demo", "1.0.0").is_err());
        let lfs = archive(&[
            manifest,
            (
                "demo-rev/data",
                b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\n",
            ),
        ]);
        assert!(inspect_git_archive_for_review(&lfs, "demo", "1.0.0").is_err());
    }

    #[test]
    fn source_only_git_package_still_requires_an_explicit_trust_decision() {
        let bytes = archive(&[(
            "demo-rev/Cargo.toml",
            b"[package]\nname='demo'\nversion='1.0.0'\nbuild=false",
        )]);
        let result = inspect_git_archive_for_review(&bytes, "demo", "1.0.0").unwrap();
        assert_eq!(result.inspection.findings.len(), 1);
        assert_eq!(
            result.inspection.findings.first().unwrap().capability,
            "git-source"
        );
    }
}
