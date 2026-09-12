//! Parses `Cargo.lock` into exact remote artifacts and dependency relationships.
//! Registry entries use checksums; Git entries use the immutable locked commit.

use crate::findings::ArtifactId;
use crate::{Result, error};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
pub struct CargoLock {
    pub package: Option<Vec<LockPackage>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

impl CargoLock {
    pub fn parse(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|parse_error| {
            error(format!(
                "invalid Cargo.lock {}: {parse_error}",
                path.display()
            ))
        })
    }

    pub fn remote_artifacts(&self) -> Result<Vec<ArtifactId>> {
        let mut artifacts = Vec::new();
        for package in self.package.as_deref().unwrap_or_default() {
            let Some(source) = &package.source else {
                continue;
            };
            if source.starts_with("git+") {
                let git = crate::git_source::GitHubSource::parse(source).map_err(|reason| {
                    error(format!(
                        "supply-chain-guard: cannot securely review Git dependency {} {} ({source}): {reason}",
                        package.name, package.version
                    ))
                })?;
                artifacts.push(ArtifactId {
                    source: source.clone(),
                    name: package.name.clone(),
                    version: package.version.clone(),
                    checksum: git.commit,
                });
                continue;
            }
            if !source.starts_with("registry+") && !source.starts_with("sparse+") {
                return Err(error(format!(
                    "supply-chain-guard: unsupported dependency source for {} {}: {source}",
                    package.name, package.version
                )));
            }
            let checksum = package.checksum.clone().ok_or_else(|| {
                error(format!(
                    "supply-chain-guard: registry package {} {} has no checksum; refusing to continue",
                    package.name, package.version
                ))
            })?;
            artifacts.push(ArtifactId {
                source: source.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
                checksum,
            });
        }
        artifacts.sort();
        Ok(artifacts)
    }

    pub fn packages_by_name(&self) -> BTreeMap<&str, Vec<&LockPackage>> {
        let mut result: BTreeMap<&str, Vec<&LockPackage>> = BTreeMap::new();
        for package in self.package.as_deref().unwrap_or_default() {
            result.entry(&package.name).or_default().push(package);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_registry_identity_requires_checksum() {
        let lock: CargoLock = toml::from_str(
            r#"version = 4
[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
"#,
        )
        .unwrap();
        let artifacts = lock.remote_artifacts().unwrap();
        assert_eq!(artifacts[0].checksum, "abc");
    }

    #[test]
    fn exact_github_git_dependencies_use_the_locked_commit_as_identity() {
        let lock: CargoLock = toml::from_str(
            r#"version = 4
[[package]]
name = "demo"
version = "1.0.0"
source = "git+https://github.com/example/demo.git?branch=main#0123456789abcdef0123456789abcdef01234567"
"#,
        )
        .unwrap();
        let artifact = lock.remote_artifacts().unwrap().remove(0);
        assert!(artifact.is_git());
        assert_eq!(
            artifact.checksum,
            "0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn unsupported_or_non_exact_git_dependencies_fail_closed() {
        for source in [
            "git+https://example.invalid/demo#0123456789abcdef0123456789abcdef01234567",
            "git+https://github.com/example/demo#abc",
            "git+ssh://git@github.com/example/demo#0123456789abcdef0123456789abcdef01234567",
        ] {
            let lock: CargoLock = toml::from_str(&format!(
                "version=4\n[[package]]\nname='demo'\nversion='1.0.0'\nsource='{source}'"
            ))
            .unwrap();
            assert!(lock.remote_artifacts().is_err(), "accepted {source}");
        }
    }
}
