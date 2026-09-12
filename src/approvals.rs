//! Persists exact artifact approvals and trusted workspace fingerprints.
//! Approval records are treated as data and matched against immutable identities.

use crate::findings::ArtifactId;
use crate::{Result, error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFile {
    #[serde(default)]
    pub approvals: Vec<ApprovalRecord>,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceRecord>,
    #[serde(default)]
    pub factory_bundles: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub source: String,
    pub name: String,
    pub version: String,
    pub checksum: String,
    /// Complete repository-tree digest for Git artifacts. Registry records omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    #[serde(default)]
    pub approved_findings: BTreeSet<String>,
    #[serde(default)]
    pub scanner_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRecord {
    pub root: String,
    pub fingerprint: String,
    #[serde(default)]
    pub lock_hash: String,
    #[serde(default)]
    pub manifests_hash: String,
}

impl ApprovalRecord {
    pub fn matches(&self, artifact: &ArtifactId) -> bool {
        let identity_matches = self.source == artifact.source
            && self.name == artifact.name
            && self.version == artifact.version
            && self.checksum == artifact.checksum;
        identity_matches
            && (!artifact.is_git() || self.content_sha256.as_deref().is_some_and(valid_sha256))
    }
}

#[derive(Debug)]
pub struct ApprovalStore {
    path: PathBuf,
    data: ApprovalFile,
}

impl ApprovalStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let data = match fs::read_to_string(&path) {
            Ok(contents) => toml::from_str(&contents).map_err(|error| {
                crate::error(format!(
                    "invalid approval file {}: {error}; refusing to continue",
                    path.display()
                ))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ApprovalFile::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, data })
    }

    pub fn default_path() -> Result<PathBuf> {
        if let Some(path) = std::env::var_os("CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_APPROVAL_FILE") {
            return Ok(PathBuf::from(path));
        }
        #[cfg(windows)]
        let directory = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| {
                error("APPDATA is not defined; set CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_APPROVAL_FILE")
            })?
            .join("CargoWrapperSupplyChainGuard");
        #[cfg(not(windows))]
        let directory = if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
            PathBuf::from(path)
        } else {
            let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
                error("HOME is not defined; set CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_APPROVAL_FILE")
            })?;
            home.join(".config")
        };
        #[cfg(not(windows))]
        let directory = directory.join("cargo-wrapper-supply-chain-guard");
        Ok(directory.join("approvals.toml"))
    }

    pub fn approved_findings(&self, artifact: &ArtifactId) -> BTreeSet<String> {
        self.data
            .approvals
            .iter()
            .find(|approval| approval.matches(artifact))
            .map(|approval| approval.approved_findings.clone())
            .unwrap_or_default()
    }

    pub fn has_artifact(&self, artifact: &ArtifactId) -> bool {
        self.data
            .approvals
            .iter()
            .any(|approval| approval.matches(artifact))
    }

    pub fn remember(&mut self, artifact: &ArtifactId, findings: BTreeSet<String>) {
        self.remember_with_content_sha256(artifact, findings, None);
    }

    pub fn remember_with_content_sha256(
        &mut self,
        artifact: &ArtifactId,
        findings: BTreeSet<String>,
        content_sha256: Option<String>,
    ) {
        if let Some(existing) = self
            .data
            .approvals
            .iter_mut()
            .find(|approval| approval.matches(artifact))
        {
            existing.approved_findings.extend(findings);
            existing.scanner_version = crate::scanner::SCANNER_VERSION;
            if content_sha256.is_some() {
                existing.content_sha256 = content_sha256;
            }
            return;
        }
        self.data.approvals.push(ApprovalRecord {
            source: artifact.source.clone(),
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            checksum: artifact.checksum.clone(),
            content_sha256,
            approved_findings: findings,
            scanner_version: crate::scanner::SCANNER_VERSION,
        });
    }

    pub fn content_sha256(&self, artifact: &ArtifactId) -> Option<&str> {
        self.data
            .approvals
            .iter()
            .find(|approval| approval.matches(artifact))
            .and_then(|approval| approval.content_sha256.as_deref())
    }

    pub fn scanner_is_current(&self, artifact: &ArtifactId) -> bool {
        self.data
            .approvals
            .iter()
            .find(|approval| approval.matches(artifact))
            .is_some_and(|approval| approval.scanner_version == crate::scanner::SCANNER_VERSION)
    }

    pub fn workspace_matches(&self, root: &Path, fingerprint: &str) -> bool {
        let root = root.to_string_lossy();
        self.data
            .workspaces
            .iter()
            .any(|record| record.root == root && record.fingerprint == fingerprint)
    }

    pub fn workspace_record(&self, root: &Path) -> Option<&WorkspaceRecord> {
        let root = root.to_string_lossy();
        self.data
            .workspaces
            .iter()
            .find(|record| record.root == root)
    }

    pub fn remember_workspace(
        &mut self,
        root: &Path,
        fingerprint: &str,
        lock_hash: &str,
        manifests_hash: &str,
    ) {
        let root = root.to_string_lossy().into_owned();
        self.data.workspaces.retain(|record| record.root != root);
        self.data.workspaces.push(WorkspaceRecord {
            root,
            fingerprint: fingerprint.to_owned(),
            lock_hash: lock_hash.to_owned(),
            manifests_hash: manifests_hash.to_owned(),
        });
    }

    pub fn remember_factory_bundle(&mut self, version: &str) {
        self.data.factory_bundles.insert(version.to_owned());
    }

    pub fn installed_factory_bundles(&self) -> &BTreeSet<String> {
        &self.data.factory_bundles
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(&self.data)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = self
            .path
            .with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ArtifactId {
        ArtifactId {
            source: "registry+test".into(),
            name: "demo".into(),
            version: "1.2.3".into(),
            checksum: "abc".into(),
        }
    }

    #[test]
    fn approvals_bind_to_the_full_artifact_and_merge_findings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("approvals.toml");
        let mut store = ApprovalStore::load(path.clone()).unwrap();
        store.remember(&artifact(), BTreeSet::from(["build-script".into()]));
        store.remember(&artifact(), BTreeSet::from(["network-access".into()]));
        store.save().unwrap();

        let loaded = ApprovalStore::load(path).unwrap();
        assert_eq!(
            loaded.approved_findings(&artifact()),
            BTreeSet::from(["build-script".into(), "network-access".into()])
        );
        let mut changed = artifact();
        changed.checksum = "different".into();
        assert!(!loaded.has_artifact(&changed));
    }

    #[test]
    fn corrupt_files_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("approvals.toml");
        fs::write(&path, "not = [valid").unwrap();
        assert!(ApprovalStore::load(path).is_err());
    }

    #[test]
    fn git_approval_requires_a_recorded_complete_tree_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("approvals.toml");
        let git = ArtifactId {
            source: "git+https://github.com/acme/demo#0123456789abcdef0123456789abcdef01234567"
                .into(),
            name: "demo".into(),
            version: "1.0.0".into(),
            checksum: "0123456789abcdef0123456789abcdef01234567".into(),
        };
        let mut store = ApprovalStore::load(path).unwrap();
        store.remember(&git, BTreeSet::new());
        assert!(!store.has_artifact(&git));
        store.remember_with_content_sha256(&git, BTreeSet::new(), Some("a".repeat(64)));
        assert!(store.has_artifact(&git));
        assert_eq!(store.content_sha256(&git), Some("a".repeat(64).as_str()));
    }
}
