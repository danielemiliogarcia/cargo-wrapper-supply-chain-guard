//! Persists cargo-vet decisions bound to exact artifacts, helpers, and policy fingerprints.

use crate::findings::ArtifactId;
use crate::vet_live;
use crate::{Result, error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DECISION_SCHEMA: u32 = 1;
const MAX_DECISION_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CachedVetDecision {
    pub schema: u32,
    pub artifact: ArtifactId,
    pub criterion: String,
    pub authority: String,
    pub policy_fingerprint: String,
    pub helper_sha256: String,
}

impl CachedVetDecision {
    pub fn new(
        artifact: ArtifactId,
        authority: String,
        policy_fingerprint: String,
        helper_sha256: String,
    ) -> Self {
        Self {
            schema: DECISION_SCHEMA,
            artifact,
            criterion: "safe-to-run".to_owned(),
            authority,
            policy_fingerprint,
            helper_sha256,
        }
    }

    pub fn matches_policy(&self, policy_fingerprint: &str, helper_sha256: &str) -> bool {
        self.policy_fingerprint == policy_fingerprint
            && self.helper_sha256.eq_ignore_ascii_case(helper_sha256)
    }
}

pub fn load(artifact: &ArtifactId) -> Result<Option<CachedVetDecision>> {
    load_from(&decision_directory()?, artifact)
}

pub fn save(decision: &CachedVetDecision) -> Result<()> {
    save_to(&decision_directory()?, decision)
}

pub fn remove(artifact: &ArtifactId) -> Result<()> {
    let path = decision_path(&decision_directory()?, artifact);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(error(format!(
                "cargo-vet decision cache entry is not a regular file: {}",
                path.display()
            )))
        }
        Ok(_) => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(remove_error) if remove_error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(remove_error) => Err(remove_error.into()),
    }
}

fn decision_directory() -> Result<PathBuf> {
    Ok(vet_live::default_evidence_dir()?.join("decisions"))
}

fn load_from(directory: &Path, artifact: &ArtifactId) -> Result<Option<CachedVetDecision>> {
    let path = decision_path(directory, artifact);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(read_error) => return Err(read_error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DECISION_BYTES
    {
        return Err(error(format!(
            "cargo-vet decision cache entry is invalid: {}",
            path.display()
        )));
    }
    let bytes = fs::read(&path)?;
    let decision: CachedVetDecision = serde_json::from_slice(&bytes).map_err(|parse_error| {
        error(format!(
            "invalid cargo-vet decision cache entry {}: {parse_error}",
            path.display()
        ))
    })?;
    validate(&decision)?;
    if decision.artifact != *artifact {
        return Err(error(format!(
            "cargo-vet decision cache identity mismatch at {}",
            path.display()
        )));
    }
    Ok(Some(decision))
}

fn save_to(directory: &Path, decision: &CachedVetDecision) -> Result<()> {
    validate(decision)?;
    create_private_directory(directory)?;
    let destination = decision_path(directory, &decision.artifact);
    if let Ok(metadata) = fs::symlink_metadata(&destination)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(error(format!(
            "cargo-vet decision cache destination is not a regular file: {}",
            destination.display()
        )));
    }
    let bytes = serde_json::to_vec(decision)?;
    if bytes.len() as u64 > MAX_DECISION_BYTES {
        return Err(error("cargo-vet decision cache entry exceeds 16 KiB"));
    }
    let temporary = directory.join(format!(
        ".decision-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if destination.exists() {
            fs::remove_file(&destination)?;
        }
        fs::rename(&temporary, &destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate(decision: &CachedVetDecision) -> Result<()> {
    if decision.schema != DECISION_SCHEMA
        || decision.criterion != "safe-to-run"
        || decision.artifact.source.is_empty()
        || decision.artifact.name.is_empty()
        || decision.artifact.version.is_empty()
        || decision.artifact.checksum.is_empty()
        || decision.authority.is_empty()
        || decision.authority.len() > 2_000
        || decision.policy_fingerprint.is_empty()
        || decision.policy_fingerprint.len() > 256
        || !is_sha256(&decision.helper_sha256)
    {
        return Err(error("cargo-vet decision cache entry failed validation"));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decision_path(directory: &Path, artifact: &ArtifactId) -> PathBuf {
    let mut hasher = Sha256::new();
    for value in [
        artifact.source.as_str(),
        artifact.name.as_str(),
        artifact.version.as_str(),
        artifact.checksum.as_str(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    directory.join(format!("decision-{:x}.json", hasher.finalize()))
}

fn create_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(error(format!(
                "cargo-vet decision cache path is not a regular directory: {}",
                path.display()
            )));
        }
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ArtifactId {
        ArtifactId {
            source: "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
            name: "demo".to_owned(),
            version: "1.2.3".to_owned(),
            checksum: "a".repeat(64),
        }
    }

    fn decision() -> CachedVetDecision {
        CachedVetDecision::new(
            artifact(),
            "fixture producer".to_owned(),
            "fixture-policy".to_owned(),
            "b".repeat(64),
        )
    }

    #[test]
    fn exact_decision_round_trips_and_changed_identity_misses() {
        let directory = tempfile::tempdir().unwrap();
        save_to(directory.path(), &decision()).unwrap();
        assert_eq!(
            load_from(directory.path(), &artifact()).unwrap(),
            Some(decision())
        );
        let mut changed = artifact();
        changed.checksum = "c".repeat(64);
        assert!(load_from(directory.path(), &changed).unwrap().is_none());
    }

    #[test]
    fn malformed_decision_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        create_private_directory(directory.path()).unwrap();
        fs::write(decision_path(directory.path(), &artifact()), b"not json").unwrap();
        assert!(load_from(directory.path(), &artifact()).is_err());
    }
}
