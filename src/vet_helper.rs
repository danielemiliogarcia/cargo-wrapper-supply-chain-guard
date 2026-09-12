//! Resolves and verifies the plugin-owned cargo-vet helper before any execution.

use crate::{Result, error};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const HELPER_ENV: &str = "CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_CARGO_VET";
pub const HELPER_SHA256_ENV: &str = "CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_CARGO_VET_SHA256";
pub const EXPECTED_VERSION: &str = "cargo-vet 0.10.2";
pub const SOURCE_COMMIT: &str = "e496a28a2cde71db0d98ef631cf4586f89a7fed6";

#[derive(Clone, Debug)]
pub struct VerifiedHelper {
    pub path: PathBuf,
    pub expected_sha256: String,
    pub actual_sha256: String,
}

impl VerifiedHelper {
    pub fn discover() -> Result<Self> {
        if let Some(path) = std::env::var_os(HELPER_ENV) {
            let expected = std::env::var(HELPER_SHA256_ENV).map_err(|_| {
                error(format!(
                    "supply-chain-guard: {HELPER_SHA256_ENV} is required with {HELPER_ENV}"
                ))
            })?;
            return Self::verify(PathBuf::from(path), &expected);
        }
        let path = default_helper_path()?;
        let manifest = path
            .parent()
            .ok_or_else(|| error("cargo-vet helper path has no parent"))?
            .join("INSTALL-MANIFEST.toml");
        let expected = helper_digest_from_manifest(&manifest)?;
        Self::verify(path, &expected)
    }

    pub fn verify(path: PathBuf, expected: &str) -> Result<Self> {
        if !path.is_absolute() {
            return Err(error("cargo-vet helper path must be absolute"));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|inspect_error| {
            error(format!(
                "cargo-vet helper is unavailable at {}: {inspect_error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(error(format!(
                "cargo-vet helper is not a regular non-symlink file: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(error(format!(
                    "cargo-vet helper is not executable: {}",
                    path.display()
                )));
            }
        }
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(error(
                "cargo-vet helper manifest contains an invalid SHA-256",
            ));
        }
        let actual = format!("{:x}", Sha256::digest(fs::read(&path)?));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(error(format!(
                "cargo-vet helper checksum mismatch at {}: expected {expected}, got {actual}",
                path.display()
            )));
        }
        Ok(Self {
            path,
            expected_sha256: expected.to_ascii_lowercase(),
            actual_sha256: actual,
        })
    }
}

pub fn default_helper_path() -> Result<PathBuf> {
    #[cfg(windows)]
    let path = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| error("LOCALAPPDATA is not defined"))?
        .join("CargoWrapperSupplyChainGuard/bin/cargo-vet.exe");
    #[cfg(not(windows))]
    let path = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(|| error("HOME is not defined"))?
        .join("cargo-wrapper-supply-chain-guard/bin/cargo-vet");
    Ok(path)
}

pub fn file_sha256(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn helper_digest_from_manifest(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path).map_err(|read_error| {
        error(format!(
            "cargo-vet install manifest is unavailable at {}: {read_error}",
            path.display()
        ))
    })?;
    let manifest: toml::Value = toml::from_str(&contents)?;
    let version = manifest
        .get("cargo-vet")
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| error("install manifest has no cargo-vet.version"))?;
    let commit = manifest
        .get("cargo-vet")
        .and_then(|value| value.get("source-commit"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| error("install manifest has no cargo-vet.source-commit"))?;
    let digest = manifest
        .get("cargo-vet")
        .and_then(|value| value.get("sha256"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| error("install manifest has no cargo-vet.sha256"))?;
    if version != "0.10.2" || commit != SOURCE_COMMIT {
        return Err(error(format!(
            "cargo-vet install manifest identity mismatch: expected 0.10.2 at {SOURCE_COMMIT}"
        )));
    }
    Ok(digest.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_requires_an_absolute_regular_file_and_exact_digest() {
        assert!(VerifiedHelper::verify(PathBuf::from("relative-helper"), &"0".repeat(64)).is_err());

        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("cargo-vet");
        fs::write(&helper, b"fixture helper").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(VerifiedHelper::verify(helper.clone(), &"0".repeat(64)).is_err());
        let digest = file_sha256(&helper).unwrap();
        let verified = VerifiedHelper::verify(helper, &digest).unwrap();
        assert_eq!(verified.expected_sha256, digest);
        assert_eq!(verified.actual_sha256, digest);
    }

    #[cfg(unix)]
    #[test]
    fn helper_symlinks_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("cargo-vet");
        fs::write(&target, b"fixture helper").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &link).unwrap();
        let digest = file_sha256(&target).unwrap();
        assert!(VerifiedHelper::verify(link, &digest).is_err());
    }

    #[test]
    fn manifest_must_pin_the_expected_version_and_commit() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("INSTALL-MANIFEST.toml");
        fs::write(
            &manifest,
            format!(
                "[cargo-vet]\nversion='0.10.2'\nsource-commit='{SOURCE_COMMIT}'\nsha256='{}'\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        assert_eq!(
            helper_digest_from_manifest(&manifest).unwrap(),
            "a".repeat(64)
        );
        fs::write(
            &manifest,
            format!(
                "[cargo-vet]\nversion='0.10.3'\nsource-commit='{SOURCE_COMMIT}'\nsha256='{}'\n",
                "a".repeat(64)
            ),
        )
        .unwrap();
        assert!(helper_digest_from_manifest(&manifest).is_err());
    }
}
