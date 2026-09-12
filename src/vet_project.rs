//! Discovers and filters a project's locked cargo-vet evidence without modifying the project.

use crate::vet_baseline::validate_filtered;
use crate::workspace::Workspace;
use crate::{Result, error};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const MAX_PROJECT_EVIDENCE_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ProjectEvidence {
    pub store_path: PathBuf,
    pub audits: String,
    pub fingerprint: String,
}

pub fn discover(workspace: &Workspace) -> Result<Option<ProjectEvidence>> {
    let root_manifest = workspace.root.join("Cargo.toml");
    let manifest: toml::Value = toml::from_str(&fs::read_to_string(&root_manifest)?)?;
    let package_vet = manifest
        .get("package")
        .and_then(|value| metadata_vet(value));
    let workspace_vet = manifest
        .get("workspace")
        .and_then(|value| metadata_vet(value));
    if package_vet.is_some() && workspace_vet.is_some() {
        return Err(error(
            "supply-chain-guard: project defines both package.metadata.vet and workspace.metadata.vet",
        ));
    }
    let relative = package_vet
        .or(workspace_vet)
        .and_then(|vet| vet.get("store"))
        .and_then(|store| store.get("path"))
        .and_then(toml::Value::as_str)
        .unwrap_or("supply-chain");
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(error(
            "supply-chain-guard: project cargo-vet store path must remain inside the reviewed workspace",
        ));
    }
    let store_path = workspace.root.join(relative);
    if !store_path.exists() {
        return Ok(None);
    }
    if !store_path.is_dir() {
        return Err(error(format!(
            "supply-chain-guard: project cargo-vet store is not a directory: {}",
            store_path.display()
        )));
    }
    if fs::symlink_metadata(&store_path)?.file_type().is_symlink() {
        return Err(error(format!(
            "supply-chain-guard: project cargo-vet store must not be a symlink: {}",
            store_path.display()
        )));
    }
    let config_bytes = required_file(&store_path.join("config.toml"))?;
    let audits_bytes = required_file(&store_path.join("audits.toml"))?;
    let imports_bytes = required_file(&store_path.join("imports.lock"))?;
    let config: toml::Value = toml::from_str(std::str::from_utf8(&config_bytes)?)?;
    let version = config
        .get("cargo-vet")
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| error("project cargo-vet config has no cargo-vet.version"))?;
    if version != "0.10" {
        return Err(error(format!(
            "supply-chain-guard: unsupported project cargo-vet format {version:?}; expected 0.10"
        )));
    }
    let imports = configured_imports(&config)?;

    let local: toml::Value = toml::from_str(std::str::from_utf8(&audits_bytes)?)?;
    let locked: toml::Value = toml::from_str(std::str::from_utf8(&imports_bytes)?)?;
    let filtered = filtered_project_audits(local, locked, &imports)?;
    validate_filtered(&filtered)?;
    let mut hasher = Sha256::new();
    for bytes in [&config_bytes, &audits_bytes, &imports_bytes] {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(Some(ProjectEvidence {
        store_path,
        audits: filtered,
        fingerprint: format!("{:x}", hasher.finalize()),
    }))
}

fn metadata_vet(value: &toml::Value) -> Option<&toml::Value> {
    value
        .get("metadata")
        .and_then(|metadata| metadata.get("vet"))
}

#[derive(Debug, Default)]
struct ImportPolicy {
    excluded_crates: BTreeSet<String>,
}

fn configured_imports(config: &toml::Value) -> Result<BTreeMap<String, ImportPolicy>> {
    let Some(imports) = config.get("imports") else {
        return Ok(BTreeMap::new());
    };
    let imports = imports
        .as_table()
        .ok_or_else(|| error("project cargo-vet imports must be a table"))?;
    let mut selected = BTreeMap::new();
    for (producer, value) in imports {
        let table = value.as_table().ok_or_else(|| {
            error(format!(
                "project cargo-vet import {producer:?} is malformed"
            ))
        })?;
        let urls = table
            .get("url")
            .ok_or_else(|| error(format!("project cargo-vet import {producer:?} has no URL")))?;
        if !valid_string_or_array(urls) {
            return Err(error(format!(
                "project cargo-vet import {producer:?} has an invalid URL list"
            )));
        }
        let excluded_crates = match table.get("exclude") {
            Some(exclude) => string_array(exclude, "import exclude")?,
            None => BTreeSet::new(),
        };
        selected.insert(producer.clone(), ImportPolicy { excluded_crates });
    }
    Ok(selected)
}

fn valid_string_or_array(value: &toml::Value) -> bool {
    value.as_str().is_some_and(|value| !value.is_empty())
        || value.as_array().is_some_and(|values| {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        })
}

fn string_array(value: &toml::Value, label: &str) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| error(format!("project cargo-vet {label} must be an array")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| error(format!("project cargo-vet {label} must contain strings")))
        })
        .collect()
}

fn required_file(path: &Path) -> Result<Vec<u8>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(error(format!(
                "supply-chain-guard: project cargo-vet input is not a regular non-symlink file: {}",
                path.display()
            )));
        }
        Ok(metadata) if metadata.len() > MAX_PROJECT_EVIDENCE_FILE_BYTES => {
            return Err(error(format!(
                "supply-chain-guard: project cargo-vet input exceeds the 32 MiB limit: {}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(inspect_error) => {
            return Err(error(format!(
                "supply-chain-guard: project cargo-vet store is present but {} is unavailable: {inspect_error}",
                path.display()
            )));
        }
    }
    fs::read(path).map_err(|read_error| {
        error(format!(
            "supply-chain-guard: project cargo-vet store is present but {} is unavailable: {read_error}",
            path.display()
        ))
    })
}

fn filtered_project_audits(
    mut local: toml::Value,
    locked: toml::Value,
    configured_imports: &BTreeMap<String, ImportPolicy>,
) -> Result<String> {
    strip_weak_sections(&mut local)?;
    let local_table = local
        .as_table_mut()
        .ok_or_else(|| error("project audits.toml must be a TOML table"))?;
    local_table
        .entry("audits")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let empty_locked_imports = toml::map::Map::new();
    let locked_imports = match locked.get("audits") {
        Some(imports) => imports
            .as_table()
            .ok_or_else(|| error("project cargo-vet imports.lock audits must be a table"))?,
        None => {
            if configured_imports.is_empty() {
                &empty_locked_imports
            } else {
                return Err(error(
                    "project cargo-vet imports.lock is missing configured imports",
                ));
            }
        }
    };
    let configured_names: BTreeSet<_> = configured_imports.keys().collect();
    let locked_names: BTreeSet<_> = locked_imports.keys().collect();
    if configured_names != locked_names {
        return Err(error(
            "project cargo-vet imports.lock does not match the configured import set",
        ));
    }
    for (producer, policy) in configured_imports {
        let mut imported = locked_imports
            .get(producer)
            .ok_or_else(|| error("configured cargo-vet import is absent from imports.lock"))?
            .clone();
        strip_weak_sections(&mut imported).map_err(|filter_error| {
            error(format!(
                "project cargo-vet import {producer:?} is malformed: {filter_error}"
            ))
        })?;
        if let Some(audits) = imported
            .get_mut("audits")
            .and_then(toml::Value::as_table_mut)
        {
            audits.retain(|crate_name, _| !policy.excluded_crates.contains(crate_name));
        }
        merge_section(local_table, &imported, "criteria")?;
        merge_section(local_table, &imported, "audits")?;
    }
    Ok(format!(
        "# Private filtered copy of project cargo-vet evidence.\n{}",
        toml::to_string_pretty(&local)?
    ))
}

fn strip_weak_sections(value: &mut toml::Value) -> Result<()> {
    let table = value
        .as_table_mut()
        .ok_or_else(|| error("cargo-vet evidence must be a TOML table"))?;
    table.remove("wildcard-audits");
    table.remove("trusted");
    table.remove("exemptions");
    table.remove("publisher");
    Ok(())
}

fn merge_section(
    destination: &mut toml::map::Map<String, toml::Value>,
    source: &toml::Value,
    section: &str,
) -> Result<()> {
    let Some(source) = source.get(section).and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let destination = destination
        .entry(section)
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| error(format!("project cargo-vet {section} must be a table")))?;
    for (name, value) in source {
        if section == "audits" {
            let entries = destination
                .entry(name.clone())
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| error(format!("cargo-vet audits.{name} must be an array")))?;
            entries.extend(
                value
                    .as_array()
                    .ok_or_else(|| error(format!("cargo-vet audits.{name} must be an array")))?
                    .clone(),
            );
        } else if let Some(previous) = destination.get(name) {
            if previous != value {
                return Err(error(format!(
                    "conflicting project cargo-vet criterion {name:?} across locked imports"
                )));
            }
        } else {
            destination.insert(name.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_filter_removes_weak_evidence() {
        let imports = BTreeMap::from([("vendor".to_owned(), ImportPolicy::default())]);
        let filtered = filtered_project_audits(
            toml::from_str(
                "[criteria.reviewed]\ndescription='reviewed'\nimplies='safe-to-run'\n[[audits.demo]]\ncriteria='reviewed'\nversion='1.0.0'\n[[wildcard-audits.demo]]\ncriteria='safe-to-run'\nuser-id=1\nstart='2020-01-01'\nend='2030-01-01'\n[trusted]\n[exemptions]\n",
            )
            .unwrap(),
            toml::from_str(
                "publisher = {}\n[audits.vendor.criteria.imported]\ndescription='imported'\nimplies='safe-to-run'\n[[audits.vendor.audits.other]]\ncriteria='imported'\nversion='2.0.0'\n[[audits.vendor.wildcard-audits.bad]]\ncriteria='safe-to-run'\nuser-id=1\nstart='2020-01-01'\nend='2030-01-01'\n[audits.vendor.trusted]\n",
            )
            .unwrap(),
            &imports,
        )
        .unwrap();
        assert!(!filtered.contains("wildcard-audits"));
        assert!(!filtered.contains("trusted"));
        assert!(!filtered.contains("publisher"));
        assert!(!filtered.contains("exemptions"));
        assert!(filtered.contains("audits.demo"));
        assert!(filtered.contains("audits.other"));
        assert!(filtered.contains("criteria.reviewed"));
        assert!(filtered.contains("criteria.imported"));
    }

    #[test]
    fn project_filter_requires_locked_imports_to_match_configuration() {
        let local = || toml::from_str("[audits]\n").unwrap();
        let locked =
            || toml::from_str("[audits.selected.audits]\n[audits.unselected.audits]\n").unwrap();
        let imports = BTreeMap::from([("selected".to_owned(), ImportPolicy::default())]);
        assert!(filtered_project_audits(local(), locked(), &imports).is_err());

        let imports = BTreeMap::from([
            ("selected".to_owned(), ImportPolicy::default()),
            ("missing".to_owned(), ImportPolicy::default()),
        ]);
        assert!(filtered_project_audits(local(), locked(), &imports).is_err());
    }

    #[test]
    fn project_filter_enforces_configured_import_exclusions() {
        let local = toml::from_str("[audits]\n").unwrap();
        let locked = toml::from_str(
            "[[audits.vendor.audits.allowed]]\ncriteria='safe-to-run'\nversion='1.0.0'\n[[audits.vendor.audits.excluded]]\ncriteria='safe-to-run'\nversion='1.0.0'\n",
        )
        .unwrap();
        let imports = BTreeMap::from([(
            "vendor".to_owned(),
            ImportPolicy {
                excluded_crates: BTreeSet::from(["excluded".to_owned()]),
            },
        )]);
        let filtered = filtered_project_audits(local, locked, &imports).unwrap();
        assert!(filtered.contains("audits.allowed"));
        assert!(!filtered.contains("audits.excluded"));
    }

    #[test]
    fn project_store_path_cannot_escape_the_workspace() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n[package.metadata.vet.store]\npath='../outside'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4\n").unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        let message = discover(&workspace).unwrap_err().to_string();
        assert!(message.contains("must remain inside"));
    }

    #[test]
    fn malformed_present_project_store_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4\n").unwrap();
        fs::create_dir(directory.path().join("supply-chain")).unwrap();
        fs::write(
            directory.path().join("supply-chain/config.toml"),
            "not valid toml = [",
        )
        .unwrap();
        fs::write(
            directory.path().join("supply-chain/audits.toml"),
            "[audits]\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("supply-chain/imports.lock"),
            "audits = {}\n",
        )
        .unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        assert!(discover(&workspace).is_err());
    }
}
