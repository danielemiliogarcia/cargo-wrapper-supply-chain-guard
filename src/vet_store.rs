//! Constructs one private cargo-vet query store per exact artifact.

use crate::findings::ArtifactId;
use crate::lockfile::CargoLock;
use crate::workspace::Workspace;
use crate::{Result, error};
use std::fs;
use std::path::Path;

pub fn write_query_store(
    store: &Path,
    workspace: &Workspace,
    lock: &CargoLock,
    target: &ArtifactId,
    audits: &str,
) -> Result<()> {
    fs::create_dir_all(store)?;
    fs::write(store.join("audits.toml"), audits)?;
    fs::write(
        store.join("imports.lock"),
        "# Intentionally empty: evidence is already pinned and filtered.\n",
    )?;

    let mut config = String::from("[cargo-vet]\nversion = \"0.10\"\n\n");
    let workspace_names = workspace_package_names(workspace)?;
    for package in lock.package.as_deref().unwrap_or_default() {
        let policy_key = if package.source.is_some() {
            format!("{}:{}", package.name, package.version)
        } else if workspace_names.contains(&package.name) {
            package.name.clone()
        } else {
            continue;
        };
        config.push_str(&format!("[policy.{}]\n", toml_key(&policy_key)));
        let mut dependencies: Vec<_> = package
            .dependencies
            .iter()
            .filter_map(|dependency| dependency.split_whitespace().next())
            .collect();
        dependencies.sort_unstable();
        dependencies.dedup();
        if !dependencies.is_empty() {
            config.push_str("dependency-criteria = { ");
            for (index, dependency) in dependencies.iter().enumerate() {
                if index != 0 {
                    config.push_str(", ");
                }
                config.push_str(&format!("{} = \"safe-to-run\"", toml_key(dependency)));
            }
            config.push_str(" }\n");
        }
        config.push('\n');
    }
    for package in lock.package.as_deref().unwrap_or_default() {
        if package.source.is_none() || package.name == target.name {
            continue;
        }
        config.push_str(&format!(
            "[[exemptions.{}]]\nversion = {}\ncriteria = \"safe-to-run\"\nsuggest = false\n\n",
            toml_key(&package.name),
            toml_string(&package.version)?
        ));
    }
    fs::write(store.join("config.toml"), config)?;
    Ok(())
}

fn workspace_package_names(workspace: &Workspace) -> Result<std::collections::BTreeSet<String>> {
    let mut names = std::collections::BTreeSet::new();
    for path in &workspace.manifests {
        let manifest: toml::Value = toml::from_str(&fs::read_to_string(path)?)?;
        if let Some(name) = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
        {
            names.insert(name.to_owned());
        }
    }
    if names.is_empty() {
        return Err(error("cargo-vet query found no workspace package names"));
    }
    Ok(names)
}

fn toml_key(value: &str) -> String {
    format!("{value:?}")
}

fn toml_string(value: &str) -> Result<String> {
    toml::Value::String(value.to_owned())
        .to_string()
        .parse()
        .map_err(|_| error("cannot encode TOML string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_name_is_never_exempted_at_any_version() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='root'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version=4\n").unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        let lock: CargoLock = toml::from_str(
            "package=[{name='demo',version='1.0.0',source='registry+x',checksum='a'}, {name='other',version='2.0.0',source='registry+x',checksum='b'}]",
        )
        .unwrap();
        let target = lock.remote_artifacts().unwrap().remove(0);
        let store = directory.path().join("store");
        write_query_store(&store, &workspace, &lock, &target, "[audits]\n").unwrap();
        let config = fs::read_to_string(store.join("config.toml")).unwrap();
        assert!(!config.contains("exemptions.\"demo\""));
        assert!(config.contains("exemptions.\"other\""));
    }
}
