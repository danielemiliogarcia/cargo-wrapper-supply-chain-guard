//! Warns when a minimum publish age is configured only where isolated candidate resolution
//! cannot see it. The guard resolves candidates with a private `CARGO_HOME` and a temporary
//! workspace copy, so `$CARGO_HOME/config.toml` is invisible there. The environment variable
//! and the project's own `.cargo/config.toml` are visible. This is a warning only.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const WARNING: &str = "supply-chain-guard: minimum publish age is set only in your Cargo home config, which isolated candidate resolution cannot see; set CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE or add it to the project's .cargo/config.toml.";

/// True for Cargo 1.100 and newer, where minimum publish age is native.
pub fn is_native_version(version_output: &str) -> bool {
    let Some(version) = version_output.split_whitespace().nth(1) else {
        return false;
    };
    let mut parts = version.split(['.', '-']);
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if major > 1 || (major == 1 && minor >= 100))
}

/// Whether a Cargo config file sets either supported minimum publish age key.
pub fn config_sets_min_age(contents: &str) -> bool {
    let Ok(value) = toml::from_str::<toml::Value>(contents) else {
        return false;
    };
    let registry = value
        .get("registry")
        .and_then(|table| table.get("global-min-publish-age"));
    let crates_io = value
        .get("registries")
        .and_then(|table| table.get("crates-io"))
        .and_then(|table| table.get("min-publish-age"));
    registry.is_some() || crates_io.is_some()
}

fn directory_sets_min_age(directory: &Path) -> bool {
    ["config.toml", "config"].iter().any(|name| {
        fs::read_to_string(directory.join(name))
            .map(|contents| config_sets_min_age(&contents))
            .unwrap_or(false)
    })
}

/// Pure decision: warn when Cargo is native, the env var is absent, the project does not set
/// the policy, and the Cargo home does.
pub fn should_warn(
    native_cargo: bool,
    env_value: Option<&OsString>,
    project_root: &Path,
    cargo_home: Option<&Path>,
) -> bool {
    native_cargo
        && env_value.is_none_or(|value| value.is_empty())
        && !directory_sets_min_age(&project_root.join(".cargo"))
        && cargo_home.is_some_and(directory_sets_min_age)
}

fn default_cargo_home() -> Option<PathBuf> {
    env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| {
        env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .map(|home| PathBuf::from(home).join(".cargo"))
    })
}

/// Prints the warning to stderr when the policy would be invisible to candidate resolution.
pub fn warn_if_policy_is_hidden(cargo: &Path, project_root: &Path) {
    let native = Command::new(cargo)
        .arg("-V")
        .output()
        .map(|output| is_native_version(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or(false);
    let env_value = env::var_os("CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE");
    if should_warn(
        native,
        env_value.as_ref(),
        project_root,
        default_cargo_home().as_deref(),
    ) {
        eprintln!("{WARNING}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBAL: &str = "[registry]\nglobal-min-publish-age = \"30 days\"\n";
    const CRATES_IO: &str = "[registries.crates-io]\nmin-publish-age = \"30 days\"\n";

    fn home_with(contents: &str) -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join("config.toml"), contents).unwrap();
        home
    }

    fn project_with(contents: Option<&str>) -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        if let Some(contents) = contents {
            fs::create_dir(project.path().join(".cargo")).unwrap();
            fs::write(project.path().join(".cargo/config.toml"), contents).unwrap();
        }
        project
    }

    #[test]
    fn detects_native_versions() {
        assert!(is_native_version("cargo 1.100.0 (3acc79c0c 2026-11-05)"));
        assert!(is_native_version("cargo 1.101.0-nightly (abc 2026-12-01)"));
        assert!(is_native_version("cargo 2.0.0 (abc 2027-01-01)"));
        assert!(!is_native_version("cargo 1.99.1 (5f94df478 2026-08-27)"));
        assert!(!is_native_version("cargo 1.9.0 (abc 2020-01-01)"));
        assert!(!is_native_version("garbage"));
        assert!(!is_native_version(""));
    }

    #[test]
    fn recognizes_both_policy_keys() {
        assert!(config_sets_min_age(GLOBAL));
        assert!(config_sets_min_age(CRATES_IO));
        assert!(!config_sets_min_age("[registry]\ndefault = \"x\"\n"));
        assert!(!config_sets_min_age("not = [valid"));
    }

    #[test]
    fn warns_when_only_cargo_home_sets_the_policy() {
        let home = home_with(GLOBAL);
        let project = project_with(None);
        assert!(should_warn(true, None, project.path(), Some(home.path())));
        assert!(should_warn(
            true,
            Some(&OsString::new()),
            project.path(),
            Some(home.path())
        ));
    }

    #[test]
    fn stays_quiet_when_the_policy_is_visible_or_absent() {
        let home = home_with(GLOBAL);
        let value = OsString::from("30 days");
        let no_policy = project_with(None);
        let with_policy = project_with(Some(CRATES_IO));
        let empty_home = home_with("");

        // Environment variable is visible to isolated resolution.
        assert!(!should_warn(
            true,
            Some(&value),
            no_policy.path(),
            Some(home.path())
        ));
        // Project config is copied into the isolated workspace.
        assert!(!should_warn(
            true,
            None,
            with_policy.path(),
            Some(home.path())
        ));
        // Older Cargo does not enforce natively.
        assert!(!should_warn(
            false,
            None,
            no_policy.path(),
            Some(home.path())
        ));
        // Cargo home does not set the policy, or there is no Cargo home.
        assert!(!should_warn(
            true,
            None,
            no_policy.path(),
            Some(empty_home.path())
        ));
        assert!(!should_warn(true, None, no_policy.path(), None));
    }
}
