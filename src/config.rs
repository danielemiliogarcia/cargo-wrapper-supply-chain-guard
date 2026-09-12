//! Loads Supply Chain Guard's own cargo-vet mode without modifying project policy.

use crate::{Result, error};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

pub const CONFIG_ENV: &str = "CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_CONFIG";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VetMode {
    #[default]
    Auto,
    Curated,
    Project,
    Off,
    Required,
}

impl VetMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Curated => "curated",
            Self::Project => "project",
            Self::Off => "off",
            Self::Required => "required",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PluginConfig {
    pub cargo_vet_mode: VetMode,
    pub path: PathBuf,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default, rename = "cargo-vet")]
    cargo_vet: CargoVetConfig,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CargoVetConfig {
    mode: Option<String>,
}

impl PluginConfig {
    pub fn load() -> Result<Self> {
        let path = default_config_path()?;
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    cargo_vet_mode: VetMode::Auto,
                    path,
                });
            }
            Err(read_error) => return Err(read_error.into()),
        };
        let parsed: ConfigFile = toml::from_str(&contents).map_err(|parse_error| {
            error(format!(
                "supply-chain-guard: invalid configuration {}: {parse_error}; refusing to continue",
                path.display()
            ))
        })?;
        let cargo_vet_mode = parse_mode(parsed.cargo_vet.mode.as_deref().unwrap_or("auto"))?;
        Ok(Self {
            cargo_vet_mode,
            path,
        })
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(CONFIG_ENV) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    let directory = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| error(format!("APPDATA is not defined; set {CONFIG_ENV}")))?
        .join("CargoWrapperSupplyChainGuard");
    #[cfg(not(windows))]
    let directory = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| error(format!("HOME is not defined; set {CONFIG_ENV}")))?
        .join("cargo-wrapper-supply-chain-guard");
    Ok(directory.join("config.toml"))
}

fn parse_mode(value: &str) -> Result<VetMode> {
    match value {
        "auto" => Ok(VetMode::Auto),
        "curated" => Ok(VetMode::Curated),
        "project" => Ok(VetMode::Project),
        "off" => Ok(VetMode::Off),
        "required" => Ok(VetMode::Required),
        _ => Err(error(format!(
            "supply-chain-guard: invalid cargo-vet mode {value:?}; expected auto, curated, project, off, or required"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_strict() {
        assert_eq!(parse_mode("required").unwrap(), VetMode::Required);
        assert!(parse_mode("optional").is_err());
    }
}
