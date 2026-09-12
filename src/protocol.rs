//! Validates Cargo Wrapper plugin protocol v1 and constructs the two execution paths.
//! This is the only module allowed to read host protocol environment variables.

use crate::cargo_runner::{DirectCargoRunner, DownstreamRunner};
use crate::{Result, error};
use std::env;
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: &str = "1";
pub const PLUGIN_NAME: &str = "supply-chain-guard";

pub const ENV_PROTOCOL: &str = "CARGO_WRAPPER_PLUGIN_PROTOCOL";
pub const ENV_PLUGIN_NAME: &str = "CARGO_WRAPPER_PLUGIN_NAME";
pub const ENV_REAL_CARGO: &str = "CARGO_WRAPPER_REAL_CARGO";
pub const ENV_NEXT: &str = "CARGO_WRAPPER_NEXT";
pub const ENV_ORIGINAL_SUBCOMMAND: &str = "CARGO_WRAPPER_ORIGINAL_SUBCOMMAND";
pub const ENV_PLUGIN_CHAIN: &str = "CARGO_WRAPPER_PLUGIN_CHAIN";

pub fn is_host_invocation() -> bool {
    env::var_os(ENV_PROTOCOL).is_some()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolContext {
    pub direct_cargo: DirectCargoRunner,
    pub downstream: DownstreamRunner,
    pub original_subcommand: Option<String>,
}

impl ProtocolContext {
    pub fn from_environment() -> Result<Self> {
        let protocol = required_unicode(ENV_PROTOCOL)?;
        if protocol != PROTOCOL_VERSION {
            return Err(error(format!(
                "supply-chain-guard: unsupported plugin protocol {protocol:?}; expected {PROTOCOL_VERSION}"
            )));
        }
        let plugin_name = required_unicode(ENV_PLUGIN_NAME)?;
        if plugin_name != PLUGIN_NAME {
            return Err(error(format!(
                "supply-chain-guard: host registered this binary as {plugin_name:?}; expected {PLUGIN_NAME:?}"
            )));
        }
        reject_conflicting_guard_plugins()?;

        let real_cargo = required_executable(ENV_REAL_CARGO)?;
        let next = required_executable(ENV_NEXT)?;
        let original_subcommand = env::var_os(ENV_ORIGINAL_SUBCOMMAND)
            .map(|value| {
                value.into_string().map_err(|_| {
                    error(format!(
                        "supply-chain-guard: {ENV_ORIGINAL_SUBCOMMAND} is not valid Unicode"
                    ))
                })
            })
            .transpose()?;

        Ok(Self {
            direct_cargo: DirectCargoRunner::new(real_cargo),
            downstream: DownstreamRunner::new(next),
            original_subcommand,
        })
    }
}

fn reject_conflicting_guard_plugins() -> Result<()> {
    let Some(chain) = env::var_os(ENV_PLUGIN_CHAIN) else {
        return Ok(());
    };
    let chain = chain.into_string().map_err(|_| {
        error(format!(
            "supply-chain-guard: {ENV_PLUGIN_CHAIN} is not valid Unicode"
        ))
    })?;
    let plugins: std::collections::BTreeSet<_> = chain.split(',').collect();
    if plugins.contains("dependency-audit") && plugins.contains("supply-chain-guard") {
        return Err(error(
            "Supply Chain Guard and Dependency Audit cannot be enabled together.\nDisable one of them with `cargo wrapper plugin disable <name>`.",
        ));
    }
    Ok(())
}

fn required_unicode(name: &str) -> Result<String> {
    env::var_os(name)
        .ok_or_else(|| error(format!("supply-chain-guard: missing host variable {name}")))?
        .into_string()
        .map_err(|_| {
            error(format!(
                "supply-chain-guard: host variable {name} is not Unicode"
            ))
        })
}

fn required_executable(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        env::var_os(name)
            .ok_or_else(|| error(format!("supply-chain-guard: missing host variable {name}")))?,
    );
    validate_executable(name, &path)?;
    Ok(path)
}

fn validate_executable(name: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(error(format!(
            "supply-chain-guard: host variable {name} must be an absolute path"
        )));
    }
    let metadata = std::fs::metadata(path).map_err(|inspect_error| {
        error(format!(
            "supply-chain-guard: executable from {name} is unavailable at {}: {inspect_error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(error(format!(
            "supply-chain-guard: executable from {name} is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(error(format!(
                "supply-chain-guard: executable from {name} lacks execute permission: {}",
                path.display()
            )));
        }
    }
    Ok(())
}
