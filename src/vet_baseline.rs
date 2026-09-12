//! Embeds the immutable, filtered cargo-vet baseline and its provenance metadata.

use crate::{Result, error};
use serde::Deserialize;

pub const BASELINE_ID: &str = "community-audits-2026-09-08";
pub const COMBINED_AUDITS: &str = include_str!("../curation/generated/combined.toml");

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BaselineProvenance {
    pub baseline: String,
    pub sources: Vec<BaselineSource>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BaselineSource {
    pub id: String,
    pub display_name: String,
    pub repository: String,
    pub commit: String,
    pub sha256: String,
    pub retained_audits: usize,
    pub retained_violations: usize,
    pub removed_wildcard_audits: usize,
    pub removed_trusted_publishers: usize,
    pub removed_unrelated_audits: usize,
}

pub fn provenance() -> Result<BaselineProvenance> {
    let provenance: BaselineProvenance =
        toml::from_str(include_str!("../curation/generated/provenance.toml"))?;
    if provenance.baseline != BASELINE_ID || provenance.sources.len() != 5 {
        return Err(error(
            "embedded cargo-vet baseline provenance is inconsistent",
        ));
    }
    validate_filtered(COMBINED_AUDITS)?;
    Ok(provenance)
}

pub fn producer_audits(id: &str) -> Option<&'static str> {
    match id {
        "google" => Some(include_str!("../curation/generated/google.toml")),
        "mozilla" => Some(include_str!("../curation/generated/mozilla.toml")),
        "bytecode-alliance" => Some(include_str!("../curation/generated/bytecode-alliance.toml")),
        "zcash" => Some(include_str!("../curation/generated/zcash.toml")),
        "isrg" => Some(include_str!("../curation/generated/isrg.toml")),
        _ => None,
    }
}

pub fn validate_filtered(contents: &str) -> Result<()> {
    let value: toml::Value = toml::from_str(contents)?;
    let table = value
        .as_table()
        .ok_or_else(|| error("cargo-vet baseline must be a TOML table"))?;
    if table.contains_key("wildcard-audits")
        || table.contains_key("trusted")
        || table.contains_key("exemptions")
        || table.contains_key("publisher")
    {
        return Err(error(
            "cargo-vet baseline contains forbidden wildcard, publisher, or exemption evidence",
        ));
    }
    if !table.get("audits").is_some_and(toml::Value::is_table) {
        return Err(error("cargo-vet baseline has no audits table"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_baseline_is_filtered_and_pinned() {
        let provenance = provenance().unwrap();
        assert_eq!(provenance.baseline, BASELINE_ID);
        assert_eq!(provenance.sources.len(), 5);
        for source in provenance.sources {
            assert_eq!(source.commit.len(), 40);
            assert_eq!(source.sha256.len(), 64);
        }
    }
}
