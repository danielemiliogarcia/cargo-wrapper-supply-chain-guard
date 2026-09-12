//! Refreshes and caches the default cargo-vet imports without weakening evidence policy.

use crate::vet_baseline::validate_filtered;
use crate::{Result, error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const EVIDENCE_DIR_ENV: &str = "CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_EVIDENCE_DIR";
pub const EVIDENCE_OFFLINE_ENV: &str = "CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_OFFLINE";
const SNAPSHOT_SCHEMA: u32 = 1;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;
const DOWNLOAD_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug)]
pub struct LiveSourceDefinition {
    pub id: &'static str,
    pub display_name: &'static str,
    pub url: &'static str,
}

// These are direct cargo-vet registry imports selected by Supply Chain Guard.
pub const DEFAULT_SOURCES: &[LiveSourceDefinition] = &[
    LiveSourceDefinition {
        id: "google",
        display_name: "Google",
        url: "https://raw.githubusercontent.com/google/supply-chain/main/audits.toml",
    },
    LiveSourceDefinition {
        id: "mozilla",
        display_name: "Mozilla",
        url: "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml",
    },
    LiveSourceDefinition {
        id: "bytecode-alliance",
        display_name: "Bytecode Alliance",
        url: "https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml",
    },
    LiveSourceDefinition {
        id: "zcash",
        display_name: "Zcash",
        url: "https://raw.githubusercontent.com/zcash/rust-ecosystem/main/supply-chain/audits.toml",
    },
    LiveSourceDefinition {
        id: "isrg",
        display_name: "ISRG",
        url: "https://raw.githubusercontent.com/divviup/libprio-rs/main/supply-chain/audits.toml",
    },
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LiveSourceEvidence {
    pub id: String,
    pub display_name: String,
    pub url: String,
    pub source_sha256: String,
    pub filtered_sha256: String,
    pub audits: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LiveEvidenceSnapshot {
    pub schema: u32,
    pub fetched_at_unix: u64,
    pub fingerprint: String,
    pub audits: String,
    pub sources: Vec<LiveSourceEvidence>,
}

impl LiveEvidenceSnapshot {
    pub fn short_fingerprint(&self) -> &str {
        &self.fingerprint[..16]
    }
}

pub fn default_evidence_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(EVIDENCE_DIR_ENV) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    let directory = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            error(format!(
                "LOCALAPPDATA is not defined; set {EVIDENCE_DIR_ENV}"
            ))
        })?
        .join("CargoWrapperSupplyChainGuard/evidence");
    #[cfg(not(windows))]
    let directory = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(|| error(format!("HOME is not defined; set {EVIDENCE_DIR_ENV}")))?
        .join("cargo-wrapper-supply-chain-guard/evidence");
    Ok(directory)
}

pub fn refresh_default_evidence() -> Result<LiveEvidenceSnapshot> {
    refresh_sources(DEFAULT_SOURCES, &default_evidence_dir()?)
}

pub fn load_cached_default_evidence() -> Result<Option<LiveEvidenceSnapshot>> {
    load_latest_snapshot(&default_evidence_dir()?, DEFAULT_SOURCES)
}

pub fn refresh_is_disabled() -> bool {
    [EVIDENCE_OFFLINE_ENV, "CARGO_NET_OFFLINE"]
        .iter()
        .any(|name| {
            std::env::var(name)
                .ok()
                .is_some_and(|value| is_true(&value))
        })
}

fn is_true(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "true")
}

fn refresh_sources(
    definitions: &[LiveSourceDefinition],
    evidence_dir: &Path,
) -> Result<LiveEvidenceSnapshot> {
    validate_definitions(definitions)?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(60))
        .build();
    let mut sources = Vec::with_capacity(definitions.len());
    for definition in definitions {
        let bytes = download_bounded(&agent, definition)?;
        let source_sha256 = digest(&bytes);
        let parsed: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
        let filtered = filter_audits(parsed)?;
        let audits = toml::to_string_pretty(&filtered)?;
        validate_filtered(&audits)?;
        sources.push(LiveSourceEvidence {
            id: definition.id.to_owned(),
            display_name: definition.display_name.to_owned(),
            url: definition.url.to_owned(),
            source_sha256,
            filtered_sha256: digest(audits.as_bytes()),
            audits,
        });
    }
    let audits = combine_sources(&sources)?;
    validate_filtered(&audits)?;
    let fetched_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let snapshot = LiveEvidenceSnapshot {
        schema: SNAPSHOT_SCHEMA,
        fetched_at_unix,
        fingerprint: snapshot_fingerprint(&sources, &audits),
        audits,
        sources,
    };
    validate_snapshot(&snapshot, definitions)?;
    persist_snapshot(evidence_dir, &snapshot, definitions)?;
    Ok(snapshot)
}

fn validate_definitions(definitions: &[LiveSourceDefinition]) -> Result<()> {
    if definitions.is_empty() {
        return Err(error("cargo-vet live import list is empty"));
    }
    let mut ids = BTreeSet::new();
    for definition in definitions {
        if definition.id.is_empty()
            || definition.display_name.is_empty()
            || !definition.url.starts_with("https://")
            || !ids.insert(definition.id)
        {
            return Err(error("cargo-vet live import definition is invalid"));
        }
    }
    Ok(())
}

fn download_bounded(agent: &ureq::Agent, definition: &LiveSourceDefinition) -> Result<Vec<u8>> {
    let mut attempt = 1;
    let response = loop {
        match agent.get(definition.url).call() {
            Ok(response) => break response,
            Err(download_error)
                if attempt < DOWNLOAD_ATTEMPTS && retryable_download_error(&download_error) =>
            {
                std::thread::sleep(Duration::from_millis(250 * attempt as u64));
                attempt += 1;
            }
            Err(download_error) => {
                return Err(error(format!(
                    "cannot refresh cargo-vet import {} from {}: {download_error}",
                    definition.display_name, definition.url
                )));
            }
        }
    };
    if let Some(length) = response.header("content-length")
        && length.parse::<u64>()? > MAX_SOURCE_BYTES
    {
        return Err(error(format!(
            "cargo-vet import {} exceeds the 8 MiB limit",
            definition.display_name
        )));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(error(format!(
            "cargo-vet import {} exceeds the 8 MiB limit",
            definition.display_name
        )));
    }
    Ok(bytes)
}

fn retryable_download_error(download_error: &ureq::Error) -> bool {
    match download_error {
        ureq::Error::Status(code, _) => *code == 429 || *code >= 500,
        ureq::Error::Transport(_) => true,
    }
}

fn filter_audits(mut input: toml::Value) -> Result<toml::Value> {
    let table = input
        .as_table_mut()
        .ok_or_else(|| error("cargo-vet import must be a TOML table"))?;
    let criteria = table
        .get("criteria")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    table.remove("wildcard-audits");
    table.remove("trusted");
    table.remove("exemptions");
    table.remove("publisher");

    let audits = table
        .remove("audits")
        .and_then(|value| value.as_table().cloned())
        .unwrap_or_default();
    let mut filtered_audits = toml::map::Map::new();
    for (crate_name, entries) in audits {
        let entries = entries
            .as_array()
            .ok_or_else(|| error(format!("cargo-vet audits.{crate_name} must be an array")))?;
        let mut filtered = Vec::new();
        for entry in entries {
            let mut entry = entry.clone();
            let entry_table = entry.as_table_mut().ok_or_else(|| {
                error(format!(
                    "cargo-vet audits.{crate_name} entry must be a table"
                ))
            })?;
            let mapped = mapped_criteria(entry_table.get("criteria"), &criteria)?;
            if mapped.is_empty() {
                continue;
            }
            entry_table.insert(
                "criteria".into(),
                if mapped.len() == 1 {
                    toml::Value::String(mapped[0].clone())
                } else {
                    toml::Value::Array(mapped.into_iter().map(toml::Value::String).collect())
                },
            );
            filtered.push(entry);
        }
        if !filtered.is_empty() {
            filtered_audits.insert(crate_name, toml::Value::Array(filtered));
        }
    }
    let mut output = toml::map::Map::new();
    output.insert("audits".into(), toml::Value::Table(filtered_audits));
    Ok(toml::Value::Table(output))
}

fn mapped_criteria(
    value: Option<&toml::Value>,
    definitions: &toml::map::Map<String, toml::Value>,
) -> Result<Vec<String>> {
    let names =
        string_or_array(value.ok_or_else(|| error("cargo-vet audit entry is missing criteria"))?)?;
    let mut mapped = BTreeSet::new();
    for name in names {
        let closure = criterion_closure(&name, definitions, &mut BTreeSet::new(), 0)?;
        if closure.contains("safe-to-deploy") {
            mapped.insert("safe-to-deploy".to_owned());
        } else if closure.contains("safe-to-run") {
            mapped.insert("safe-to-run".to_owned());
        }
    }
    Ok(mapped.into_iter().collect())
}

fn criterion_closure(
    name: &str,
    definitions: &toml::map::Map<String, toml::Value>,
    visiting: &mut BTreeSet<String>,
    depth: usize,
) -> Result<BTreeSet<String>> {
    if depth > 64 {
        return Err(error("cargo-vet criteria implication depth exceeds 64"));
    }
    if !visiting.insert(name.to_owned()) {
        return Err(error(format!(
            "cargo-vet criteria implication cycle involving {name:?}"
        )));
    }
    let mut result = BTreeSet::from([name.to_owned()]);
    if name == "safe-to-deploy" {
        result.insert("safe-to-run".to_owned());
    }
    if let Some(entry) = definitions.get(name) {
        let table = entry
            .as_table()
            .ok_or_else(|| error(format!("cargo-vet criteria.{name} must be a table")))?;
        if let Some(implies) = table.get("implies") {
            for implied in string_or_array(implies)? {
                result.extend(criterion_closure(
                    &implied,
                    definitions,
                    visiting,
                    depth + 1,
                )?);
            }
        }
    }
    visiting.remove(name);
    Ok(result)
}

fn string_or_array(value: &toml::Value) -> Result<Vec<String>> {
    if let Some(value) = value.as_str() {
        return Ok(vec![value.to_owned()]);
    }
    value
        .as_array()
        .ok_or_else(|| error("cargo-vet criteria must be a string or string array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| error("cargo-vet criteria arrays must contain strings"))
        })
        .collect()
}

fn combine_sources(sources: &[LiveSourceEvidence]) -> Result<String> {
    let mut combined = toml::map::Map::new();
    combined.insert("audits".into(), toml::Value::Table(toml::map::Map::new()));
    for source in sources {
        let source: toml::Value = toml::from_str(&source.audits)?;
        let entries = source
            .get("audits")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| error("filtered cargo-vet import has no audits table"))?;
        let target = combined
            .get_mut("audits")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| error("combined cargo-vet audits table is unavailable"))?;
        for (crate_name, entries) in entries {
            let destination = target
                .entry(crate_name.clone())
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| error("combined cargo-vet crate entry is not an array"))?;
            destination.extend(
                entries
                    .as_array()
                    .ok_or_else(|| error("cargo-vet crate entry is not an array"))?
                    .clone(),
            );
        }
    }
    Ok(toml::to_string_pretty(&toml::Value::Table(combined))?)
}

fn snapshot_fingerprint(sources: &[LiveSourceEvidence], audits: &str) -> String {
    let mut hasher = Sha256::new();
    for source in sources {
        for value in [
            source.id.as_str(),
            source.url.as_str(),
            source.source_sha256.as_str(),
            source.filtered_sha256.as_str(),
        ] {
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hasher.update((audits.len() as u64).to_le_bytes());
    hasher.update(audits.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn validate_snapshot(
    snapshot: &LiveEvidenceSnapshot,
    definitions: &[LiveSourceDefinition],
) -> Result<()> {
    if snapshot.schema != SNAPSHOT_SCHEMA
        || snapshot.fingerprint.len() != 64
        || !snapshot
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || snapshot.sources.len() != definitions.len()
    {
        return Err(error(
            "cached cargo-vet evidence snapshot has an invalid identity",
        ));
    }
    validate_filtered(&snapshot.audits)?;
    for (source, definition) in snapshot.sources.iter().zip(definitions) {
        if source.id != definition.id
            || source.display_name != definition.display_name
            || source.url != definition.url
            || source.source_sha256.len() != 64
            || !source
                .source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || source.filtered_sha256 != digest(source.audits.as_bytes())
        {
            return Err(error("cached cargo-vet evidence source failed validation"));
        }
        validate_filtered(&source.audits)?;
    }
    if snapshot.audits != combine_sources(&snapshot.sources)?
        || snapshot.fingerprint != snapshot_fingerprint(&snapshot.sources, &snapshot.audits)
    {
        return Err(error(
            "cached cargo-vet evidence snapshot checksum mismatch",
        ));
    }
    Ok(())
}

fn persist_snapshot(
    evidence_dir: &Path,
    snapshot: &LiveEvidenceSnapshot,
    definitions: &[LiveSourceDefinition],
) -> Result<()> {
    create_private_directory(evidence_dir)?;
    let filename = format!("snapshot-{}.json", snapshot.fingerprint);
    let destination = evidence_dir.join(filename);
    if destination.exists() {
        let metadata = fs::symlink_metadata(&destination)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(error(format!(
                "cargo-vet snapshot destination is not a regular file: {}",
                destination.display()
            )));
        }
        let existing = fs::read(&destination)?;
        if existing.len() as u64 <= MAX_SNAPSHOT_BYTES
            && let Ok(existing) = serde_json::from_slice::<LiveEvidenceSnapshot>(&existing)
            && validate_snapshot(&existing, definitions).is_ok()
            && existing.fingerprint == snapshot.fingerprint
        {
            prune_old_snapshots(evidence_dir, &destination)?;
            return Ok(());
        }
        fs::remove_file(&destination)?;
    }
    let temporary = evidence_dir.join(format!(
        ".snapshot-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let bytes = serde_json::to_vec(snapshot)?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(error(
                "cargo-vet evidence snapshot exceeds the 32 MiB limit",
            ));
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        match fs::rename(&temporary, &destination) {
            Ok(()) => {}
            Err(rename_error)
                if rename_error.kind() == std::io::ErrorKind::AlreadyExists
                    && destination.is_file() =>
            {
                fs::remove_file(&temporary)?;
            }
            Err(rename_error) => return Err(rename_error.into()),
        }
        prune_old_snapshots(evidence_dir, &destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn prune_old_snapshots(evidence_dir: &Path, keep: &Path) -> Result<()> {
    for entry in fs::read_dir(evidence_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == keep {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if name.starts_with("snapshot-") && name.ends_with(".json") && entry.file_type()?.is_file()
        {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(error(format!(
                "cargo-vet evidence path is not a regular directory: {}",
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

fn load_latest_snapshot(
    evidence_dir: &Path,
    definitions: &[LiveSourceDefinition],
) -> Result<Option<LiveEvidenceSnapshot>> {
    if !evidence_dir.exists() {
        return Ok(None);
    }
    create_private_directory(evidence_dir)?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(evidence_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("snapshot-") && name.ends_with(".json") {
            candidates.push(entry.path());
        }
    }
    let mut newest = None;
    for path in candidates.into_iter().take(32) {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_SNAPSHOT_BYTES
        {
            continue;
        }
        let bytes = fs::read(&path)?;
        let Ok(snapshot) = serde_json::from_slice::<LiveEvidenceSnapshot>(&bytes) else {
            continue;
        };
        if validate_snapshot(&snapshot, definitions).is_ok()
            && newest
                .as_ref()
                .is_none_or(|current: &LiveEvidenceSnapshot| {
                    snapshot.fetched_at_unix > current.fetched_at_unix
                })
        {
            newest = Some(snapshot);
        }
    }
    Ok(newest)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    const FIXTURE: &str = "[criteria.reviewed]\ndescription='reviewed'\nimplies='safe-to-run'\n[criteria.license]\ndescription='license'\n[[audits.demo]]\ncriteria='reviewed'\nversion='1.0.0'\n[[audits.demo]]\ncriteria='license'\nversion='2.0.0'\n[[audits.demo]]\ncriteria='reviewed'\nviolation='>=3.0.0'\n[[wildcard-audits.demo]]\ncriteria='safe-to-run'\nuser-id=1\nstart='2020-01-01'\nend='2030-01-01'\n[[trusted.demo]]\ncriteria='safe-to-run'\nuser-id=1\nstart='2020-01-01'\nend='2030-01-01'\n";

    #[test]
    fn live_filter_keeps_only_relevant_full_delta_and_violation_evidence() {
        let filtered = filter_audits(toml::from_str(FIXTURE).unwrap()).unwrap();
        let text = toml::to_string(&filtered).unwrap();
        assert!(text.contains("version = \"1.0.0\""));
        assert!(text.contains("violation"));
        assert!(!text.contains("version = \"2.0.0\""));
        assert!(!text.contains("wildcard-audits"));
        assert!(!text.contains("trusted"));
    }

    #[test]
    fn offline_switch_values_are_deliberately_narrow() {
        assert!(is_true("1"));
        assert!(is_true("TRUE"));
        assert!(!is_true("yes"));
        assert!(!is_true("0"));
    }

    #[test]
    fn refresh_persists_a_valid_snapshot_and_cache_can_reload_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                FIXTURE.len(),
                FIXTURE
            )
            .unwrap();
        });
        let leaked_url: &'static str =
            Box::leak(format!("http://{address}/audits.toml").into_boxed_str());
        let definitions = [LiveSourceDefinition {
            id: "fixture",
            display_name: "Fixture",
            url: leaked_url,
        }];
        // Test-only local HTTP is accepted after validating production definitions separately.
        let directory = tempfile::tempdir().unwrap();
        let snapshot = refresh_sources_for_test(&definitions, directory.path()).unwrap();
        server.join().unwrap();
        assert!(snapshot.audits.contains("audits.demo"));
        let cached = load_latest_snapshot(directory.path(), &definitions)
            .unwrap()
            .unwrap();
        assert_eq!(cached.fingerprint, snapshot.fingerprint);
    }

    #[test]
    fn live_default_sources_refresh_when_explicitly_enabled() {
        if std::env::var_os("SUPPLY_CHAIN_GUARD_RUN_LIVE_IMPORT_TEST").is_none() {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let snapshot = refresh_sources(DEFAULT_SOURCES, directory.path()).unwrap();
        assert_eq!(snapshot.sources.len(), DEFAULT_SOURCES.len());
        assert!(snapshot.audits.contains("[audits"));
        assert!(
            load_latest_snapshot(directory.path(), DEFAULT_SOURCES)
                .unwrap()
                .is_some()
        );
    }

    fn refresh_sources_for_test(
        definitions: &[LiveSourceDefinition],
        evidence_dir: &Path,
    ) -> Result<LiveEvidenceSnapshot> {
        let agent = ureq::AgentBuilder::new().build();
        let mut sources = Vec::new();
        for definition in definitions {
            let response = agent.get(definition.url).call()?;
            let mut bytes = Vec::new();
            response.into_reader().read_to_end(&mut bytes)?;
            let audits = toml::to_string_pretty(&filter_audits(toml::from_str(
                std::str::from_utf8(&bytes)?,
            )?)?)?;
            sources.push(LiveSourceEvidence {
                id: definition.id.to_owned(),
                display_name: definition.display_name.to_owned(),
                url: definition.url.to_owned(),
                source_sha256: digest(&bytes),
                filtered_sha256: digest(audits.as_bytes()),
                audits,
            });
        }
        let audits = combine_sources(&sources)?;
        let snapshot = LiveEvidenceSnapshot {
            schema: SNAPSHOT_SCHEMA,
            fetched_at_unix: 1,
            fingerprint: snapshot_fingerprint(&sources, &audits),
            audits,
            sources,
        };
        validate_snapshot(&snapshot, definitions)?;
        persist_snapshot(evidence_dir, &snapshot, definitions)?;
        Ok(snapshot)
    }
}
