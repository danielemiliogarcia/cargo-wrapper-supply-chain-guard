//! Evaluates exact artifacts with the pinned cargo-vet resolver after static inspection.

use crate::candidate::copy_local_workspace;
use crate::config::VetMode;
use crate::findings::{ArtifactId, ArtifactReview};
use crate::lockfile::CargoLock;
use crate::prompt::sanitize_untrusted;
use crate::vet_baseline::{self, BASELINE_ID, COMBINED_AUDITS};
use crate::vet_cache::{self, CachedVetDecision};
use crate::vet_helper::{EXPECTED_VERSION, VerifiedHelper};
use crate::vet_live::{self, LiveEvidenceSnapshot};
use crate::vet_project::{self, ProjectEvidence};
use crate::vet_store::write_query_store;
use crate::workspace::Workspace;
use crate::{Result, error};
use semver::{Version, VersionReq};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const HELPER_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_HELPER_OUTPUT: u64 = 4 * 1024 * 1024;
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalEvidence {
    pub artifact: ArtifactId,
    pub criterion: String,
    pub authority: String,
    pub policy: String,
    pub detail: String,
}

pub trait EvidenceProvider {
    fn reuse_or_revalidate(
        &mut self,
        _workspace: &Workspace,
        _lock: &CargoLock,
        _artifact: &ArtifactId,
    ) -> Result<Option<ExternalEvidence>> {
        Ok(None)
    }

    fn evaluate(
        &mut self,
        workspace: &Workspace,
        lock: &CargoLock,
        review: &ArtifactReview,
    ) -> Result<Option<ExternalEvidence>>;
}

#[derive(Clone, Debug)]
enum SelectedPolicy {
    Community(CommunityPolicy),
    Project(ProjectEvidence),
}

#[derive(Clone, Debug)]
struct CommunityPolicy {
    label: String,
    fingerprint: String,
    audits: String,
    sources: Vec<CommunitySource>,
}

#[derive(Clone, Debug)]
struct CommunitySource {
    display_name: String,
    audits: String,
}

impl CommunityPolicy {
    fn embedded() -> Result<Self> {
        let provenance = vet_baseline::provenance()?;
        let sources = provenance
            .sources
            .into_iter()
            .map(|source| {
                Ok(CommunitySource {
                    display_name: source.display_name,
                    audits: vet_baseline::producer_audits(&source.id)
                        .ok_or_else(|| error("embedded cargo-vet producer data is missing"))?
                        .to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            label: format!("embedded fallback {BASELINE_ID}"),
            fingerprint: BASELINE_ID.to_owned(),
            audits: COMBINED_AUDITS.to_owned(),
            sources,
        })
    }

    fn refreshed(snapshot: LiveEvidenceSnapshot) -> Self {
        let short = snapshot.short_fingerprint().to_owned();
        Self {
            label: format!("live cargo-vet imports ({short})"),
            fingerprint: snapshot.fingerprint,
            audits: snapshot.audits,
            sources: snapshot
                .sources
                .into_iter()
                .map(|source| CommunitySource {
                    display_name: source.display_name,
                    audits: source.audits,
                })
                .collect(),
        }
    }
}

impl SelectedPolicy {
    fn label(&self) -> String {
        match self {
            Self::Community(community) => community.label.clone(),
            Self::Project(project) => format!("project cargo-vet ({})", &project.fingerprint[..16]),
        }
    }

    fn audits(&self) -> &str {
        match self {
            Self::Community(community) => &community.audits,
            Self::Project(project) => &project.audits,
        }
    }

    fn fingerprint(&self) -> &str {
        match self {
            Self::Community(community) => &community.fingerprint,
            Self::Project(project) => &project.fingerprint,
        }
    }
}

pub struct VetService {
    mode: VetMode,
    real_cargo: PathBuf,
    helper: std::result::Result<VerifiedHelper, String>,
    selected: Option<SelectedPolicy>,
    warned_unavailable: bool,
    refresh_default_imports: bool,
    cache: BTreeMap<String, Option<ExternalEvidence>>,
}

impl VetService {
    pub fn new(mode: VetMode, real_cargo: PathBuf) -> Self {
        let helper = VerifiedHelper::discover()
            .and_then(|helper| {
                verify_helper_version(&helper)?;
                Ok(helper)
            })
            .map_err(|helper_error| helper_error.to_string());
        Self {
            mode,
            real_cargo,
            helper,
            selected: None,
            warned_unavailable: false,
            refresh_default_imports: true,
            cache: BTreeMap::new(),
        }
    }

    pub fn mode(&self) -> VetMode {
        self.mode
    }

    pub fn helper(&self) -> std::result::Result<&VerifiedHelper, &str> {
        self.helper.as_ref().map_err(String::as_str)
    }

    fn select_policy(&mut self, workspace: &Workspace) -> Result<Option<&SelectedPolicy>> {
        if self.mode == VetMode::Off {
            return Ok(None);
        }
        if self.selected.is_none() {
            self.selected = Some(match self.mode {
                VetMode::Curated => SelectedPolicy::Community(self.community_policy()?),
                VetMode::Auto | VetMode::Required => match vet_project::discover(workspace)? {
                    Some(project) => SelectedPolicy::Project(project),
                    None => SelectedPolicy::Community(self.community_policy()?),
                },
                VetMode::Project => {
                    SelectedPolicy::Project(vet_project::discover(workspace)?.ok_or_else(|| {
                        error(
                            "supply-chain-guard: cargo-vet mode is project but no project store exists",
                        )
                    })?)
                }
                VetMode::Off => unreachable!(),
            });
        }
        Ok(self.selected.as_ref())
    }

    fn community_policy(&mut self) -> Result<CommunityPolicy> {
        if self.refresh_default_imports && !vet_live::refresh_is_disabled() {
            match vet_live::refresh_default_evidence() {
                Ok(snapshot) => {
                    eprintln!(
                        "cargo-vet: refreshed {} trusted audit import{} (snapshot {})",
                        snapshot.sources.len(),
                        if snapshot.sources.len() == 1 { "" } else { "s" },
                        snapshot.short_fingerprint()
                    );
                    return Ok(CommunityPolicy::refreshed(snapshot));
                }
                Err(refresh_error) => match vet_live::load_cached_default_evidence() {
                    Ok(Some(snapshot)) => {
                        eprintln!(
                            "supply-chain-guard: could not refresh default cargo-vet imports: {refresh_error}\nUsing the last validated cached snapshot {}.",
                            snapshot.short_fingerprint()
                        );
                        return Ok(CommunityPolicy::refreshed(snapshot));
                    }
                    Ok(None) => {
                        eprintln!(
                            "supply-chain-guard: could not refresh default cargo-vet imports: {refresh_error}\nUsing embedded recovery baseline {BASELINE_ID}."
                        );
                    }
                    Err(cache_error) => {
                        eprintln!(
                            "supply-chain-guard: could not refresh default cargo-vet imports: {refresh_error}\nCached evidence was unavailable: {cache_error}\nUsing embedded recovery baseline {BASELINE_ID}."
                        );
                    }
                },
            }
        }
        if self.refresh_default_imports && vet_live::refresh_is_disabled() {
            if let Some(snapshot) = vet_live::load_cached_default_evidence()? {
                eprintln!(
                    "cargo-vet: evidence refresh is disabled; using cached audit snapshot {}",
                    snapshot.short_fingerprint()
                );
                return Ok(CommunityPolicy::refreshed(snapshot));
            }
            eprintln!(
                "cargo-vet: evidence refresh is disabled and no cached audit snapshot exists; using embedded recovery baseline {BASELINE_ID}"
            );
        }
        CommunityPolicy::embedded()
    }

    fn unavailable(&mut self, message: String) -> Result<Option<ExternalEvidence>> {
        if self.mode == VetMode::Required {
            return Err(error(format!(
                "supply-chain-guard: cargo-vet evidence is required but unavailable: {message}"
            )));
        }
        if !self.warned_unavailable {
            eprintln!(
                "supply-chain-guard: cargo-vet evidence unavailable: {message}\nContinuing with static review; this failure cannot approve a crate."
            );
            self.warned_unavailable = true;
        }
        Ok(None)
    }

    fn evaluate_artifact(
        &mut self,
        workspace: &Workspace,
        lock: &CargoLock,
        artifact: &ArtifactId,
    ) -> Result<Option<ExternalEvidence>> {
        if artifact.source != CRATES_IO_SOURCE {
            return Ok(None);
        }
        let Some(policy) = self.select_policy(workspace)?.cloned() else {
            return Ok(None);
        };
        let helper = match self.helper.clone() {
            Ok(helper) => helper,
            Err(message) => return self.unavailable(message),
        };
        if let Some(violation) = matching_violation(policy.audits(), artifact)? {
            return Err(error(format!(
                "supply-chain-guard: cargo-vet violation applies to {} {}: {violation}; refusing automatic or manual acceptance in this invocation",
                artifact.name, artifact.version
            )));
        }
        let policy_label = policy.label();
        let key = cache_key(policy.fingerprint(), artifact);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached.clone());
        }

        let combined = match run_query(
            &helper,
            &self.real_cargo,
            workspace,
            lock,
            artifact,
            policy.audits(),
        ) {
            Ok(value) => value,
            Err(query_error) => return self.unavailable(query_error.to_string()),
        };
        if !combined {
            eprintln!(
                "! {} {}\n  No qualifying cargo-vet safe-to-run audit path was found.\n  Continuing with Supply Chain Guard static review.",
                sanitize_untrusted(&artifact.name, 512),
                sanitize_untrusted(&artifact.version, 512)
            );
            self.cache.insert(key, None);
            return Ok(None);
        }

        let authority = match &policy {
            SelectedPolicy::Project(project) => {
                format!("project policy at {}", project.store_path.display())
            }
            SelectedPolicy::Community(community) => {
                let mut authority = None;
                for source in &community.sources {
                    match run_query(
                        &helper,
                        &self.real_cargo,
                        workspace,
                        lock,
                        artifact,
                        &source.audits,
                    ) {
                        Ok(true) => {
                            authority = Some(source.display_name.clone());
                            break;
                        }
                        Ok(false) => {}
                        Err(attribution_error) => {
                            eprintln!(
                                "supply-chain-guard: source-specific cargo-vet attribution was unavailable: {attribution_error}; retaining the valid combined-policy result"
                            );
                            break;
                        }
                    }
                }
                authority.unwrap_or_else(|| "combined trusted cargo-vet imports".to_owned())
            }
        };
        let evidence = ExternalEvidence {
            artifact: artifact.clone(),
            criterion: "safe-to-run".to_owned(),
            authority: authority.clone(),
            policy: policy_label,
            detail: "validated full/delta cargo-vet audit path; exemptions, wildcard audits, and publisher trust were excluded".to_owned(),
        };
        let decision = CachedVetDecision::new(
            artifact.clone(),
            authority,
            policy.fingerprint().to_owned(),
            helper.actual_sha256,
        );
        if let Err(cache_error) = vet_cache::save(&decision) {
            eprintln!(
                "supply-chain-guard: could not persist the fingerprint-bound cargo-vet decision: {cache_error}"
            );
        }
        self.cache.insert(key, Some(evidence.clone()));
        Ok(Some(evidence))
    }
}

impl EvidenceProvider for VetService {
    fn reuse_or_revalidate(
        &mut self,
        workspace: &Workspace,
        lock: &CargoLock,
        artifact: &ArtifactId,
    ) -> Result<Option<ExternalEvidence>> {
        if artifact.source != CRATES_IO_SOURCE {
            return Ok(None);
        }
        let Some(cached) = vet_cache::load(artifact)? else {
            return Ok(None);
        };
        let Some(policy) = self.select_policy(workspace)?.cloned() else {
            return Ok(None);
        };
        let helper = match self.helper.clone() {
            Ok(helper) => helper,
            Err(message) => return self.unavailable(message),
        };
        if let Some(violation) = matching_violation(policy.audits(), artifact)? {
            return Err(error(format!(
                "supply-chain-guard: cargo-vet violation applies to {} {}: {violation}; refusing cached acceptance in this invocation",
                artifact.name, artifact.version
            )));
        }
        if cached.matches_policy(policy.fingerprint(), &helper.actual_sha256) {
            let evidence = ExternalEvidence {
                artifact: artifact.clone(),
                criterion: cached.criterion,
                authority: cached.authority,
                policy: policy.label(),
                detail: "reused a fingerprint-bound cargo-vet decision because the exact artifact, verified helper, and evidence policy are unchanged".to_owned(),
            };
            self.cache.insert(
                cache_key(policy.fingerprint(), artifact),
                Some(evidence.clone()),
            );
            return Ok(Some(evidence));
        }

        eprintln!(
            "cargo-vet: evidence changed since the cached decision for {} {}; revalidating before source inspection",
            sanitize_untrusted(&artifact.name, 512),
            sanitize_untrusted(&artifact.version, 512)
        );
        let evidence = self.evaluate_artifact(workspace, lock, artifact)?;
        if evidence.is_none() {
            vet_cache::remove(artifact)?;
        }
        Ok(evidence)
    }

    fn evaluate(
        &mut self,
        workspace: &Workspace,
        lock: &CargoLock,
        review: &ArtifactReview,
    ) -> Result<Option<ExternalEvidence>> {
        self.evaluate_artifact(workspace, lock, &review.artifact)
    }
}

fn cache_key(policy: &str, artifact: &ArtifactId) -> String {
    let mut hasher = Sha256::new();
    for value in [
        policy,
        &artifact.source,
        &artifact.name,
        &artifact.version,
        &artifact.checksum,
        "safe-to-run",
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn verify_helper_version(helper: &VerifiedHelper) -> Result<()> {
    let mut command = Command::new(&helper.path);
    command.arg("--version");
    harden_helper_environment(&mut command);
    let output = run_bounded_helper(&mut command, "version")?;
    if !output.status.success() {
        return Err(error(format!(
            "cargo-vet helper version check failed with {}",
            output.status
        )));
    }
    if output.stdout.len() > 256 {
        return Err(error("cargo-vet helper version output exceeds limit"));
    }
    let version = String::from_utf8(output.stdout)?;
    if version.trim() != EXPECTED_VERSION {
        return Err(error(format!(
            "cargo-vet helper version mismatch: expected {EXPECTED_VERSION:?}, got {:?}",
            version.trim()
        )));
    }
    Ok(())
}

fn run_query(
    helper: &VerifiedHelper,
    real_cargo: &Path,
    workspace: &Workspace,
    lock: &CargoLock,
    target: &ArtifactId,
    audits: &str,
) -> Result<bool> {
    let private = tempfile::Builder::new()
        .prefix("supply-chain-guard-vet-")
        .tempdir()?;
    let store = private.path().join("store");
    let cargo_home = private.path().join("cargo-home");
    let cache = private.path().join("cache");
    let workspace_copy_root = private.path().join("workspace");
    fs::create_dir(&cargo_home)?;
    fs::create_dir(&cache)?;
    copy_local_workspace(&workspace.root, &workspace_copy_root)?;
    let private_workspace = Workspace::discover(&workspace_copy_root)?;
    if private_workspace.fingerprint()? != workspace.fingerprint()? {
        return Err(error(
            "private cargo-vet workspace copy differs from the reviewed workspace",
        ));
    }
    write_query_store(&store, &private_workspace, lock, target, audits)?;
    format_private_store(
        helper,
        real_cargo,
        &private_workspace,
        &store,
        &cargo_home,
        &cache,
    )?;

    let stdout_path = private.path().join("stdout.json");
    let stderr_path = private.path().join("stderr.txt");
    let stdout = fs::File::create(&stdout_path)?;
    let stderr = fs::File::create(&stderr_path)?;
    let mut command = Command::new(&helper.path);
    command
        .arg("vet")
        .arg("--manifest-path")
        .arg(private_workspace.root.join("Cargo.toml"))
        .arg("--store-path")
        .arg(&store)
        .arg("--locked")
        .arg("--no-minimize-exemptions")
        .arg("--no-registry-suggestions")
        .arg("--output-format=json")
        .arg("--cache-dir")
        .arg(&cache)
        .current_dir(&private_workspace.root)
        .env("CARGO", real_cargo)
        .env("CARGO_HOME", &cargo_home)
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    harden_helper_environment(&mut command);
    let mut child = command.spawn().map_err(|launch_error| {
        error(format!(
            "cannot launch verified cargo-vet helper {}: {launch_error}",
            helper.path.display()
        ))
    })?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if file_exceeds_limit(&stdout_path, MAX_HELPER_OUTPUT)?
            || file_exceeds_limit(&stderr_path, MAX_HELPER_OUTPUT)?
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error("cargo-vet helper output exceeds the 4 MiB limit"));
        }
        if started.elapsed() >= HELPER_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error("cargo-vet helper exceeded the 120-second limit"));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout_len = fs::metadata(&stdout_path)?.len();
    let stderr_len = fs::metadata(&stderr_path)?.len();
    if stdout_len > MAX_HELPER_OUTPUT || stderr_len > MAX_HELPER_OUTPUT {
        return Err(error("cargo-vet helper output exceeds the 4 MiB limit"));
    }
    let stdout = fs::read_to_string(&stdout_path)?;
    let stderr = fs::read_to_string(&stderr_path)?;
    let output: serde_json::Value = serde_json::from_str(&stdout).map_err(|parse_error| {
        error(format!(
            "cargo-vet returned malformed JSON with {status}: {parse_error}"
        ))
    })?;
    let conclusion = output.get("conclusion").and_then(serde_json::Value::as_str);
    if status.success() && conclusion == Some("success") {
        return Ok(true);
    }
    if conclusion.is_some_and(|conclusion| conclusion.starts_with("fail (vetting)")) {
        return Ok(false);
    }
    Err(error(format!(
        "cargo-vet helper failed with {status}: stderr={} stdout={}",
        bounded_message(&stderr),
        bounded_message(&stdout)
    )))
}

fn harden_helper_environment(command: &mut Command) {
    for name in [
        "CARGO_WRAPPER_PLUGIN_PROTOCOL",
        "CARGO_WRAPPER_PLUGIN_NAME",
        "CARGO_WRAPPER_REAL_CARGO",
        "CARGO_WRAPPER_NEXT",
        "CARGO_WRAPPER_ORIGINAL_SUBCOMMAND",
        "CARGO_WRAPPER_PLUGIN_CHAIN",
        "CARGO_WRAPPER_PLUGIN_INDEX",
        "CARGO_WRAPPER_PLUGIN_ROOT",
        "CARGO_WRAPPER_PLUGIN_SESSION",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(name);
    }
}

fn format_private_store(
    helper: &VerifiedHelper,
    real_cargo: &Path,
    workspace: &Workspace,
    store: &Path,
    cargo_home: &Path,
    cache: &Path,
) -> Result<()> {
    let mut command = Command::new(&helper.path);
    command
        .arg("vet")
        .arg("fmt")
        .arg("--manifest-path")
        .arg(workspace.root.join("Cargo.toml"))
        .arg("--store-path")
        .arg(store)
        .arg("--no-registry-suggestions")
        .arg("--cache-dir")
        .arg(cache)
        .current_dir(&workspace.root)
        .env("CARGO", real_cargo)
        .env("CARGO_HOME", cargo_home);
    harden_helper_environment(&mut command);
    let output = run_bounded_helper(&mut command, "fmt")?;
    if !output.status.success() {
        return Err(error(format!(
            "cargo-vet rejected the filtered evidence store: stderr={} stdout={}",
            bounded_message(&String::from_utf8_lossy(&output.stderr)),
            bounded_message(&String::from_utf8_lossy(&output.stdout))
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bounded_helper(command: &mut Command, operation: &str) -> Result<BoundedOutput> {
    run_bounded_helper_with_limits(command, operation, HELPER_TIMEOUT, MAX_HELPER_OUTPUT)
}

fn run_bounded_helper_with_limits(
    command: &mut Command,
    operation: &str,
    timeout: Duration,
    output_limit: u64,
) -> Result<BoundedOutput> {
    let capture = tempfile::Builder::new()
        .prefix("supply-chain-guard-helper-output-")
        .tempdir()?;
    let stdout_path = capture.path().join("stdout");
    let stderr_path = capture.path().join("stderr");
    command
        .stdout(Stdio::from(fs::File::create(&stdout_path)?))
        .stderr(Stdio::from(fs::File::create(&stderr_path)?));
    let mut child = command.spawn().map_err(|launch_error| {
        error(format!(
            "cannot launch cargo-vet helper for {operation}: {launch_error}"
        ))
    })?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if file_exceeds_limit(&stdout_path, output_limit)?
            || file_exceeds_limit(&stderr_path, output_limit)?
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error(format!(
                "cargo-vet {operation} output exceeds its configured limit"
            )));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error(format!(
                "cargo-vet {operation} exceeded its runtime limit"
            )));
        }
        thread::sleep(Duration::from_millis(25));
    };
    if file_exceeds_limit(&stdout_path, output_limit)?
        || file_exceeds_limit(&stderr_path, output_limit)?
    {
        return Err(error(format!(
            "cargo-vet {operation} output exceeds its configured limit"
        )));
    }
    Ok(BoundedOutput {
        status,
        stdout: fs::read(stdout_path)?,
        stderr: fs::read(stderr_path)?,
    })
}

fn file_exceeds_limit(path: &Path, limit: u64) -> Result<bool> {
    Ok(fs::metadata(path)?.len() > limit)
}

fn bounded_message(message: &str) -> String {
    let message = message.trim();
    if message.len() <= 2_000 {
        message.to_owned()
    } else {
        let mut end = 2_000;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &message[..end])
    }
}

fn matching_violation(audits: &str, artifact: &ArtifactId) -> Result<Option<String>> {
    let value: toml::Value = toml::from_str(audits)?;
    let definitions = value
        .get("criteria")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    let entries = value
        .get("audits")
        .and_then(|audits| audits.get(&artifact.name))
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let version = Version::parse(&artifact.version)?;
    for entry in entries {
        let Some(table) = entry.as_table() else {
            continue;
        };
        let Some(requirement) = table.get("violation").and_then(toml::Value::as_str) else {
            continue;
        };
        if !VersionReq::parse(requirement)?.matches(&version) {
            continue;
        }
        let criteria = table
            .get("criteria")
            .map(string_or_array)
            .transpose()?
            .unwrap_or_default();
        for criterion in criteria {
            if implies_safe_to_run(&criterion, &definitions, &mut BTreeSet::new())? {
                return Ok(Some(format!(
                    "version requirement {requirement:?} violates criterion {criterion:?}"
                )));
            }
        }
    }
    Ok(None)
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

fn implies_safe_to_run(
    criterion: &str,
    definitions: &toml::map::Map<String, toml::Value>,
    visiting: &mut BTreeSet<String>,
) -> Result<bool> {
    if matches!(criterion, "safe-to-run" | "safe-to-deploy") {
        return Ok(true);
    }
    if !visiting.insert(criterion.to_owned()) {
        return Err(error(format!(
            "cargo-vet criteria implication cycle involving {criterion:?}"
        )));
    }
    let result = if let Some(entry) = definitions.get(criterion).and_then(toml::Value::as_table) {
        if let Some(implies) = entry.get("implies") {
            let mut found = false;
            for implied in string_or_array(implies)? {
                found |= implies_safe_to_run(&implied, definitions, visiting)?;
            }
            found
        } else {
            false
        }
    } else {
        false
    };
    visiting.remove(criterion);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn artifact(version: &str) -> ArtifactId {
        ArtifactId {
            source: "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
            name: "demo".to_owned(),
            version: version.to_owned(),
            checksum: "abc".to_owned(),
        }
    }

    fn service(mode: VetMode) -> VetService {
        VetService {
            mode,
            real_cargo: PathBuf::from("/unused/cargo"),
            helper: Err("fixture helper failure".to_owned()),
            selected: None,
            warned_unavailable: false,
            refresh_default_imports: false,
            cache: BTreeMap::new(),
        }
    }

    #[test]
    fn helper_failure_falls_back_only_when_not_required() {
        assert!(
            service(VetMode::Auto)
                .unavailable("fixture".to_owned())
                .unwrap()
                .is_none()
        );
        assert!(
            service(VetMode::Required)
                .unavailable("fixture".to_owned())
                .unwrap_err()
                .to_string()
                .contains("required")
        );
    }

    #[test]
    fn off_mode_selects_no_policy_and_project_mode_requires_one() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4\n").unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        assert!(
            service(VetMode::Off)
                .select_policy(&workspace)
                .unwrap()
                .is_none()
        );
        let mut project = service(VetMode::Project);
        assert!(
            project
                .select_policy(&workspace)
                .unwrap_err()
                .to_string()
                .contains("no project store exists")
        );
    }

    #[test]
    fn auto_mode_prefers_a_valid_project_policy() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4\n").unwrap();
        let store = directory.path().join("supply-chain");
        fs::create_dir(&store).unwrap();
        fs::write(store.join("config.toml"), "[cargo-vet]\nversion='0.10'\n").unwrap();
        fs::write(store.join("audits.toml"), "[audits]\n").unwrap();
        fs::write(store.join("imports.lock"), "audits = {}\n").unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        let mut auto = service(VetMode::Auto);
        assert!(matches!(
            auto.select_policy(&workspace).unwrap(),
            Some(SelectedPolicy::Project(_))
        ));
    }

    #[test]
    fn curated_mode_ignores_project_cargo_vet_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4\n").unwrap();
        fs::create_dir(directory.path().join("supply-chain")).unwrap();
        fs::write(
            directory.path().join("supply-chain/config.toml"),
            "malformed = [",
        )
        .unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        let mut curated = service(VetMode::Curated);
        assert!(matches!(
            curated.select_policy(&workspace).unwrap(),
            Some(SelectedPolicy::Community(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn helper_runtime_and_output_are_bounded() {
        let mut timeout = Command::new("sh");
        timeout.arg("-c").arg("sleep 1");
        assert!(
            run_bounded_helper_with_limits(
                &mut timeout,
                "fixture",
                Duration::from_millis(20),
                1024,
            )
            .unwrap_err()
            .to_string()
            .contains("runtime limit")
        );

        let mut output = Command::new("sh");
        output.arg("-c").arg("head -c 4096 /dev/zero");
        assert!(
            run_bounded_helper_with_limits(&mut output, "fixture", Duration::from_secs(2), 1024,)
                .unwrap_err()
                .to_string()
                .contains("configured limit")
        );
    }

    #[test]
    fn safe_to_run_violation_is_a_hard_conflict() {
        let audits = "[[audits.demo]]\ncriteria='safe-to-run'\nviolation='>=1.2.0, <2.0.0'\n";
        assert!(
            matching_violation(audits, &artifact("1.3.0"))
                .unwrap()
                .is_some()
        );
        assert!(
            matching_violation(audits, &artifact("2.0.0"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unrelated_violation_does_not_claim_safe_to_run() {
        let audits = "[criteria.license]\ndescription='license'\n[[audits.demo]]\ncriteria='license'\nviolation='>=1.0.0'\n";
        assert!(
            matching_violation(audits, &artifact("1.3.0"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn curated_evidence_is_never_applied_across_registry_identities() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(directory.path().join("Cargo.lock"), "version = 4\n").unwrap();
        let workspace = Workspace::discover(directory.path()).unwrap();
        let lock: CargoLock = toml::from_str("version = 4\npackage = []\n").unwrap();
        let review = ArtifactReview {
            artifact: ArtifactId {
                source: "registry+https://private.example/index".to_owned(),
                name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: "a".repeat(64),
            },
            findings: BTreeSet::new(),
            sources: Vec::new(),
            content_sha256: None,
        };
        let mut service = service(VetMode::Required);
        assert!(
            service
                .evaluate(&workspace, &lock, &review)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pinned_real_cargo_vet_resolves_full_and_delta_evidence_without_executing_code() {
        if std::env::var_os("SUPPLY_CHAIN_GUARD_RUN_REAL_VET_TEST").is_none() {
            return;
        }
        let helper_path = std::env::var_os("SUPPLY_CHAIN_GUARD_TEST_CARGO_VET")
            .map(PathBuf::from)
            .expect("SUPPLY_CHAIN_GUARD_TEST_CARGO_VET");
        let helper_hash = crate::vet_helper::file_sha256(&helper_path).unwrap();
        let helper = VerifiedHelper::verify(helper_path, &helper_hash).unwrap();
        verify_helper_version(&helper).unwrap();

        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname='vet-fixture'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nitoa='=1.0.11'\n",
        )
        .unwrap();
        let canary = project.path().join("CARGO_VET_EXECUTED_CODE");
        fs::write(
            project.path().join("build.rs"),
            format!(
                "fn main() {{ std::fs::write({:?}, b\"bad\").unwrap(); }}",
                canary
            ),
        )
        .unwrap();
        fs::create_dir(project.path().join("src")).unwrap();
        fs::write(project.path().join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        let resolution_home = tempfile::tempdir().unwrap();
        let cargo = PathBuf::from(std::env::var_os("CARGO").expect("CARGO"));
        let status = Command::new(&cargo)
            .arg("generate-lockfile")
            .arg("--manifest-path")
            .arg(project.path().join("Cargo.toml"))
            .env("CARGO_HOME", resolution_home.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!canary.exists());

        let workspace = Workspace::discover(project.path()).unwrap();
        let lock = CargoLock::parse(&workspace.lockfile).unwrap();
        let target = lock
            .remote_artifacts()
            .unwrap()
            .into_iter()
            .find(|artifact| artifact.name == "itoa")
            .unwrap();
        let full = "[[audits.itoa]]\nwho='fixture'\ncriteria='safe-to-run'\nversion='1.0.11'\n";
        assert!(run_query(&helper, &cargo, &workspace, &lock, &target, full).unwrap());
        let deploy =
            "[[audits.itoa]]\nwho='fixture'\ncriteria='safe-to-deploy'\nversion='1.0.11'\n";
        assert!(run_query(&helper, &cargo, &workspace, &lock, &target, deploy).unwrap());
        let custom = "[criteria.reviewed]\ndescription='fixture review'\nimplies='safe-to-run'\n[[audits.itoa]]\nwho='fixture'\ncriteria='reviewed'\nversion='1.0.11'\n";
        assert!(run_query(&helper, &cargo, &workspace, &lock, &target, custom).unwrap());
        let unrelated = "[criteria.license]\ndescription='license only'\n[[audits.itoa]]\nwho='fixture'\ncriteria='license'\nversion='1.0.11'\n";
        assert!(!run_query(&helper, &cargo, &workspace, &lock, &target, unrelated).unwrap());
        assert!(run_query(&helper, &cargo, &workspace, &lock, &target, COMBINED_AUDITS).unwrap());
        let incomplete =
            "[[audits.itoa]]\nwho='fixture'\ncriteria='safe-to-run'\ndelta='1.0.10 -> 1.0.11'\n";
        assert!(!run_query(&helper, &cargo, &workspace, &lock, &target, incomplete).unwrap());
        assert!(
            !canary.exists(),
            "cargo-vet metadata must not execute build.rs"
        );
    }
}
