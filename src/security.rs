//! Orchestrates the trust gate from fast-path fingerprints through artifact review.
//! It coordinates remote metadata, bounded source inspection, decisions, and approvals.

use crate::approvals::ApprovalStore;
use crate::archive_inspector::inspect_archive_for_review;
use crate::findings::{ArtifactId, ArtifactReview, Finding};
use crate::git_source::inspect_git_archive_for_review;
use crate::lockfile::CargoLock;
use crate::prompt::{Decision, DecisionProvider};
use crate::registry::{RegistryClient, load_index_metadata, stage_one_findings};
use crate::vet::EvidenceProvider;
use crate::workspace::{Workspace, local_build_dependency_names};
use crate::{Result, error};
use std::collections::{BTreeMap, BTreeSet};

pub struct SecurityGate<'a> {
    pub store: &'a mut ApprovalStore,
    pub registry: &'a dyn RegistryClient,
    pub decisions: &'a mut dyn DecisionProvider,
    pub evidence: Option<&'a mut dyn EvidenceProvider>,
}

#[derive(Clone, Debug)]
pub struct ReviewOutcome {
    pub fingerprint: String,
    pub fully_remembered: bool,
}

impl SecurityGate<'_> {
    pub fn fast_path(&self, workspace: &Workspace) -> Result<Option<String>> {
        let fingerprint = workspace.fingerprint()?;
        let (lock_hash, manifests_hash) = workspace.component_hashes()?;
        if let Some(previous) = self.store.workspace_record(&workspace.root)
            && !previous.lock_hash.is_empty()
            && previous.lock_hash == lock_hash
            && previous.manifests_hash != manifests_hash
        {
            return Err(error(
                "supply-chain-guard: Cargo.toml dependency state changed while Cargo.lock did not.\n\nRun:\n\n    cargo forcegenerate-lockfile\n\nto resolve and security-review the changed dependency declarations before Cargo runs.",
            ));
        }
        Ok(self
            .store
            .workspace_matches(&workspace.root, &fingerprint)
            .then_some(fingerprint))
    }

    pub fn review_workspace(&mut self, workspace: &Workspace) -> Result<ReviewOutcome> {
        let lock = CargoLock::parse(&workspace.lockfile)?;
        let fingerprint = workspace.fingerprint()?;
        let local_build_dependencies = local_build_dependency_names(workspace)?;
        self.review_lock_with_roots(
            &lock,
            fingerprint,
            &local_build_dependencies,
            Some(workspace),
        )
    }

    pub fn review_lock(&mut self, lock: &CargoLock, fingerprint: String) -> Result<ReviewOutcome> {
        self.review_lock_with_roots(lock, fingerprint, &BTreeSet::new(), None)
    }

    fn review_lock_with_roots(
        &mut self,
        lock: &CargoLock,
        fingerprint: String,
        local_build_dependencies: &BTreeSet<String>,
        workspace: Option<&Workspace>,
    ) -> Result<ReviewOutcome> {
        let artifacts = lock.remote_artifacts()?;
        if artifacts.is_empty() {
            return Ok(ReviewOutcome {
                fingerprint,
                fully_remembered: true,
            });
        }

        // Registry index metadata is the pre-source boundary. Any mismatch aborts here.
        let metadata = load_index_metadata(lock, self.registry)?;
        let stage_one = stage_one_findings(lock, &artifacts, &metadata, local_build_dependencies);
        let mut accepted_once = BTreeSet::<ArtifactId>::new();
        let mut externally_vetted = BTreeSet::<ArtifactId>::new();
        let mut accepted_capabilities = BTreeMap::<ArtifactId, BTreeSet<String>>::new();

        // A prior cargo-vet result is reusable only when its exact artifact, helper,
        // and selected evidence-policy fingerprint still match. Changed evidence is
        // revalidated by the provider before source inspection can be skipped.
        if !self.decisions.remember_external_evidence()
            && let (Some(workspace), Some(provider)) = (workspace, self.evidence.as_deref_mut())
        {
            for artifact in artifacts
                .iter()
                .filter(|artifact| artifact.is_registry())
                .filter(|artifact| !self.store.scanner_is_current(artifact))
            {
                if let Some(evidence) = provider.reuse_or_revalidate(workspace, lock, artifact)? {
                    self.decisions.record_external_evidence(&evidence);
                    externally_vetted.insert(artifact.clone());
                }
            }
        }

        let inspection_needed: Vec<_> = artifacts
            .iter()
            .filter(|artifact| {
                !self.store.scanner_is_current(artifact) && !externally_vetted.contains(*artifact)
            })
            .cloned()
            .collect();
        let needs_authorization: Vec<_> = inspection_needed
            .iter()
            .filter(|artifact| !self.store.has_artifact(artifact))
            .cloned()
            .collect();
        if !needs_authorization.is_empty()
            && !self.decisions.authorize_inspection(&needs_authorization)?
        {
            return Err(error(
                "supply-chain-guard: isolated source inspection rejected; no review archive was downloaded and any candidate-only Git metadata remains disposable",
            ));
        }

        let mut all_findings = stage_one;
        let mut inspected = BTreeSet::new();
        let mut inspected_sources = BTreeMap::new();
        let mut inspected_digests = BTreeMap::<ArtifactId, String>::new();
        for artifact in &inspection_needed {
            let inspection = if artifact.is_git() {
                let bytes = self.registry.download_git_archive(artifact)?;
                let git = inspect_git_archive_for_review(
                    &bytes,
                    &artifact.name,
                    &artifact.version,
                )
                .map_err(|inspection_error| {
                    error(format!(
                        "Git artifact {} {} failed bounded memory-only inspection: {inspection_error}",
                        artifact.name, artifact.version
                    ))
                })?;
                if let Some(expected) = self.store.content_sha256(artifact)
                    && expected != git.content_sha256
                {
                    return Err(error(format!(
                        "GIT INTEGRITY FAILURE\n\nartifact: {} {}\ncommit: {}\napproved tree SHA-256: {}\nreceived tree SHA-256: {}\n\nABORTING.",
                        artifact.name,
                        artifact.version,
                        artifact.checksum,
                        expected,
                        git.content_sha256
                    )));
                }
                inspected_digests.insert(artifact.clone(), git.content_sha256);
                git.inspection
            } else {
                let bytes = self.registry.download_archive(artifact)?;
                inspect_archive_for_review(&bytes, &artifact.checksum).map_err(
                    |inspection_error| {
                        error(format!(
                            "crate {} {} failed memory-only inspection: {inspection_error}",
                            artifact.name, artifact.version
                        ))
                    },
                )?
            };
            all_findings
                .entry(artifact.clone())
                .or_default()
                .extend(inspection.findings);
            inspected.insert(artifact.clone());
            inspected_sources.insert(artifact.clone(), inspection.sources);
        }

        for artifact in &artifacts {
            if externally_vetted.contains(artifact) {
                continue;
            }
            let findings = all_findings.get(artifact).cloned().unwrap_or_default();
            let new_findings = unapproved_findings(self.store, artifact, &findings);
            if !new_findings.is_empty() {
                let review = ArtifactReview {
                    artifact: artifact.clone(),
                    findings: new_findings.clone(),
                    sources: inspected_sources.remove(artifact).unwrap_or_default(),
                    content_sha256: inspected_digests.get(artifact).cloned(),
                };
                let evidence = if let (Some(workspace), Some(provider)) =
                    (workspace, self.evidence.as_deref_mut())
                {
                    provider.evaluate(workspace, lock, &review)?
                } else {
                    None
                };
                if let Some(evidence) = evidence {
                    self.decisions.record_external_evidence(&evidence);
                    if self.decisions.remember_external_evidence() {
                        accepted_capabilities
                            .entry(artifact.clone())
                            .or_default()
                            .extend(capabilities(&new_findings));
                    } else {
                        externally_vetted.insert(artifact.clone());
                    }
                    continue;
                }
                match self.decisions.decide(&review)? {
                    Decision::Reject => return Err(rejected(artifact)),
                    Decision::AcceptOnce => {
                        accepted_once.insert(artifact.clone());
                    }
                    Decision::AcceptAndRemember => {
                        accepted_capabilities
                            .entry(artifact.clone())
                            .or_default()
                            .extend(capabilities(&new_findings));
                    }
                }
            }

            if new_findings.is_empty() && inspected.contains(artifact) {
                self.store.remember_with_content_sha256(
                    artifact,
                    BTreeSet::new(),
                    inspected_digests.get(artifact).cloned(),
                );
            }
        }

        for (artifact, accepted) in accepted_capabilities {
            self.store.remember_with_content_sha256(
                &artifact,
                accepted,
                inspected_digests.get(&artifact).cloned(),
            );
        }
        let fully_remembered = artifacts.iter().all(|artifact| {
            if accepted_once.contains(artifact) {
                return false;
            }
            if externally_vetted.contains(artifact) {
                return false;
            }
            let findings = all_findings.get(artifact).cloned().unwrap_or_default();
            let approved = self.store.approved_findings(artifact);
            self.store.scanner_is_current(artifact) && capabilities(&findings).is_subset(&approved)
        });
        Ok(ReviewOutcome {
            fingerprint,
            fully_remembered,
        })
    }
}

fn unapproved_findings(
    store: &ApprovalStore,
    artifact: &ArtifactId,
    findings: &BTreeSet<Finding>,
) -> BTreeSet<Finding> {
    let approved = store.approved_findings(artifact);
    findings
        .iter()
        .filter(|finding| !approved.contains(&finding.capability))
        .cloned()
        .collect()
}

fn capabilities(findings: &BTreeSet<Finding>) -> BTreeSet<String> {
    findings
        .iter()
        .map(|finding| finding.capability.clone())
        .collect()
}

fn rejected(artifact: &ArtifactId) -> crate::BoxError {
    error(format!(
        "supply-chain-guard: security review rejected {} {}; Cargo was not invoked",
        artifact.name, artifact.version
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::{BatchDecisionProvider, DecisionProvider};
    use crate::registry::{IndexDependency, IndexVersion};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use sha2::{Digest, Sha256};
    use std::cell::Cell;
    use std::io::Write;

    struct ClearingEvidence;

    impl crate::vet::EvidenceProvider for ClearingEvidence {
        fn evaluate(
            &mut self,
            _workspace: &Workspace,
            _lock: &CargoLock,
            review: &ArtifactReview,
        ) -> Result<Option<crate::vet::ExternalEvidence>> {
            Ok(Some(crate::vet::ExternalEvidence {
                artifact: review.artifact.clone(),
                criterion: "safe-to-run".to_owned(),
                authority: "fixture producer".to_owned(),
                policy: "fixture policy".to_owned(),
                detail: "fixture full audit".to_owned(),
            }))
        }
    }

    struct ReusingEvidence;

    impl crate::vet::EvidenceProvider for ReusingEvidence {
        fn reuse_or_revalidate(
            &mut self,
            _workspace: &Workspace,
            _lock: &CargoLock,
            artifact: &ArtifactId,
        ) -> Result<Option<crate::vet::ExternalEvidence>> {
            Ok(Some(crate::vet::ExternalEvidence {
                artifact: artifact.clone(),
                criterion: "safe-to-run".to_owned(),
                authority: "cached fixture producer".to_owned(),
                policy: "unchanged fixture policy".to_owned(),
                detail: "fingerprint-bound fixture decision".to_owned(),
            }))
        }

        fn evaluate(
            &mut self,
            _workspace: &Workspace,
            _lock: &CargoLock,
            _review: &ArtifactReview,
        ) -> Result<Option<crate::vet::ExternalEvidence>> {
            panic!("a reusable decision must bypass source inspection and fresh evaluation")
        }
    }

    struct FakeRegistry {
        archive: Vec<u8>,
        checksum: String,
        index_requests: Cell<usize>,
        downloads: Cell<usize>,
        build_dependency: bool,
    }

    impl RegistryClient for FakeRegistry {
        fn index_version(&self, artifact: &ArtifactId) -> Result<IndexVersion> {
            self.index_requests.set(self.index_requests.get() + 1);
            Ok(IndexVersion {
                name: artifact.name.clone(),
                vers: artifact.version.clone(),
                deps: if self.build_dependency {
                    vec![IndexDependency {
                        name: "network-helper".into(),
                        req: "1".into(),
                        kind: Some("build".into()),
                        package: None,
                    }]
                } else {
                    Vec::new()
                },
                cksum: self.checksum.clone(),
                yanked: false,
            })
        }

        fn download_archive(&self, _: &ArtifactId) -> Result<Vec<u8>> {
            self.downloads.set(self.downloads.get() + 1);
            Ok(self.archive.clone())
        }
    }

    struct Decisions {
        inspect: bool,
        decisions: Vec<Decision>,
        prompts: usize,
    }

    struct FakeGitSource {
        archive: Vec<u8>,
        downloads: Cell<usize>,
    }

    impl RegistryClient for FakeGitSource {
        fn index_version(&self, _: &ArtifactId) -> Result<IndexVersion> {
            panic!("Git artifacts must not query a registry index")
        }

        fn download_archive(&self, _: &ArtifactId) -> Result<Vec<u8>> {
            panic!("Git artifacts must not use the registry download path")
        }

        fn download_git_archive(&self, _: &ArtifactId) -> Result<Vec<u8>> {
            self.downloads.set(self.downloads.get() + 1);
            Ok(self.archive.clone())
        }
    }

    impl DecisionProvider for Decisions {
        fn authorize_inspection(&mut self, _: &[ArtifactId]) -> Result<bool> {
            Ok(self.inspect)
        }

        fn decide(&mut self, _: &ArtifactReview) -> Result<Decision> {
            self.prompts += 1;
            Ok(self.decisions.remove(0))
        }
    }

    fn fixture(build_script: bool) -> (FakeRegistry, CargoLock) {
        let manifest = if build_script {
            "[package]\nname='demo'\nversion='1.0.0'\nbuild='build.rs'"
        } else {
            "[package]\nname='demo'\nversion='1.0.0'\nbuild=false"
        };
        let source = "fn main(){std::process::Command::new(\"sh\").status().unwrap();}";
        let mut archive = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            append(&mut tar, "demo-1.0.0/Cargo.toml", manifest.as_bytes());
            append(&mut tar, "demo-1.0.0/build.rs", source.as_bytes());
            tar.into_inner().unwrap().finish().unwrap();
        }
        let checksum = format!("{:x}", Sha256::digest(&archive));
        let lock: CargoLock = toml::from_str(&format!(
            "version=4\n[[package]]\nname='demo'\nversion='1.0.0'\nsource='sparse+http://127.0.0.1/index/'\nchecksum='{checksum}'"
        ))
        .unwrap();
        (
            FakeRegistry {
                archive,
                checksum,
                index_requests: Cell::new(0),
                downloads: Cell::new(0),
                build_dependency: false,
            },
            lock,
        )
    }

    fn append<W: Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }

    #[test]
    fn exact_git_commit_is_scanned_remembered_with_tree_digest_and_then_skipped() {
        let mut archive = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive, Compression::default());
            let mut tar = tar::Builder::new(encoder);
            append(
                &mut tar,
                "demo-revision/Cargo.toml",
                b"[package]\nname='demo'\nversion='1.0.0'\nbuild='build.rs'",
            );
            append(
                &mut tar,
                "demo-revision/build.rs",
                b"fn main(){std::process::Command::new(\"sh\").status();}",
            );
            tar.into_inner().unwrap().finish().unwrap();
        }
        let registry = FakeGitSource {
            archive,
            downloads: Cell::new(0),
        };
        let lock: CargoLock = toml::from_str(
            "version=4\n[[package]]\nname='demo'\nversion='1.0.0'\nsource='git+https://github.com/acme/demo.git?branch=main#0123456789abcdef0123456789abcdef01234567'",
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
        let artifact = lock.remote_artifacts().unwrap().remove(0);
        let mut decisions = Decisions {
            inspect: true,
            decisions: vec![Decision::AcceptAndRemember],
            prompts: 0,
        };
        let outcome = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
            evidence: None,
        }
        .review_lock(&lock, "first".into())
        .unwrap();
        assert!(outcome.fully_remembered);
        assert_eq!(registry.downloads.get(), 1);
        assert!(store.has_artifact(&artifact));
        assert_eq!(store.content_sha256(&artifact).unwrap().len(), 64);

        let mut no_prompt = Decisions {
            inspect: false,
            decisions: Vec::new(),
            prompts: 0,
        };
        let outcome = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut no_prompt,
            evidence: None,
        }
        .review_lock(&lock, "second".into())
        .unwrap();
        assert!(outcome.fully_remembered);
        assert_eq!(registry.downloads.get(), 1);
        assert_eq!(no_prompt.prompts, 0);
    }

    #[test]
    fn reject_after_memory_scan_never_persists() {
        let (registry, lock) = fixture(true);
        let directory = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
        let mut decisions = Decisions {
            inspect: true,
            decisions: vec![Decision::Reject],
            prompts: 0,
        };
        let mut gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
            evidence: None,
        };
        assert!(gate.review_lock(&lock, "hash".into()).is_err());
        assert_eq!(registry.downloads.get(), 1);
        assert!(!store.has_artifact(&lock.remote_artifacts().unwrap()[0]));
    }

    #[test]
    fn accept_once_does_not_persist_but_remember_does() {
        for (decision, expected) in [
            (Decision::AcceptOnce, false),
            (Decision::AcceptAndRemember, true),
        ] {
            let (registry, lock) = fixture(true);
            let directory = tempfile::tempdir().unwrap();
            let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
            let mut decisions = Decisions {
                inspect: true,
                decisions: vec![decision],
                prompts: 0,
            };
            let mut gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions: &mut decisions,
                evidence: None,
            };
            let outcome = gate.review_lock(&lock, "hash".into()).unwrap();
            assert_eq!(outcome.fully_remembered, expected);
            assert_eq!(
                store.has_artifact(&lock.remote_artifacts().unwrap()[0]),
                expected
            );
        }
    }

    #[test]
    fn external_evidence_omits_decision_without_creating_an_approval() {
        let (registry, lock) = fixture(true);
        let workspace_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace_directory.path().join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'",
        )
        .unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let approvals = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(approvals.path().join("approvals.toml")).unwrap();
        let mut decisions = Decisions {
            inspect: true,
            decisions: Vec::new(),
            prompts: 0,
        };
        let mut evidence = ClearingEvidence;
        let outcome = {
            let mut gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions: &mut decisions,
                evidence: Some(&mut evidence),
            };
            gate.review_lock_with_roots(&lock, "hash".into(), &BTreeSet::new(), Some(&workspace))
                .unwrap()
        };
        let artifact = lock.remote_artifacts().unwrap().remove(0);
        assert_eq!(decisions.prompts, 0);
        assert!(!outcome.fully_remembered);
        assert!(!store.has_artifact(&artifact));
    }

    #[test]
    fn reusable_external_evidence_skips_repeated_source_inspection() {
        let (registry, lock) = fixture(true);
        let workspace_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace_directory.path().join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'",
        )
        .unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let approvals = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(approvals.path().join("approvals.toml")).unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: Vec::new(),
            prompts: 0,
        };
        let mut evidence = ReusingEvidence;
        let outcome = {
            let mut gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions: &mut decisions,
                evidence: Some(&mut evidence),
            };
            gate.review_lock_with_roots(&lock, "hash".into(), &BTreeSet::new(), Some(&workspace))
                .unwrap()
        };
        assert_eq!(registry.downloads.get(), 0);
        assert_eq!(decisions.prompts, 0);
        assert!(!outcome.fully_remembered);
    }

    #[test]
    fn explicit_remember_all_persists_externally_vetted_artifacts() {
        let (registry, lock) = fixture(true);
        let workspace_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace_directory.path().join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'",
        )
        .unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let approvals = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(approvals.path().join("approvals.toml")).unwrap();
        let mut decisions = BatchDecisionProvider::new(Decision::AcceptAndRemember);
        let mut evidence = ClearingEvidence;
        let outcome = {
            let mut gate = SecurityGate {
                store: &mut store,
                registry: &registry,
                decisions: &mut decisions,
                evidence: Some(&mut evidence),
            };
            gate.review_lock_with_roots(&lock, "hash".into(), &BTreeSet::new(), Some(&workspace))
                .unwrap()
        };
        let artifact = lock.remote_artifacts().unwrap().remove(0);
        assert!(outcome.fully_remembered);
        assert!(store.has_artifact(&artifact));
        assert_eq!(decisions.review_count(), 0);
        assert_eq!(decisions.external_evidence_count(), 1);
    }

    #[test]
    fn rejecting_stage_one_downloads_no_archive() {
        let (mut registry, lock) = fixture(false);
        registry.build_dependency = true;
        let directory = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::load(directory.path().join("approvals.toml")).unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: vec![Decision::Reject],
            prompts: 0,
        };
        let mut gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
            evidence: None,
        };
        assert!(gate.review_lock(&lock, "hash".into()).is_err());
        assert_eq!(registry.downloads.get(), 0);
    }

    #[test]
    fn fast_path_performs_no_registry_or_archive_work() {
        let (registry, _) = fixture(false);
        let workspace_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace_directory.path().join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'",
        )
        .unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let fingerprint = workspace.fingerprint().unwrap();
        let (lock_hash, manifests_hash) = workspace.component_hashes().unwrap();
        let approvals_directory = tempfile::tempdir().unwrap();
        let mut store =
            ApprovalStore::load(approvals_directory.path().join("approvals.toml")).unwrap();
        store.remember_workspace(&workspace.root, &fingerprint, &lock_hash, &manifests_hash);
        let mut decisions = Decisions {
            inspect: false,
            decisions: Vec::new(),
            prompts: 0,
        };
        let gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
            evidence: None,
        };
        assert_eq!(gate.fast_path(&workspace).unwrap(), Some(fingerprint));
        assert_eq!(registry.index_requests.get(), 0);
        assert_eq!(registry.downloads.get(), 0);
        assert_eq!(decisions.prompts, 0);
    }

    #[test]
    fn manifest_only_drift_is_rejected_before_registry_access() {
        let (registry, _) = fixture(false);
        let workspace_directory = tempfile::tempdir().unwrap();
        let manifest = workspace_directory.path().join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname='local'\nversion='0.1.0'").unwrap();
        std::fs::write(workspace_directory.path().join("Cargo.lock"), "version=4").unwrap();
        let workspace = Workspace::discover(workspace_directory.path()).unwrap();
        let fingerprint = workspace.fingerprint().unwrap();
        let (lock_hash, manifests_hash) = workspace.component_hashes().unwrap();
        let approvals_directory = tempfile::tempdir().unwrap();
        let mut store =
            ApprovalStore::load(approvals_directory.path().join("approvals.toml")).unwrap();
        store.remember_workspace(&workspace.root, &fingerprint, &lock_hash, &manifests_hash);
        std::fs::write(
            &manifest,
            "[package]\nname='local'\nversion='0.1.0'\n[dependencies]\nnew='1'",
        )
        .unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: Vec::new(),
            prompts: 0,
        };
        let gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
            evidence: None,
        };
        let message = gate.fast_path(&workspace).unwrap_err().to_string();
        assert!(message.contains("Cargo.toml dependency state changed"));
        assert_eq!(registry.index_requests.get(), 0);
        assert_eq!(registry.downloads.get(), 0);
    }

    #[test]
    fn scanner_upgrade_prompts_for_new_capabilities_on_same_checksum() {
        let (registry, lock) = fixture(true);
        let artifact = lock.remote_artifacts().unwrap().remove(0);
        let approvals_directory = tempfile::tempdir().unwrap();
        let approval_path = approvals_directory.path().join("approvals.toml");
        std::fs::write(
            &approval_path,
            format!(
                "[[approvals]]\nsource={:?}\nname={:?}\nversion={:?}\nchecksum={:?}\napproved_findings=['build-script']\nscanner_version=0\n",
                artifact.source, artifact.name, artifact.version, artifact.checksum
            ),
        )
        .unwrap();
        let mut store = ApprovalStore::load(approval_path).unwrap();
        let mut decisions = Decisions {
            inspect: false,
            decisions: vec![Decision::AcceptAndRemember],
            prompts: 0,
        };
        let mut gate = SecurityGate {
            store: &mut store,
            registry: &registry,
            decisions: &mut decisions,
            evidence: None,
        };
        let outcome = gate.review_lock(&lock, "hash".into()).unwrap();
        assert!(outcome.fully_remembered);
        assert_eq!(decisions.prompts, 1);
        assert!(
            store
                .approved_findings(&artifact)
                .contains("process-execution")
        );
    }
}
