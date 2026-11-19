# Releasing Supply Chain Guard

Releases use checksum-pinned `cargo-dist` 0.32.0 and GitHub Actions. A version tag builds the plugin and the source-pinned cargo-vet 0.10.2 helper on Linux, macOS, and Windows. The workflow packages verified bundles, installers, checksums, a source archive, and an install manifest; attests every published file; and creates the GitHub Release only after every target succeeds.

## Release targets

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

The matrix is defined in `dist-workspace.toml`. Each supported target receives a `cargo-wrapper-supply-chain-guard-bundle-<target>` archive containing:

```text
cargo-wrapper-plugin-supply-chain-guard[.exe]
cargo-vet[.exe]
INSTALL-MANIFEST.toml
LICENSE
README.md
THIRD_PARTY_NOTICES.md
```

The helper is always built from Git submodule commit `e496a28a2cde71db0d98ef631cf4586f89a7fed6`. A release bundle never contains a binary named `cargo`.

## Build a host bundle locally

Initialize the helper submodule, install the repository-pinned dist executable, and build the bundle for the current target:

```sh
git submodule update --init --recursive
./scripts/install-pinned-dist.sh
dist --version                 # cargo-dist 0.32.0
dist plan
./scripts/build-release-bundle.sh x86_64-unknown-linux-gnu
```

Use the version from `Cargo.toml`. Add `--allow-dirty` only for a local smoke test; never publish a dirty build because its binary and Git-derived source archive can represent different trees. Artifacts appear in `target/distrib/`, with names such as:

```text
cargo-wrapper-supply-chain-guard-bundle-x86_64-unknown-linux-gnu.tar.xz
cargo-wrapper-supply-chain-guard-bundle-x86_64-unknown-linux-gnu.tar.xz.sha256
INSTALL-MANIFEST-x86_64-unknown-linux-gnu.toml
```

Verify them from `target/distrib`:

```sh
sha256sum --check cargo-wrapper-supply-chain-guard-bundle-x86_64-unknown-linux-gnu.tar.xz.sha256
tar -tJf cargo-wrapper-supply-chain-guard-bundle-x86_64-unknown-linux-gnu.tar.xz
```

A single host cannot natively produce and validate all five binaries. The GitHub workflow runs the bundle builder on the suitable Linux, macOS, and Windows runners and releases only after all target jobs pass.

## Cut a release

1. Update the package version in `Cargo.toml` and `Cargo.lock`, and update the matching default version in `install.sh` and `install.ps1`.
2. Run:

   ```sh
   cargo test --all-targets --locked
   cargo clippy --all-targets --locked -- -D warnings
   cargo fmt --all --check
   CARGO_TARGET_DIR=target/cargo-vet-helper \
     cargo build --manifest-path third-party/cargo-vet/Cargo.toml --locked --release
   SUPPLY_CHAIN_GUARD_CARGO_VET="$PWD/target/cargo-vet-helper/release/cargo-vet" \
     cargo run --locked --example generate_curated_audits -- --check
   dist plan
   ```

3. Review the plan, commit the release, and push a matching annotated tag:

   ```sh
   git tag -a v0.1.1 -m "Supply Chain Guard 0.1.0"
   git push origin v0.1.1
   ```

The workflow publishes only tags shaped like `vMAJOR.MINOR.PATCH`. Any verification, build, packaging, or attestation failure prevents publication. Target-specific `INSTALL-MANIFEST-<target>.toml` files are published separately as well as inside their bundles so GitHub can attest each manifest directly.

## Release trust model

The workflow does not use `curl | sh` to bootstrap `dist`. The local action downloads the exact 0.32.0 executable and verifies a repository-pinned SHA-256 digest. External GitHub Actions are pinned to full commits, and the publishing job has the only attestation identity-token permission.

The release installers require GitHub CLI and verify the downloaded bundle's repository/workflow attestation before extraction. Users must separately verify the downloaded installer script itself before executing it. For a manual artifact download, verify both its checksum and repository provenance:

```sh
gh attestation verify \
  cargo-wrapper-supply-chain-guard-bundle-x86_64-unknown-linux-gnu.tar.xz \
  --repo danielemiliogarcia/cargo-wrapper-supply-chain-guard \
  --signer-workflow danielemiliogarcia/cargo-wrapper-supply-chain-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.1 \
  --deny-self-hosted-runners
```

Checksums detect corruption and attestations identify the producing repository/workflow. Neither proves the source safe. macOS code signing and Windows Authenticode are not currently configured.

## Update cargo-vet

Cargo-vet upgrades are deliberate, not automatic. The repository tracks Mozilla's source as the `third-party/cargo-vet` Git submodule and release bundles contain the helper compiled from one reviewed commit. To upgrade it:

1. Review the upstream release and the exact source commit, then move the submodule gitlink to that commit.
2. Update the expected version and commit in `src/vet_helper.rs`, `scripts/build-release-bundle.sh`, `.github/workflows/release.yml`, installer identity checks, smoke tests, and third-party notices.
3. Reproduce the embedded recovery audit inputs and review any deliberate provenance diff.
4. Run the real cargo-vet resolver test, all Rust tests and lints, both installer smoke tests, and the Docker `sbx` chain test.
5. Publish a new Supply Chain Guard release so every supported platform receives the newly pinned helper.

There is no requirement to follow every cargo-vet release immediately. Upgrade for relevant security fixes, compatibility fixes, or features after review; pinning prevents an unreviewed upstream update from silently changing policy behavior.

The cargo-vet executable and the default audit imports have separate lifecycles. The helper remains source-pinned and requires a plugin release to upgrade. Current full/delta audits from the five selected producers are refreshed and cached by installed plugins at runtime, so ordinary upstream audit additions require no release. The embedded recovery baseline should still be refreshed periodically and whenever its producer set changes.

## Update `cargo-dist` or release actions

Treat release-infrastructure changes as security-sensitive:

1. Review the upstream release and immutable source revision.
2. Update `cargo-dist-version` in `dist-workspace.toml`, `DIST_VERSION` in `.github/actions/install-dist/action.yml`, and `dist_version` in `scripts/install-pinned-dist.sh` together.
3. Independently verify and update every platform digest in both installer helpers.
4. Update action commit hashes in `dist-workspace.toml` and the workflow together.
5. Run `dist plan` and review the generated workflow difference. Preserve the checksum-verifying bootstrap.

## Update the optional trust bundle

`factory-approvals.toml` is embedded but inert until the user explicitly runs `cargo supply-chain-guard trust-bundle install`.

Regenerate it from the widest source root containing the Cargo projects whose exact locked artifacts should be trusted:

```sh
./scripts/generate-factory-approvals.sh /path/to/source-root
```

Generation is cumulative by default. Existing exact identities are combined with the current lockfile inventory, checked again against the current RustSec database, checksum-verified, and rescanned before the output is replaced. This preserves previously reviewed coverage without preserving an identity that now fails validation.

Transient registry failures are retried with bounded exponential backoff. If any archive still cannot be downloaded or strictly inspected, generation aborts before replacing the existing bundle or report. Resolve the failure and rerun; never publish a bundle made smaller by unavailable scan input.

Each successful run appends its scope and exclusions to `FACTORY-SCAN.md`. Keep this cumulative history with the generated bundle; generation never truncates an earlier scan record.

To deliberately discard all previous identities and rebuild only from current lockfiles, use the explicit destructive mode:

```sh
./scripts/generate-factory-approvals.sh --reset /path/to/source-root
```

Always review the resulting exact-identity diff. A large unexpected deletion should block the release.

1. Use exact lockfile identities: source, name, version, and checksum.
2. Run `cargo audit` with a fresh RustSec database and exclude vulnerable, unsound, unmaintained, and yanked releases.
3. Run `examples/scan_factory_bundle.rs`; it verifies archives and uses the plugin's bounded memory-only scanner.
4. Fail closed for unavailable archives, conflicts, unsupported Git sources, or unresolved manifests. Record exclusions.
5. Manually review findings, update `bundle_version` and `reviewed_at`, and bind records to the current scanner version.
6. Keep each release checksum-exact. Never replace versions with ranges, wildcards, or SemVer ceilings.
7. Run all tests and both sandbox paths: no bundle installed, then an explicitly installed bundle.

Installing or updating the plugin must never import a trust bundle automatically.
