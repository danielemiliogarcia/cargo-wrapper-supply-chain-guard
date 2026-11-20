<!-- Overview, installation, policy, and operator guide for Supply Chain Guard. -->
# Cargo Wrapper Supply Chain Guard

Supply Chain Guard is a pre-execution supply-chain firewall for Cargo Wrapper. It resolves an exact candidate dependency graph, verifies and statically scans each unapproved crates.io or supported GitHub artifact, and asks the pinned `cargo-vet` resolver whether selected crates.io audit evidence satisfies `safe-to-run` before Cargo may compile or execute dependency code.

The plugin is registered as `supply-chain-guard` and distributed as `cargo-wrapper-plugin-supply-chain-guard[.exe]`.

New to Cargo Wrapper? The [hands-on guide](https://github.com/danielemiliogarcia/cargowrapper/blob/fork-main/TRY-IT.md) walks through the whole flow in a throwaway folder, including `cargo forceadd` and this plugin's review, without installing anything.

This project preserves the scanner and transaction protections derived from [Cargo Wrapper Dependency Audit](https://github.com/danielemiliogarcia/cargo-wrapper-dependency-audit), with an independent product identity, trust state, release history, and cargo-vet evidence policy.

## What it protects

- `cargo add`, `update`, lock generation, build, run, test, check, clippy, doc, bench, rustc, rustdoc, metadata, fetch, package, publish, and tree operations that pass through Cargo Wrapper;
- exact direct and transitive registry artifacts and immutable GitHub commits, including build dependencies and procedural macros;
- build-time process, network, filesystem, environment, and custom build-script capabilities detected by static analysis;
- candidate/final lock consistency, transaction rollback, and `--locked` replay;
- explicit reject, accept once, exact remember, and LLM batch-review workflows.

Untrusted `.crate` archives are first downloaded into bounded private memory, checked against their registry SHA-256, and parsed as archive data. No crate source is cached, extracted, compiled, macro-expanded, loaded, or executed during this first inspection stage.

For a `git+https://github.com/...#<commit>` lock entry, the plugin downloads GitHub's archive for that exact 40-hex commit over TLS into the same bounded memory-only path. It does not run `git`, create a checkout, or invoke hooks, submodules, Git LFS filters, or credential helpers. It rejects other Git hosts, missing or abbreviated locked commits, symlinks, submodules, unresolved LFS pointers, ambiguous packages, and oversized archives. A remembered Git approval is bound to the complete lock source, package name/version, locked commit, scanner version, approved findings, and a deterministic SHA-256 of the complete repository tree.

For a crate that still needs human review, the cargo-vet phase may let Cargo metadata unpack source beneath a private temporary Cargo home. It never enters the developer's normal Cargo cache or real workspace and is never compiled or executed. The complete temporary directory is destroyed after the decision. See [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

## What it is not

Supply Chain Guard is not an operating-system sandbox and static analysis is not proof of safety. It is also not vulnerability scanning. Continue using `cargo audit`, Dependabot, OSV, or equivalent tools for known advisories. Cargo-vet's `safe-to-run` evidence addresses whether reviewed code is suitable to execute locally; this plugin does not claim a separate `safe-to-deploy` production certification.

## Default zero-configuration policy

The default cargo-vet mode is `auto`:

1. A valid project `supply-chain` store and its locked imports take precedence.
2. Without project cargo-vet policy, the plugin refreshes its selected default imports directly from Google, Mozilla, Bytecode Alliance, Zcash, and ISRG.
3. Each successfully fetched set is strictly filtered, fingerprinted, and saved as an exact plugin-owned snapshot. The last valid snapshot is used when refresh is unavailable; the embedded `community-audits-2026-09-08` baseline is the first-run recovery fallback.
4. A present but malformed or unlocked project store fails closed.
5. No qualifying audit path means the existing static review still appears.
6. An unavailable helper warns and falls back to static review. In `required` mode it rejects.

The default imports are the direct audit URLs published through cargo-vet's registry by those five selected producers. Only full audits, delta audits, violations, and necessary criterion implications are retained. Exemptions, wildcard audits, and trusted-publisher entries can never suppress review. The embedded baseline remains immutable and digest-verified so the plugin has a known recovery policy. See [CURATED-AUDITS.md](CURATED-AUDITS.md).

Cargo-vet evidence applies only to artifacts whose Cargo lock source is the canonical crates.io registry. Private registries, mirrors, and Git dependencies always remain in the static review path, even if their crate name and version match a crates.io audit.

## Install verified precompiled releases

Precompiled releases avoid the chicken-and-egg problem of compiling this security plugin and its dependencies before its protection exists. Each platform bundle contains the plugin, pinned cargo-vet 0.10.2 helper, install manifest, licenses, notices, and exact hashes.

If you prefer source because you audited it and do not trust a binary, build in an isolated disposable sandbox. Do not expose your normal Cargo home, credentials, writable host projects, or Docker socket.

### Linux and macOS

Download `install.sh`, inspect it, and verify its GitHub attestation before executing it:

```sh
version=0.2.2
gh attestation verify install.sh \
  --repo danielemiliogarcia/cargo-wrapper-supply-chain-guard \
  --signer-workflow danielemiliogarcia/cargo-wrapper-supply-chain-guard/.github/workflows/release.yml \
  --source-ref "refs/tags/v$version" \
  --deny-self-hosted-runners
chmod +x install.sh
CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_VERSION="$version" ./install.sh
cargo wrapper plugin enable supply-chain-guard
cargo supply-chain-guard cargo-vet status
```

For a GitHub release installation, a current GitHub CLI is required. Before extracting anything, the installer verifies the bundle checksum and verifies that the bundle was produced by this repository's release workflow from the requested version tag on a GitHub-hosted runner. After extraction, it verifies the manifest identities and hashes for both executables.

For a local release directory instead of GitHub:

```sh
CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL=file:///absolute/path/to/target/distrib \
  ./install.sh
```

### Windows PowerShell

Download and inspect `install.ps1`, verify its GitHub attestation, then run:

```powershell
$Version = "0.2.2"
gh attestation verify .\install.ps1 `
  --repo danielemiliogarcia/cargo-wrapper-supply-chain-guard `
  --signer-workflow danielemiliogarcia/cargo-wrapper-supply-chain-guard/.github/workflows/release.yml `
  --source-ref "refs/tags/v$Version" `
  --deny-self-hosted-runners
Set-ExecutionPolicy -Scope Process Bypass
$env:CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_VERSION = $Version
.\install.ps1
cargo wrapper plugin enable supply-chain-guard
cargo supply-chain-guard cargo-vet status
```

The installer leaves the plugin disabled until explicit enablement. If you download a bundle manually instead, verify its provenance before extracting it:

```sh
gh attestation verify <archive> \
  --repo danielemiliogarcia/cargo-wrapper-supply-chain-guard \
  --signer-workflow danielemiliogarcia/cargo-wrapper-supply-chain-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v<version> \
  --deny-self-hosted-runners
```

Both installers verify the archive checksum and then verify both executable hashes and identities from `INSTALL-MANIFEST.toml` before writing plugin-owned files. For a manual installation, perform those same checks, copy `cargo-vet[.exe]` plus `INSTALL-MANIFEST.toml` to the platform data path documented below, and register the extracted plugin binary:

The `file://` download override is intended for locally built bundles and disposable CI or sandbox tests. Because those files are not GitHub release artifacts, the installer explicitly reports that GitHub attestation verification was skipped. Never treat that local mode as proof of release provenance.

```sh
cargo wrapper plugin install supply-chain-guard \
  /absolute/path/to/cargo-wrapper-plugin-supply-chain-guard
cargo wrapper plugin enable supply-chain-guard
```

The helper and manifest belong in `$XDG_DATA_HOME/cargo-wrapper-supply-chain-guard/bin` (or `~/.local/share/cargo-wrapper-supply-chain-guard/bin`) on Linux/macOS, and `%LOCALAPPDATA%\CargoWrapperSupplyChainGuard\bin` on Windows. Keep the executable names from the release bundle unchanged.

## Interactive review

Use force commands when changing dependency resolution:

```sh
cargo forcegenerate-lockfile
cargo forceadd <dependency-name> --features <feature-name>
cargo forceremove <dependency-name>
cargo remove <dependency-name>
cargo forceupdate
```

For each unresolved finding the interactive UI offers:

- `V`: view matched code evidence;
- `S`: show a complete relevant source file;
- `C`: show the exact crates.io release or immutable GitHub commit link;
- `D`: show the exact docs.rs link when the artifact comes from crates.io;
- `L`: print a copy-ready LLM audit prompt;
- `F`: save that prompt to an `audit-prompt-*.md` file and print a short agent handoff containing its absolute path.

The final decisions remain reject, accept once, or accept and remember for the exact immutable identity and finding set. Git approvals additionally record the complete tree SHA-256.

## GitHub Git dependencies

Both direct and transitive GitHub dependencies go through the same static capability scanner and reject/once/remember decisions as registry crates. The non-registry Git source is itself a finding, so every new exact commit requires an explicit Reject, Accept Once, or Accept and Remember decision even when no additional build-time capability is detected. A branch, tag, or `rev` in `Cargo.toml` is never trusted as the identity: Cargo must resolve it to the full commit stored after `#` in `Cargo.lock`, and that immutable lock identity is what Supply Chain Guard reviews.

The initial candidate calculation may fetch a Git dependency only into its disposable private Cargo home because Cargo needs the repository metadata to resolve a Git package. Cargo does not build or execute it there. The security review then independently obtains the exact commit as a bounded no-checkout archive and computes its deterministic tree digest before the real workspace or normal Cargo cache changes. See [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

Public HTTPS GitHub dependencies are supported initially. Private repositories and other Git hosts fail closed rather than silently weakening authentication or archive bounds. Path dependencies remain governed as local workspace code, outside remote-artifact approvals.

When an ordinary guarded command such as `cargo check` or a commit hook encounters an unapproved locked Git artifact, the same review UI is attached to the invoking terminal. EOF or unavailable input follows the default reject path instead of hanging or silently accepting. Review and remember the exact dependency once from a terminal if hooks or IDE tasks must subsequently run noninteractively.

When cargo-vet supplies eligible evidence, the UI states exactly what happened:

```text
✓ example-crate 1.2.3
  Interactive review omitted: cargo-vet safe-to-run satisfied by Mozilla
  Evidence: validated full/delta cargo-vet audit path
  Policy: live cargo-vet imports (0123456789abcdef)
```

This means the selected audit authority satisfied a specific criterion. It does not mean the crate is universally safe.

## LLM batch review

```sh
cargo forceadd <dependency-name> --dump-audit-prompt
```

If one or more artifacts remain unresolved, the terminal prints ticked cargo-vet evidence for covered candidates and `!` notices for candidates that still need review. Supply Chain Guard then creates a Markdown report containing every unresolved artifact, exact links, matching source excerpts, and strict instructions never to execute crate code. Artifacts cleared by cargo-vet appear only in its evidence context and are excluded from the LLM workload. The requested Cargo operation stops until you review the overall verdict and rerun it with one of:

```sh
cargo forceadd <dependency-name> --accept-all-once
cargo forceadd <dependency-name> --accept-and-remember-all
```

`--accept-all-once` applies only to unresolved artifacts and never converts cargo-vet evidence into a personal approval. `--accept-and-remember-all` is an explicit instruction to remember every exact reviewed artifact, including cargo-vet-covered artifacts, as personal trust.

Cargo-vet decisions also have a separate non-approval cache for canonical crates.io artifacts. Each entry is bound to the exact registry source, crate name, version, checksum, verified helper binary, and selected evidence-policy fingerprint. Repeating an operation with an unchanged identity and policy reuses that decision without asking `[I] Inspect` or downloading the `.crate` again. Git artifacts do not inherit cargo-vet evidence. If the policy snapshot or helper changes, Supply Chain Guard re-runs cargo-vet before source inspection; if the audit no longer covers the artifact, the normal static review returns. This preserves audit revocation while avoiding repetitive prompts.

If cargo-vet covers every static-review candidate, there is nothing for an LLM to audit. Supply Chain Guard prints the exact cargo-vet evidence, does not create an empty Markdown report, and immediately continues the originally requested Cargo operation. No repeated command or acceptance flag is needed.

## Configuration modes

The plugin configuration is:

- Linux/macOS: `$XDG_CONFIG_HOME/cargo-wrapper-supply-chain-guard/config.toml`, or `~/.config/cargo-wrapper-supply-chain-guard/config.toml`;
- Windows: `%APPDATA%\CargoWrapperSupplyChainGuard\config.toml`;
- override: `CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_CONFIG`.

```toml
[cargo-vet]
mode = "auto" # auto | curated | project | off | required
```

- `auto`: project policy when present, otherwise refresh the selected default imports;
- `curated`: ignore project policy and refresh the selected default imports;
- `project`: require valid project policy;
- `off`: retain static scanning without cargo-vet evidence;
- `required`: project policy when present, otherwise the default imports, and reject helper failures.

When cargo-vet evidence is needed, an online guarded operation refreshes the selected default imports once for that invocation. `CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_OFFLINE=true` disables only this refresh and uses the last validated cached snapshot, or the embedded recovery baseline if no cache exists. `CARGO_NET_OFFLINE=true` has the same effect on evidence refresh, but also makes Cargo itself offline, so a dependency operation can fail if its isolated Cargo home does not already contain the required index data. Project cargo-vet stores remain project-controlled: update their `imports.lock` with normal cargo-vet tooling and commit the result for reproducible team policy.

Force an immediate default-import refresh with:

```sh
cargo supply-chain-guard cargo-vet update
```

Read-only diagnostics:

```sh
cargo supply-chain-guard
cargo supply-chain-guard cargo-vet status
cargo supply-chain-guard cargo-vet sources
cargo supply-chain-guard cargo-vet explain-policy
```

## Factory trust bundle

The optional factory bundle contains exact static-scanner approvals. Inspect it before installation:

```sh
cargo supply-chain-guard trust-bundle show
cargo supply-chain-guard trust-bundle install
```

It is separate from cargo-vet evidence. It can reduce prompts for organization-approved artifacts but does not authorize future versions or changed checksums.

## Direct Cargo installation

`cargo install` and `cargo forceinstall` are blocked because resolving an install package requires Cargo to download its source graph before this plugin can enforce the pre-download boundary. Even a trusted top-level tool may have a newly compromised transitive dependency.

Prefer a disposable sandbox. To bypass review exactly once after accepting this limitation:

```sh
cargo forceinstall <package-name> --accept-unreviewed-install-risk
```

The plugin displays a prominent warning, removes its private flag, and invokes downstream `cargo install --locked`. It creates no approvals.

The `--locked` flag matters on older Cargo: up to Cargo 1.99, `cargo install` ignores the package's published `Cargo.lock` unless `--locked` is passed. Cargo 1.100 uses the packaged lockfile by default, and `--locked` does not change dependency resolution for `cargo install` there (it only warns if no lockfile is packaged). Either way, do not rely on minimum publish age for `cargo install`, and treat a forced install as unreviewed.

## Plugin interaction

Cargo Wrapper protocol v1 orders plugins by name, so any plugin named `age-policy` runs before `supply-chain-guard`. Do not enable `dependency-audit` and `supply-chain-guard` together; startup rejects the duplicate guard chain with instructions to disable one.

### Cargo 1.100 and newer

Do not install the `age-policy` plugin. Cargo 1.100 enforces minimum publish age natively, so configure Cargo instead, with a checked-in `.cargo/config.toml` and/or an environment variable:

```toml
# .cargo/config.toml in the project
[registry]
global-min-publish-age = "30 days"
```

```sh
export CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="30 days"
```

Supply Chain Guard resolves its candidate lockfile in a private `CARGO_HOME` and a temporary copy of the project (see [HOW_IT_WORKS.md](HOW_IT_WORKS.md)). That resolution therefore sees the environment variable and the project's own `.cargo/config.toml`, but it does not see `~/.cargo/config.toml` or any `.cargo/config.toml` in directories above the project. A policy that lives only in those places is applied by the final Cargo run but not by the candidate resolution, which can produce a lockfile mismatch (the operation is rolled back) or a review of different versions than the ones finally locked. Use the project file, the environment variable, or both.

When a guarded operation starts, Supply Chain Guard prints a warning (never an error) if Cargo is 1.100 or newer, `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE` is unset, the project's `.cargo/config.toml` does not set `registry.global-min-publish-age` or `registries.crates-io.min-publish-age`, and `$CARGO_HOME/config.toml` does. Set the environment variable or add the setting to the project file to silence it. Policies that live only in directories above the project are not detected.

### Cargo 1.99 and older

Native configuration is silently ignored (or nightly-only), so install the legacy `age-policy` plugin, which selects old-enough versions first; Supply Chain Guard then scans and vets those exact versions.

## Uninstall

```sh
./uninstall.sh          # retain approvals/configuration
./uninstall.sh --purge  # also remove plugin-owned approvals/configuration
```

Windows:

```powershell
.\uninstall.ps1
.\uninstall.ps1 -Purge
```

The uninstallers never remove Cargo Wrapper, Cargo, Rustup, another plugin, or a shared parent directory. Purge removes the plugin-owned cargo-vet import snapshots and fingerprint-bound decision cache; a normal uninstall retains them.

## Development and testing

Clone the repository together with its pinned cargo-vet source:

```sh
git clone --recurse-submodules \
  https://github.com/danielemiliogarcia/cargo-wrapper-supply-chain-guard.git
cd cargo-wrapper-supply-chain-guard
```

For an existing clone, initialize or repair the same submodule state with:

```sh
git submodule update --init --recursive
```

Both commands check out the exact cargo-vet commit recorded by this repository;
they do not follow cargo-vet's latest branch tip.

```sh
cargo fmt --all --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
```

Build the pinned helper and run the real resolver canary:

```sh
CARGO_TARGET_DIR=target/cargo-vet-helper \
  cargo build --manifest-path third-party/cargo-vet/Cargo.toml --locked --release

SUPPLY_CHAIN_GUARD_RUN_REAL_VET_TEST=1 \
SUPPLY_CHAIN_GUARD_TEST_CARGO_VET="$PWD/target/cargo-vet-helper/release/cargo-vet" \
  cargo test --locked \
  vet::tests::pinned_real_cargo_vet_resolves_full_and_delta_evidence_without_executing_code \
  -- --nocapture
```

Curated data regeneration requires that exact helper:

```sh
SUPPLY_CHAIN_GUARD_CARGO_VET="$PWD/target/cargo-vet-helper/release/cargo-vet" \
  cargo run --locked --example generate_curated_audits -- --check
```

See [THREAT_MODEL.md](THREAT_MODEL.md) for boundaries, [MIGRATING-FROM-DEPENDENCY-AUDIT.md](MIGRATING-FROM-DEPENDENCY-AUDIT.md) for migration, and [RELEASING.md](RELEASING.md) for release procedure.

## License

MIT. The bundled cargo-vet helper is available under MIT or Apache-2.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
