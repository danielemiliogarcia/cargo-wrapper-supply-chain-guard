<!-- Provenance and maintenance policy for the embedded cargo-vet audit baseline. -->
# Default cargo-vet imports and recovery baseline

Supply Chain Guard's zero-configuration policy selects five established producers from cargo-vet's public registry: Google, Mozilla, Bytecode Alliance, Zcash, and ISRG. During normal online guarded operations, the plugin fetches their current audit files directly, filters them to the evidence described below, and caches an exact fingerprinted snapshot. Selecting these sources is an explicit Supply Chain Guard trust decision, not an endorsement of every producer in the public registry.

The plugin also embeds `community-audits-2026-09-08` as an immutable recovery baseline for first use without network access or when no validated cache exists. Its exact repositories, commits, source SHA-256 values, and entry counts are recorded in [curation/sources.toml](curation/sources.toml) and generated [curation/generated/provenance.toml](curation/generated/provenance.toml). The machine-readable [curation/generated/edge-provenance.toml](curation/generated/edge-provenance.toml) maps every retained embedded audit-entry digest to its producer or producers.

Eligible evidence is deliberately narrow:

- full audits and complete delta chains that cargo-vet resolves as `safe-to-run`;
- `safe-to-deploy` only through cargo-vet's built-in implication to `safe-to-run`;
- custom criteria only when their declared implication reaches a built-in eligible criterion;
- violation records, which can block but never approve.

Both live-import filtering and recovery-baseline generation remove wildcard audits and trusted-publisher entries. Per-query stores remove exemptions. The plugin does not rely on publisher identity as a substitute for reviewing exact code.

## Runtime refresh and cache

The live source URLs and the last cached SHA-256 for each source are shown by:

```sh
cargo supply-chain-guard cargo-vet sources
```

Guarded operations refresh the sources automatically when cargo-vet evidence is needed. An explicit refresh is also available:

```sh
cargo supply-chain-guard cargo-vet update
```

Validated snapshots are stored under `$XDG_DATA_HOME/cargo-wrapper-supply-chain-guard/evidence` (normally `~/.local/share/cargo-wrapper-supply-chain-guard/evidence`) or `%LOCALAPPDATA%\CargoWrapperSupplyChainGuard\evidence` on Windows. They contain audit data and digests, never crate source or executable code. Snapshot files are immutable; a complete newly downloaded set is validated before it becomes eligible for use.

The `decisions` subdirectory stores non-approval cargo-vet results. Each result is keyed by the exact artifact identity and records the evidence-policy fingerprint and verified helper SHA-256 that produced it. An unchanged entry avoids repeated archive inspection. A changed policy or helper forces cargo-vet revalidation, and removed audit coverage restores the normal static-review path. Malformed entries fail closed and can be cleared with the purge uninstaller.

`CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_OFFLINE=true` disables only evidence refresh and selects the latest valid cached snapshot, falling back to the embedded baseline when necessary. `CARGO_NET_OFFLINE=true` also disables evidence refresh but additionally applies Cargo's normal offline behavior to dependency resolution.

## Reproduce the baseline

Build cargo-vet from the pinned submodule commit, then run:

```sh
git submodule update --init --recursive
CARGO_TARGET_DIR=target/cargo-vet-helper \
  cargo build --manifest-path third-party/cargo-vet/Cargo.toml --locked --release

SUPPLY_CHAIN_GUARD_CARGO_VET="$PWD/target/cargo-vet-helper/release/cargo-vet" \
  cargo run --locked --example generate_curated_audits -- --check
```

The generator downloads only immutable commit URLs over TLS, caps each response at 8 MiB, verifies the pinned source digest before TOML parsing, filters weak evidence, asks pinned cargo-vet to parse and canonically format each output, and byte-compares committed files in `--check` mode. It never downloads or executes crate source.

Use `--update` only after intentionally changing the embedded recovery pins. A recovery-baseline change must review producer-by-producer counts and violations, confirm weak evidence remains absent, run synthetic and real cargo-vet tests, update the baseline identifier/date, and ship a new plugin release. Ordinary upstream audit additions reach online users through live imports and do not require a plugin release.

## Limitations

An audit represents the selected producer's review under a stated criterion. Audit scope, reviewer judgment, enabled features, and later discoveries can still matter. No audit path means the developer must review the scanner evidence; an audit path is not a universal safety guarantee.
