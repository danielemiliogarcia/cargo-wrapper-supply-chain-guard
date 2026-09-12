<!-- Security assumptions, trusted components, untrusted inputs, and explicit non-goals. -->
# Threat model

## Protected risk

The plugin reduces the chance that a newly selected registry or supported GitHub dependency, transitive dependency, build script, or procedural macro executes before the developer sees relevant capability evidence or eligible cargo-vet review evidence.

## Trusted computing base

- Cargo Wrapper's protocol-v1 host and plugin-chain enforcement;
- the installed Supply Chain Guard binary;
- pinned cargo-vet 0.10.2 built from commit `e496a28a2cde71db0d98ef631cf4586f89a7fed6`;
- the Rust toolchain and real Cargo path supplied by Cargo Wrapper;
- selected audit producers, their live HTTPS endpoints, and the exact snapshot used for a decision;
- the immutable embedded cargo-vet evidence used only as a recovery baseline;
- the operating system, TLS implementation, crates.io index/checksum service, and GitHub's exact-commit archive endpoint for reviewed GitHub dependencies.

Release checksums and GitHub attestations establish artifact identity and build provenance. They do not prove source harmless.

## Untrusted inputs

- registry indexes, `.crate` bytes, GitHub commit archives, filenames, manifests, build scripts, procedural macros, and source text;
- project-controlled Cargo manifests and cargo-vet configuration;
- live cargo-vet audit files downloaded from selected producers before strict filtering;
- plugin-owned cargo-vet snapshot and decision-cache files;
- terminal-facing crate metadata and URLs;
- helper stdout/stderr beyond the pinned protocol expectations;
- arbitrary code in the developer's workspace.

Untrusted terminal text is sanitized. Archive counts, sizes, paths, and helper output/runtime are bounded. Symlinked candidate workspace entries and unsupported Git dependencies fail closed. Git archive inspection rejects mutable or abbreviated lock identities, non-GitHub hosts, links, submodules, unresolved LFS pointers, ambiguous package identities, and tree-digest changes.

Cargo-vet audit evidence is source-scoped to canonical crates.io identities. Matching names and versions from private registries or mirrors cannot inherit crates.io evidence.

Live default imports are accepted only from the five URLs compiled into the plugin, are size-bounded and parsed as data, and have exemptions, wildcard audits, publisher trust, and unrelated criteria removed. A complete filtered set is fingerprinted before use and cached as an immutable snapshot. A selected producer compromise can still introduce false audit claims and remains part of the trusted computing base, matching cargo-vet's direct-import trust model.

Cached cargo-vet decisions are strict data records keyed to the full artifact identity and bound to the selected policy fingerprint plus verified helper SHA-256. Malformed or identity-mismatched records fail closed. A policy or helper change requires fresh cargo-vet validation, and loss of coverage returns the artifact to source inspection rather than treating the cache as a permanent approval.

## Security boundaries

Before static inspection completes, registry archives and exact GitHub commit archives exist only as bounded in-memory bytes and are not executed. Candidate resolution may fetch Git objects only inside a private disposable Cargo home because Cargo needs them to construct the candidate graph; cargo-vet metadata may similarly unpack registry source there. None of these stages compiles, links, macro-expands, dynamically loads, or executes dependency code.

Downstream Cargo executes only after evidence or explicit user acceptance, and still runs with the developer's privileges. This is a policy gate, not a kernel sandbox.

## Out of scope

- commands that bypass Cargo Wrapper or use an absolute real Cargo path;
- malicious local workspace/path-dependency code;
- private Git repositories and Git hosts other than public HTTPS GitHub sources;
- compromised trusted binaries, Rust toolchain, operating system, or selected audit producer;
- known-vulnerability/advisory detection;
- proving runtime correctness or `safe-to-deploy` suitability;
- network or filesystem containment after the developer accepts execution.
