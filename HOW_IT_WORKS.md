<!-- Question-and-answer explanation of Supply Chain Guard's execution and trust boundaries. -->
# How Supply Chain Guard works

## Does Cargo resolve dependencies before the plugin reviews them?

Yes, but this first pass only calculates the proposed dependency graph. Before invoking Cargo, Supply Chain Guard creates two temporary, per-invocation directories:

- A **workspace copy** contains a copy of the project, excluding `.git` and `target`. Cargo writes proposed manifest and lockfile changes to this copy, not to the real project.
- An **isolated Cargo home** is assigned through `CARGO_HOME` only to that Cargo subprocess. Registry index metadata and temporary Cargo state go there instead of into the developer's normal `~/.cargo` directory.

Cargo can read registry index records and create a candidate `Cargo.lock` during this pass, but dependency code is not compiled or executed: build scripts and procedural macros do not run. Supply Chain Guard verifies that Cargo did not place registry archives or extracted registry source in the isolated Cargo home. Cargo may fetch a Git repository into that disposable home because it cannot resolve a Git package's name, version, and dependency edges from a registry index. That private fetch is never built or executed, never enters the real project or normal Cargo home, and is deleted with the candidate directory.

This is process-state isolation, not a VM or operating-system sandbox. It prevents normal dependency resolution from exposing the real workspace or Cargo cache to unreviewed source; it is not intended to contain a vulnerability in Cargo itself.

## Can rust-analyzer react to candidate resolution?

Normally, no. Rust-analyzer watches the real project, while candidate manifest and lockfile changes happen in a separate temporary directory. The real workspace remains unchanged until the dependency graph has passed review and the operation is accepted. After acceptance, rust-analyzer may observe the real manifest change and run Cargo normally; by then, the exact dependency artifacts have already passed the configured review policy.

## When is the actual `.crate` archive downloaded?

After the exact candidate name, version, source, and registry checksum are known, and only after the user authorizes inspection. The plugin downloads the archive into bounded private memory, verifies its checksum, parses it strictly as tar/gzip data, and scans relevant text as inert source. This stage never writes the archive to Cargo's cache and never executes it.

## How is a GitHub dependency inspected?

Cargo records a Git dependency as a complete source URL ending in the exact commit, for example `git+https://github.com/owner/repository?branch=main#<40-hex-commit>`. Supply Chain Guard treats the branch or tag only as resolution context and uses the locked commit as the immutable identity.

The plugin requests GitHub's tar/gzip archive for that exact commit over verified TLS and reads it into bounded private memory. It does not invoke the `git` executable or create a checkout, so repository-controlled hooks, submodule commands, smudge/LFS filters, and Git credential helpers are never run by the review stage. Archive paths, entry count, compressed/decompressed sizes, relevant-file sizes, package name/version, and entry types are validated before scanning. Symlinks, hard links, submodules, and unresolved LFS pointers fail closed.

The plugin computes a deterministic SHA-256 from every regular file path, executable mode, and content digest in the complete repository archive. “Accept and remember” stores that tree digest together with the full Cargo lock source, package name/version, exact commit, scanner version, and approved capabilities. A later identical operation therefore passes without prompting; a changed commit is a new identity and requires review.

The Git source itself is always reported as a security finding. This prevents a source-only Git package from becoming a permanent approval merely because it has no build script or procedural macro: the developer must explicitly reject it, accept it once, or remember that exact commit and tree digest.

Initially this bounded path supports public `https://github.com` Cargo sources. Other hosts and private archives are rejected with an explanation because using an arbitrary Git client or credential helper would weaken the no-execution boundary.

## What does the static scanner look for?

It reports build scripts, procedural macros, process creation, network access, filesystem mutation, sensitive environment-name references, dynamic command targets, and high-risk combinations. The result tells a reviewer which build-time capabilities deserve attention; it is not a proof that code is malicious or safe.

## Why is cargo-vet involved after the scan?

Static findings can be noisy. For an exact canonical crates.io artifact that would otherwise require review, Supply Chain Guard asks pinned cargo-vet 0.10.2 whether selected code-review evidence forms a complete full/delta path satisfying `safe-to-run`. Git and non-crates.io registry artifacts do not inherit that evidence.

The query removes exemptions, wildcard audits, and trusted-publisher entries. It temporarily exempts every other exact third-party artifact and never exempts any version of the target crate. Therefore a successful query means cargo-vet resolved qualifying review evidence for that target, not merely a convenient project exemption.

## Does the default cargo-vet evidence update online?

Yes. When no project cargo-vet store takes precedence, a guarded invocation that needs cargo-vet evidence refreshes the five selected default imports directly from their producer URLs. The plugin treats those producers as trust authorities, just as a cargo-vet project trusts the imports it configures. It downloads each audit file as bounded data over TLS, removes exemptions, wildcard audits, publisher trust, and criteria unrelated to `safe-to-run`, then fingerprints and caches the exact combined result before using it.

If refresh fails, the operation uses the last validated plugin-owned snapshot. If no cached snapshot exists, it uses the immutable evidence embedded in the plugin as a recovery baseline. `CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_OFFLINE=true` skips only the audit refresh and follows the same fallback order while leaving Cargo networking unchanged. `CARGO_NET_OFFLINE=true` also skips refresh, but retains its normal Cargo-wide meaning. The selected snapshot fingerprint is included in the policy shown to the user, so a decision remains attributable to exact evidence even though the producer lists continue to evolve.

This follows cargo-vet's federated model rather than consulting a central “safe crate” service. Only the explicitly selected producers are contacted. Their imports are non-transitive: a producer's own choice of other imports does not silently expand Supply Chain Guard's trust set.

## Why can cargo-vet create extracted files?

Cargo-vet needs Cargo metadata for the candidate graph. Cargo metadata can download and unpack registry sources even though it does not compile them. Supply Chain Guard first makes a private workspace copy, then redirects `CARGO_HOME`, cargo-vet's store, cache, stdout, and stderr into private temporary storage. Untrusted source therefore never enters the developer's normal Cargo cache or real workspace.

## Can metadata execute a crate's `build.rs` or procedural macro?

No. Metadata resolution does not compile, macro-expand, dynamically load, or execute dependency source. The test suite places an observable malicious `build.rs` canary in a fixture and verifies that candidate resolution, archive inspection, and cargo-vet evaluation leave it untouched.

## How does project cargo-vet policy take precedence?

In `auto` mode, a normal `supply-chain` store beside `Cargo.lock`, or the `package.metadata.vet`/`workspace.metadata.vet` store path, is detected. The plugin copies and filters the project's local audits and locked imported audits in memory, then constructs its private per-artifact query. It does not fetch moving imports or edit project files. A present but malformed or incomplete store fails closed.

This preserves the project's normal cargo-vet workflow: the project updates and commits `imports.lock`, while Supply Chain Guard consumes that exact reviewed state. The plugin-owned online snapshot is used only when no project policy takes precedence.

## What happens when no cargo-vet proof exists?

Nothing is automatically accepted. The crate remains in the normal interactive or LLM review flow. In ordinary modes a broken helper also falls back to static review with a warning; `required` mode rejects instead.

## What happens after acceptance?

For dependency mutations, downstream Cargo runs through the remaining plugin chain. Supply Chain Guard compares the final lockfile with the reviewed candidate and restores original manifests and lockfile if Cargo fails or resolution differs. Approved locked operations receive `--locked`.

Cargo-vet results are never written as personal approvals. They are stored separately as non-approval cache entries bound to the exact artifact identity, verified helper hash, and evidence-policy fingerprint. An unchanged entry can bypass repeated source-inspection authorization. When the selected audit snapshot or helper changes, cargo-vet must validate the exact artifact again before the cache is updated; lost coverage sends the artifact back through static review.

Only an explicit user “accept and remember” decision persists an exact static finding approval. `--accept-and-remember-all` additionally converts the cargo-vet-covered artifacts in that reviewed graph into personal approvals.
