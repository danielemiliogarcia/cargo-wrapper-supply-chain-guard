<!-- Disposable Docker sbx build, installation, plugin-chain, and security smoke test. -->
# Docker `sbx` smoke testing

This guide builds everything inside a cloned sandbox. It does not copy host `target` files or expose the host Cargo home.

## Create the isolated clone

From this repository on the host:

```sh
sbx run \
  --name supply-chain-guard-smoke \
  --memory 8g \
  --clone shell
```

`--clone` creates an isolated Git worktree while mounting the host repository source read-only at `/run/sandbox/source`. Do not use the normal read/write workspace mode for this test.

The Git clone contains committed files only. To test the current unstaged implementation, copy the live read-only source into private sandbox storage before building. The `target` directory is deliberately excluded so every binary is built inside the sandbox:

```sh
set -eu
review_root=$(mktemp -d /tmp/supply-chain-guard-review.XXXXXX)
(cd /run/sandbox/source && tar --exclude='./target' --exclude='*/target' -cf - .) | \
  (cd "$review_root" && tar -xf -)
cd "$review_root"

grep '^name = "cargo-wrapper-supply-chain-guard"$' Cargo.toml
test -f third-party/cargo-vet/Cargo.toml
git -C third-party/cargo-vet rev-parse HEAD
```

The last command must print `e496a28a2cde71db0d98ef631cf4586f89a7fed6`. This copy includes the unstaged and untracked files for review, but all writes and build products remain inside the sandbox.

## Bootstrap build tools inside the sandbox

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl git xz-utils pkg-config libssl-dev

curl --proto '=https' --tlsv1.2 --fail https://sh.rustup.rs --output /tmp/rustup-init.sh
sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.96.0
. "$HOME/.cargo/env"
rustup component add rust-src --toolchain 1.96.0
real_cargo=$(rustup which cargo)

git submodule update --init --recursive
```

The smoke guide deliberately pins Cargo 1.96.0. This makes the test reproducible and exercises Age Policy's old-Cargo compatibility filter instead of changing behavior whenever the system's `stable` channel advances. Installing `rust-src` once before compilation also avoids concurrent rustup component-install races in heavily parallel builds.

Clone the matching Cargo Wrapper fork inside the sandbox, build it, install its binary into the sandbox user's path, and verify ordinary Cargo before adding plugins:

```sh
git clone --branch fork-main \
  https://github.com/danielemiliogarcia/cargowrapper.git \
  /tmp/cargowrapper
"$real_cargo" build --locked --release --manifest-path /tmp/cargowrapper/Cargo.toml
mkdir -p "$HOME/.local/bin"
install -m 0755 /tmp/cargowrapper/target/release/cargowrapper "$HOME/.local/bin/cargo"
export PATH="$HOME/.local/bin:$PATH"
cargo wrapper
cargo --version
```

## Build and install this plugin entirely inside the sandbox

From the writable Supply Chain Guard review copy created above:

```sh
"$real_cargo" build --locked --release --bin cargo-wrapper-plugin-supply-chain-guard
CARGO_TARGET_DIR=target/cargo-vet-helper \
  "$real_cargo" build --manifest-path third-party/cargo-vet/Cargo.toml --locked --release

helper="$PWD/target/cargo-vet-helper/release/cargo-vet"
helper_sha=$(sha256sum "$helper" | awk '{print $1}')
data_dir="$HOME/.local/share/cargo-wrapper-supply-chain-guard/bin"
mkdir -p "$data_dir"
install -m 0755 "$helper" "$data_dir/cargo-vet"
cat > "$data_dir/INSTALL-MANIFEST.toml" <<EOF
[cargo-vet]
version = "0.10.2"
source-commit = "e496a28a2cde71db0d98ef631cf4586f89a7fed6"
sha256 = "$helper_sha"
EOF

cargo wrapper plugin install supply-chain-guard \
  "$PWD/target/release/cargo-wrapper-plugin-supply-chain-guard"
cargo wrapper plugin list
cargo wrapper plugin enable supply-chain-guard
export CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_EVIDENCE_DIR=/tmp/supply-chain-guard-live-evidence
cargo supply-chain-guard cargo-vet status
cargo supply-chain-guard cargo-vet update
cargo supply-chain-guard cargo-vet status
cargo supply-chain-guard cargo-vet sources
```

The list must show the plugin disabled before `enable` and active afterward. Before the explicit update, status must report that no cached import snapshot exists. The update must fetch five trusted imports and print an exact snapshot fingerprint. The second status and `sources` output must show cargo-vet 0.10.2, its absolute sandbox path, matching SHA-256, the cache location, the cached fingerprint, each live URL and source SHA-256, and the embedded recovery baseline.

## Exercise automatic cargo-vet coverage

```sh
cd /tmp
"$real_cargo" new guard-demo
cd guard-demo
cargo forceadd 'proc-macro2@=1.0.95' --dump-audit-prompt
```

The command first refreshes the live default imports. It must report that cargo-vet covered `proc-macro2`, create no `audit-prompt-*.md`, and complete the requested `cargo add` immediately. Confirm both effects:

```sh
grep 'proc-macro2' Cargo.toml
if find . -maxdepth 1 -name 'audit-prompt-*.md' -print -quit | grep .; then
  echo 'ERROR: an empty audit prompt was created' >&2
  exit 1
fi
```

Repeat the exact operation without providing interactive input. The fingerprint-bound cargo-vet decision must be reused, the `.crate` must not be inspected again, and the command must not print an `[I] Inspect` prompt:

```sh
repeat_output=/tmp/guard-demo/repeated-proc-macro2.txt
cargo forceadd 'proc-macro2@=1.0.95' </dev/null >"$repeat_output" 2>&1
cat "$repeat_output"
grep 'reused a fingerprint-bound cargo-vet decision' "$repeat_output"
if grep -q '\[I\] Inspect' "$repeat_output"; then
  echo 'ERROR: unchanged cargo-vet evidence requested repeated inspection' >&2
  exit 1
fi
```

This cache is not a personal approval. If the selected audit snapshot or verified cargo-vet helper changes, the plugin revalidates the exact artifact; if coverage disappears, static inspection is required again.

## Exercise mixed cargo-vet evidence and LLM review

Live audit producers can add evidence at any time, so use offline mode with an empty cache for this deterministic mixed-result example. That selects the embedded recovery baseline without changing the normal online default. Remain in the same `guard-demo` project; its exact `proc-macro2 1.0.95` dependency is covered by the recovery baseline, while adding Serde with derive introduces artifacts not covered by that snapshot:

```sh
cd /tmp/guard-demo
export CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_OFFLINE=true
export CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_EVIDENCE_DIR=/tmp/supply-chain-guard-empty-evidence
cargo forceadd serde --features derive --dump-audit-prompt
```

This time the terminal must show ticked cargo-vet evidence for `proc-macro2 1.0.95` and `quote 1.0.47`, followed by `!` notices for the unresolved Serde artifacts. The operation then stops and creates one non-empty `audit-prompt-*.md`. The report repeats the covered artifacts as traceability context while its artifact-review sections contain only `serde`, `serde_core`, and `serde_derive`. Inspect those distinctions:

```sh
audit_file=$(find "$PWD" -maxdepth 1 -name 'audit-prompt-*.md' -type f | sort | tail -1)
test -n "$audit_file"
grep -A8 '^## Artifacts omitted from LLM review by cargo-vet evidence' "$audit_file"
grep '^## Artifact review' "$audit_file"
if grep -q '^serde' Cargo.toml; then
  echo 'ERROR: the rejected first pass modified Cargo.toml' >&2
  exit 1
fi
```

Give the generated file to a read-only reviewing agent using the short handoff printed by Supply Chain Guard. Only if its overall verdict is `ACCEPT_ALL`, compare every exact artifact identity with the report and make an explicit risk decision:

```sh
cargo forceadd serde --features derive --accept-and-remember-all
grep 'serde' Cargo.toml
```

That command remembers the unresolved exact Serde artifacts and the cargo-vet-covered exact artifacts, then completes the add. Repeating the same resolved operation should therefore require no inspection authorization. For a one-operation decision that creates no personal approvals, use `--accept-all-once` instead. Never use either option merely to bypass a `REJECT` or `UNCERTAIN` verdict. Cargo-vet-based acceptance is revalidated on later operations unless the user explicitly selects `--accept-and-remember-all`.

Verify the remembered fast path:

```sh
cargo forceadd serde --features derive
```

It must complete without an `[I] Inspect` prompt and print that every resolved exact artifact is already approved, so no inspection or risk decision is required. With `CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_VERBOSE=1`, the plugin additionally prints that approved trust state is being enforced with `--locked`.

To try the equivalent file handoff during normal interactive review, run the same `forceadd` without a batch option before accepting it. Choose `I` to authorize memory-only inspection, then choose `F` at an artifact finding. Supply Chain Guard saves that artifact's prompt and prints a short instruction containing its absolute path. The menu remains open, so you can also choose `L` to print the prompt, `S` to view a complete relevant source file, or `R` to reject without changing the project:

```sh
cargo forceadd serde --features derive
# Choice [R]: I
# At an artifact finding: F
# After inspecting the saved prompt path: R
```

There is no need to run `cargo forceupdate --dump-audit-prompt`; it would repeat the same batch-mode behavior against another operation. The repository's deterministic POC tests also exercise an uncovered malicious artifact, rejection before execution, and explicit acceptance. Run them with output:

```sh
cd "$review_root"
"$real_cargo" test --test security_poc -- --nocapture --test-threads=1
```

## Exercise an immutable GitHub dependency

This example uses `git ls-remote` only as test setup to discover the commit behind a known tag. Supply Chain Guard itself never invokes `git` while reviewing the source archive.

```sh
cd /tmp
"$real_cargo" new git-guard-demo
cd git-guard-demo
git_revision=$(git ls-remote https://github.com/dtolnay/proc-macro2.git 'refs/tags/1.0.95^{}' | awk '{print $1}')
test ${#git_revision} -eq 40

cargo forceadd proc-macro2 \
  --git https://github.com/dtolnay/proc-macro2.git \
  --rev "$git_revision" \
  --dump-audit-prompt
```

The candidate Cargo pass may fetch Git objects only beneath its disposable private Cargo home. The independent review must then report a `git+https://github.com/...#<commit>` identity, scan the exact GitHub commit archive without invoking Git, and create a non-empty audit prompt because cargo-vet evidence is deliberately unavailable to Git artifacts. The real manifest must still be unchanged:

```sh
if grep -q '^proc-macro2' Cargo.toml; then
  echo 'ERROR: Git dependency changed the real manifest before acceptance' >&2
  exit 1
fi
git_audit=$(find . -maxdepth 1 -name 'audit-prompt-*.md' -type f | sort | tail -1)
grep 'locked Git commit' "$git_audit"
grep 'Git tree SHA-256' "$git_audit"
```

After a read-only review returns `ACCEPT_ALL`, explicitly remember the exact Git identity:

```sh
cargo forceadd proc-macro2 \
  --git https://github.com/dtolnay/proc-macro2.git \
  --rev "$git_revision" \
  --accept-and-remember-all
grep 'proc-macro2' Cargo.toml
approval_file=${CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_APPROVAL_FILE:-$HOME/.config/cargo-wrapper-supply-chain-guard/approvals.toml}
grep -A8 'git+https://github.com/dtolnay/proc-macro2' \
  "$approval_file"
```

The approval entry must include the exact 40-hex commit in `checksum` and a 64-hex `content_sha256`. Repeat without batch flags and without stdin:

```sh
repeat_git=/tmp/git-guard-demo/repeated-git.txt
cargo forceadd proc-macro2 \
  --git https://github.com/dtolnay/proc-macro2.git \
  --rev "$git_revision" \
  </dev/null >"$repeat_git" 2>&1
cat "$repeat_git"
if grep -q '\[I\] Inspect' "$repeat_git"; then
  echo 'ERROR: remembered immutable Git dependency prompted again' >&2
  exit 1
fi
```

For fail-closed coverage, replace the GitHub URL with another host or use a lock entry without a full commit. The operation must stop before downstream Cargo changes the real workspace.

## Test Age Policy in the same chain

Clone/build `cargo-wrapper-age-policy` inside the same sandbox and register it as `age-policy`:

```sh
unset CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_OFFLINE
export CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_EVIDENCE_DIR=/tmp/supply-chain-guard-live-evidence
real_cargo=$(rustup which cargo)

git clone \
  https://github.com/danielemiliogarcia/cargo-wrapper-age-policy.git \
  /tmp/cargo-wrapper-age-policy

"$real_cargo" build \
  --manifest-path /tmp/cargo-wrapper-age-policy/Cargo.toml \
  --locked \
  --release
cargo wrapper plugin install age-policy \
  /tmp/cargo-wrapper-age-policy/target/release/cargo-wrapper-plugin-age-policy
cargo wrapper plugin enable age-policy
cargo wrapper plugin list
```

`cargo wrapper plugin list` must then show alphabetical order:

```text
age-policy
supply-chain-guard
```

Run the deterministic Age Policy fixture. Its output must say Cargo selected and compiled `v0.0.1` while the 29-day `v0.0.2` archive was withheld:

```sh
"$real_cargo" test \
  --manifest-path /tmp/cargo-wrapper-age-policy/Cargo.toml \
  --locked \
  fallback::tests::mock_registry_selects_old_enough_version_instead_of_29_day_release \
  -- --nocapture
```

Now exercise both active plugins on one new project:

```sh
chain_demo=$(mktemp -d /tmp/supply-chain-guard-chain.XXXXXX)
"$real_cargo" init --quiet --name supply-chain-guard-chain "$chain_demo"
cd "$chain_demo"
cargo forceadd 'proc-macro2@=1.0.95' --dump-audit-prompt

grep 'proc-macro2' Cargo.toml
if find . -maxdepth 1 -name 'audit-prompt-*.md' -print -quit | grep .; then
  echo 'ERROR: the combined fully covered operation created an empty prompt' >&2
  exit 1
fi
```

The output must first say Age Policy is enforcing `"30 days"` through its private sparse-index filter, then show Supply Chain Guard's cargo-vet evidence, and finally complete the add. The protocol integration tests cover rejection when `dependency-audit` and `supply-chain-guard` are enabled simultaneously.

## Disable and remove

```sh
cargo wrapper plugin disable age-policy
cargo wrapper plugin uninstall age-policy
"$review_root/uninstall.sh"
cargo --version
exit
```

On the host, remove only this disposable sandbox when finished:

```sh
sbx rm supply-chain-guard-smoke
```
