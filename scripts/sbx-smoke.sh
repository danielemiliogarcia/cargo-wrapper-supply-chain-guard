#!/usr/bin/env sh
# Runs the reproducible build/install/review smoke flow from inside a Docker sbx clone.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf 'usage: %s <cargo-wrapper-source-dir> [cargo-wrapper-age-policy-source-dir]\n' "$0" >&2
    exit 2
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
wrapper_root=$(CDPATH= cd -- "$1" && pwd)
age_root=${2:-}
if command -v rustup >/dev/null 2>&1; then
    real_cargo=$(rustup which cargo)
else
    real_cargo=$(command -v cargo)
fi
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-gnu ;;
    Darwin/x86_64) target=x86_64-apple-darwin ;;
    Darwin/arm64|Darwin/aarch64) target=aarch64-apple-darwin ;;
    *) printf 'unsupported smoke-test host\n' >&2; exit 1 ;;
esac

printf '\n==> Building and activating Cargo Wrapper inside the sandbox\n'
"$real_cargo" build --manifest-path "$wrapper_root/Cargo.toml" --locked --release
mkdir -p "$HOME/.local/bin"
install -m 0755 "$wrapper_root/target/release/cargowrapper" "$HOME/.local/bin/cargo"
PATH="$HOME/.local/bin:$PATH"
export PATH
cargo wrapper
cargo --version

printf '\n==> Building the release bundle wholly inside the sandbox\n'
(cd "$project_root" && CARGO="$real_cargo" ./scripts/build-release-bundle.sh "$target")

printf '\n==> Installing the verified local bundle\n'
CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL="file://$project_root/target/distrib" \
    "$project_root/install.sh"
cargo wrapper plugin list
if ! cargo wrapper plugin list | grep 'supply-chain-guard.*inactive' >/dev/null 2>&1; then
    printf 'error: installer did not leave the plugin inactive\n' >&2
    exit 1
fi
cargo wrapper plugin enable supply-chain-guard
export CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_EVIDENCE_DIR="${TMPDIR:-/tmp}/supply-chain-guard-live-evidence"
cargo supply-chain-guard cargo-vet status
cargo supply-chain-guard cargo-vet update
cargo supply-chain-guard cargo-vet sources

printf '\n==> Testing review and batch evidence output\n'
demo=$(mktemp -d "${TMPDIR:-/tmp}/supply-chain-guard-demo.XXXXXX")
"$real_cargo" init --quiet --name supply-chain-guard-demo "$demo"
demo_output="$demo/supply-chain-guard-output.txt"
if ! (cd "$demo" && cargo forceadd 'proc-macro2@=1.0.95' --dump-audit-prompt) \
    >"$demo_output" 2>&1; then
    cat "$demo_output" >&2
    exit 1
fi
cat "$demo_output"
grep 'cargo-vet covered 1 static-review candidate' "$demo_output" >/dev/null
grep 'No audit prompt was created. Continuing the requested Cargo operation.' "$demo_output" >/dev/null
grep 'proc-macro2' "$demo/Cargo.toml" >/dev/null
if find "$demo" -maxdepth 1 -name 'audit-prompt-*.md' -type f -print -quit | grep . >/dev/null; then
    printf 'error: fully covered operation created an empty audit prompt\n' >&2
    exit 1
fi
repeat_output="$demo/supply-chain-guard-repeat-output.txt"
if ! (cd "$demo" && cargo forceadd 'proc-macro2@=1.0.95' </dev/null) \
    >"$repeat_output" 2>&1; then
    cat "$repeat_output" >&2
    exit 1
fi
cat "$repeat_output"
grep 'reused a fingerprint-bound cargo-vet decision' "$repeat_output" >/dev/null
if grep '\[I\] Inspect' "$repeat_output" >/dev/null; then
    printf 'error: unchanged cargo-vet evidence requested repeated inspection\n' >&2
    exit 1
fi

printf '\n==> Running reject-before-execution and explicit-acceptance POCs\n'
(cd "$project_root" && CARGO="$real_cargo" "$real_cargo" test --test security_poc -- \
    --nocapture --test-threads=1)

if [ -n "$age_root" ]; then
    age_root=$(CDPATH= cd -- "$age_root" && pwd)
    printf '\n==> Building and enabling Age Policy in the same plugin chain\n'
    "$real_cargo" build --manifest-path "$age_root/Cargo.toml" --locked --release
    cargo wrapper plugin install age-policy \
        "$age_root/target/release/cargo-wrapper-plugin-age-policy"
    cargo wrapper plugin enable age-policy
    plugin_names=$(cargo wrapper plugin list | awk 'NR > 1 && $2 == "active" { print $1 }')
    test "$(printf '%s\n' "$plugin_names" | grep -n '^age-policy$' | cut -d: -f1)" \
        -lt "$(printf '%s\n' "$plugin_names" | grep -n '^supply-chain-guard$' | cut -d: -f1)"

    printf '\n==> Proving deterministic 30-day selection with Age Policy real-Cargo fixture\n'
    (cd "$age_root" && "$real_cargo" test --locked \
        fallback::tests::mock_registry_selects_old_enough_version_instead_of_29_day_release \
        -- --nocapture)

    printf '\n==> Proving both plugins cooperate on one Cargo invocation\n'
    chain_demo=$(mktemp -d "${TMPDIR:-/tmp}/supply-chain-guard-chain.XXXXXX")
    "$real_cargo" init --quiet --name supply-chain-guard-chain "$chain_demo"
    chain_output="$chain_demo/supply-chain-guard-output.txt"
    if ! (cd "$chain_demo" && cargo forceadd 'proc-macro2@=1.0.95' --dump-audit-prompt) \
        >"$chain_output" 2>&1; then
        cat "$chain_output" >&2
        exit 1
    fi
    cat "$chain_output"
    grep 'cargo-vet covered 1 static-review candidate' "$chain_output" >/dev/null
    grep 'proc-macro2' "$chain_demo/Cargo.toml" >/dev/null
    if find "$chain_demo" -maxdepth 1 -name 'audit-prompt-*.md' -type f -print -quit | grep . >/dev/null; then
        printf 'error: chained fully covered operation created an empty audit prompt\n' >&2
        exit 1
    fi
fi

printf '\n==> Uninstalling Supply Chain Guard and checking ordinary Cargo\n'
if [ -n "$age_root" ]; then
    cargo wrapper plugin disable age-policy
    cargo wrapper plugin uninstall age-policy
fi
"$project_root/uninstall.sh"
cargo --version
printf '\nSupply Chain Guard sandbox smoke test completed successfully.\n'
