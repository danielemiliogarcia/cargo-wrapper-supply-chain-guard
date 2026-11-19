#!/usr/bin/env sh
# Installs a verified precompiled Supply Chain Guard bundle and registers it disabled.
set -eu

version=${CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_VERSION:-0.1.1}
base_url=${CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL:-"https://github.com/danielemiliogarcia/cargo-wrapper-supply-chain-guard/releases/download/v$version"}
attestation_repository=danielemiliogarcia/cargo-wrapper-supply-chain-guard
attestation_workflow=danielemiliogarcia/cargo-wrapper-supply-chain-guard/.github/workflows/release.yml
case "$base_url" in
    file://*) local_release=true ;;
    *) local_release=false ;;
esac
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-gnu ;;
    Darwin/x86_64) target=x86_64-apple-darwin ;;
    Darwin/arm64|Darwin/aarch64) target=aarch64-apple-darwin ;;
    *) printf 'unsupported platform: %s/%s\n' "$(uname -s)" "$(uname -m)" >&2; exit 1 ;;
esac

archive="cargo-wrapper-supply-chain-guard-bundle-$target.tar.xz"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/supply-chain-guard-install.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf 'error: sha256sum or shasum is required\n' >&2
        exit 1
    fi
}

verify_sha256() {
    expected=$1
    file=$2
    label=$3
    actual=$(sha256_file "$file")
    if [ "$actual" != "$expected" ]; then
        printf '%s checksum mismatch\n' "$label" >&2
        exit 1
    fi
}

curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 --fail --location "$base_url/$archive" --output "$temporary/$archive"
curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 --fail --location "$base_url/$archive.sha256" --output "$temporary/$archive.sha256"
archive_hash=$(awk 'NR == 1 { print $1 }' "$temporary/$archive.sha256")
verify_sha256 "$archive_hash" "$temporary/$archive" 'archive'
if [ "$local_release" = true ]; then
    printf '%s\n' 'Local release directory selected; GitHub attestation verification was skipped.' >&2
else
    if ! command -v gh >/dev/null 2>&1; then
        printf '%s\n' 'error: GitHub CLI (gh) is required to verify release provenance before installation' >&2
        exit 1
    fi
    gh attestation verify "$temporary/$archive" \
        --repo "$attestation_repository" \
        --signer-workflow "$attestation_workflow" \
        --source-ref "refs/tags/v$version" \
        --deny-self-hosted-runners
fi
tar -C "$temporary" -xJf "$temporary/$archive"
bundle="$temporary/cargo-wrapper-supply-chain-guard-bundle-$target"
manifest="$bundle/INSTALL-MANIFEST.toml"

manifest_value() {
    section=$1
    key=$2
    awk -v wanted_section="$section" -v wanted_key="$key" '
        /^\[[^]]+\]$/ {
            current = substr($0, 2, length($0) - 2)
            next
        }
        current == wanted_section && $0 ~ "^" wanted_key "[[:space:]]*=" {
            value = $0
            sub(/^[^=]+=[[:space:]]*"/, "", value)
            sub(/"[[:space:]]*$/, "", value)
            print value
            exit
        }
    ' "$manifest"
}

test -f "$manifest" || { printf 'bundle has no install manifest\n' >&2; exit 1; }
plugin_file=$(manifest_value plugin file)
plugin_name=$(manifest_value plugin name)
plugin_version=$(manifest_value plugin version)
plugin_hash=$(manifest_value plugin sha256)
helper_file=$(manifest_value cargo-vet file)
helper_version=$(manifest_value cargo-vet version)
helper_commit=$(manifest_value cargo-vet source-commit)
helper_hash=$(manifest_value cargo-vet sha256)
test "$(sed -n 's/^target = "\([^"]*\)"/\1/p' "$manifest")" = "$target" || {
    printf 'bundle target does not match this platform\n' >&2; exit 1;
}
test "$plugin_file" = "cargo-wrapper-plugin-supply-chain-guard" || {
    printf 'bundle plugin filename is invalid\n' >&2; exit 1;
}
test "$plugin_name" = "supply-chain-guard" || { printf 'bundle plugin name is invalid\n' >&2; exit 1; }
test "$plugin_version" = "$version" || {
    printf 'bundle plugin version does not match requested version\n' >&2; exit 1;
}
test "$helper_file" = "cargo-vet" || { printf 'bundle helper filename is invalid\n' >&2; exit 1; }
test "$helper_version" = "0.10.2" || { printf 'bundle helper version is invalid\n' >&2; exit 1; }
test "$helper_commit" = "e496a28a2cde71db0d98ef631cf4586f89a7fed6" || {
    printf 'bundle helper source commit is invalid\n' >&2; exit 1;
}
verify_sha256 "$plugin_hash" "$bundle/$plugin_file" 'plugin'
verify_sha256 "$helper_hash" "$bundle/$helper_file" 'cargo-vet helper'

data_home=${XDG_DATA_HOME:-"$HOME/.local/share"}
install_dir="$data_home/cargo-wrapper-supply-chain-guard/bin"
mkdir -p "$install_dir"
install -m 0755 "$bundle/$helper_file" "$install_dir/cargo-vet"
install -m 0600 "$bundle/INSTALL-MANIFEST.toml" "$install_dir/INSTALL-MANIFEST.toml"
cargo wrapper plugin install supply-chain-guard "$bundle/$plugin_file"
printf '%s\n' 'Supply Chain Guard was installed but remains disabled.'
printf '%s\n' 'Enable it with: cargo wrapper plugin enable supply-chain-guard'
if [ "$local_release" = true ]; then
    printf '%s\n' 'The local bundle passed checksum and internal executable verification; release provenance was not checked.'
else
    printf '%s\n' 'The downloaded release bundle passed checksum and GitHub provenance verification.'
fi
