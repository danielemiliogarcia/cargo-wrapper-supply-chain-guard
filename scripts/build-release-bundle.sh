#!/usr/bin/env sh
# Builds the plugin and pinned cargo-vet helper for one target and packages both with hashes.
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <rust-target-triple>\n' "$0" >&2
    exit 2
fi

target=$1
case "$target" in
    aarch64-apple-darwin|aarch64-unknown-linux-gnu|x86_64-apple-darwin|x86_64-unknown-linux-gnu|x86_64-pc-windows-msvc) ;;
    *) printf 'error: unsupported release target: %s\n' "$target" >&2; exit 2 ;;
esac
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
expected_commit=e496a28a2cde71db0d98ef631cf4586f89a7fed6
actual_commit=$(git -C "$project_root/third-party/cargo-vet" rev-parse HEAD)
if [ "$actual_commit" != "$expected_commit" ]; then
    printf 'error: cargo-vet submodule must be at %s, got %s\n' "$expected_commit" "$actual_commit" >&2
    exit 1
fi

cargo_bin=${CARGO:-cargo}
plugin_target="$project_root/target/release-bundle/$target/plugin"
helper_target="$project_root/target/release-bundle/$target/helper"
output="$project_root/target/distrib"
bundle_name="cargo-wrapper-supply-chain-guard-bundle-$target"
stage="$project_root/target/release-bundle/$target/$bundle_name"

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

rm -rf "$stage"
mkdir -p "$plugin_target" "$helper_target" "$output" "$stage"
CARGO_TARGET_DIR="$plugin_target" "$cargo_bin" build --locked --profile dist --target "$target" --bin cargo-wrapper-plugin-supply-chain-guard
CARGO_TARGET_DIR="$helper_target" "$cargo_bin" build --locked --release --target "$target" --manifest-path "$project_root/third-party/cargo-vet/Cargo.toml"

suffix=
if [ "$target" = "x86_64-pc-windows-msvc" ]; then
    suffix=.exe
fi
plugin="cargo-wrapper-plugin-supply-chain-guard$suffix"
helper="cargo-vet$suffix"
cp "$plugin_target/$target/dist/$plugin" "$stage/$plugin"
cp "$helper_target/$target/release/$helper" "$stage/$helper"
cp "$project_root/LICENSE" "$project_root/README.md" "$project_root/THIRD_PARTY_NOTICES.md" "$stage/"

plugin_hash=$(sha256_file "$stage/$plugin")
helper_hash=$(sha256_file "$stage/$helper")
cat > "$stage/INSTALL-MANIFEST.toml" <<EOF
target = "$target"

[plugin]
name = "supply-chain-guard"
version = "$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -1)"
file = "$plugin"
sha256 = "$plugin_hash"

[cargo-vet]
version = "0.10.2"
source-commit = "$expected_commit"
file = "$helper"
sha256 = "$helper_hash"
EOF
manifest_output="$output/INSTALL-MANIFEST-$target.toml"
cp "$stage/INSTALL-MANIFEST.toml" "$manifest_output"

if [ "$target" = "x86_64-pc-windows-msvc" ]; then
    archive="$output/$bundle_name.zip"
    rm -f "$archive" "$archive.sha256"
    (cd "$(dirname "$stage")" && 7z a -tzip "$archive" "$bundle_name" >/dev/null)
else
    archive="$output/$bundle_name.tar.xz"
    rm -f "$archive" "$archive.sha256"
    tar -C "$(dirname "$stage")" -cJf "$archive" "$bundle_name"
fi
archive_name=$(basename "$archive")
archive_hash=$(sha256_file "$archive")
printf '%s  %s\n' "$archive_hash" "$archive_name" > "$archive.sha256"
printf '%s\n%s\n%s\n' "$archive" "$archive.sha256" "$manifest_output"
