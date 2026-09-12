#!/usr/bin/env sh
# Exercises the POSIX release installer and uninstaller in private CI directories.
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <release-target>\n' "$0" >&2
    exit 2
fi

target=$1
case "$target" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin) ;;
    *) printf 'POSIX installer smoke does not support %s\n' "$target" >&2; exit 2 ;;
esac

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/supply-chain-guard-ci-install.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/config" "$temporary/data"

cat > "$temporary/bin/cargo" <<'EOF'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$*" >> "$SUPPLY_CHAIN_GUARD_FAKE_CARGO_TRACE"
EOF
chmod 0755 "$temporary/bin/cargo"

trace="$temporary/cargo-calls"
PATH="$temporary/bin:$PATH" \
XDG_CONFIG_HOME="$temporary/config" \
XDG_DATA_HOME="$temporary/data" \
SUPPLY_CHAIN_GUARD_FAKE_CARGO_TRACE="$trace" \
CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL="file://$project_root/target/distrib" \
    "$project_root/install.sh"

helper="$temporary/data/cargo-wrapper-supply-chain-guard/bin/cargo-vet"
manifest="$temporary/data/cargo-wrapper-supply-chain-guard/bin/INSTALL-MANIFEST.toml"
test -x "$helper"
test -f "$manifest"
grep '^wrapper plugin install supply-chain-guard ' "$trace" >/dev/null
"$helper" --version | grep '^cargo-vet 0.10.2$' >/dev/null

PATH="$temporary/bin:$PATH" \
XDG_CONFIG_HOME="$temporary/config" \
XDG_DATA_HOME="$temporary/data" \
SUPPLY_CHAIN_GUARD_FAKE_CARGO_TRACE="$trace" \
    "$project_root/uninstall.sh"

test ! -e "$helper"
test ! -e "$manifest"
grep '^wrapper plugin disable supply-chain-guard$' "$trace" >/dev/null
grep '^wrapper plugin uninstall supply-chain-guard$' "$trace" >/dev/null
printf 'installer smoke passed for %s\n' "$target"
