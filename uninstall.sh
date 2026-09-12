#!/usr/bin/env sh
# Unregisters Supply Chain Guard and removes only plugin-owned helper files.
set -eu

purge=false
if [ "${1:-}" = "--purge" ]; then
    purge=true
elif [ "$#" -ne 0 ]; then
    printf 'usage: %s [--purge]\n' "$0" >&2
    exit 2
fi
cargo wrapper plugin disable supply-chain-guard 2>/dev/null || true
cargo wrapper plugin uninstall supply-chain-guard 2>/dev/null || true
data_home=${XDG_DATA_HOME:-"$HOME/.local/share"}
install_dir="$data_home/cargo-wrapper-supply-chain-guard/bin"
rm -f "$install_dir/cargo-vet" "$install_dir/INSTALL-MANIFEST.toml"
rmdir "$install_dir" "$data_home/cargo-wrapper-supply-chain-guard" 2>/dev/null || true
if [ "$purge" = true ]; then
    evidence_dir="$data_home/cargo-wrapper-supply-chain-guard/evidence"
    rm -rf "$evidence_dir"
    rmdir "$data_home/cargo-wrapper-supply-chain-guard" 2>/dev/null || true
    config_home=${XDG_CONFIG_HOME:-"$HOME/.config"}
    config_dir="$config_home/cargo-wrapper-supply-chain-guard"
    rm -f "$config_dir/approvals.toml" "$config_dir/config.toml"
    rmdir "$config_dir" 2>/dev/null || true
fi
printf '%s\n' 'Supply Chain Guard was uninstalled. Configuration was retained unless --purge was used.'
