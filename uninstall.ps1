# Unregisters Supply Chain Guard and removes only plugin-owned Windows files.
param([switch]$Purge)
$ErrorActionPreference = "Stop"
cargo wrapper plugin disable supply-chain-guard 2>$null
cargo wrapper plugin uninstall supply-chain-guard 2>$null
$InstallRoot = Join-Path $env:LOCALAPPDATA "CargoWrapperSupplyChainGuard"
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $InstallRoot "bin\cargo-vet.exe")
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $InstallRoot "bin\INSTALL-MANIFEST.toml")
Remove-Item -ErrorAction SilentlyContinue (Join-Path $InstallRoot "bin")
Remove-Item -ErrorAction SilentlyContinue $InstallRoot
if ($Purge) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $InstallRoot "evidence")
    Remove-Item -ErrorAction SilentlyContinue $InstallRoot
    $ConfigRoot = Join-Path $env:APPDATA "CargoWrapperSupplyChainGuard"
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $ConfigRoot "approvals.toml")
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $ConfigRoot "config.toml")
    Remove-Item -ErrorAction SilentlyContinue $ConfigRoot
}
Write-Host "Supply Chain Guard was uninstalled. Configuration was retained unless -Purge was used."
