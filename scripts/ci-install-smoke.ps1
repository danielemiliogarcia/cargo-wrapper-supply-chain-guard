# Exercises the Windows release installer and uninstaller in private CI directories.
param([string]$Target = "x86_64-pc-windows-msvc")
$ErrorActionPreference = "Stop"
if ($Target -ne "x86_64-pc-windows-msvc") { throw "unsupported Windows smoke target: $Target" }

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Temporary = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
New-Item -ItemType Directory $Temporary | Out-Null
try {
    $Bin = Join-Path $Temporary "bin"
    New-Item -ItemType Directory $Bin | Out-Null
    $Trace = Join-Path $Temporary "cargo-calls.txt"
    @"
@echo off
echo %*>>"$Trace"
exit /b 0
"@ | Set-Content -Encoding Ascii (Join-Path $Bin "cargo.cmd")

    $env:PATH = "$Bin;$($env:PATH)"
    $env:LOCALAPPDATA = Join-Path $Temporary "local-data"
    $env:APPDATA = Join-Path $Temporary "config"
    $env:CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL = ([Uri](Join-Path $ProjectRoot "target\distrib")).AbsoluteUri.TrimEnd('/')

    & (Join-Path $ProjectRoot "install.ps1")
    $Helper = Join-Path $env:LOCALAPPDATA "CargoWrapperSupplyChainGuard\bin\cargo-vet.exe"
    $Manifest = Join-Path $env:LOCALAPPDATA "CargoWrapperSupplyChainGuard\bin\INSTALL-MANIFEST.toml"
    if (!(Test-Path $Helper) -or !(Test-Path $Manifest)) { throw "installer omitted helper files" }
    if ((& $Helper --version) -ne "cargo-vet 0.10.2") { throw "installed helper version mismatch" }
    if (!(Select-String -Quiet -Path $Trace -Pattern '^wrapper plugin install supply-chain-guard ')) { throw "plugin was not registered" }

    & (Join-Path $ProjectRoot "uninstall.ps1")
    if ((Test-Path $Helper) -or (Test-Path $Manifest)) { throw "uninstaller retained helper files" }
    if (!(Select-String -Quiet -Path $Trace -Pattern '^wrapper plugin disable supply-chain-guard$')) { throw "plugin was not disabled" }
    if (!(Select-String -Quiet -Path $Trace -Pattern '^wrapper plugin uninstall supply-chain-guard$')) { throw "plugin was not unregistered" }
    Write-Host "installer smoke passed for $Target"
} finally {
    Remove-Item -Recurse -Force $Temporary
}
