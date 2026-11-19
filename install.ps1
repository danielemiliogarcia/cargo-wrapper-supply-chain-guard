# Installs a verified Windows Supply Chain Guard bundle and registers it disabled.
$ErrorActionPreference = "Stop"
$Version = if ($env:CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_VERSION) { $env:CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_VERSION } else { "0.1.1" }
$BaseUrl = if ($env:CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL) { $env:CARGO_WRAPPER_SUPPLY_CHAIN_GUARD_DOWNLOAD_URL } else { "https://github.com/danielemiliogarcia/cargo-wrapper-supply-chain-guard/releases/download/v$Version" }
$AttestationRepository = "danielemiliogarcia/cargo-wrapper-supply-chain-guard"
$AttestationWorkflow = "danielemiliogarcia/cargo-wrapper-supply-chain-guard/.github/workflows/release.yml"
$LocalRelease = ([Uri]::new("$($BaseUrl.TrimEnd('/'))/")).IsFile
if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") { throw "Only x86_64 Windows is supported" }
$Target = "x86_64-pc-windows-msvc"
$Archive = "cargo-wrapper-supply-chain-guard-bundle-$Target.zip"
$Temporary = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
New-Item -ItemType Directory $Temporary | Out-Null
function Receive-ReleaseFile([string]$Name, [string]$Destination) {
    $Source = [Uri]::new("$BaseUrl/$Name")
    if ($Source.IsFile) {
        Copy-Item $Source.LocalPath $Destination
    } else {
        Invoke-WebRequest $Source.AbsoluteUri -OutFile $Destination
    }
}
try {
    Receive-ReleaseFile $Archive (Join-Path $Temporary $Archive)
    Receive-ReleaseFile "$Archive.sha256" (Join-Path $Temporary "$Archive.sha256")
    $Expected = (Get-Content (Join-Path $Temporary "$Archive.sha256")).Split(' ')[0].Trim()
    $Actual = (Get-FileHash (Join-Path $Temporary $Archive) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected.ToLowerInvariant()) { throw "archive checksum mismatch" }
    if ($LocalRelease) {
        Write-Warning "Local release directory selected; GitHub attestation verification was skipped."
    } else {
        if (!(Get-Command gh -ErrorAction SilentlyContinue)) {
            throw "GitHub CLI (gh) is required to verify release provenance before installation"
        }
        & gh attestation verify (Join-Path $Temporary $Archive) `
            --repo $AttestationRepository `
            --signer-workflow $AttestationWorkflow `
            --source-ref "refs/tags/v$Version" `
            --deny-self-hosted-runners
        if ($LASTEXITCODE -ne 0) { throw "GitHub release provenance verification failed" }
    }
    Expand-Archive (Join-Path $Temporary $Archive) -DestinationPath $Temporary
    $Bundle = Join-Path $Temporary "cargo-wrapper-supply-chain-guard-bundle-$Target"
    $ManifestPath = Join-Path $Bundle "INSTALL-MANIFEST.toml"
    $ManifestValues = @{}
    $Section = ""
    foreach ($Line in Get-Content $ManifestPath) {
        if ($Line -match '^\[([^]]+)\]$') {
            $Section = $Matches[1]
        } elseif ($Line -match '^([A-Za-z0-9-]+)\s*=\s*"([^"]*)"\s*$') {
            $ManifestValues["$Section.$($Matches[1])"] = $Matches[2]
        }
    }
    if ($ManifestValues[".target"] -ne $Target) { throw "bundle target does not match this platform" }
    if ($ManifestValues["plugin.name"] -ne "supply-chain-guard") { throw "bundle plugin name is invalid" }
    if ($ManifestValues["plugin.version"] -ne $Version) { throw "bundle plugin version does not match requested version" }
    if ($ManifestValues["plugin.file"] -ne "cargo-wrapper-plugin-supply-chain-guard.exe") { throw "bundle plugin filename is invalid" }
    if ($ManifestValues["cargo-vet.version"] -ne "0.10.2") { throw "bundle helper version is invalid" }
    if ($ManifestValues["cargo-vet.source-commit"] -ne "e496a28a2cde71db0d98ef631cf4586f89a7fed6") { throw "bundle helper source commit is invalid" }
    if ($ManifestValues["cargo-vet.file"] -ne "cargo-vet.exe") { throw "bundle helper filename is invalid" }
    $PluginPath = Join-Path $Bundle $ManifestValues["plugin.file"]
    $HelperPath = Join-Path $Bundle $ManifestValues["cargo-vet.file"]
    $PluginHash = (Get-FileHash $PluginPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $HelperHash = (Get-FileHash $HelperPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($PluginHash -ne $ManifestValues["plugin.sha256"].ToLowerInvariant()) { throw "plugin checksum mismatch" }
    if ($HelperHash -ne $ManifestValues["cargo-vet.sha256"].ToLowerInvariant()) { throw "cargo-vet checksum mismatch" }
    $InstallDir = Join-Path $env:LOCALAPPDATA "CargoWrapperSupplyChainGuard\bin"
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    Copy-Item $HelperPath (Join-Path $InstallDir "cargo-vet.exe") -Force
    Copy-Item $ManifestPath (Join-Path $InstallDir "INSTALL-MANIFEST.toml") -Force
    cargo wrapper plugin install supply-chain-guard $PluginPath
    Write-Host "Supply Chain Guard was installed but remains disabled."
    Write-Host "Enable it with: cargo wrapper plugin enable supply-chain-guard"
    if ($LocalRelease) {
        Write-Host "The local bundle passed checksum and internal executable verification; release provenance was not checked."
    } else {
        Write-Host "The downloaded release bundle passed checksum and GitHub provenance verification."
    }
} finally {
    Remove-Item -Recurse -Force $Temporary
}
