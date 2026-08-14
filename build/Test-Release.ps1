[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PackagePath).TrimEnd('\')
$manifestPath = Join-Path $root 'RELEASE-MANIFEST.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'RELEASE-MANIFEST.json is missing.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$seen = @{}
foreach ($entry in $manifest.files) {
    $relative = ([string]$entry.path).Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($relative) -or $seen.ContainsKey($relative)) { throw "Manifest path '$relative' is empty or duplicated." }
    $seen[$relative] = $true
    $candidate = [IO.Path]::GetFullPath((Join-Path $root ([string]$entry.path).Replace('/', '\')))
    if (-not $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Manifest path '$($entry.path)' escapes the package root." }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Manifest file '$($entry.path)' is missing." }
    $file = Get-Item -LiteralPath $candidate
    if ($file.Length -ne [long]$entry.length) { throw "Length mismatch for '$($entry.path)'." }
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -ne [string]$entry.sha256) { throw "SHA-256 mismatch for '$($entry.path)'." }
}

$actualFiles = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object { $_.FullName -ne $manifestPath })
foreach ($file in $actualFiles) {
    $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
    if (-not $seen.ContainsKey($relative)) { throw "Package file '$relative' is not recorded in RELEASE-MANIFEST.json." }
}

[pscustomobject]@{ Valid = $true; PackagePath = $root; Version = [string]$manifest.version; FileCount = @($manifest.files).Count; Integrity = 'SHA256' }
