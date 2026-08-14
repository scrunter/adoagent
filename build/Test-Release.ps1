[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [string]$PublisherThumbprint,
    [switch]$AllowLabUnsigned
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PackagePath).TrimEnd('\')
$manifestPath = Join-Path $root 'RELEASE-MANIFEST.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'RELEASE-MANIFEST.json is missing.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($entry in $manifest.files) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $root ([string]$entry.path).Replace('/', '\')))
    if (-not $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Manifest path '$($entry.path)' escapes the package root." }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Manifest file '$($entry.path)' is missing." }
    $file = Get-Item -LiteralPath $candidate
    if ($file.Length -ne [long]$entry.length) { throw "Length mismatch for '$($entry.path)'." }
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -ne [string]$entry.sha256) { throw "SHA-256 mismatch for '$($entry.path)'." }
}

$labMarker = Join-Path $root 'UNSIGNED-LAB-ONLY.txt'
if (Test-Path -LiteralPath $labMarker) {
    if (-not $AllowLabUnsigned) { throw 'The package is explicitly marked unsigned/lab-only.' }
}
else {
    if ([string]::IsNullOrWhiteSpace($PublisherThumbprint)) { throw 'PublisherThumbprint is required for production release verification.' }
    $expected = ($PublisherThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    foreach ($file in Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -in @('.exe','.dll','.ps1','.psm1','.psd1','.vbs') }) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        $actual = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { '' }
        if ($signature.Status -ne 'Valid' -or $actual -ne $expected) { throw "Authenticode verification failed for '$($file.Name)'." }
    }

    $signaturePath = Join-Path $root 'RELEASE-MANIFEST.json.p7s'
    if (-not (Test-Path -LiteralPath $signaturePath -PathType Leaf)) { throw 'Detached release-manifest signature is missing.' }
    Add-Type -AssemblyName System.Security
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo (,[IO.File]::ReadAllBytes($manifestPath))
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content, $true)
    $cms.Decode([IO.File]::ReadAllBytes($signaturePath))
    $cms.CheckSignature($true)
    if ($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint.ToUpperInvariant() -ne $expected) { throw 'Detached manifest signer does not match PublisherThumbprint.' }
}

[pscustomobject]@{ Valid = $true; PackagePath = $root; Version = [string]$manifest.version; FileCount = @($manifest.files).Count; LabUnsigned = Test-Path -LiteralPath $labMarker }
