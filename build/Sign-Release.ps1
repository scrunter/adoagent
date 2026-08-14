[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [switch]$AuthenticodeOnly,
    [switch]$ManifestOnly
)

$ErrorActionPreference = 'Stop'
$normalized = ($CertificateThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
$certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
    Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalized -and $_.HasPrivateKey } |
    Select-Object -First 1
if ($null -eq $certificate) { throw "A code-signing certificate with private key '$normalized' was not found." }

$files = @()
if (-not $ManifestOnly) {
    $files = @(Get-ChildItem -LiteralPath $PackagePath -File | Where-Object { $_.Extension -in @('.exe', '.dll', '.ps1', '.psm1', '.psd1', '.vbs') })
    foreach ($file in $files) {
        $parameters = @{ FilePath = $file.FullName; Certificate = $certificate; HashAlgorithm = 'SHA256' }
        if ($TimestampServer) { $parameters.TimestampServer = $TimestampServer }
        $signature = Set-AuthenticodeSignature @parameters
        if ($signature.Status -ne 'Valid') { throw "Signing failed for '$($file.Name)': $($signature.StatusMessage)" }
    }
}

if (-not $AuthenticodeOnly) {
    $manifestPath = Join-Path $PackagePath 'RELEASE-MANIFEST.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Release manifest '$manifestPath' does not exist." }
    Add-Type -AssemblyName System.Security
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo (,[IO.File]::ReadAllBytes($manifestPath))
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content, $true)
    $signer = New-Object Security.Cryptography.Pkcs.CmsSigner($certificate)
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer)
    [IO.File]::WriteAllBytes((Join-Path $PackagePath 'RELEASE-MANIFEST.json.p7s'), $cms.Encode())
}

Write-Output "Signed $($files.Count) Authenticode files; detached manifest signature requested=$(-not $AuthenticodeOnly); signer='$normalized'."
