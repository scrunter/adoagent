[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Version = '0.3.0',
    [string]$OutputPath,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repositoryRoot 'artifacts' }
$packagePath = Join-Path $OutputPath "AdoAgentClusterKey-$Version-win-x64"
$publishPath = Join-Path $OutputPath 'publish'

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Recurse -Force }
if (Test-Path -LiteralPath $publishPath) { Remove-Item -LiteralPath $publishPath -Recurse -Force }
New-Item -ItemType Directory -Path $packagePath -Force | Out-Null

Push-Location $repositoryRoot
try {
    if (-not $SkipTests) {
        & dotnet build AdoAgentClusterKey.slnx -c $Configuration
        if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
        & dotnet run --project tests\AdoAgent.ClusterKey.Tests\AdoAgent.ClusterKey.Tests.csproj -c $Configuration --no-build
        if ($LASTEXITCODE -ne 0) { throw 'Native helper tests failed.' }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\PowerShell\Invoke-StaticTests.ps1
        if ($LASTEXITCODE -ne 0) { throw 'PowerShell/VBS static tests failed.' }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\PowerShell\Invoke-PesterTests.ps1
        if ($LASTEXITCODE -ne 0) { throw 'PowerShell Pester tests failed.' }
    }
    & dotnet publish src\AdoAgent.ClusterKey\AdoAgent.ClusterKey.csproj -c $Configuration -r win-x64 --self-contained true -p:PublishAot=true -p:DebugType=None -p:Version=$Version -o $publishPath
    if ($LASTEXITCODE -ne 0) { throw 'Native AOT publish failed.' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\PowerShell\Invoke-CliOutputTests.ps1 -Executable (Join-Path $publishPath 'AdoAgent.ClusterKey.exe')
    if ($LASTEXITCODE -ne 0) { throw 'CLI sanitized-output tests failed.' }
}
finally { Pop-Location }

Copy-Item -LiteralPath (Join-Path $publishPath 'AdoAgent.ClusterKey.exe') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'cluster\AdoAgentClusterKey.vbs') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.Setup.ps1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'setup\Install-AdoAgentCluster.ps1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'setup\Initialize-AdoAgentCluster.ps1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'setup\Reset-AdoAgentCluster.ps1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'build\Test-Release.ps1') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'README.md') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'LICENSE') -Destination $packagePath
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'docs') -Destination $packagePath -Recurse

$versionInfo = [ordered]@{
    schemaVersion = 1
    version = $Version
    runtimeIdentifier = 'win-x64'
    targetFramework = 'net10.0-windows'
    nativeAot = $true
    builtUtc = [DateTime]::UtcNow.ToString('o')
    integrity = 'SHA256 release manifest and locked deployment ACLs'
}
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $packagePath 'version.json'), ($versionInfo | ConvertTo-Json -Depth 5), $utf8)

$sbomFiles = @()
$sbomIndex = 0
foreach ($file in Get-ChildItem -LiteralPath $packagePath -File -Recurse) {
    $sbomIndex++
    $relative = $file.FullName.Substring($packagePath.Length + 1).Replace('\', '/')
    $sbomFiles += [ordered]@{ SPDXID = 'SPDXRef-File-' + $sbomIndex; fileName = './' + $relative; checksums = @([ordered]@{ algorithm = 'SHA256'; checksumValue = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }) }
}
$sbom = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "AdoAgentClusterKey-$Version-win-x64"
    documentNamespace = "https://spdx.org/spdxdocs/AdoAgentClusterKey-$Version-$([Guid]::NewGuid())"
    creationInfo = [ordered]@{ created = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); creators = @('Tool: build/Build.ps1') }
    packages = @([ordered]@{ name = 'AdoAgentClusterKey'; SPDXID = 'SPDXRef-Package'; versionInfo = $Version; downloadLocation = 'NOASSERTION'; filesAnalyzed = $true; licenseConcluded = 'MIT'; licenseDeclared = 'MIT'; copyrightText = 'NOASSERTION' })
    files = $sbomFiles
    relationships = @($sbomFiles | ForEach-Object { [ordered]@{ spdxElementId = 'SPDXRef-Package'; relationshipType = 'CONTAINS'; relatedSpdxElement = $_.SPDXID } })
}
[IO.File]::WriteAllText((Join-Path $packagePath 'sbom.spdx.json'), ($sbom | ConvertTo-Json -Depth 10), $utf8)

$hashes = @()
foreach ($file in Get-ChildItem -LiteralPath $packagePath -File -Recurse | Where-Object { $_.Name -notlike 'RELEASE-MANIFEST*' }) {
    $hashes += [ordered]@{ path = $file.FullName.Substring($packagePath.Length + 1).Replace('\', '/'); sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash; length = $file.Length }
}
$releaseManifest = [ordered]@{ schemaVersion = 1; product = 'AdoAgentClusterKey'; version = $Version; createdUtc = [DateTime]::UtcNow.ToString('o'); files = $hashes }
[IO.File]::WriteAllText((Join-Path $packagePath 'RELEASE-MANIFEST.json'), ($releaseManifest | ConvertTo-Json -Depth 10), $utf8)

$zipPath = Join-Path $OutputPath "AdoAgentClusterKey-$Version-win-x64.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path (Join-Path $packagePath '*') -DestinationPath $zipPath -CompressionLevel Optimal
$zipSha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
$zipHashPath = $zipPath + '.sha256'
[IO.File]::WriteAllText($zipHashPath, $zipSha256 + '  ' + [IO.Path]::GetFileName($zipPath), $utf8)
Write-Output ([pscustomobject]@{ PackagePath = $packagePath; ZipPath = $zipPath; ZipSha256 = $zipSha256; ZipHashPath = $zipHashPath; Version = $Version })
