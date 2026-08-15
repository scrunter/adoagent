[CmdletBinding()]
param(
    [string[]]$Path
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
$dependencies = Import-PowerShellDataFile -LiteralPath (Join-Path $repositoryRoot 'build\Build.Dependencies.psd1')
$requiredPesterVersion = [Version]$dependencies.Pester
$pesterModule = Get-Module -ListAvailable -Name Pester |
    Where-Object { $_.Version -eq $requiredPesterVersion } |
    Select-Object -First 1
if (-not $pesterModule) {
    throw "Pester $requiredPesterVersion is required. Install it with: Install-Module Pester -RequiredVersion $requiredPesterVersion -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber"
}

Remove-Module Pester -Force -ErrorAction SilentlyContinue
Import-Module -Name $pesterModule.Path -Force -ErrorAction Stop
$loadedPesterVersion = (Get-Module -Name Pester).Version
if ($loadedPesterVersion -ne $requiredPesterVersion) {
    throw "Expected Pester $requiredPesterVersion but loaded $loadedPesterVersion."
}

Write-Output "Running PowerShell tests with Pester $loadedPesterVersion."
if (-not $Path) {
    $Path = @('Module.Tests.ps1', 'AgentSetup.Tests.ps1', 'ClusterInstall.Tests.ps1', 'Reset.Tests.ps1', 'ReleaseWorkflow.Tests.ps1')
}

foreach ($testPath in $Path) {
    $resolvedTestPath = if ([IO.Path]::IsPathRooted($testPath)) { $testPath } else { Join-Path $here $testPath }
    $result = Invoke-Pester -Path $resolvedTestPath -PassThru
    if ($result.FailedCount -ne 0) { throw "Pester suite '$resolvedTestPath' failed." }
}

Write-Output 'PowerShell Pester tests passed.'
