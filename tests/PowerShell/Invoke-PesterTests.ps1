[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($name in @('Module.Tests.ps1', 'AgentSetup.Tests.ps1', 'ClusterInstall.Tests.ps1', 'ReleaseWorkflow.Tests.ps1')) {
    $result = Invoke-Pester -Path (Join-Path $here $name) -PassThru
    if ($result.FailedCount -ne 0) { throw "Pester suite '$name' failed." }
}

Write-Output 'PowerShell Pester tests passed.'
