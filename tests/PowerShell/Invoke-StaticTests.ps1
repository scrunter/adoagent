[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
$modulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1'
$manifestPath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1'
$vbsPath = Join-Path $repositoryRoot 'cluster\AdoAgentClusterKey.vbs'
$setupModulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.Setup.ps1'
$setupScriptPath = Join-Path $repositoryRoot 'setup\Initialize-AdoAgentCluster.ps1'
$installScriptPath = Join-Path $repositoryRoot 'setup\Install-AdoAgentCluster.ps1'

foreach ($path in @($modulePath, $setupModulePath, $setupScriptPath, $installScriptPath)) {
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) | Out-Null
    if (@($errors).Count -ne 0) { throw "PowerShell parse errors in '$path': $($errors.Message -join '; ')" }
}

Import-Module $manifestPath -Force
$expected = @(
    'Initialize-AdoAgentCluster',
    'Test-AdoAgentClusterPrerequisite', 'Install-AdoAgentCluster', 'Add-AdoAgentClusterNode',
    'Repair-AdoAgentCluster', 'Remove-AdoAgentClusterNode', 'Uninstall-AdoAgentCluster',
    'Invoke-AdoAgentClusterEvaluation'
)
$actual = @(Get-Command -Module AdoAgentClusterKey | Select-Object -ExpandProperty Name)
foreach ($name in $expected) { if ($actual -notcontains $name) { throw "Missing exported command '$name'." } }

foreach ($name in $expected | Where-Object { $_ -ne 'Test-AdoAgentClusterPrerequisite' }) {
    if ((Get-Command $name).Parameters.Keys -notcontains 'WhatIf') { throw "Mutating command '$name' does not support -WhatIf." }
}

$source = Get-Content -LiteralPath $vbsPath -Raw
foreach ($entryPoint in @('Open', 'Online', 'LooksAlive', 'IsAlive', 'Offline', 'Close')) {
    if ($source -notmatch ("Function " + $entryPoint + "\(\)")) { throw "VBS entry point '$entryPoint' is missing." }
}
if ($source -notmatch 'Function Terminate\(\)') { throw "VBS entry point 'Terminate' is missing." }
if ($source -match 'https://' -or $source -match 'OpenCluster') { throw 'VBS contains a prohibited network or Cluster API call.' }

$body = $source -replace '^Option Explicit\s*', ''
$harness = @'
Option Explicit
Class FakeResourceClass
    Public ConfigId
    Public Sub LogInformation(message)
    End Sub
End Class
Dim Resource
Set Resource = New FakeResourceClass
Resource.ConfigId = "11111111-2222-3333-4444-555555555555"
'@ + "`r`n" + $body + @'

If Not Open() Then WScript.Quit 9
WScript.Quit 0
'@
$temporary = Join-Path $env:TEMP ('AdoAgentClusterKey-vbs-' + [Guid]::NewGuid().ToString('N') + '.vbs')
try {
    [IO.File]::WriteAllText($temporary, $harness, (New-Object Text.UTF8Encoding($false)))
    & cscript.exe //nologo $temporary
    if ($LASTEXITCODE -ne 0) { throw "The VBS fake Resource test failed with exit code $LASTEXITCODE." }
}
finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}

Write-Output 'PowerShell and VBS static tests passed.'
