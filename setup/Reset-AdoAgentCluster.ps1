[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][Guid]$ConfigId,
    [Parameter(Mandatory = $true)][string]$AgentRoot,
    [Parameter(Mandatory = $true)][string]$EscrowPath,
    [Parameter(Mandatory = $true)][string]$ClusterRoleName,
    [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
    [Parameter(Mandatory = $true)][string]$KeyResourceName,
    [Parameter(Mandatory = $true)][string]$ServiceResourceName,
    [ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth = 'PersonalAccessToken',
    [Security.SecureString]$RegistrationToken,
    [string]$RegistrationTokenEnvironmentVariableName,
    [System.Management.Automation.PSCredential]$RegistrationCredential,
    [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
    [Parameter(Mandatory = $true)][switch]$ConfirmPermanentReset,
    [switch]$SkipAzureDevOpsUnregister,
    [switch]$RemoveToolkitBinaries,
    [string]$ToolkitPackagePath = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$moduleCandidates = @(
    (Join-Path $ToolkitPackagePath 'AdoAgentClusterKey.psd1'),
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1')
)
$modulePath = $moduleCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $modulePath) { throw 'AdoAgentClusterKey.psd1 was not found in ToolkitPackagePath or the source-tree module location.' }
Import-Module $modulePath -Force

$invoke = @{}
foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    if ($entry.Key -ne 'ToolkitPackagePath') { $invoke[$entry.Key] = $entry.Value }
}
Reset-AdoAgentCluster @invoke
