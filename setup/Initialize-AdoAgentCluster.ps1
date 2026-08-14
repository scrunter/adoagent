[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Services', 'Server')][string]$ServerType,
    [Parameter(Mandatory = $true)][string]$AzureDevOpsUrl,
    [Parameter(Mandatory = $true)][ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth,
    [Security.SecureString]$RegistrationToken,
    [string]$RegistrationTokenEnvironmentVariableName,
    [System.Management.Automation.PSCredential]$RegistrationCredential,
    [Parameter(Mandatory = $true)][string]$PoolName,
    [Parameter(Mandatory = $true)][string]$AgentName,
    [Parameter(Mandatory = $true)][string]$AgentRoot,
    [string]$WorkDirectory = '_work',
    [Parameter(Mandatory = $true)][string]$ClusterRoleName,
    [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
    [Parameter(Mandatory = $true)][string]$ProtectorGroup,
    [Parameter(Mandatory = $true)][string]$EscrowPath,
    [string]$ToolkitPackagePath = $PSScriptRoot,
    [string]$AgentPackagePath,
    [string]$AgentPackageSha256,
    [string[]]$Node,
    [Guid]$ConfigId = [Guid]::Empty,
    [string]$KeyResourceName,
    [string]$ServiceResourceName,
    [Parameter(Mandatory = $true)][string]$ServiceAccount,
    [System.Management.Automation.PSCredential]$ServiceCredential,
    [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
    [switch]$Resume,
    [switch]$ReplaceExistingAgent,
    [switch]$AllowInsecureServerUrl
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
foreach ($entry in $PSBoundParameters.GetEnumerator()) { $invoke[$entry.Key] = $entry.Value }
if (-not $invoke.ContainsKey('ToolkitPackagePath')) { $invoke.ToolkitPackagePath = $ToolkitPackagePath }
Initialize-AdoAgentCluster @invoke
