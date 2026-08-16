[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Services', 'Server')][string]$ServerType = 'Services',
    [Parameter(Mandatory = $true)][string]$AzureDevOpsUrl,
    [ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth = 'PersonalAccessToken',
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
    [string]$EscrowPath,
    [string]$ToolkitPackagePath = $PSScriptRoot,
    [string]$AgentPackagePath,
    [string]$AgentPackageSha256,
    [string[]]$Node,
    [Guid]$ConfigId = [Guid]::Empty,
    [string]$KeyResourceName,
    [string]$ServiceResourceName,
    [string]$ServiceAccount = 'NT AUTHORITY\NETWORK SERVICE',
    [System.Management.Automation.PSCredential]$ServiceCredential,
    [System.Management.Automation.PSCredential]$ProvisioningCredential,
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
if (-not $Resume -and
    $RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken') -and
    -not $invoke.ContainsKey('RegistrationToken') -and
    -not $invoke.ContainsKey('RegistrationTokenEnvironmentVariableName')) {
    $invoke.RegistrationToken = Read-Host -Prompt 'Azure DevOps registration token' -AsSecureString
}
if (-not $Resume -and -not $invoke.ContainsKey('ProvisioningCredential')) {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $invoke.ProvisioningCredential = Get-Credential `
        -UserName $currentIdentity `
        -Message 'DPAPI-NG protector-group operator used for passive-node sealing'
}
Initialize-AdoAgentCluster @invoke
