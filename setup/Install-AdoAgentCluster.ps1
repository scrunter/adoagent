[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$AgentRoot,
    [Parameter(Mandatory = $true)][string]$ClusterRoleName,
    [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
    [Parameter(Mandatory = $true)][string]$ProtectorGroup,
    [Parameter(Mandatory = $true)][string]$EscrowPath,
    [string]$ToolkitPackagePath = $PSScriptRoot,
    [Guid]$ConfigId = [Guid]::Empty,
    [string]$KeyResourceName,
    [string]$ServiceResourceName,
    [System.Management.Automation.PSCredential]$ServiceCredential,
    [System.Management.Automation.PSCredential]$ProvisioningCredential,
    [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated Windows PowerShell 5.1 session on the current shared-disk owner.'
}

if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1') {
    throw 'This installer requires Windows PowerShell 5.1.'
}

if (-not (Test-Path -LiteralPath $ToolkitPackagePath -PathType Container)) {
    throw "ToolkitPackagePath '$ToolkitPackagePath' does not exist or is not a directory."
}
$resolvedToolkit = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $ToolkitPackagePath).Path).TrimEnd('\')
if (((Get-Item -LiteralPath $resolvedToolkit -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'ToolkitPackagePath must not be a reparse point.'
}

$moduleCandidates = @(
    (Join-Path $resolvedToolkit 'AdoAgentClusterKey.psd1'),
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1')
)
$modulePath = $moduleCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $modulePath) {
    throw 'AdoAgentClusterKey.psd1 was not found in ToolkitPackagePath or the source-tree module location.'
}

Import-Module $modulePath -Force
Import-Module FailoverClusters -ErrorAction Stop

$group = Get-ClusterGroup -Name $ClusterRoleName -ErrorAction Stop
$disk = Get-ClusterResource -Name $SharedDiskResourceName -ErrorAction Stop
if ($disk.OwnerGroup.Name -ne $ClusterRoleName) {
    throw "Shared disk resource '$SharedDiskResourceName' does not belong to role '$ClusterRoleName'."
}
if ($disk.State -ne 'Online') {
    throw "Shared disk resource '$SharedDiskResourceName' must be Online during installation."
}
if ($disk.OwnerNode.Name -ne $env:COMPUTERNAME -or $group.OwnerNode.Name -ne $env:COMPUTERNAME) {
    throw "Run this installer on current role/disk owner '$($disk.OwnerNode.Name)'."
}

$ownerNodeList = $disk | Get-ClusterOwnerNode
if ($null -eq $ownerNodeList -or $null -eq $ownerNodeList.PSObject.Properties['OwnerNodes']) {
    throw "Get-ClusterOwnerNode returned an unexpected result for '$SharedDiskResourceName'."
}
[string[]]$nodes = @(
    $ownerNodeList.OwnerNodes |
        ForEach-Object {
            $nameProperty = $_.PSObject.Properties['Name']
            $candidate = if ($null -ne $nameProperty) { $nameProperty.Value } else { $_ }
            [Convert]::ToString($candidate, [Globalization.CultureInfo]::InvariantCulture)
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)
if ($nodes.Count -eq 0) {
    throw "Shared disk resource '$SharedDiskResourceName' has no possible owner nodes."
}
$clusterNodes = @(Get-ClusterNode -ErrorAction Stop)
foreach ($nodeNameValue in $nodes) {
    [string]$nodeName = $nodeNameValue
    $clusterNode = $clusterNodes | Where-Object { [string]$_.Name -ieq $nodeName } | Select-Object -First 1
    if ($null -eq $clusterNode) {
        throw "Possible owner '$nodeName' was not returned by Get-ClusterNode."
    }
    if ($clusterNode.State -ne 'Up') {
        throw "Possible owner '$nodeName' must be Up before installation."
    }
}

if ($ConfigId -eq [Guid]::Empty) { $ConfigId = [Guid]::NewGuid() }
if (-not $KeyResourceName) { $KeyResourceName = "$ClusterRoleName - Key Selector" }
if (-not $ServiceResourceName) { $ServiceResourceName = "$ClusterRoleName - ADO Agent" }

$installParameters = @{
    AgentRoot = $AgentRoot
    ClusterRoleName = $ClusterRoleName
    SharedDiskResourceName = $SharedDiskResourceName
    ProtectorGroup = $ProtectorGroup
    EscrowPath = $EscrowPath
    PackagePath = $resolvedToolkit
    ConfirmAgentIdle = $true
    Node = $nodes
    ConfigId = $ConfigId
    KeyResourceName = $KeyResourceName
    ServiceResourceName = $ServiceResourceName
    WhatIf = [bool]$WhatIfPreference
}
if ($null -ne $ServiceCredential) { $installParameters.ServiceCredential = $ServiceCredential }
if ($null -ne $ProvisioningCredential) { $installParameters.ProvisioningCredential = $ProvisioningCredential }
if ($PSBoundParameters.ContainsKey('Confirm')) { $installParameters.Confirm = [bool]$PSBoundParameters['Confirm'] }

$installer = Get-Command -Name 'Install-AdoAgentCluster' -Module 'AdoAgentClusterKey' -ErrorAction Stop
$result = & $installer @installParameters

if ($WhatIfPreference) {
    return [pscustomobject]@{
        ConfigId = $ConfigId
        Planned = $true
        ClusterRoleName = $ClusterRoleName
        SharedDiskResourceName = $SharedDiskResourceName
        AgentRoot = $AgentRoot
        Nodes = $nodes
        KeyResourceName = $KeyResourceName
        ServiceResourceName = $ServiceResourceName
    }
}

if ($null -eq $result) {
    return
}

Stop-ClusterGroup -Name $ClusterRoleName -Wait 60 | Out-Null
$group = Get-ClusterGroup -Name $ClusterRoleName
if ($group.State -ne 'Offline') {
    throw "Installation completed but clustered role '$ClusterRoleName' did not reach Offline. Keep the ADO service Offline and investigate before first start."
}

[pscustomobject]@{
    ConfigId = $result.ConfigId
    EnvelopePath = $result.EnvelopePath
    ManifestPath = $result.ManifestPath
    ClusterRoleName = $ClusterRoleName
    SharedDiskResourceName = $SharedDiskResourceName
    AgentRoot = $AgentRoot
    Nodes = $nodes
    KeyResourceName = $result.KeyResource
    ServiceResourceName = $result.ServiceResource
    RoleState = [string]$group.State
}
