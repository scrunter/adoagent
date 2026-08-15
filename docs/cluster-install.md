# Full cluster installation

`Install-AdoAgentCluster.ps1` is the standard installation entry point for an Azure DevOps agent that is already registered on shared cluster storage. Run it once, from the current shared-disk owner. It discovers every possible owner of the shared-disk resource and deploys the toolkit, service definition, node-local sealed key, runtime configuration, and WSFC resources to the complete owner set.

Do not use this script to register a new agent. For a new logical registration, use [New agent setup](agent-setup.md), which finishes by invoking the same installation engine.

## Installation result

The script creates or repairs this dependency chain:

```text
Shared disk -> Key Selector -> ADO Agent service
```

On every possible owner it installs:

```text
C:\Program Files\AdoAgentClusterKey\
  AdoAgent.ClusterKey.exe
  AdoAgentClusterKey.vbs
  AdoAgentClusterKey.psm1
  AdoAgentClusterKey.psd1
  AdoAgentClusterKey.Setup.ps1
  Install-AdoAgentCluster.ps1
  Initialize-AdoAgentCluster.ps1
  Test-Release.ps1

C:\ProgramData\AdoAgentClusterKey\<ConfigId>\
  config.json
  sealed.credentials_rsaparams
  rollback.json
```

The role is left Offline. The first clustered start is always a separate operator action.

## Relevant nodes

The relevant node set is the complete possible-owner list on `SharedDiskResourceName`. The script has no `-Node` parameter and does not accept a hand-maintained subset.

Installation fails before changes if:

- the disk has no possible owners;
- any possible owner is not Up;
- the current computer is not the role and disk owner;
- PowerShell remoting to any owner fails; or
- any owner fails its service-identity, service-logon, package, or platform preflight.

To change the deployment set, first change the shared disk's possible owners under the normal WSFC change process.

## Prerequisites

Complete [Prerequisites](prerequisites.md) and [Initial migration and setup](migration-and-setup.md) before production installation. In particular:

1. The existing agent root is on the shared disk and contains `.agent`, `.credentials`, `.credentials_rsaparams`, and `.service`.
2. The agent key is file-backed and was created on the current owner.
3. No pipeline job is running; the ADO service and any existing selector resource are Offline.
4. The shared disk is Online on the node where the installer will run.
5. The existing role and disk resource names are known.
6. The service identity resolves, has `Log on as a service`, and can access the shared agent root on every possible owner.
7. The current operator is elevated and belongs to the DPAPI-NG protector group in the current logon token.
8. The escrow directory already exists outside shared/runtime storage.
9. The release ZIP SHA-256 matches the independently approved deployment record and the extracted package passes `Test-Release.ps1`.

Use elevated Windows PowerShell 5.1 on the current owner:

```powershell
Import-Module FailoverClusters

Get-ClusterGroup -Name '<existing-role>'
Get-ClusterResource -Name '<shared-disk-resource>' |
    Format-List Name,State,OwnerGroup,OwnerNode
Get-ClusterResource -Name '<shared-disk-resource>' |
    Get-ClusterOwnerNode
```

## Run the installation preview

Generate one ConfigId and keep it in the change record:

```powershell
$release = 'C:\Deployment\AdoAgentClusterKey-0.3.0-win-x64'
$configId = [Guid]::NewGuid()

$install = @{
    AgentRoot = 'S:\AdoAgent'
    ClusterRoleName = 'ADO Build Agent'
    SharedDiskResourceName = 'Cluster Disk 3'
    ProtectorGroup = 'CONTOSO\AdoAgentKeyRecoveryOperators'
    EscrowPath = '\\secure-files\ado-escrow\cluster-agent-01'
    ToolkitPackagePath = $release
    ConfigId = $configId
    ConfirmAgentIdle = $true
}

& "$release\Install-AdoAgentCluster.ps1" `
    @install `
    -WhatIf
```

The preview performs read-only validation, including release-manifest verification, agent-key inspection, cluster discovery, remoting, service identity/logon rights, and agent-root access. It does not export the key, copy files, create services, seal node keys, or change cluster resources.

Resolve every failed check before continuing.

## Install on every possible owner

Run the same parameters without `-WhatIf`:

```powershell
$result = & "$release\Install-AdoAgentCluster.ps1" @install
$result | Format-List
```

After an external change approval, an unattended invocation may suppress the confirmation prompt:

```powershell
$result = & "$release\Install-AdoAgentCluster.ps1" `
    @install `
    -Confirm:$false
```

For a built-in identity or gMSA, no service credential is required. For an ordinary domain service account, acquire it only in memory:

```powershell
$install.ServiceCredential =
    Get-Credential -UserName 'CONTOSO\svc-adoagent'

$result = & "$release\Install-AdoAgentCluster.ps1" @install
$install.Remove('ServiceCredential')
```

The installer never writes that password to config, escrow, rollback state, cluster properties, or command arguments. SCM receives it through the existing in-memory/remoting path.

## What the installer does

In order, the script and module:

1. require elevation, Windows PowerShell 5.1, FailoverClusters, the exact role/disk relationship, an Online disk, and execution on the current owner;
2. discover every possible owner from the shared disk and require every node to be Up;
3. validate the complete release against `RELEASE-MANIFEST.json`;
4. validate remoting, OS/domain state, protector SID/current token, service identity/logon right, shared-root ACL, agent metadata files, file-backed RSA, and absence of unsupported protected credential stores;
5. capture a nonsecret rollback snapshot;
6. create or reuse a matching SID-protected DPAPI-NG escrow envelope and manifest;
7. copy the release to each node, verify source-to-node SHA-256 values, and lock the Program Files ACL;
8. create or repair an identical Manual-start Windows service on every node and disable independent SCM recovery;
9. unwrap escrow in memory on each node and create that node's classic `LocalMachine` DPAPI blob;
10. write and protect `config.json`, the sealed key, and rollback snapshot under the ConfigId directory;
11. create or repair the Generic Script and Generic Service resources, additive dependencies, timing values, separate Resource Monitor, and possible owners; and
12. stop the complete clustered role and return `RoleState: Offline`.

No plaintext RSA key is written to disk. The escrow envelope is copied only to a unique node temporary directory during sealing and is removed in `finally`.

## Review before first start

Require `RoleState: Offline` in the result, then inspect:

```powershell
Get-ClusterGroup -Name $install.ClusterRoleName

Get-ClusterResource |
    Where-Object OwnerGroup -eq $install.ClusterRoleName |
    Format-Table Name,ResourceType,State,OwnerNode

Get-ClusterResource -Name "$($install.ClusterRoleName) - Key Selector" |
    Get-ClusterOwnerNode
```

Confirm every possible owner has a nonempty node-local sealed file without reading its content:

```powershell
$owners = @(
    (Get-ClusterResource -Name $install.SharedDiskResourceName |
        Get-ClusterOwnerNode).OwnerNodes |
        ForEach-Object {
            $nameProperty = $_.PSObject.Properties['Name']
            $candidate = if ($null -ne $nameProperty) { $nameProperty.Value } else { $_ }
            [Convert]::ToString($candidate, [Globalization.CultureInfo]::InvariantCulture)
        }
)

Invoke-Command -ComputerName $owners -ArgumentList $configId -ScriptBlock {
    param($id)
    $path = Join-Path `
        (Join-Path 'C:\ProgramData\AdoAgentClusterKey' ([Guid]$id).ToString('D')) `
        'sealed.credentials_rsaparams'
    $file = Get-Item -LiteralPath $path
    [pscustomobject]@{
        Node = $env:COMPUTERNAME
        Present = $file.Length -gt 0
    }
}
```

Retain the ConfigId, release ZIP SHA-256, envelope/manifest paths, rollback path, owner list, and sanitized result in the change record.

## First online and failover

Only after review:

```powershell
Start-ClusterGroup -Name $install.ClusterRoleName -Wait 300
```

Run a full owner-side probe, verify one Azure DevOps session, execute a canary, and move the role to every possible owner. Follow [Two-node evaluation](evaluation.md) for the complete acceptance sequence.

## Retry and recovery

A retry must use the same ConfigId and immutable installation inputs. The underlying installer reuses a matching escrow pair, rollback snapshot, and node artifacts; it fails closed rather than overwriting a mismatched set.

```powershell
& "$release\Install-AdoAgentCluster.ps1" @install
```

If installation fails:

- keep the service and key resource Offline;
- preserve the returned/sanitized error, escrow pair, rollback snapshot, and agent `_diag` data;
- do not delete or edit individual agent credential files;
- repair the failed prerequisite or node; and
- rerun the same command with the same ConfigId.

Use [Recovery and uninstall](recovery-and-uninstall.md) if cluster resources or node artifacts require rollback. Default rollback preserves escrow and sealed keys.
