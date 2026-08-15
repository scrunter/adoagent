# Quick start: new clustered Azure DevOps agent

This guide creates one new logical Azure DevOps agent on shared Windows Failover Cluster storage, registers it without starting it, enrolls a node-specific DPAPI key on each possible owner, and leaves the clustered role Offline for review.

Use this procedure only when the shared agent root is absent or empty. To adopt an existing registration, run the packaged [full cluster installation](cluster-install.md) from the current shared-disk owner.

## Result

After setup, the dependency order is:

```text
Shared disk -> Key Selector -> ADO Agent service
```

The short-lived deployment credential is no longer needed after registration. Runtime Azure DevOps communication uses the agent's server-issued identity and clustered RSA key.

## 1. Prepare the prerequisites

Run setup from an elevated Windows PowerShell 5.1 session on the node that currently owns the shared disk.

Before continuing, confirm that:

- the nodes are domain-joined Windows Server 2019, 2022, or 2025 x64 systems;
- the existing WSFC role and shared disk are healthy;
- the shared disk is Online on the node running setup;
- both target nodes are possible owners of the disk;
- no pipeline job is running and any existing agent/key-selector resources are Offline;
- PowerShell remoting works from the current owner to every possible owner;
- the shared agent root is absent or empty and has no reparse points;
- an administrator-only escrow directory exists outside shared cluster storage and the agent-accessible filesystem; and
- the toolkit release ZIP and its approved SHA-256 are available through controlled distribution.

List the current cluster objects:

```powershell
Import-Module FailoverClusters

Get-ClusterGroup
Get-ClusterResource |
    Format-Table Name, ResourceType, OwnerGroup, OwnerNode, State
```

Read [Prerequisites](prerequisites.md) before a production installation.

## 2. Prepare the identities

Three separate identities are involved:

| Identity | Purpose |
|---|---|
| Deployment identity | Authorizes package discovery and the one-time agent registration |
| Logical ADO agent | Uses the server-issued identity and clustered RSA key at runtime |
| Windows service identity | Runs pipeline jobs and accesses the shared agent/work directories |

For Azure DevOps Services, use a short-lived OAuth token supplied by the deployment system. The deployment identity must already have Agent Pool Administrator permission on the exact target pool.

Managed identity is not a direct registration mode. A deployment system running under managed identity must obtain an acceptable Azure DevOps OAuth token before calling the setup script.

A gMSA is the preferred Windows service identity. It must already be installed on every possible owner and have:

- `Log on as a service`; and
- an explicit inheritable Modify ACE on the shared agent root, or its existing parent when the root does not yet exist.

Create a dedicated domain security group for DPAPI-NG recovery operators, for example `CONTOSO\AdoAgentKeyRecoveryOperators`. The administrator running setup must have this group in their current logon token:

```powershell
whoami /groups
```

Do not add the agent service identity, pipeline identities, or cluster computer accounts to the recovery group.

## 3. Prepare the shared root and escrow

Example shared root and service-account ACL:

```powershell
$agentRoot = 'S:\AdoAgent'

New-Item -Path $agentRoot -ItemType Directory
icacls $agentRoot /grant 'CONTOSO\svc-adoagent$:(OI)(CI)M'
```

Keep this directory empty. The `_work` directory will inherit the access rule when the Microsoft agent creates it.

Pre-create a protected escrow directory, for example:

```powershell
$escrowPath = '\\secure-files\ado-escrow\cluster-agent-01'
```

Only recovery administrators should be able to access escrow. The agent service identity and pipeline jobs must not be able to read it.

## 4. Build and verify a release

In the controlled build environment:

```powershell
.\build\Build.ps1 -Version '0.3.0'
```

Record the reported ZIP SHA-256 in the approved deployment/change record. On the current cluster owner, compare the copied ZIP with that independently obtained value before extraction:

```powershell
$zip = 'C:\Deployment\AdoAgentClusterKey-0.3.0-win-x64.zip'
$expectedZipSha256 = '<sha256-from-approved-record>'

if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $expectedZipSha256) {
    throw 'Release ZIP SHA-256 does not match the approved value.'
}
```

Extract it, then validate the internal manifest:

```powershell
$release = 'C:\Deployment\AdoAgentClusterKey-0.3.0-win-x64'

& "$release\Test-Release.ps1" `
    -PackagePath $release
```

The toolkit does not require or validate Authenticode signatures. The ZIP checksum must come from a protected channel because the internal manifest does not establish publisher identity.

## 5. Supply deployment authorization

The recommended production method is a secret process environment variable created by the deployment system, for example:

```text
ADO_AGENT_REGISTRATION_TOKEN
```

The variable must exist in the PowerShell process running on the current cluster owner. Do not put the token value in a script, command argument, transcript, or parameter file.

For an attended setup, use a `SecureString` instead:

```powershell
$registrationToken = Read-Host 'Azure DevOps registration token' -AsSecureString
```

## 6. Define the installation

Generate and retain one ConfigId:

```powershell
$configId = [Guid]::NewGuid()
$configId
```

Prepare the setup parameters. Replace every placeholder before running:

```powershell
$setupParameters = @{
    ServerType                                = 'Services'
    AzureDevOpsUrl                           = 'https://dev.azure.com/<organization>'
    RegistrationAuth                         = 'OAuthToken'
    RegistrationTokenEnvironmentVariableName = 'ADO_AGENT_REGISTRATION_TOKEN'

    PoolName                                 = '<agent-pool>'
    AgentName                                = 'cluster-agent-01'
    AgentRoot                                = 'S:\AdoAgent'
    WorkDirectory                            = '_work'

    ClusterRoleName                          = 'ADO Build Agent'
    SharedDiskResourceName                   = 'Cluster Disk 3'
    Node                                     = @('ADOCL01', 'ADOCL02')

    ProtectorGroup                           = 'CONTOSO\AdoAgentKeyRecoveryOperators'
    EscrowPath                               = '\\secure-files\ado-escrow\cluster-agent-01'

    ServiceAccount                           = 'CONTOSO\svc-adoagent$'
    ConfigId                                 = $configId
    ConfirmAgentIdle                         = $true
}
```

No `ServiceCredential` is required for a gMSA or built-in service identity. For a regular domain account, add an in-memory credential:

```powershell
$setupParameters.ServiceAccount = 'CONTOSO\svc-adoagent'
$setupParameters.ServiceCredential =
    Get-Credential -UserName 'CONTOSO\svc-adoagent'
```

Azure DevOps Server can instead use `Integrated`, `Negotiate`, or `PersonalAccessToken` registration. See [New agent setup](agent-setup.md#azure-devops-server-examples).

## 7. Run the read-only preflight

Always run `-WhatIf` first:

```powershell
& "$release\Initialize-AdoAgentCluster.ps1" `
    @setupParameters `
    -WhatIf
```

This validates the cluster, service identity, access rights, remoting, required toolkit files, exact-pool permission, agent-name availability, and matching Microsoft agent package. It does not download, extract, register, write setup state, export keys, change services, or create cluster resources.

Resolve every reported failure before continuing.

## 8. Run setup

Run the same command without `-WhatIf`:

```powershell
$result = & "$release\Initialize-AdoAgentCluster.ps1" `
    @setupParameters

$result | Format-List
```

After an external change approval, an unattended deployment can suppress only the confirmation prompt:

```powershell
$result = & "$release\Initialize-AdoAgentCluster.ps1" `
    @setupParameters `
    -Confirm:$false
```

The setup script:

1. selects and downloads the matching Microsoft `win-x64` agent;
2. validates and safely extracts it onto shared storage;
3. registers it with `--preventServiceStart`;
4. stops the service, sets Manual startup, and clears independent SCM recovery;
5. confirms the Azure DevOps agent remained Offline;
6. verifies file-backed RSA and rejects unsupported credential stores;
7. creates the DPAPI-NG escrow envelope;
8. creates one node-local LocalMachine DPAPI copy on every owner;
9. installs the selector and local runtime configuration;
10. creates the Generic Script and Generic Service resources and dependencies; and
11. leaves the entire clustered role Offline.

The real run reads the named token once and removes it from the setup process environment.

## 9. Review the offline installation

Confirm setup reached `Complete`:

```powershell
$statePath = Join-Path `
    $escrowPath `
    ($configId.ToString('D') + '.setup.json')

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$state | Format-List

if ($state.phase -ne 'Complete') {
    throw "Setup is not complete. Current phase: $($state.phase)"
}
```

Review the role and resources:

```powershell
Get-ClusterGroup -Name $setupParameters.ClusterRoleName

Get-ClusterResource |
    Where-Object OwnerGroup -eq $setupParameters.ClusterRoleName |
    Format-Table Name, ResourceType, State, OwnerNode
```

Confirm that each node has a nonempty sealed key without reading or copying its content:

```powershell
Invoke-Command `
    -ComputerName $setupParameters.Node `
    -ArgumentList $configId `
    -ScriptBlock {
        param($id)

        $directory = Join-Path `
            'C:\ProgramData\AdoAgentClusterKey' `
            ([Guid]$id).ToString('D')
        $sealed = Get-Item -LiteralPath (
            Join-Path $directory 'sealed.credentials_rsaparams'
        )

        [pscustomobject]@{
            Node = $env:COMPUTERNAME
            Present = $sealed.Length -gt 0
        }
    }
```

## 10. Perform the first clustered start

Bring the role Online explicitly:

```powershell
Start-ClusterGroup `
    -Name $setupParameters.ClusterRoleName `
    -Wait 300

Get-ClusterGroup -Name $setupParameters.ClusterRoleName
```

Run a full key probe on the owner:

```powershell
& 'C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe' `
    probe `
    --config-id $configId `
    --mode full `
    --json
```

In Azure DevOps, confirm that exactly one logical agent is Online and run a harmless canary job.

## 11. Test both possible owners

Move the role to the second node:

```powershell
Move-ClusterGroup `
    -Name $setupParameters.ClusterRoleName `
    -Node 'ADOCL02' `
    -Wait 300
```

Run the full probe on the new owner:

```powershell
Invoke-Command `
    -ComputerName 'ADOCL02' `
    -ArgumentList $configId `
    -ScriptBlock {
        param($id)

        & 'C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe' `
            probe `
            --config-id $id `
            --mode full `
            --json
    }
```

Verify that:

- the role reaches Online within five minutes;
- the logical agent returns Online in Azure DevOps;
- a canary job completes on the new owner;
- the service remains stopped on the passive node; and
- Azure DevOps never reports two active sessions.

Move the role back and repeat. Complete the broader negative and recovery testing in [Two-node evaluation guide](evaluation.md) before production approval.

## Resume after a failure

Do not delete individual `.agent`, `.credentials`, `.credentials_rsaparams`, or `.service` files.

Repeat the immutable parameters and ConfigId, then add `-Resume`:

```powershell
& "$release\Initialize-AdoAgentCluster.ps1" `
    @setupParameters `
    -Resume
```

If the failure happened before `RegisteredStopped` and the Offline verification, the deployment system must provide a fresh token to the new setup process. After that checkpoint, resume does not require the registration token.

A changed URL, pool, name, root, node set, service identity, Microsoft agent-package choice, insecure-URL policy, or ConfigId is rejected. A corrected toolkit release may be used from its new extracted path; its manifest is verified and only `toolkitPackagePath` is rebound after confirmation. Use `-ReplaceExistingAgent` only when approved change control has confirmed that an existing Offline server-side registration with the same name is intentionally being replaced.

For ambiguous partial registration, preserve the setup state and `_diag` evidence and follow [Recovery and uninstall](recovery-and-uninstall.md). Never silently remove or re-register the agent.
