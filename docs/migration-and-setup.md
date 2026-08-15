# Initial migration and setup

Use a two-node nonproduction cluster first. Preserve the existing agent package and Azure DevOps registration throughout the file-backed path.

This procedure is for an existing registration. To download and register a new stopped agent before installing the cluster resources, use [New agent setup](agent-setup.md). Do not run both paths against the same AgentRoot or ConfigId.

## 1. Prepare maintenance

1. Pause or drain pipeline demand for the logical agent.
2. Confirm no job is running. In-flight jobs are not resumable.
3. Capture Azure DevOps pool status, cluster group/resources/dependencies/owners, Windows service configuration, and existing agent diagnostics.
4. Stop/offline the current clustered agent service and existing selector, if any. Keep its shared disk online on the current owner.
5. Confirm the current command host is the group's owner. Classic DPAPI export must run on the machine that created the active ciphertext.
6. Verify the release ZIP against its independently recorded approved SHA-256, extract it to an administrator-only local path, and run `Test-Release.ps1`.
7. Pre-create the escrow directory with the approved external ACL; the installer refuses to create it or place it beneath the agent root.

## 2. Preflight

```powershell
Import-Module '<release-folder>\AdoAgentClusterKey.psd1' -Force

$preflight = Test-AdoAgentClusterPrerequisite `
  -AgentRoot '<shared-agent-root>' `
  -ClusterRoleName '<role>' `
  -SharedDiskResourceName '<disk-resource>' `
  -ProtectorGroup '<domain\recovery-group>' `
  -Node '<node-a>','<node-b>' `
  -PackagePath '<release-folder>'

$preflight.Checks | Format-Table -AutoSize
if (-not $preflight.Passed) { throw 'Do not continue.' }
```

Also run `AdoAgent.ClusterKey.exe inspect`. Archive only its sanitized JSON—not console transcripts that may contain unrelated operator input.

## 3. Preview and install

Use the packaged full installer on the current role/disk owner. It discovers every possible owner from the shared-disk resource. `-WhatIf` performs validation and planning but intentionally does not export/decrypt the key or mutate nodes/cluster state.

```powershell
$release = '<release-folder>'
$provisioningCredential = Get-Credential -UserName '<domain\protector-group-operator>'
$install = @{
  ConfigId = [Guid]::NewGuid()
  AgentRoot = '<shared-agent-root>'
  ClusterRoleName = '<role>'
  SharedDiskResourceName = '<disk-resource>'
  ProtectorGroup = '<domain\recovery-group>'
  EscrowPath = '<secure-admin-escrow-folder>'
  ToolkitPackagePath = $release
  ConfirmAgentIdle = $true
  ProvisioningCredential = $provisioningCredential
}

& "$release\Install-AdoAgentCluster.ps1" @install -WhatIf
$result = & "$release\Install-AdoAgentCluster.ps1" @install
$result | Format-List
```

Keep the generated ConfigId in the change record before execution. A retry with the same ConfigId reuses a matching escrow pair, original rollback snapshot, and matching node artifacts; it fails rather than overwriting a mismatched set. The result must report every shared-disk possible owner and `RoleState: Offline`.

The provisioning credential is separate from `ServiceCredential`. It supplies a fresh domain logon only while the fixed helper unwraps DPAPI-NG on passive nodes, is never placed on a command line or in setup state, and may be removed from the caller after installation.

For an ordinary domain service account, acquire the credential without embedding it:

```powershell
$install.ServiceCredential = Get-Credential -UserName '<domain\service-account>'
& "$release\Install-AdoAgentCluster.ps1" @install
$install.Remove('ServiceCredential')
Remove-Variable serviceCredential -ErrorAction SilentlyContinue
```

The installer:

1. validates OS/domain/cluster/remoting, required package files, protector SID/token, files, role/disk owners, key mode, and additional credential stores;
2. captures a nonsecret rollback snapshot;
3. exports the exact RSA JSON once into SID-protected DPAPI-NG escrow;
4. installs and revalidates the package on each node;
5. creates/repairs Manual SCM entries and disables independent recovery;
6. unwraps escrow and seals one classic machine-DPAPI blob per node without writing plaintext;
7. writes node-local config and locks its ACL;
8. creates/repairs Generic Script and Generic Service resources in the existing role;
9. adds disk-to-selector and selector-to-service dependencies without removing unrelated dependencies;
10. aligns possible owners with the supplied subset of shared-disk owners.

Record returned `ConfigId`, envelope path, manifest path, resource names, release version, and approved ZIP SHA-256 in the change record.

## 4. Verify installed state

On each node:

```text
C:\Program Files\AdoAgentClusterKey\
  AdoAgent.ClusterKey.exe
  AdoAgentClusterKey.vbs
  AdoAgentClusterKey.psm1
  AdoAgentClusterKey.psd1
  AdoAgentClusterKey.Setup.ps1
  Install-AdoAgentCluster.ps1
  Initialize-AdoAgentCluster.ps1

C:\ProgramData\AdoAgentClusterKey\<ConfigId>\
  config.json
  sealed.credentials_rsaparams
  rollback.json
```

Program Files and ProgramData runtime directories must grant full control only to SYSTEM and built-in Administrators. The sealed file is Hidden. The escrow envelope must exist only at the administrator-selected external path.

Cluster checks:

```powershell
Get-ClusterResource '<role> - Key Selector','<role> - ADO Agent' |
  Format-List Name,ResourceType,State,OwnerGroup,PendingTimeout,LooksAlivePollInterval,IsAlivePollInterval

Get-ClusterResourceDependency -Resource '<role> - Key Selector'
Get-ClusterResourceDependency -Resource '<role> - ADO Agent'
```

Expected: selector depends on the shared disk, service depends on the selector, selector uses a separate Resource Monitor, pending timeout is 60 seconds, LooksAlive is 15 seconds, and IsAlive is 60 seconds.

## 5. First online and rollback point

1. Start the role on the current node.
2. Confirm disk, selector, then service become Online in that order.
3. Confirm the logical Azure DevOps agent returns Online and run a harmless canary job.
4. Move the role to the second node and repeat.
5. Move it back and complete [evaluation](evaluation.md).

Stop and roll back if the selector cannot activate, the service starts without the selector, two pool sessions appear, an unsupported credential store is found, installed package hashes differ from the approved release, or the five-minute release gate is missed.

Default rollback preserves escrow and node-sealed copies. Follow [recovery and uninstall](recovery-and-uninstall.md).

## Named-container branch

If `inspect` returns `keyStorage: namedContainer`, the private key is not available as exportable RSA JSON. The toolkit must not copy or attempt to export a CSP/CNG container.

1. Obtain explicit authorization for a one-time agent re-registration and a maintenance outage.
2. Save nonsecret registration/service settings; remove the existing registration using the Microsoft agent's supported configuration command.
3. Remove/disable the named-container configuration switch used by that agent build or environment.
4. Configure the same logical agent name with the Microsoft agent's supported `--replace` path so it creates file-backed `.credentials_rsaparams`. Supply registration credentials interactively or through your approved one-time secret channel; do not put them in history.
5. Start the agent on the source node and validate one canary job.
6. Stop it, run `inspect`, and require `keyStorage: file` with no additional credential stores.
7. Begin the normal migration above.

This is the only path in v1 that changes the Azure DevOps registration. It is deliberately separate from toolkit automation so no cluster operation can silently re-register an agent.
