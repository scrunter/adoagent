# New agent setup

`Initialize-AdoAgentCluster.ps1` prepares a new logical Azure DevOps agent on shared cluster storage, registers it without starting it, and invokes the key-clustering installer. Use this path only for a new registration. Use the existing-agent migration in [Initial migration and setup](migration-and-setup.md) when `.agent`, `.credentials`, `.credentials_rsaparams`, and `.service` already exist.

The script does not create an identity, obtain a token, grant Azure DevOps permissions, create a cluster role, or create shared storage. Those are deployment prerequisites.

## Authentication boundary

Three different identities are involved:

| Identity | Purpose | Persistence |
|---|---|---|
| deployment identity | download the matching package, verify pool administration, register the agent | its supplied token exists only during setup |
| logical ADO agent | communicate with Azure DevOps after registration | server-issued OAuth metadata plus the clustered RSA key |
| Windows service identity | run pipeline jobs and access the shared agent/work directories | stored by Windows SCM |

Managed identity, device code, Alternate/Basic authentication, and service-principal client-secret acquisition are not supported. A deployment service principal is supported by supplying the short-lived OAuth token that the deployment system has already obtained.

Supported registration modes:

| `RegistrationAuth` | Target | Input |
|---|---|---|
| `OAuthToken` | Azure DevOps Services | `SecureString` or named process environment variable |
| `PersonalAccessToken` | Services or Server | `SecureString` or named process environment variable |
| `Integrated` | Azure DevOps Server | current Windows identity |
| `Negotiate` | Azure DevOps Server | `RegistrationCredential` |

The deployment identity must already be present in the Azure DevOps organization and able to manage the exact target pool. Setup performs a read-only `actionFilter=manage` query and fails if that exact pool is not returned. It never changes identity membership, access level, or permissions.

## Preflight

Before setup:

1. Create the WSFC role and shared disk and make the disk Online on the node running setup.
2. Keep every existing key-selector or ADO service resource Offline and confirm no job is running.
3. Create an absent or empty shared `AgentRoot`. Reject all reparse points in its ancestry.
4. Grant the selected service identity an explicit inheritable Modify ACE on `AgentRoot`, or on its existing parent if the root is absent.
5. Grant `Log on as a service` on every possible owner. Built-in service identities do not require an explicit assignment; gMSAs and domain users do.
6. Pre-create the administrator-only escrow directory outside the shared/runtime filesystem.
7. Verify the toolkit ZIP SHA-256 against the approved deployment record, then validate its internal release manifest.
8. Supply an already authorized short-lived registration token from the deployment system.

For a regular domain service identity, pass a `ServiceCredential` acquired in memory. Built-in identities and gMSAs do not accept a password.

## Azure DevOps Services example

The deployment system exposes its short-lived token as a secret environment variable. The value is not included in arguments. The setup process removes the variable after reading it, except during `-WhatIf`, when no child process is created.

```powershell
$configId = [Guid]::NewGuid()

& '<release-folder>\Initialize-AdoAgentCluster.ps1' `
  -ServerType Services `
  -AzureDevOpsUrl 'https://dev.azure.com/<organization>' `
  -RegistrationAuth OAuthToken `
  -RegistrationTokenEnvironmentVariableName 'SYSTEM_ACCESSTOKEN' `
  -PoolName '<pool>' `
  -AgentName '<logical-agent-name>' `
  -AgentRoot '<shared-disk>:\AdoAgent' `
  -WorkDirectory '_work' `
  -ClusterRoleName '<existing-role>' `
  -SharedDiskResourceName '<existing-disk-resource>' `
  -Node '<node-a>','<node-b>' `
  -ProtectorGroup '<domain>\<dpapi-ng-operator-group>' `
  -EscrowPath '<administrator-only-escrow-folder>' `
  -ServiceAccount '<domain>\<gmsa>$' `
  -ConfigId $configId `
  -ConfirmAgentIdle
```

When an Azure DevOps pipeline supplies `System.AccessToken`, explicitly map it to the process environment as a secret and grant the corresponding deployment/build-service identity pool administration before the run. The toolkit does not make that assignment.

Use `-RegistrationToken (Read-Host -AsSecureString)` for an attended token source. Never put the value after a script parameter.

## Azure DevOps Server examples

Integrated authentication:

```powershell
& '<release-folder>\Initialize-AdoAgentCluster.ps1' `
  -ServerType Server `
  -AzureDevOpsUrl 'https://<ado-server>/<collection>' `
  -RegistrationAuth Integrated `
  -PoolName '<pool>' `
  -AgentName '<logical-agent-name>' `
  -AgentRoot '<shared-disk>:\AdoAgent' `
  -ClusterRoleName '<existing-role>' `
  -SharedDiskResourceName '<existing-disk-resource>' `
  -Node '<node-a>','<node-b>' `
  -ProtectorGroup '<domain>\<dpapi-ng-operator-group>' `
  -EscrowPath '<administrator-only-escrow-folder>' `
  -ServiceAccount 'NT AUTHORITY\NETWORK SERVICE' `
  -ConfigId ([Guid]::NewGuid()) `
  -ConfirmAgentIdle
```

For Negotiate, acquire `Get-Credential` into `RegistrationCredential`. A PAT is also accepted through the secure token inputs. HTTP is rejected by default; `-AllowInsecureServerUrl` is an explicit Azure DevOps Server-only exception that should be limited to controlled legacy environments.

## Package selection and offline installation

The default flow calls the target instance's matching-agent endpoint for `win-x64`, follows no more than five validated redirects, and records the selected version, final URL, and downloaded SHA-256. Authorization is sent only to the configured Azure DevOps host, never to an external download host.

For a disconnected installation, supply both:

```powershell
-AgentPackagePath '<approved-agent-zip>' `
-AgentPackageSha256 '<64-character-sha256>'
```

The archive is expanded entry by entry into a sibling staging directory. Absolute paths, traversal, alternate data streams, symbolic-link entries, reparse points, duplicate files, and missing agent entry points fail closed. The validated directory is renamed into place on the same volume.

## Registration and stopped-service guarantee

The Microsoft agent is configured with `--unattended --runAsService --preventServiceStart`. Token, Negotiate password, and regular service-account password are supplied only in the child process environment. The command line contains none of them.

After registration, setup:

1. requires all four agent metadata/credential files;
2. stops the SCM service defensively;
3. sets Manual startup and clears independent recovery actions;
4. verifies the Azure DevOps agent reports Offline;
5. inspects the key and rejects named-container or additional protected credential stores;
6. invokes `Install-AdoAgentCluster`;
7. stops the entire WSFC role so first Online remains an explicit operator action.

## Resume state

The nonsecret state is `<EscrowPath>\<ConfigId>.setup.json`. It contains immutable target metadata, package version/hash, pool/agent/service IDs, timestamps, the last completed phase, and sanitized failure phase/operation identifiers. It never contains a token, password, agent RSA value, protected blob, or envelope content.

Phases are:

```text
Preflight -> PackageStaged -> RegisteredStopped -> KeyValidated -> ClusterInstalled -> Complete
```

To resume, repeat the immutable inputs and add `-Resume`. A changed URL, pool, name, root, node set, identity, package choice, insecure-URL policy, or ConfigId is rejected. Once `RegisteredStopped` and the Offline check are recorded, a retry does not require the expired registration token.

If setup sees an ambiguous mixture of registration files, it stops and preserves them. Do not delete individual dot-files. Follow the recovery procedure below.

## Existing names and replacement

Setup queries the exact agent name before registration. It refuses an existing server-side name unless `-ReplaceExistingAgent` is explicitly supplied. That switch is appropriate only when change control has established that the old logical registration is stopped and is the one being replaced.

The script never silently unregisters an agent. If configuration failed midway and left an unrecorded or partial local registration:

1. keep the service stopped and retain the setup state and `_diag` directory;
2. determine whether Azure DevOps created the server-side agent object;
3. preserve evidence;
4. use the Microsoft `config.cmd remove` command with a fresh approved registration credential when removal is required;
5. clean or replace `AgentRoot` only after explicit approval;
6. restart setup with a new ConfigId, using `-ReplaceExistingAgent` only when the retained server object is intentional.

## Completion and first Online

Successful output includes ConfigId, state path, agent ID, service name, cluster role, root, and nodes. It contains no credential. The role is Offline.

Verify the setup state and escrow/manifest, then bring the role Online, move it to both nodes, run the canary and negative-key evaluation, and confirm exactly one Azure DevOps session exists.
