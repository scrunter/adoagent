# CLI, schema, and WSFC reference

## Existing-agent full installation script

```text
Install-AdoAgentCluster.ps1
  -AgentRoot <shared-path>
  -ClusterRoleName <role>
  -SharedDiskResourceName <disk-resource>
  -ProtectorGroup <domain-group>
  -EscrowPath <path>
  -ConfirmAgentIdle
  [-ToolkitPackagePath <release-folder>]
  [-ConfigId <guid>]
  [-KeyResourceName <name>]
  [-ServiceResourceName <name>]
  [-ServiceCredential <PSCredential>]
  [-WhatIf] [-Confirm]
```

Run this script on the current role/shared-disk owner for an already registered agent. It intentionally has no `Node` parameter: the node set is every possible owner returned by `Get-ClusterOwnerNode` for the shared-disk resource. Every node must be Up and pass preflight. The script validates the release manifest, calls the module installer with that complete set, and leaves the clustered role Offline.

`ToolkitPackagePath` defaults to the directory containing the packaged script. `ConfigId` defaults to a new GUID, but operators should generate and record it before `-WhatIf` so the same identity is used for the actual run and any retry.

## New-agent setup script

```text
Initialize-AdoAgentCluster.ps1
  -ServerType Services|Server
  -AzureDevOpsUrl <url>
  -RegistrationAuth OAuthToken|PersonalAccessToken|Integrated|Negotiate
  -PoolName <pool> -AgentName <name> -AgentRoot <shared-path>
  -ClusterRoleName <role> -SharedDiskResourceName <disk-resource>
  -ProtectorGroup <domain-group> -EscrowPath <path>
  -ServiceAccount <identity> -ConfirmAgentIdle
  [-RegistrationToken <SecureString>]
  [-RegistrationTokenEnvironmentVariableName <name>]
  [-RegistrationCredential <PSCredential>]
  [-ServiceCredential <PSCredential>]
  [-WorkDirectory <relative-path>] [-Node <node[]>] [-ConfigId <guid>]
  [-ToolkitPackagePath <release-folder>]
  [-AgentPackagePath <zip> -AgentPackageSha256 <sha256>]
  [-KeyResourceName <name>] [-ServiceResourceName <name>]
  [-Resume] [-ReplaceExistingAgent] [-AllowInsecureServerUrl]
  [-WhatIf]
```

Authentication rules:

- `OAuthToken`: Services only; exactly one secure token source unless resuming after the Offline registration check.
- `PersonalAccessToken`: Services/Server; same secure-source rule.
- `Integrated`: Server only; no token or credential parameter.
- `Negotiate`: Server only; requires `RegistrationCredential`.
- `AllowInsecureServerUrl`: Server only and explicit; HTTPS remains the default.
- regular domain `ServiceAccount`: requires matching `ServiceCredential`; built-in identities and gMSAs are passwordless.

The script consumes an environment variable by name, not by value. `-WhatIf` retains the source variable because it creates no child process. OAuth/PAT and passwords are placed only in the `config.cmd` child environment. The process arguments contain only nonsecret switches, including `--preventServiceStart` and optional explicit `--replace`.

### Setup-state schema

Path: `<EscrowPath>\<ConfigId>.setup.json`

```json
{
  "schemaVersion": 1,
  "configId": "11111111-2222-3333-4444-555555555555",
  "immutableSha256": "<sha256-of-canonical-immutable-inputs>",
  "immutable": {
    "serverType": "Services",
    "azureDevOpsUrl": "https://dev.azure.com/<organization>",
    "registrationAuth": "OAuthToken",
    "poolName": "<pool>",
    "agentName": "<name>",
    "agentRoot": "<canonical-shared-root>",
    "workDirectory": "_work",
    "clusterRoleName": "<role>",
    "sharedDiskResourceName": "<disk>",
    "node": ["<node-a>", "<node-b>"],
    "protectorGroup": "<domain-group>",
    "escrowPath": "<canonical-escrow-path>",
    "toolkitPackagePath": "<canonical-release-path>",
    "serviceAccount": "<service-identity>"
  },
  "phase": "RegisteredStopped",
  "packageVersion": "<version>",
  "packageDownloadUrl": "<validated-url-or-null>",
  "packageSha256": "<sha256>",
  "poolId": 1,
  "agentId": "<agent-id>",
  "serviceName": "<service-name>",
  "registrationOfflineVerified": true,
  "lastFailurePhase": null
}
```

The immutable object also records the offline package choice and insecure-URL switch. It contains no token, password, RSA data, protected blob, or envelope content. Valid phases are `Preflight`, `PackageStaged`, `RegisteredStopped`, `KeyValidated`, `ClusterInstalled`, and `Complete`.

## Helper CLI

The executable returns zero on success and a stable nonzero code on failure. Add `--json` for a single sanitized JSON object. Do not redirect output into an agent-accessible location.

### `inspect`

```text
AdoAgent.ClusterKey.exe inspect --agent-root <path> [--json]
```

Decrypts the current machine-DPAPI key and returns `agentId`, `agentName`, `agentVersion`, `publicKeySha256`, `targetFileSddl`, `keyStorage` (`file` or `namedContainer`), `usesCng`, and detected additional credential-store names. It never returns RSA values.

### `export`

```text
AdoAgent.ClusterKey.exe export --agent-root <path> --protector-sid <sid> --envelope <path> --manifest <path> [--force] [--json]
```

Requires file-backed RSA, no blocked credential store, and a valid SID. Creates descriptor `SID=<sid>`, DPAPI-NG envelope, and manifest. Existing destinations require `--force`. Use only on the node that can decrypt the active classic-DPAPI key.

### `seal`

```text
AdoAgent.ClusterKey.exe seal --envelope <path> --manifest <path> --config-id <guid> [--force] [--json]
```

Validates envelope hash and RSA fingerprint, unwraps DPAPI-NG under the caller token, creates a classic `LocalMachine` DPAPI blob, locks it to SYSTEM/Administrators, hides it, and decrypts it once for verification. Default output is:

```text
C:\ProgramData\AdoAgentClusterKey\<ConfigId>\sealed.credentials_rsaparams
```

The output path is fixed; the release CLI does not accept an override.

### `activate`

```text
AdoAgent.ClusterKey.exe activate --config-id <guid> [--json]
```

Reads runtime config from fixed ProgramData, validates exact paths/agent/additional credentials/sealed key/fingerprint, and atomically installs the node ciphertext. It returns `changed: false` when the correct ciphertext is already active.

### `probe`

```text
AdoAgent.ClusterKey.exe probe --config-id <guid> --mode quick|full [--json]
```

- `quick`: validates config, paths, files, agent identity, unsupported credential stores, and exact ciphertext equality.
- `full`: performs quick checks, then classic-DPAPI unwrap and RSA fingerprint verification.

The shared disk must be online on the invoking node. A passive node can validate local file presence during setup, but it cannot probe shared `.agent`/active key until it owns storage.

## JSON output

Success:

```json
{"ok":true,"code":0,"command":"probe","message":"Full key probe succeeded.","data":{"configId":"<guid>","agentId":"<agent-id>","agentName":"<agent-name>","ownerNode":"<node>","mode":"full","healthy":true}}
```

Failure:

```json
{"ok":false,"code":12,"command":"probe","message":"The active agent key does not match this node's sealed key."}
```

Messages never contain exception stacks or secret values. See [exit codes](troubleshooting.md#exit-codes).

## Runtime configuration schema

Path: `C:\ProgramData\AdoAgentClusterKey\<ConfigId>\config.json`

```json
{
  "schemaVersion": 1,
  "configId": "11111111-2222-3333-4444-555555555555",
  "resourceName": "<key-resource-name>",
  "agentRoot": "<shared-agent-root>",
  "activeKeyPath": "<shared-agent-root>\\.credentials_rsaparams",
  "sealedKeyPath": "C:\\ProgramData\\AdoAgentClusterKey\\11111111-2222-3333-4444-555555555555\\sealed.credentials_rsaparams",
  "expectedAgentId": "<exact-scalar-from-.agent>",
  "expectedPublicKeySha256": "<64-uppercase-hex-characters>",
  "targetFileSddl": "<owner-group-dacl-sddl>"
}
```

Constraints:

- schema must be exactly 1;
- `configId` must match the requested canonical GUID and parent directory;
- active path must be exactly `.credentials_rsaparams` directly in the canonical agent root;
- sealed path must be exactly the fixed file in this ConfigId directory;
- ConfigId directory, sealed file, agent root, and active file must not be reparse points;
- opened agent root/parent/active paths must resolve to their expected canonical locations;
- `expectedAgentId` is a string representation, not necessarily a GUID;
- fingerprint comparison and ciphertext comparison are fixed-time.

## Escrow manifest schema

```json
{
  "schemaVersion": 1,
  "agentId": "<agent-id>",
  "agentName": "<agent-name>",
  "agentVersion": "<agent-version-if-present>",
  "publicKeySha256": "<sha256-of-subject-public-key-info>",
  "envelopeSha256": "<sha256-of-envelope-file>",
  "protectorSid": "<domain-security-group-sid>",
  "createdUtc": "<ISO-8601-UTC>",
  "targetFileSddl": "<captured-owner-group-dacl>"
}
```

It is nonsecret but integrity-sensitive. Keep it beside the envelope under escrow controls.

## PowerShell module

| Command | Purpose | Key safety controls |
|---|---|---|
| `Initialize-AdoAgentCluster` | download/register a new stopped agent, then install cluster integration | deployment-supplied auth, nonsecret resume state, explicit replacement, `SupportsShouldProcess` |
| `Test-AdoAgentClusterPrerequisite` | inventory/preflight | read-only, optional throw-on-failure |
| `Install-AdoAgentCluster` | initial export, enrollment, services/resources | `SupportsShouldProcess`, idle confirmation, source-to-node hash verification, rollback snapshot |
| `Add-AdoAgentClusterNode` | package/service/sealed key on new owner | disk-owner prerequisite, DPAPI-NG authorization |
| `Repair-AdoAgentCluster` | restore package/service/resource drift | optional explicit reseal, additive dependencies |
| `Remove-AdoAgentClusterNode` | remove possible owner | refuses active/last owner, preserves sealed data by default |
| `Uninstall-AdoAgentCluster` | restore snapshot/remove toolkit resources | preserves sealed/escrow by default, distinct purge switches |
| `Invoke-AdoAgentClusterEvaluation` | evidence-producing two-node tests | `SupportsShouldProcess`, negative tests opt-in, restoration in `finally` |

Every mutating function supports `-WhatIf`. `-ConfirmAgentIdle` is an explicit operator assertion; it does not make running jobs resumable.

## WSFC properties

### Generic Script resource

| Property | Value |
|---|---|
| `ScriptFilePath` | `C:\Program Files\AdoAgentClusterKey\AdoAgentClusterKey.vbs` |
| custom private `ConfigId` | canonical configuration GUID |
| Resource Monitor | separate |
| `PendingTimeout` | 60000 ms |
| `LooksAlivePollInterval` | 15000 ms |
| `IsAlivePollInterval` | 60000 ms |
| dependency | shared disk, added with AND without overwriting existing dependencies |

Callbacks:

| Callback | Behavior |
|---|---|
| `Open` | retrieves and validates only `Resource.ConfigId` |
| `Online` | fixed helper `activate` command |
| `LooksAlive` | fixed helper quick probe |
| `IsAlive` | fixed helper full probe |
| `Offline` | no key deletion; returns success |
| `Close` | returns success |
| `Terminate` | no key deletion; logs sanitized status |

The VBS uses no Cluster API calls and no network calls. Its only dynamic command value is a regex-validated GUID.

### Generic Service resource

- `ServiceName` equals the existing ADO agent Windows service name.
- Dependency includes the key selector.
- Possible owners align with selector and chosen shared-disk owners.
- Local service entries are Manual with independent SCM recovery disabled.

## Release files

The release ZIP contains the Native AOT EXE, setup entry point, static scripts/module, docs, `version.json`, SPDX 2.3 SBOM, and recursive SHA-256 release manifest. The build also emits a companion ZIP checksum file. The package contains no escrow, PAT, password, agent key, or environment-specific configuration. Authenticode and detached CMS signatures are not required or validated.
