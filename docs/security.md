# Security guide

## Required ACL model

| Location | Required access |
|---|---|
| `C:\Program Files\AdoAgentClusterKey` | SYSTEM and built-in Administrators: Full Control; no write for agent/service/pipeline identities |
| `C:\ProgramData\AdoAgentClusterKey\<ConfigId>` | SYSTEM and built-in Administrators: Full Control; protected inheritance |
| node sealed file | same as ConfigId directory; Hidden; never readable by the ADO service |
| shared `.credentials_rsaparams` | exact owner/group/DACL captured from source plus Hidden; accessible only as required by the ADO service and administrators |
| shared agent root | pipeline identity cannot create reparse points, rename root metadata, or replace `.agent`/key files outside the controlled service model |
| escrow | recovery custodians only; explicitly deny/exclude ADO service, Cluster runtime, pipeline identities, and general shares |
| evaluation output | administrators/readers; it contains metadata only, but may expose topology and agent names |

The helper captures and reapplies owner, group, and DACL SDDL. SACL collection is omitted because reading it requires `SeSecurityPrivilege` and audit policy is managed independently. Apply required SACLs at the parent by policy and verify them separately.

## Signing policy

- Production config sets `allowUnsigned: false` and a normalized signer thumbprint.
- Runtime uses Windows trust policy (`WinVerifyTrust`) and then pins the signer certificate thumbprint.
- Setup validates each executable, DLL, PowerShell script/module/manifest, and VBS in the package before use and on each node.
- Release file hashes are in `RELEASE-MANIFEST.json`; its detached CMS signature is `RELEASE-MANIFEST.json.p7s`.
- Treat timestamp and revocation failures according to enterprise signing policy; do not paper over them with lab bypass.
- Rotate config and package together when the certificate changes.

The 15-second runtime probe does not force online revocation retrieval; doing so could turn CA/CRL network loss into cluster churn. Enforce certificate revocation with release verification and enterprise WDAC/AppLocker/code-integrity policy, and rotate the pinned release immediately on revocation.

`-LabAllowUnsigned` is an explicit testing escape hatch. It sets `allowUnsigned`, emits a warning, and writes `UNSIGNED-LAB-ONLY.txt` under Program Files and ProgramData. Any production discovery of these markers is a security incident/configuration failure.

## DPAPI-NG governance

The protector SID is a recovery authorization boundary.

- Use one dedicated domain security group per appropriate administrative boundary.
- Review direct and nested membership on a schedule and after every recovery.
- Alert on group membership changes.
- Separate approval from execution where possible.
- Preserve the SID if renaming the group; do not delete/recreate it without first rotating escrow.
- Require privileged access workstations/JIT membership for envelope operations.
- Ensure the ADO service and pipeline principals are not members.

The manifest records the SID and envelope SHA-256 but is not secret. Both envelope and manifest must still be protected from deletion/substitution and retained with the signed release.

## Plaintext handling

The C# helper keeps plaintext only in process memory, zeros managed buffers with `CryptographicOperations.ZeroMemory`, zeroes native outputs before `LocalFree`, and never returns private fields. OS/runtime copies outside application control can still exist transiently; reduce exposure by:

- using dedicated elevated maintenance sessions;
- disabling unapproved process dumps/debuggers on nodes;
- excluding the helper from verbose command transcription that captures environment/context beyond sanitized output;
- keeping swap/crash dumps encrypted and access-controlled;
- using credential guard/EDR policies compatible with the signed binary.

No PAT, password, certificate password, envelope bytes, DPAPI blob, or RSA JSON is accepted as a command-line option.

## Deployment authentication

The new-agent setup treats deployment authorization as an external prerequisite. It does not create a service principal, managed identity, access level, group membership, or Azure DevOps permission.

- Prefer a short-lived OAuth token issued to a dedicated deployment identity that is unavailable to pipeline jobs on the new agent.
- Grant that identity administration only on the target pool and review it independently of the agent service identity.
- Supply the token as a `SecureString` or named secret process environment variable. Setup removes a consumed variable from its own process and injects it only into the Microsoft configuration child process.
- Authorization headers are sent only to the configured Azure DevOps host. Redirects to approved Microsoft download hosts are anonymous.
- The nonsecret setup state stores only the authentication mode, never token material or token claims.
- PAT is break-glass. Integrated/Negotiate are Azure DevOps Server-only.
- Managed identity is deliberately unsupported: attaching a pool-administrator machine identity to a host that later runs pipeline code creates an avoidable privilege boundary.

After registration, the deployment credential is no longer used. The agent's `.credentials` metadata and RSA private key establish its runtime identity. Expiry or removal of the deployment token must not affect failover.

## Escrow handling

- Store it outside cluster/runtime paths in encrypted, backed-up administrative storage.
- Hash and inventory it; regularly test authorized recovery in nonproduction.
- Copy to a node only into a unique administrative temporary directory during sealing; cleanup occurs in `finally`.
- Never email, attach to ordinary tickets, put in source control, or expose through an agent-accessible share.
- Record every unwrap/reseal with ConfigId, node, operator, reason, outcome, and envelope hash—never envelope content.

## Audit events and monitoring

Collect:

- Security events for protector-group membership and privileged logon;
- code-integrity/AppLocker/WDAC signature decisions;
- Service Control Manager create/change/start/stop/failure events;
- FailoverClustering resource state, dependency, ownership, and Resource Monitor events;
- Application events/WSFC `Resource.LogInformation` lines containing helper command and exit code;
- file auditing for package/config/escrow changes where policy permits;
- Azure DevOps pool status, agent session duplication, and job assignment around moves.

The VBS logs only the operation name and numeric exit status. Use exit codes to retrieve sanitized detail manually; do not change it to log helper stdout/stderr.

## Pipeline trust implications

Anyone able to run a pipeline on a self-hosted agent can generally execute code as the agent service identity and persist in its workspace. This toolkit does not sandbox pipelines. Use dedicated pools, protected pipeline permissions, clean workspaces, least-privileged service identities, and no interactive administrator sessions in job-accessible locations. Protect `.agent`, `.credentials*`, service scripts, toolkit files, and parent directory topology from pipeline write access.

Compromise of LocalSystem or a cluster administrator on the active node is outside the encryption isolation guarantee: that principal can observe/use any secret the agent must use. The design limits cross-node copying and accidental exposure; it does not defend a node from its own fully privileged administrator.
