# Prerequisites

Complete every item before scheduling migration.

## Platform and cluster

- Two or more x64, domain-joined Windows Server 2019/2022/2025 nodes with current security updates.
- A healthy WSFC validated with `Test-Cluster` according to your organization's policy.
- The existing ADO role and shared disk already exist. The agent root and `.credentials_rsaparams` use the same drive/path on every possible owner.
- Failover Clustering tools, including the `FailoverClusters` Windows PowerShell module, are installed on the management/current-owner node.
- PowerShell remoting works from the current owner to every possible owner and is constrained to cluster administrators.
- The operator can administer cluster resources, services, local Program Files/ProgramData, and the shared agent root.
- Endpoint security permits the signed helper and static VBS in `C:\Program Files\AdoAgentClusterKey`.

## Active Directory

Create a dedicated domain security group for DPAPI-NG recovery, for example `<domain>\AdoAgentKeyRecoveryOperators`.

- Use a security group, not a distribution group.
- Resolve and record its immutable SID.
- Add only designated provisioning/recovery operators.
- Make membership changes subject to approval and directory auditing.
- Ensure the initial operator's current logon token contains the group SID. Sign out/in after new membership; nested or just-added membership might not be in the current token.
- Do not add the ADO service identity, cluster computer account, pipeline users, or general server administrators by default.

DPAPI-NG SID protection requires domain controllers and AD connectivity when an envelope is protected/unprotected and authorization information is obtained. Runtime activation uses only classic local DPAPI and has no domain or escrow dependency.

## Agent preparation

Choose one preparation path:

- For a new logical agent, satisfy the deployment-authentication and empty-root requirements below, then use [New agent setup](agent-setup.md).
- For an existing logical agent, it must already be registered and working on the current owner before using [Initial migration and setup](migration-and-setup.md).

### New-agent deployment authorization

The existing deployment service must supply authorization; the toolkit does not create identities or assign permissions.

- Azure DevOps Services: use a short-lived OAuth token from the deployment identity. A PAT is break-glass only.
- Azure DevOps Server: use Integrated, Negotiate, or a PAT.
- The identity must already be present/licensed where required and have Agent Pool Administrator permission on the exact pool.
- Managed identity, device code, Alternate/Basic, and local service-principal secret acquisition are unsupported.
- Pass tokens as `SecureString` or by the name of a secret process environment variable. Never put a value in command history.

The shared AgentRoot must be absent or empty, have no reparse points in its ancestry, and inherit an explicit Modify ACE for the selected Windows service identity. The setup script requires a matching existing role and disk and registers with `--preventServiceStart`.

### Existing-agent files

Required shared files:

- `.agent`
- `.credentials`
- `.credentials_rsaparams`
- `.service`

The key must be file-backed. Run from the current owner with the release helper:

```powershell
& '<release-folder>\AdoAgent.ClusterKey.exe' inspect `
  --agent-root '<shared-agent-root>' `
  --json
```

Expected result: `keyStorage` is `file`, `additionalCredentialStores` is empty, and a public fingerprint is returned.

Installation blocks if it finds:

- nonempty `.proxycredentials`;
- a populated or malformed `.credential_store`;
- a nonempty `clientCertPasswordLookupKey` in `.certificates`.

Remove authenticated proxy/client-certificate dependence or place that connection function outside this clustered agent before proceeding. Anonymous proxy configuration without protected credentials is not blocked.

## Service identity

Preferred choices are a gMSA or a built-in identity where appropriate. The same service name, binary path, identity, and Manual startup must be valid on each node.

- A gMSA must be installed/tested on every possible owner and granted local rights needed by the agent.
- An ordinary domain identity must already exist. Acquire a `PSCredential` interactively only when a missing node service must be created or its identity changed. The module passes it through encrypted remoting and gives the password only to SCM/CIM in memory.
- Grant `Log on as a service` and agent-root/work-folder access through managed policy.
- Do not place passwords in scripts, parameter files, transcripts, shell history, or cluster private properties.

## Signing

Production requires a trusted Authenticode code-signing certificate supplied outside this repository.

- The private key should reside in a protected signing service, HSM, or tightly controlled signing host.
- All nodes must trust the issuing chain and be able to perform the organization's required revocation checks.
- Record the leaf certificate thumbprint used for pinning.
- Timestamp release signatures so packages remain valid after normal certificate expiry.
- Treat `-LabAllowUnsigned` as nonproduction only. It persists warnings by design.

Verify the signed manifest and package before copying it into the maintenance environment; see [build and release](build-and-release.md).

## Escrow

Choose a secure administrator-controlled path that is:

- outside shared cluster storage and the agent-accessible filesystem;
- backed up and recoverable independently of the cluster;
- accessible only to recovery custodians;
- protected with auditing and retention controls;
- unavailable to pipeline jobs, the ADO service identity, Cluster service runtime, and ordinary node administration.

Store the `.envelope.bin`, `.manifest.json`, signed release manifest, detached signature, release ZIP, and change record together. Never place a plaintext RSA export there.

## Maintenance state

No pipeline job may be running. Stop the clustered ADO Generic Service while leaving the shared disk accessible on the current owner. `Install-AdoAgentCluster` requires `-ConfirmAgentIdle` and refuses an Online existing service resource. A job interrupted by cluster movement cannot resume; configure pipeline retry policy separately.
