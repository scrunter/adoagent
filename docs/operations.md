# Day-two operations

All operations use elevated Windows PowerShell 5.1 and the same signed module version installed on the nodes. Preserve `ConfigId`; changing it creates a different artifact set.

## Planned failover

1. Stop dispatching new work and wait for the current job to finish.
2. Confirm the target node is Up and has `config.json`, `sealed.credentials_rsaparams`, package signatures, service entry, and shared-disk ownership eligibility.
3. Move the role with Failover Cluster Manager or `Move-ClusterGroup`.
4. Observe disk Online, selector Online, then Generic Service Online.
5. Confirm the old owner's SCM service is Stopped, one Azure DevOps session is Online, and a canary job runs on the target.

An interrupted job does not resume. Use pipeline retry policy for node failure during a job.

## Add a possible owner

First add the node as a possible owner of the shared disk and satisfy all prerequisites. Keep the ADO service idle/offline. The provisioning identity must be in the DPAPI-NG protector group.

```powershell
$credential = Get-Credential -UserName '<domain\service-account>' # omit for gMSA/built-in

Add-AdoAgentClusterNode `
  -Node '<new-node>' `
  -ConfigId '<config-guid>' `
  -AgentRoot '<shared-agent-root>' `
  -ClusterRoleName '<role>' `
  -SharedDiskResourceName '<disk-resource>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>' `
  -EnvelopePath '<secure-escrow-envelope>' `
  -ManifestPath '<secure-escrow-manifest>' `
  -PackagePath '<signed-release-folder>' `
  -PublisherThumbprint '<thumbprint>' `
  -ServiceCredential $credential `
  -ConfirmAgentIdle
```

The command copies escrow only to a node temporary folder for the duration of sealing and removes it in `finally`. It never copies escrow to shared storage or runtime ProgramData.

Move the role to the new node and run owner-side full probe plus canary before declaring it available.

## Remove a possible owner

Move the role away first:

```powershell
Remove-AdoAgentClusterNode `
  -Node '<retiring-node>' `
  -ConfigId '<config-guid>' `
  -ClusterRoleName '<role>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>'
```

By default the sealed material is retained for rollback. Add the distinct `-PurgeSealedKey` switch only after retention approval. The command refuses to remove the last owner and validates the purge path beneath the fixed ProgramData root.

## Repair drift

Use repair when package files, service settings, owners, parameters, or dependencies drift. It preserves unrelated dependencies.

```powershell
Repair-AdoAgentCluster `
  -ConfigId '<config-guid>' `
  -AgentRoot '<shared-agent-root>' `
  -ClusterRoleName '<role>' `
  -SharedDiskResourceName '<disk-resource>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>' `
  -PackagePath '<signed-release-folder>' `
  -Node '<node-a>','<node-b>' `
  -PublisherThumbprint '<thumbprint>' `
  -ConfirmAgentIdle
```

Use `-Reseal -EnvelopePath ... -ManifestPath ...` only when node ciphertext needs recreation from the same escrow. Repair checks the sealed/config files on passive nodes; a full probe is possible only on the current storage owner.

## Recover or enroll from escrow

On an authorized administrative host/current owner:

1. verify envelope SHA-256 against its manifest;
2. verify release/signatures;
3. confirm the operator token contains the manifest protector SID;
4. run repair with `-Reseal`, or run `seal` directly for controlled diagnostics;
5. remove all temporary envelope copies and review security/audit events.

Loss of every node blob is recoverable while the DPAPI-NG envelope, AD protector group/SID, authorized membership, and compatible Windows domain trust remain available.

## Reseal after ADO reconfiguration

Any operation that causes the Microsoft agent to generate a new `.credentials_rsaparams` changes the canonical key.

1. Keep the role on that source node, service idle/offline, and disk online.
2. Run `inspect`; compare agent ID and fingerprint with current config.
3. Treat a fingerprint change as a new key generation, not ordinary repair.
4. Create a new `ConfigId`, new DPAPI-NG envelope/manifest, and a fresh rollback snapshot using `Install-AdoAgentCluster` after removing/rolling back the old selector resources as approved.
5. Retain the old escrow under the organization's rotation/rollback policy; do not overwrite it in place.

## Service-account change

1. Drain work and stop the clustered service.
2. Grant the new account rights on every node, shared agent/work directories, and other required resources. Do not grant escrow/runtime-key read access unless separately justified.
3. Acquire an in-memory `PSCredential` for an ordinary domain identity; use none for gMSA/built-in.
4. Update the existing owner service under change control, then run `Repair-AdoAgentCluster` for all nodes.
5. Verify all SCM entries are identical, Manual, recovery disabled, and passive services Stopped.
6. Fail over both directions and run a canary.

The RSA agent registration normally remains unchanged because the private key, not the Windows logon identity, authenticates the agent listener.

## Publisher-certificate rotation

1. Build and sign a new release with the new certificate.
2. Ensure every node trusts its chain and revocation behavior.
3. Drain/offline the service.
4. Run repair with the new `PublisherThumbprint`; it replaces package and node configs.
5. Verify no node retains the old thumbprint in `config.json`, then move both directions.
6. Revoke/retire the old certificate only after rollback retention requirements are resolved.

## Toolkit upgrade

Use a signed semantic version, review release notes/security changes, back up current nonsecret config/snapshot, then run repair with the new release. Upgrade every possible owner in one maintenance window so the role cannot move onto a mismatched package. Complete two-node evaluation before returning pool demand.

## Shared ADO agent upgrade

Microsoft agent upgrades change shared binaries and may change credential behavior.

1. Drain and hold the role on one node.
2. Back up the agent root according to Microsoft guidance, excluding active jobs.
3. Upgrade while the service is offline and the disk is owned locally.
4. Run `inspect`. If agent ID/fingerprint and file-backed mode are unchanged, repair and evaluate. If fingerprint changes, follow the reseal/new-`ConfigId` procedure.
5. Recheck proxy/client-certificate stores because new configuration can introduce a blocked protected credential.

The initial setup state records the originally selected package version and hash for evidence only. Do not edit it to represent an upgrade; record the Microsoft-agent upgrade in the change record and retain before/after hashes separately.
