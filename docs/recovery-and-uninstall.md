# Recovery and uninstall

## Recovery principles

- Fail closed: do not start the ADO service by removing its selector dependency.
- Preserve the shared `.agent`, `.credentials`, agent binaries, and Azure DevOps registration.
- Preserve escrow and node-sealed material unless a separately approved purge is required.
- Keep the role idle while changing keys or dependencies.
- Copy sanitized evidence before repair; never collect ciphertext/plaintext or command process dumps into ordinary tickets.

## New-agent setup interruption

Read `<EscrowPath>\<ConfigId>.setup.json` and use its `phase` and `lastFailurePhase`; the file is nonsecret but integrity-sensitive.

- `Preflight` or `PackageStaged`: correct the prerequisite and rerun the same immutable inputs with `-Resume`. A registration token is still required.
- `RegisteredStopped` with `registrationOfflineVerified: false`: keep the service stopped, supply a fresh registration credential, and resume the Offline check.
- `RegisteredStopped` with `registrationOfflineVerified: true` or later: resume does not require the expired deployment token.
- `Complete`: `-Resume` is an idempotent validation/no-op and returns the completed identity.
- partial/ambiguous local dot-files: do not delete individual files or let setup infer ownership. Preserve `_diag`, determine whether the server-side object exists, and use an explicitly authorized Microsoft-agent removal/replacement procedure.

Every setup failure defensively stops the locally discovered service and leaves existing cluster key/service resources Offline. Never work around failure by starting the service directly.

## Selector will not come online

1. Leave the Generic Service offline.
2. Record ConfigId, owner node, resource states, dependency expression, sanitized helper exit code, and Application/FailoverClustering events.
3. On the owner, run:

   ```powershell
   & 'C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe' `
     probe --config-id '<config-guid>' --mode full --json
   ```

4. Use the exit-code table in [troubleshooting](troubleshooting.md).
5. If sealed material is missing/corrupt, restore it with `Repair-AdoAgentCluster -Reseal` under a protector-group identity.
6. If the expected fingerprint/agent ID no longer matches, stop. Determine whether the agent was reconfigured. Do not edit expected values merely to make the probe pass.
7. If installed package hashes differ, restore the release whose ZIP hash matches the approved deployment record and run repair; investigate the node and distribution path for tampering.

## Loss of a node-local sealed copy

Use escrow to reseal on that node. DPAPI-NG authorization occurs only during this maintenance action. If escrow unwrap returns code 14, validate group SID, current token, domain/DC access, and envelope integrity. Never move a sealed blob from another node; that correctly produces wrong-machine DPAPI failure.

## Loss of active shared key

If the current owner still has its sealed key, `activate` recreates the active file. Start the key resource, not the service directly. If no current-owner sealed key exists, reseal from escrow first.

## Escrow loss

If at least one enrolled node can still decrypt its sealed or active key, hold the role on that node and schedule a new authorized export to a new protector group/envelope. If no node can decrypt and escrow is lost, the private key is unrecoverable; perform a separately authorized Microsoft-agent re-registration.

## Default uninstall and rollback

`Uninstall-AdoAgentCluster` reads the nonsecret rollback snapshot, removes toolkit-created resources, restores retained resource parameters/owners/dependency expression, and restores original service path/start mode. It does not reapply a regular domain account password; existing SCM secrets remain in SCM throughout normal install/rollback.

```powershell
Uninstall-AdoAgentCluster `
  -ConfigId '<config-guid>' `
  -ClusterRoleName '<role>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>' `
  -ConfirmAgentIdle `
  -WhatIf

Uninstall-AdoAgentCluster `
  -ConfigId '<config-guid>' `
  -ClusterRoleName '<role>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>' `
  -ConfirmAgentIdle
```

After rollback:

1. Compare resources, dependencies, owners, service path/start mode, and file SDDL with the snapshot/change record.
2. Confirm the toolkit key/service resources are gone when they did not pre-exist.
3. Decide whether the original nonclustered agent should run. Do not permit both clustered and standalone services.
4. Retain escrow, manifest, approved release/checksum, node ConfigId directories, and rollback evidence until the rollback window closes.

## Explicit key purge

Purge is intentionally separate and irreversible.

```powershell
Uninstall-AdoAgentCluster `
  -ConfigId '<config-guid>' `
  -ClusterRoleName '<role>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>' `
  -ConfirmAgentIdle `
  -PurgeSealedKeys `
  -PurgeEscrow `
  -EnvelopePath '<secure-envelope-path>' `
  -ManifestPath '<secure-manifest-path>'
```

Before approval, verify no recovery/add-node need remains, required retention expired, a replacement registration/key exists if service continues, and backups follow the same deletion policy. File deletion is not a guarantee of forensic erasure on SSD, backup, or replicated storage; use the platform's cryptographic-erasure and media-handling controls.

Package removal from Program Files is deliberately not automatic because another ConfigId may use the same binaries. Remove it only after inventory proves no cluster resource/config references it.

## Remove a registration created by the setup script

Cluster uninstall and Azure DevOps unregistration are intentionally separate:

1. drain work and run default `Uninstall-AdoAgentCluster` without purge;
2. obtain a fresh approved registration credential from the deployment system;
3. from the shared AgentRoot, run Microsoft's `config.cmd remove --unattended` using secret environment input, never a literal token argument;
4. confirm the server-side agent object and every node service entry are gone;
5. retain setup state, escrow, sealed keys, rollback snapshot, and approved release/checksum through the rollback window;
6. delete AgentRoot or protected key material only through separately approved purge actions.

If the deployment identity is unavailable, an Azure DevOps administrator can remove the server-side object in the portal, but local files still require controlled cleanup. An agent ID by itself is not an authentication credential.
