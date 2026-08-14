# Two-node evaluation guide

Run in a nonproduction two-node cluster with a disposable but genuine Azure DevOps agent registration. Use the same OS patch, artifact-integrity, ACL, and network controls intended for production.

## Inputs and evidence directory

Required:

- ConfigId, role/key/service resource names;
- exactly two node names;
- administrator-only evidence directory outside the agent workspace.

For a fresh-registration evaluation, also retain the nonsecret setup-state JSON, selected Microsoft agent version/download host/hash, registration mode, and proof that the deployment token was removed or expired before failover testing. Never retain the token itself.

Optional scriptblocks let the organization supply Azure DevOps checks without embedding tokens in module parameters or history:

- `PoolStatusProbe($ownerNode)` returns Boolean after using an approved runtime-only credential source;
- `CanaryPipeline($ownerNode)` queues/waits for a harmless canary and returns Boolean.

The toolkit does not define how these credentials are obtained. Use a secure secret broker/environment and remove them immediately. A read-only pool status token cannot queue a job; use separate least-privilege identities if both checks are enabled.

## Automated run

```powershell
$result = Invoke-AdoAgentClusterEvaluation `
  -ConfigId '<config-guid>' `
  -ClusterRoleName '<role>' `
  -KeyResourceName '<key-resource>' `
  -ServiceResourceName '<service-resource>' `
  -Node '<node-a>','<node-b>' `
  -OutputPath '<evidence-folder>' `
  -PoolStatusProbe $poolProbe `
  -CanaryPipeline $canary `
  -IncludeServiceRecoveryTest `
  -IncludeNegativeTests `
  -IncludeRepairTest -RepairParameters $repair `
  -IncludeRollbackTest -RollbackParameters $rollback
```

First use `-WhatIf`. Negative tests deliberately remove/corrupt a passive node's sealed key, attempt ownership, assert fail-closed service behavior, and restore the original in `finally`. Maintain console access and current backups.

The command writes timestamped JSON and Markdown. It never writes protected blobs, envelope content, private parameters, passwords, PATs, or helper command lines containing credentials.

## Test sequence and expected evidence

| # | Test | Expected evidence |
|---:|---|---|
| 1 | node preflight | config and nonempty sealed file on both nodes; installed runtime hashes match the separately approved release |
| 2 | move A to B | move <=300 s; key/service Online; owner full probe succeeds; passive service Stopped; optional pool/canary pass |
| 3 | move B to A | same evidence in reverse |
| 4 | terminate service process | WSFC observes termination and returns resource Online; recovery time recorded |
| 5 | missing sealed key on passive | selector/role fails; service never Online; backup restored |
| 6 | corrupt sealed key on passive | activation fails closed; service never Online; exact backup restored; recovery succeeds |
| 7 | repair and planned move | run `Repair-AdoAgentCluster`, then repeat move/full probe |
| 8 | default uninstall/rollback | in a disposable evaluation only, snapshot state restored while escrow/sealed material remains |
| 9 | canary per owner | optional pipeline starts/completes and reports expected machine name |
| 10 | one active session | passive SCM service Stopped plus Azure DevOps pool check shows one logical session |

Before test 1 when evaluating the setup entry point:

1. run `Initialize-AdoAgentCluster.ps1 -WhatIf` and confirm no files, services, state, registration, or cluster resources changed;
2. run setup with a short-lived deployment OAuth token and confirm the Microsoft service never started independently;
3. confirm setup reaches `Complete`, the entire role is Offline, and state/console/process arguments contain no credential;
4. remove or allow the deployment token to expire;
5. begin the normal two-node sequence without supplying registration authorization.

Add negative setup cases for insufficient pool permission, wrong pool/name, expired token, unapproved redirect host, wrong offline-package hash, traversal ZIP, partial registration, and existing-name replacement without the explicit switch. None may start the service or create cluster resources after the failing phase.

The function automates all ten when the corresponding switches, scriptblocks, and complete repair/rollback hashtables are supplied. The rollback test is last because it removes toolkit-created resources. It calls the same public commands and therefore needs their full parameters, including `ConfirmAgentIdle = $true`; the outer evaluation and nested commands both run under the explicit evaluation approval. Omit repair/rollback switches for routine health checks.

## Manual timing detail

For deeper evidence, collect these UTC timestamps around each move:

- cluster move start;
- disk Online;
- selector Online start/completion;
- Generic Service Online;
- Azure DevOps pool status Online;
- canary queue/start/completion.

Correlate sanitized FailoverClustering, Application, SCM, and agent diagnostic events. Redact organization URLs/IDs if required, but do not weaken the evidence that exactly one agent session existed.

## Go/no-go gates

GO requires:

- each selected automated/manual test passes;
- idle agent returns Azure DevOps Online within five minutes of both planned moves;
- every job dispatched after failover completes;
- exactly one logical session is active and passive SCM service is Stopped;
- missing/corrupt/wrong-node key never permits service start;
- install and repair repeated with unchanged inputs produce no harmful drift;
- rollback matches the pre-install resource/service/dependency/owner snapshot;
- artifact, event, console, filesystem, and evidence scans find no plaintext or reusable credential;
- setup succeeds from deployment authorization, then failover remains functional after that authorization is removed or expired;
- security owner approves ACLs, artifact distribution/hash evidence, protector group, escrow, and audit coverage.

NO-GO if any gate is unmeasured or fails. An omitted pool/canary scriptblock is recorded as null, not as proof of Azure DevOps availability.

## Idempotency evaluation

1. Save `Get-ClusterResource`, dependency expressions, parameters, owners, services, file hashes, config hashes, and ACLs.
2. Run the packaged `Install-AdoAgentCluster.ps1` with the same ConfigId only in a purpose-built test workflow, or run `Repair-AdoAgentCluster` twice.
3. Recollect state and compare. Expected differences are only timestamps/log events; no duplicate resource/service/dependency or new escrow is allowed.
4. Run each mutating command with `-WhatIf` and confirm state hashes do not change.

## Uninstall evaluation

In a disposable cluster, run default uninstall first and prove escrow plus node ConfigId directories remain. Compare snapshot values. Reinstall and evaluate. Test purge only with disposable escrow/registration and separately record that deletion is not guaranteed physical media erasure.
