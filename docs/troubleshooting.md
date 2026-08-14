# Troubleshooting reference

All helper messages are sanitized. Capture `--json`, exit code, ConfigId, owner node, and resource state. Do not attach agent credential files or node/escrow blobs.

For new-agent bootstrap failures, also record the nonsecret setup phase, package version/hash, registration mode, pool/agent names, and whether `registrationOfflineVerified` is true. Never capture the registration-token environment value or a process environment dump.

## Setup failures

| Failure | Meaning and action |
|---|---|
| exact pool not returned with `actionFilter=manage` | deployment identity is missing effective administration on that pool, token is scoped incorrectly, or URL/tenant is wrong; fix externally and retry |
| unapproved request/redirect host | package endpoint returned an unexpected origin; verify server/CDN configuration rather than bypassing validation |
| package hash mismatch | offline package is not the approved artifact; replace it, do not update the expected hash without provenance review |
| unsafe/malformed ZIP | absolute, traversal, ADS, symlink, duplicate, reparse, or required-file check failed; quarantine the package |
| existing agent name | confirm the old registration is stopped; use `-ReplaceExistingAgent` only under explicit change control |
| partial registration | preserve dot-files and `_diag`; reconcile the local/server registration manually before a new ConfigId |
| service identity prerequisite | ensure SID resolves on every node, `SeServiceLogonRight` exists, and AgentRoot has an explicit inheritable Modify ACE |
| agent not Offline | `--preventServiceStart` guarantee could not be verified; stop services, check for another listener with the same name, and do not cluster it |
| resume input mismatch | one or more immutable values differ from setup state; use the original values or start a separately approved new setup |

`RegisteredStopped` is a safe recovery point. When its Offline verification is true, downstream key/cluster setup can resume after the deployment token has expired.

## Exit codes

| Code | Symbol | Meaning | Operator action |
|---:|---|---|---|
| 0 | `Success` | operation/probe succeeded | continue |
| 2 | `InvalidArguments` | unknown/missing option, malformed GUID/mode/SID | correct invocation; ConfigId must use canonical hyphenated GUID form |
| 3 | `InvalidConfiguration` | JSON/schema/RSA payload or canonical path contract invalid | compare config with schema; do not insert key material manually |
| 10 | `MissingFile` | agent metadata, active/sealed key, envelope, manifest, config, or directory missing | restore correct artifact or reseal; keep service offline |
| 11 | `WrongMachineDpapi` | classic DPAPI cannot decrypt on this machine or blob is corrupt | confirm owner/blob; reseal locally from escrow; never copy another node's blob |
| 12 | `FingerprintMismatch` | key/envelope hash, RSA fingerprint, ciphertext equality, or agent identity mismatch | investigate reconfiguration/substitution; do not edit expected values casually |
| 13 | `NamedContainerKey` | CSP/CNG named container detected | use documented one-time file-mode re-registration branch |
| 14 | `DpapiNgAuthorizationFailure` | descriptor create/protect/unprotect failed, commonly authorization/domain/envelope issue | verify SID, current token membership, AD/DC access, and envelope hash |
| 15 | `ActivationFailure` | atomic write/replace/ACL/attribute operation failed | verify disk online, ACL, free space, locks, path controls, and SYSTEM access |
| 16 | `AdditionalCredentialStore` | authenticated proxy, protected client-cert password, or credential store detected | remove/migrate unsupported protected credential before v1 installation/runtime |
| 17 | `SignatureFailure` | Windows trust or pinned signer check failed | reinstall verified release, repair thumbprint/trust/revocation; never bypass in production |
| 18 | `PathSecurityFailure` | target not exact, reparse point, resolved handle mismatch, or sealed key outside ConfigId directory | remove redirection/tamper and restore locked directory topology |
| 20 | `UnexpectedError` | unclassified internal failure; details deliberately suppressed | correlate OS/cluster events and reproduce in controlled diagnostics; do not enable secret logging |

## Resource log message codes

| Code | Meaning |
|---|---|
| `ADOCK1000` | `Open` accepted the ConfigId |
| `ADOCK1100` | `activate` completed; message includes sanitized helper exit code |
| `ADOCK1200` | quick probe completed; message includes sanitized helper exit code |
| `ADOCK1300` | full probe completed; message includes sanitized helper exit code |
| `ADOCK1400` | `Offline` retained the active node-protected file |
| `ADOCK1500` | `Terminate` retained the active node-protected file |
| `ADOCK1901` | ConfigId cluster property is missing/unreadable |
| `ADOCK1902` | ConfigId is not a canonical GUID |

These identifiers are message prefixes written through `Resource.LogInformation`; WSFC supplies the surrounding event provider/ID. The helper exit code after `exit=` is the actionable failure classification above.

## Wrong-node DPAPI

Symptoms: key resource fails Online on only one node; code 11 on full probe. Confirm `sealedKeyPath` is local ProgramData, not shared storage, and its creation happened on that same node. Reseal from DPAPI-NG escrow on the affected node. A ciphertext hash can differ on every node while the RSA fingerprint remains identical—that is expected.

## Fingerprint or identity mismatch

Compare sanitized `inspect` output with manifest/config. Common causes are agent reconfiguration, accidental use of another agent root, wrong escrow/ConfigId pairing, or malicious replacement. Stop and establish which key Azure DevOps currently associates with the logical agent. If a legitimate new key was generated, create a new escrow and ConfigId; do not mutate the old manifest.

## Named container

`ContainerName` nonempty means the JSON references a Windows key container rather than containing private RSA parameters. `UseCng` identifies the provider family but does not make the key portable. The toolkit never tries to export container material. Follow the named-container migration branch.

## Signature failures

Check all of:

- file came from the signed ZIP and its SHA-256 matches the signed release manifest;
- Authenticode status is Valid on every node;
- current config thumbprint matches the actual release signer after normalization;
- issuing chain/revocation/timestamp policy succeeds under LocalSystem, not just the operator;
- no `UNSIGNED-LAB-ONLY.txt` exists in production;
- endpoint tooling did not rewrite/quarantine the file after signing.

## Cluster dependency failures

Use `Get-ClusterResourceDependency`, not the MHT-producing `Get-ClusterResourceDependencyReport`, to inspect expressions. Expected additive dependencies are `[shared disk]` for the selector and `[key selector]` for the service. Existing dependencies may also remain. Ensure all three resources are in the same role and share aligned possible owners.

If disk Online succeeds but selector fails, use the helper exit code. If the service starts before selector, immediately offline it and repair the dependency. The VBS must reside at the fixed Program Files path on every owner and the Generic Script `ConfigId` private property must match node config.

## Missing/mismatched Windows services

Every possible owner needs the same service name, display name, quoted binary path, identity, and Manual start mode. Independent SCM recovery actions must be empty. Passive services must be Stopped. For gMSA, verify installation and `Log on as a service` on each node. For a regular account, reacquire `PSCredential`; no password is stored in rollback/config.

## Authenticated proxy or client certificate

Code 16 may appear after a later agent configuration change even if installation originally passed. Inspect `.proxycredentials`, `.credential_store`, and `.certificates` only through approved secure administration; do not disclose contents. v1 has no portable representation for those machine-bound protected values, so remove that dependency or do not cluster this agent.

## Resource timing

- `PendingTimeout`: 60,000 ms
- `LooksAlivePollInterval`: 15,000 ms
- `IsAlivePollInterval`: 60,000 ms

`LooksAlive` compares paths, identity, and ciphertext; it does not decrypt. `IsAlive` decrypts and fingerprints. Neither checks Azure DevOps connectivity. ADO/network outages should be handled by service/pipeline monitoring without moving the key resource repeatedly.
