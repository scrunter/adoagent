# Troubleshooting reference

All helper messages are sanitized. Capture `--json`, exit code, ConfigId, owner node, and resource state. Do not attach agent credential files or node/escrow blobs.

For new-agent bootstrap failures, also record the nonsecret `phase`, `lastFailurePhase`, `lastFailureOperation`, package version/hash, registration mode, pool/agent names, and whether `registrationOfflineVerified` is true. The terminating error includes the same sanitized operation as `AdoAgentClusterSetup.<operation>`. Never capture the registration-token environment value or a process environment dump.

If version `0.4.19` fails at `ValidateClusterPrerequisites` with only `ServiceAgentRootAccess`, upgrade to `0.4.20` or later and resume with the same `ConfigId` and immutable inputs. Version `0.4.19` could lose the prepared service-account ACL when its safely extracted staging directory was promoted into `AgentRoot`. The corrected setup reapplies and verifies that ACL after package promotion and before cluster installation. Do not re-register the agent or create a new `ConfigId` for this failure.

## Setup failures

| Failure | Meaning and action |
|---|---|
| exact pool not returned with `actionFilter=manage` | deployment identity is missing effective administration on that pool, token is scoped incorrectly, or URL/tenant is wrong; fix externally and retry |
| unapproved request/redirect host | package endpoint returned an unexpected origin; verify server/CDN configuration rather than bypassing validation |
| package hash mismatch | offline package is not the approved artifact; replace it, do not update the expected hash without provenance review |
| unsafe/malformed ZIP | absolute, traversal, ADS, symlink, duplicate, reparse, or required-file check failed; quarantine the package |
| existing agent name | confirm the old registration is stopped; use `-ReplaceExistingAgent` only under explicit change control |
| partial registration | preserve dot-files and `_diag`; reconcile the local/server registration manually before a new ConfigId |
| service identity prerequisite | ensure the SID resolves on every node and `SeServiceLogonRight` exists; setup now creates AgentRoot and applies the required inheritable Modify ACE |
| `PrepareDirectories` or `icacls` failure | verify the shared disk is Online on the current node, both selected paths have non-reparse ancestry, the operator can create/secure them, and Group Policy or endpoint protection is not blocking ACL changes |
| `ProtectorSid` | use a domain-qualified Active Directory group such as `CONTOSO\AdoAgentKeyRecoveryOperators`; local groups are not valid DPAPI-NG recovery principals |
| `ProtectorSecurityGroup` | the resolved AD object is not a security-enabled group; use a security group rather than a distribution group |
| `ProvisioningIdentity` | add the setup administrator to the protector group, then sign out and sign back in so the new SID is present in the logon token |
| `NCrypt status 0x8009002C` during remote `seal` | Windows reports `NTE_DECRYPTION_FAILURE`; ordinary WinRM cannot make the DPAPI-NG domain-controller second hop. Resume with a fresh in-memory `ProvisioningCredential` for a protector-group operator; do not enable CredSSP or replace the envelope |
| `This command cannot be run ... Access is denied` during passive sealing | releases 0.4.11-0.4.12 used `Start-Process -Credential` from the noninteractive WinRM window station. Upgrade to 0.4.13 or later and resume with the same ConfigId and escrow; the helper now performs an in-process `LogonUser`/impersonated unwrap through anonymous stdin |
| `Could not find item ...\sealed.credentials_rsaparams` after sealing | release 0.4.13 checked the length of the intentionally Hidden sealed-key file without requesting hidden items from Windows PowerShell. Upgrade to 0.4.14 or later and resume with the same ConfigId and escrow; the installer now treats hidden node artifacts correctly |
| `Cannot find drive. A drive with the name '<letter>' does not exist` after passive-node sealing | release 0.4.14 used the PowerShell path provider to construct `activeKeyPath` on the passive node, where the clustered disk is correctly not mounted. Upgrade to 0.4.15 or later and resume with the same ConfigId and escrow; node-local configuration now constructs the shared path without resolving the drive |
| `ADOCK1100 activate exit=18` and the helper reports that the active key path is not exactly in the configured agent root | an older malformed derived `activeKeyPath` survived because the sealed-key preservation branch retained the entire runtime configuration. Upgrade to 0.4.17 or later and run `Repair-AdoAgentCluster`; the runtime configuration is regenerated canonically while the existing node-sealed key and ADO registration are preserved |
| `Unable to save property changes for '<role> - Key Selector'` | release 0.4.15 read the custom Generic Script `ConfigId` property without first declaring it through the WSFC `Resource` object. Upgrade to 0.4.16 or later and resume with the same ConfigId and escrow; `Open` now declares the property during schema discovery, and subsequent failures identify the exact private or common property |
| `Provisioning credential logon failed with Windows error 1326` | the supplied password or account name is invalid; use `DOMAIN\user` or `user@domain` and reacquire the in-memory credential |
| `Provisioning credential logon failed with Windows error 1385` | Group Policy denies the account the requested local logon type on that node; grant the approved protector operator local-logon permission and refresh policy |
| `Type mismatch for parameter "ServiceType"` | resume with a toolkit release that passes the unsigned byte types required by `Win32_Service.Create`; retain the same ConfigId because matching escrow and rollback artifacts are safely reused |
| unable to disable independent service recovery | keep the registered service stopped and resume with a corrected toolkit release; the recovery-action call must pass an explicit quoted empty `actions=` value to `sc.exe` under Windows PowerShell 5.1 |
| `.agent` metadata is not valid JSON during inspection | preserve the Microsoft-generated file and resume with a BOM-aware toolkit release; do not rewrite the registration metadata or re-register the agent merely to change its encoding |
| agent not Offline | `--preventServiceStart` guarantee could not be verified; stop services, check for another listener with the same name, and do not cluster it |
| resume input mismatch | one or more immutable values differ from setup state; use the original values or start a separately approved new setup. After escrow exists, an alternate protector-group spelling is accepted only when it resolves to the protector SID recorded in the manifest |

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

## Package integrity failures

Check all of:

- the downloaded ZIP SHA-256 matches the value retained in the approved deployment/change record;
- `Test-Release.ps1` passes after extraction;
- each installed runtime file matches the corresponding hash in that approved release package;
- `C:\Program Files\AdoAgentClusterKey` has protected inheritance and grants write access only to SYSTEM and built-in Administrators; and
- endpoint tooling did not rewrite or quarantine a runtime file after installation.

The toolkit does not validate Authenticode. A matching internal manifest without an independently trusted ZIP hash proves consistency only, not publisher identity.

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
