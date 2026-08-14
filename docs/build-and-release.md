# Build, test, and release

## Toolchain

- Windows x64 build host
- .NET SDK selected by `global.json` (10.0.201 in this repository)
- Visual C++/Native AOT prerequisites installed with the .NET SDK/build image
- Windows PowerShell 5.1 for module/VBS tests and Authenticode tooling
- production code-signing certificate with private key, supplied outside the repository

The projects enable nullable analysis, warnings as errors, current .NET analyzers, deterministic compilation metadata, Native AOT compatibility analysis, and self-contained `win-x64` publishing.

## Local validation

```powershell
dotnet build .\AdoAgentClusterKey.slnx -c Release
dotnet run --project .\tests\AdoAgent.ClusterKey.Tests\AdoAgent.ClusterKey.Tests.csproj -c Release --no-build
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\PowerShell\Invoke-StaticTests.ps1
Invoke-Pester .\tests\PowerShell\Module.Tests.ps1
Invoke-Pester .\tests\PowerShell\AgentSetup.Tests.ps1
```

The native suite covers RSA JSON/casing/private fields, SPKI fingerprinting, named-container detection, actual classic DPAPI, actual DPAPI-NG with `LOCAL=user`, credential-store detection, export/seal/activate/probe workflow, identity mismatch, and ciphertext mismatch. The workflow uses an injected data protector for domain-independent repeatability; native DPAPI APIs are tested separately.

The static suite parses/imports the Windows PowerShell module and setup entry point, verifies public/`-WhatIf` contracts, checks additive dependency implementation, and executes VBS `Open` with a fake `Resource` object. Setup Pester tests cover the auth-mode contract, secure environment consumption, credential-free command arguments, phase schema, and safe ZIP extraction/traversal rejection. Full cluster-state behavior and all VBS callbacks must also run on the WSFC test environment because FailoverClusters/Resource Monitor are not faithfully emulatable on a workstation.

After installation, run `tests\Cluster\Cluster.Integration.Tests.ps1` through Pester with its named parameters. It asserts resource types/order/timing/owners, pinned signatures, protected local config ACLs, passive service state, and owner-side full cryptographic probe.

## Lab package

```powershell
.\build\Build.ps1 -Version '<version>' -LabUnsigned
```

The ZIP and package contain conspicuous unsigned-lab markers. The production installer still requires the explicit `-LabAllowUnsigned` switch. Never promote this artifact.

## Production package

```powershell
.\build\Build.ps1 `
  -Version '<version>' `
  -CertificateThumbprint '<code-signing-thumbprint>' `
  -TimestampServer '<approved-rfc3161-or-authenticode-url>'
```

Build order is security-sensitive:

1. build/tests;
2. self-contained Native AOT publish;
3. copy static artifacts/docs/version;
4. Authenticode-sign executable and scripts;
5. generate SPDX SBOM over signed files;
6. generate SHA-256 manifest over final signed files/SBOM;
7. create detached CMS signature over the manifest;
8. compress without changing package files.

The signing script looks in CurrentUser/LocalMachine personal stores and never accepts a PFX/password argument. For a remote signing service, replace `Sign-Release.ps1` with the approved service integration while retaining ordering and verification.

## Verification on a clean host

1. Extract to a new directory.
2. Verify detached CMS signature against organizational trust policy.
3. Recalculate every `RELEASE-MANIFEST.json` SHA-256 and length.
4. Run `Get-AuthenticodeSignature` for EXE/VBS/PS1/PSM1/PSD1; require Valid and the release thumbprint.
5. Validate `sbom.spdx.json` and `version.json`.
6. Run helper `help --json` and static tests.
7. Scan for secrets/private-key field values and malware under release policy.

The repository verifier automates path, length, hash, Authenticode thumbprint, and detached CMS checks:

```powershell
<extracted-release-folder>\Test-Release.ps1 `
  -PackagePath '<extracted-release-folder>' `
  -PublisherThumbprint '<publisher-thumbprint>'
```

For the deliberately unsigned validation package, add `-AllowLabUnsigned`; that verifies file hashes but is not publisher authentication.

Example detached-signature verification can be implemented with `SignedCms` on the controlled verification host; validate both `CheckSignature($true)` and the signer certificate chain/revocation policy. Do not treat hash equality alone as publisher authenticity.

## CI

`azure-pipelines.yml` builds/tests and publishes an explicitly unsigned validation artifact. Production signing is not performed in general CI. Connect a protected release stage to an approved signing service, require manual/security approval, and publish only after clean-host verification and two-node release evaluation.

## Release gates

- clean build with zero warnings;
- all native, PowerShell, VBS, and security-output tests pass;
- Native AOT executable starts on Server 2019/2022/2025 test nodes;
- package/manifest/SBOM/signature verification passes;
- two-node evaluation passes the [go/no-go gates](evaluation.md#go-no-go-gates);
- operator/security documentation reviewed;
- no lab marker or `allowUnsigned: true` in production artifacts/config;
- release ZIP, manifest signature, source revision, certificate identity, and evaluation report retained.
