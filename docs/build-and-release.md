# Build, test, and release

## Toolchain

- Windows x64 build host
- .NET SDK selected by `global.json` (10.0.201 in this repository)
- Visual C++/Native AOT prerequisites installed with the .NET SDK/build image
- Windows PowerShell 5.1 for module and VBS tests

The projects enable nullable analysis, warnings as errors, current .NET analyzers, deterministic compilation metadata, Native AOT compatibility analysis, and self-contained `win-x64` publishing.

The toolkit does not require or validate Authenticode signatures. Protect the build pipeline, source revision, artifact repository, deployment approvals, and recorded release hash as the software-supply boundary.

## Local validation

```powershell
dotnet build .\AdoAgentClusterKey.slnx -c Release
dotnet run --project .\tests\AdoAgent.ClusterKey.Tests\AdoAgent.ClusterKey.Tests.csproj -c Release --no-build
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\PowerShell\Invoke-StaticTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\PowerShell\Invoke-PesterTests.ps1
```

The native suite covers RSA JSON/casing/private fields, SPKI fingerprinting, named-container detection, actual classic DPAPI, actual DPAPI-NG with `LOCAL=user`, credential-store detection, export/seal/activate/probe workflow, identity mismatch, and ciphertext mismatch. The workflow uses an injected data protector for domain-independent repeatability; native DPAPI APIs are tested separately.

The static suite parses/imports the Windows PowerShell module and setup entry point, verifies public/`-WhatIf` contracts, checks additive dependency implementation, and executes VBS `Open` with a fake `Resource` object. Setup Pester tests cover the auth-mode contract, secure environment consumption, credential-free command arguments, phase schema, package-file policy, and safe ZIP extraction/traversal rejection. Full cluster-state behavior and all VBS callbacks must also run on the WSFC test environment because FailoverClusters/Resource Monitor are not faithfully emulatable on a workstation.

After installation, run `tests\Cluster\Cluster.Integration.Tests.ps1` through Pester with its named parameters, including `PackagePath` for the approved extracted release. It asserts resource types/order/timing/owners, installed runtime hashes, protected local config ACLs, passive service state, and owner-side full cryptographic probe.

## Build a release

```powershell
.\build\Build.ps1 -Version '<version>'
```

The build performs:

1. build and automated tests;
2. self-contained Native AOT publish;
3. copy of helper, scripts, module, full existing-agent installer, new-agent setup entry point, documentation, and metadata;
4. SPDX SBOM generation with file SHA-256 values;
5. recursive `RELEASE-MANIFEST.json` generation with SHA-256 and length for every package file except the manifest itself;
6. ZIP creation; and
7. ZIP SHA-256 generation in a sibling `<release>.zip.sha256` file.

The command returns the package directory, ZIP path, ZIP SHA-256, checksum-file path, and version. Retain that output with the source revision and build record.

There is one release type. `CertificateThumbprint`, `TimestampServer`, `LabUnsigned`, and related bypass parameters do not exist.

## Integrity and provenance model

The controls serve different purposes:

| Control | Detects | Does not prove |
|---|---|---|
| independently recorded ZIP SHA-256 | downloaded archive differs from the approved build | publisher identity unless the record/channel is trusted |
| `RELEASE-MANIFEST.json` | a file is missing, altered, duplicated, escaping, or unlisted after extraction | that the manifest itself came from the intended publisher |
| installer copy-time hashes | node runtime bytes differ from the selected source package | that the selected source package is trustworthy |
| protected Program Files ACL | non-administrative post-install modification | protection from SYSTEM or an administrator |

Publish the ZIP hash through an approved artifact system or change record that is separate from the downloaded archive. Do not treat a `.sha256` file downloaded from the same untrusted location as independent publisher authentication.

Organizations may independently sign the files or use WDAC/AppLocker hash/path policy, but the toolkit does not inspect or require those controls.

## Verification on a clean host

1. Obtain the expected ZIP SHA-256 from the approved deployment/change record.
2. Calculate the downloaded ZIP SHA-256 and require an exact match before extraction.
3. Extract to a new administrator-controlled directory.
4. Run the repository verifier:

   ```powershell
   <extracted-release-folder>\Test-Release.ps1 `
     -PackagePath '<extracted-release-folder>'
   ```

5. Validate `sbom.spdx.json` and `version.json` against the release/change record.
6. Run helper `help --json` and the required local/static tests under the organization's release policy.
7. Scan the package for secrets/private-key values and malware.

`Test-Release.ps1` validates canonical paths, duplicate entries, file inventory, lengths, and SHA-256 values. It validates internal consistency only. The independently retained ZIP SHA-256 supplies the binding to the approved build/distribution record.

## CI

`azure-pipelines.yml` builds, tests, and publishes the normal release artifact plus its hash evidence. Protect the pipeline definition, branch, build service, artifact retention, and approval path. Require manual/security approval and two-node evaluation before production promotion.

## GitHub Releases

`.github/workflows/release.yml` builds and publishes repository releases on a GitHub-hosted `windows-2025` runner. It uses the SDK pinned by `global.json`, runs the full `build\Build.ps1` test/package path, validates the extracted package manifest and companion ZIP checksum, and retains the four release files as a workflow artifact for 30 days.

The normal release path is a version tag:

```powershell
git tag v<major>.<minor>.<patch>
git push origin v<major>.<minor>.<patch>
```

Tags must begin with `v`; the remainder must be a semantic version such as `0.4.0` or `0.4.0-rc.1`. A hyphenated version is always published as a prerelease. The workflow publishes these GitHub Release assets:

- `AdoAgentClusterKey-<version>-win-x64.zip`;
- the companion `.zip.sha256`;
- `RELEASE-MANIFEST.json`; and
- `sbom.spdx.json`.

The Actions page also exposes a manual **Build and publish release** run. Supply the version without a leading `v`, select the source revision, and leave **prerelease** enabled unless this is an approved production release. After all validation passes, the workflow creates or reuses a lightweight tag pointing directly at that revision and publishes the release. It refuses a tag that points elsewhere and never overwrites an existing release or asset.

The workflow requests only `contents: write`, uses the repository-scoped `GITHUB_TOKEN`, and does not persist checkout credentials. Repository or organization policy must permit Actions to request write access. Protect release tags and restrict manual workflow execution through the repository's normal branch, ruleset, and Actions controls. No PAT or repository secret is required.

The checksum attached to a GitHub Release detects download corruption, but it is hosted alongside the ZIP. For production approval, continue to copy the reported ZIP SHA-256 into the independent deployment/change record described above.

## Release gates

- clean build with zero warnings;
- all native, PowerShell, VBS, and security-output tests pass;
- Native AOT executable starts on Server 2019/2022/2025 test nodes;
- expected ZIP SHA-256 is retained through an approved independent channel;
- extracted package manifest/SBOM verification passes;
- installed runtime hashes match the approved package on every possible owner;
- two-node evaluation passes the [go/no-go gates](evaluation.md#go-no-go-gates);
- operator/security documentation is reviewed;
- release ZIP, ZIP hash, internal manifest, source revision, build identity, and evaluation report are retained; and
- no plaintext or reusable credential is present in build/release artifacts.
