BeforeAll {
    $here = Split-Path -Parent $PSCommandPath
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
    $manifestPath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1'
    $setupModulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.Setup.ps1'
    $setupScriptPath = Join-Path $repositoryRoot 'setup\Initialize-AdoAgentCluster.ps1'
    Import-Module $manifestPath -Force
}

Describe 'Deployment-authenticated agent setup contract' {
    It 'exposes the supported authentication modes without managed identity or device code' {
        $command = Get-Command Initialize-AdoAgentCluster
        $validValues = @($command.Parameters['RegistrationAuth'].Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] } | Select-Object -ExpandProperty ValidValues)
        foreach ($value in @('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')) { ($validValues -contains $value) | Should -Be $true }
        ($validValues -contains 'ManagedIdentity') | Should -Be $false
        ($validValues -contains 'DeviceCode') | Should -Be $false
    }

    It 'makes the entry script support WhatIf and secure token sources' {
        $command = Get-Command $setupScriptPath
        ($command.Parameters.Keys -contains 'WhatIf') | Should -Be $true
        ($command.Parameters.Keys -contains 'RegistrationToken') | Should -Be $true
        ($command.Parameters.Keys -contains 'RegistrationTokenEnvironmentVariableName') | Should -Be $true
        ($command.Parameters.Keys -contains 'ProvisioningCredential') | Should -Be $true
        $command.Parameters['RegistrationToken'].ParameterType.FullName | Should -Be 'System.Security.SecureString'
        $command.Parameters['ProvisioningCredential'].ParameterType.FullName | Should -Be 'System.Management.Automation.PSCredential'
        ($command.Parameters.Keys -contains 'PublisherThumbprint') | Should -Be $false
        ($command.Parameters.Keys -contains 'LabAllowUnsigned') | Should -Be $false
    }

    It 'uses a nonsecret six-phase resume state machine' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        foreach ($phase in @('Preflight', 'PackageStaged', 'RegisteredStopped', 'KeyValidated', 'ClusterInstalled', 'Complete')) { $source | Should -Match ("'" + $phase + "'") }
        $source | Should -Match '\.setup\.json'
        $source | Should -Not -Match 'registrationToken\s*='
        $source | Should -Not -Match 'servicePassword\s*='
        $source | Should -Not -Match 'provisioningCredential\s*='
    }

    It 'allows a verified toolkit path and only a pre-escrow protector correction during resume' {
        InModuleScope AdoAgentClusterKey {
            $saved = [ordered]@{
                schemaVersion = 1
                configId = '11111111-2222-3333-4444-555555555555'
                agentRoot = 'K:\adoagent'
                node = @('node-a', 'node-b')
                protectorGroup = 'test'
                toolkitPackagePath = 'C:\Toolkit\0.4.6'
                serviceAccount = 'NT AUTHORITY\NETWORK SERVICE'
            }
            $requested = [ordered]@{
                schemaVersion = 1
                configId = '11111111-2222-3333-4444-555555555555'
                agentRoot = 'K:\adoagent'
                node = @('node-a', 'node-b')
                protectorGroup = 'test'
                toolkitPackagePath = 'C:\Toolkit\0.4.7'
                serviceAccount = 'NT AUTHORITY\NETWORK SERVICE'
            }
            (Test-AdoSetupToolkitPathOnlyChange -SavedImmutable $saved -RequestedImmutable $requested) | Should -Be $true
            (Test-AdoSetupPermittedResumeChange -SavedImmutable $saved -RequestedImmutable $requested) | Should -Be $true
            $requested.protectorGroup = 'CONTOSO\AdoAgentKeyRecoveryOperators'
            (Test-AdoSetupPermittedResumeChange -SavedImmutable $saved -RequestedImmutable $requested) | Should -Be $false
            (Test-AdoSetupPermittedResumeChange -SavedImmutable $saved -RequestedImmutable $requested -AllowProtectorGroupChange) | Should -Be $true
            $requested.agentRoot = 'K:\different-agent'
            (Test-AdoSetupPermittedResumeChange -SavedImmutable $saved -RequestedImmutable $requested -AllowProtectorGroupChange) | Should -Be $false
        }

        $source = Get-Content -LiteralPath $setupModulePath -Raw
        $source.IndexOf('if ($rebindToolkitPackage -or $rebindProtectorGroup)') | Should -BeGreaterThan $source.IndexOf('if (-not $PSCmdlet.ShouldProcess')
        $source | Should -Match 'Test-AdoSetupKeyArtifactsExist'
        $source | Should -Match 'RebindProtectorGroup'
    }

    It 'reports protector resolution, group type, and logon membership separately' {
        $moduleSource = Get-Content -LiteralPath (Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1') -Raw
        $moduleSource | Should -Match "Add-Check 'ProtectorSid'"
        $moduleSource | Should -Match "Add-Check 'ProtectorSecurityGroup'"
        $moduleSource | Should -Match "Add-Check 'ProvisioningIdentity'"
        $moduleSource | Should -Match 'sign out and sign back in'
    }

    It 'blocks protector rebinding when any key artifact already exists' {
        $global:AdoSetupArtifactPath = $TestDrive
        InModuleScope AdoAgentClusterKey {
            $configId = [Guid]'11111111-2222-3333-4444-555555555555'
            (Test-AdoSetupKeyArtifactsExist -EscrowPath $global:AdoSetupArtifactPath -ConfigId $configId) | Should -Be $false
            Set-Content -LiteralPath (Join-Path $global:AdoSetupArtifactPath ($configId.ToString('D') + '.rollback.json')) -Value '{}'
            (Test-AdoSetupKeyArtifactsExist -EscrowPath $global:AdoSetupArtifactPath -ConfigId $configId) | Should -Be $true
        }
    }

    It 'uses child environment variables and never puts credentials in config.cmd arguments' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        $source | Should -Match 'VSTS_AGENT_INPUT_TOKEN'
        $source | Should -Match 'VSTS_AGENT_INPUT_WINDOWSLOGONPASSWORD'
        $source | Should -Match '--preventServiceStart'
        $source | Should -Not -Match "--token\s+\$"
        $source | Should -Not -Match "--windowsLogonPassword\s+\$"
    }

    It 'removes a token environment variable when it is consumed' {
        $global:AdoSetupTokenVariable = 'ADO_SETUP_PESTER_TOKEN'
        [Environment]::SetEnvironmentVariable($global:AdoSetupTokenVariable, 'sentinel-secret-value', 'Process')
        InModuleScope AdoAgentClusterKey {
            $value = Get-AdoRegistrationSecret -RegistrationTokenEnvironmentVariableName $global:AdoSetupTokenVariable
            $value | Should -Be 'sentinel-secret-value'
            [Environment]::GetEnvironmentVariable($global:AdoSetupTokenVariable, 'Process') | Should -BeNullOrEmpty
            $value = $null
        }
    }

    It 'preserves a token environment variable for WhatIf inspection' {
        $global:AdoSetupTokenVariable = 'ADO_SETUP_PESTER_WHATIF_TOKEN'
        [Environment]::SetEnvironmentVariable($global:AdoSetupTokenVariable, 'whatif-sentinel', 'Process')
        InModuleScope AdoAgentClusterKey {
            $value = Get-AdoRegistrationSecret -RegistrationTokenEnvironmentVariableName $global:AdoSetupTokenVariable -PreserveEnvironmentVariable
            $value | Should -Be 'whatif-sentinel'
            [Environment]::GetEnvironmentVariable($global:AdoSetupTokenVariable, 'Process') | Should -Be 'whatif-sentinel'
            $value = $null
        }
        [Environment]::SetEnvironmentVariable($global:AdoSetupTokenVariable, $null, 'Process')
    }

    It 'rejects invalid authentication combinations' {
        $secure = ConvertTo-SecureString 'sentinel' -AsPlainText -Force
        $global:AdoSetupSecure = $secure
        InModuleScope AdoAgentClusterKey {
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth Integrated -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should -Throw
            { Assert-AdoSetupParameters -ServerType Server -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should -Throw
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -RegistrationTokenEnvironmentVariableName 'TOKEN' -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should -Throw
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '..\work' } | Should -Throw
        }
    }

    It 'accepts the production OAuth-token combination' {
        $secure = ConvertTo-SecureString 'sentinel' -AsPlainText -Force
        $global:AdoSetupSecure = $secure
        InModuleScope AdoAgentClusterKey {
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should -Not -Throw
        }
    }

    It 'uses Bearer for OAuth and Basic for PAT API requests' {
        InModuleScope AdoAgentClusterKey {
            $oauth = Get-AdoAuthorizationHeaderValue -RegistrationAuth OAuthToken -RegistrationSecret 'oauth-sentinel'
            $oauth.Scheme | Should -Be 'Bearer'
            $oauth.Parameter | Should -Be 'oauth-sentinel'
            $pat = Get-AdoAuthorizationHeaderValue -RegistrationAuth PersonalAccessToken -RegistrationSecret 'pat-sentinel'
            $pat.Scheme | Should -Be 'Basic'
            [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($pat.Parameter)) | Should -Be ':pat-sentinel'
        }
    }

    It 'selects a singleton package from wrapped and bare API responses' {
        $global:AdoSetupPackageResponses = @(
            '{"count":1,"value":[{"version":"4.999.1","downloadUrl":"https://vstsagentpackage.azureedge.net/agent/test.zip"}]}',
            '{"version":"4.999.1","downloadUrl":"https://vstsagentpackage.azureedge.net/agent/test.zip"}'
        )
        try {
            InModuleScope AdoAgentClusterKey {
                foreach ($content in $global:AdoSetupPackageResponses) {
                    $global:AdoSetupCurrentResponse = $content
                    Mock Invoke-AdoHttpGet { [pscustomobject]@{ Content = $global:AdoSetupCurrentResponse } }
                    $metadata = Get-AdoAgentPackageMetadata `
                        -BaseUri ([Uri]'https://dev.azure.com/example/') `
                        -ServerType Services `
                        -RegistrationAuth PersonalAccessToken `
                        -RegistrationSecret 'sentinel'
                    $metadata.Version | Should -Be '4.999.1'
                    $metadata.DownloadUri.AbsoluteUri | Should -Be 'https://vstsagentpackage.azureedge.net/agent/test.zip'
                }
            }
        }
        finally {
            Remove-Variable -Name AdoSetupPackageResponses -Scope Global -ErrorAction SilentlyContinue
            Remove-Variable -Name AdoSetupCurrentResponse -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'rejects empty and ambiguous package API responses without strict-mode errors' {
        $global:AdoSetupPackageResponses = @(
            '{"count":0,"value":[]}',
            '{"count":2,"value":[{"version":"4.999.1","downloadUrl":"https://vstsagentpackage.azureedge.net/agent/one.zip"},{"version":"4.999.2","downloadUrl":"https://vstsagentpackage.azureedge.net/agent/two.zip"}]}'
        )
        try {
            InModuleScope AdoAgentClusterKey {
                foreach ($content in $global:AdoSetupPackageResponses) {
                    $global:AdoSetupCurrentResponse = $content
                    Mock Invoke-AdoHttpGet { [pscustomobject]@{ Content = $global:AdoSetupCurrentResponse } }
                    {
                        Get-AdoAgentPackageMetadata `
                            -BaseUri ([Uri]'https://dev.azure.com/example/') `
                            -ServerType Services `
                            -RegistrationAuth PersonalAccessToken `
                            -RegistrationSecret 'sentinel'
                    } | Should -Throw '*exactly one compatible*'
                }
            }
        }
        finally {
            Remove-Variable -Name AdoSetupPackageResponses -Scope Global -ErrorAction SilentlyContinue
            Remove-Variable -Name AdoSetupCurrentResponse -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'keeps singleton pool and agent query results as arrays' {
        $global:AdoSetupApiResponse = '{"count":1,"value":[{"id":42,"name":"test"}]}'
        try {
            InModuleScope AdoAgentClusterKey {
                Mock Invoke-AdoHttpGet { [pscustomobject]@{ Content = $global:AdoSetupApiResponse } }
                $pool = Get-AdoManagedAgentPool `
                    -BaseUri ([Uri]'https://dev.azure.com/example/') `
                    -PoolName 'test' `
                    -ServerType Services `
                    -RegistrationAuth PersonalAccessToken `
                    -RegistrationSecret 'sentinel'
                $pool.id | Should -Be 42

                $agent = Get-AdoExistingAgent `
                    -BaseUri ([Uri]'https://dev.azure.com/example/') `
                    -PoolId 42 `
                    -AgentName 'test' `
                    -ServerType Services `
                    -RegistrationAuth PersonalAccessToken `
                    -RegistrationSecret 'sentinel'
                $agent.id | Should -Be 42
            }
        }
        finally {
            Remove-Variable -Name AdoSetupApiResponse -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'restricts service URLs and external package hosts' {
        InModuleScope AdoAgentClusterKey {
            $base = Get-AdoNormalizedServerUri -AzureDevOpsUrl 'https://dev.azure.com/example' -ServerType Services
            { Assert-AdoHttpUri -Uri ([Uri]'https://dev.azure.com/example/_apis/test') -BaseUri $base -ServerType Services } | Should -Not -Throw
            { Assert-AdoHttpUri -Uri ([Uri]'https://vstsagentpackage.azureedge.net/agent/test.zip') -BaseUri $base -ServerType Services -PackageDownload } | Should -Not -Throw
            { Assert-AdoHttpUri -Uri ([Uri]'https://example.invalid/agent.zip') -BaseUri $base -ServerType Services -PackageDownload } | Should -Throw
            { Get-AdoNormalizedServerUri -AzureDevOpsUrl 'http://dev.azure.com/example' -ServerType Services } | Should -Throw
        }
    }

    It 'stores a download URL without a reusable query string' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        $source | Should -Match 'GetLeftPart\(\[UriPartial\]::Path\)'
    }

    It 'normalizes the LocalSystem service alias for Windows APIs' {
        InModuleScope AdoAgentClusterKey {
            (Get-AdoServiceIdentityForWindows -Identity 'LocalSystem') | Should -Be 'NT AUTHORITY\SYSTEM'
        }
    }

    It 'returns built-in service identity checks under Windows PowerShell 5.1' {
        $global:AdoSetupAgentRoot = Join-Path $TestDrive 'service-identity-agent-root'
        New-Item -ItemType Directory -Path $global:AdoSetupAgentRoot | Out-Null
        try {
            InModuleScope AdoAgentClusterKey {
                Mock Invoke-Command { [pscustomobject]@{ Sid = 'S-1-5-20'; HasLogonRight = $true } }
                Mock Test-AdoPathAclForIdentity { $true }

                $checks = @(Get-AdoServiceIdentityChecks `
                    -ServiceIdentity 'NT AUTHORITY\NETWORK SERVICE' `
                    -Node @('node-a', 'node-b') `
                    -AgentRoot $global:AdoSetupAgentRoot)

                $checks.Count | Should -Be 5
                @($checks | Where-Object { -not $_.Passed }).Count | Should -Be 0
                @($checks.Name) | Should -Contain 'ServiceIdentity:node-a'
                @($checks.Name) | Should -Contain 'ServiceIdentity:node-b'
                @($checks.Name) | Should -Contain 'ServiceAgentRootAccess'
            }
        }
        finally {
            Remove-Variable -Name AdoSetupAgentRoot -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'does not wrap generic lists in the incompatible array subexpression' {
        $setupSource = Get-Content -LiteralPath $setupModulePath -Raw
        $moduleSource = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $setupModulePath) 'AdoAgentClusterKey.psm1') -Raw
        $setupSource | Should -Not -Match 'return @\(\$checks\)'
        $moduleSource | Should -Not -Match 'Checks = @\(\$checks\)'
        $moduleSource | Should -Not -Match 'Evidence = @\(\$records\)'
        $setupSource | Should -Match '\$checks\.ToArray\(\)'
        $moduleSource | Should -Match '\$records\.ToArray\(\)'
    }

    It 'atomically creates and replaces setup state under Windows PowerShell 5.1' {
        $global:AdoSetupStatePath = Join-Path $TestDrive 'setup-state.json'
        try {
            InModuleScope AdoAgentClusterKey {
                Write-AdoSetupState -Path $global:AdoSetupStatePath -State ([pscustomobject]@{ phase = 'Preflight'; sequence = 1 })
                Write-AdoSetupState -Path $global:AdoSetupStatePath -State ([pscustomobject]@{ phase = 'PackageStaged'; sequence = 2 })

                $saved = Get-Content -LiteralPath $global:AdoSetupStatePath -Raw | ConvertFrom-Json
                $saved.phase | Should -Be 'PackageStaged'
                $saved.sequence | Should -Be 2
                $bytes = [IO.File]::ReadAllBytes($global:AdoSetupStatePath)
                ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -Be $false
                $parent = Split-Path -Parent $global:AdoSetupStatePath
                $leaf = Split-Path -Leaf $global:AdoSetupStatePath
                @(
                    Get-ChildItem -LiteralPath $parent -Force |
                        Where-Object { $_.Name -like ($leaf + '.tmp.*') -or $_.Name -like ($leaf + '.bak.*') }
                ).Count | Should -Be 0
            }
        }
        finally {
            Remove-Variable -Name AdoSetupStatePath -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'records a sanitized operation and preserves the original setup error as the inner exception' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        $source | Should -Match '\$originalError = \$_'
        $source | Should -Match 'Unable to persist sanitized setup failure metadata'
        $source | Should -Match 'lastFailureOperation'
        $source | Should -Match 'AdoAgentClusterSetup\.\$currentOperation'
        $source | Should -Match 'InvalidOperationException.*\$originalError\.Exception'
    }
}

Describe 'Agent package extraction security' {
    BeforeEach {
        $global:AdoSetupExtractionRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $global:AdoSetupExtractionRoot | Out-Null
    }

    It 'walks a mapped drive root without calling Split-Path on the root' {
        $available = @('Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z') |
            Where-Object { -not (Test-Path -LiteralPath ($_ + ':\')) }
        if (@($available).Count -eq 0) { throw 'No drive letter is available for the mapped-root regression test.' }
        $driveName = [string]$available[0] + ':'
        & subst.exe $driveName $global:AdoSetupExtractionRoot
        if ($LASTEXITCODE -ne 0) { throw "Unable to create test drive $driveName." }
        try {
            $global:AdoSetupMappedRoot = $driveName + '\'
            $global:AdoSetupMappedChild = Join-Path $global:AdoSetupMappedRoot 'agent-root'
            New-Item -ItemType Directory -Path $global:AdoSetupMappedChild | Out-Null
            InModuleScope AdoAgentClusterKey {
                { Assert-AdoNoReparsePoint -Path $global:AdoSetupMappedRoot } | Should -Not -Throw
                { Assert-AdoNoReparsePoint -Path $global:AdoSetupMappedChild } | Should -Not -Throw
            }
        }
        finally {
            & subst.exe $driveName /D
            Remove-Variable -Name AdoSetupMappedRoot -Scope Global -ErrorAction SilentlyContinue
            Remove-Variable -Name AdoSetupMappedChild -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'extracts a minimal valid package into an empty target' {
        $source = Join-Path $global:AdoSetupExtractionRoot 'source'
        New-Item -ItemType Directory -Path (Join-Path $source 'bin') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $source 'config.cmd') -Value '@exit /b 0'
        Set-Content -LiteralPath (Join-Path $source 'run.cmd') -Value '@exit /b 0'
        Set-Content -LiteralPath (Join-Path $source 'bin\Agent.Listener.exe') -Value 'test'
        $archive = Join-Path $global:AdoSetupExtractionRoot 'agent.zip'
        Compress-Archive -Path (Join-Path $source '*') -DestinationPath $archive
        $target = Join-Path $global:AdoSetupExtractionRoot 'agent'
        $global:AdoSetupArchive = $archive
        $global:AdoSetupTarget = $target
        InModuleScope AdoAgentClusterKey {
            Expand-AdoAgentArchive -ArchivePath $global:AdoSetupArchive -AgentRoot $global:AdoSetupTarget
            (Get-AdoAgentRegistrationState -AgentRoot $global:AdoSetupTarget) | Should -Be 'PackageStaged'
        }
    }

    It 'rejects an archive traversal entry' {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = Join-Path $global:AdoSetupExtractionRoot 'bad.zip'
        $stream = [IO.File]::Open($archive, [IO.FileMode]::CreateNew)
        $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $zip.CreateEntry('../escape.txt')
            $writer = New-Object IO.StreamWriter($entry.Open())
            try { $writer.Write('bad') } finally { $writer.Dispose() }
        }
        finally { $zip.Dispose(); $stream.Dispose() }
        $global:AdoSetupArchive = $archive
        $global:AdoSetupTarget = Join-Path $global:AdoSetupExtractionRoot 'agent'
        InModuleScope AdoAgentClusterKey {
            { Expand-AdoAgentArchive -ArchivePath $global:AdoSetupArchive -AgentRoot $global:AdoSetupTarget } | Should -Throw
        }
        (Test-Path -LiteralPath (Join-Path $global:AdoSetupExtractionRoot 'escape.txt')) | Should -Be $false
    }
}
