$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
$manifestPath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1'
$setupModulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.Setup.ps1'
$setupScriptPath = Join-Path $repositoryRoot 'setup\Initialize-AdoAgentCluster.ps1'
Import-Module $manifestPath -Force

Describe 'Deployment-authenticated agent setup contract' {
    It 'exposes the supported authentication modes without managed identity or device code' {
        $command = Get-Command Initialize-AdoAgentCluster
        $validValues = @($command.Parameters['RegistrationAuth'].Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] } | Select-Object -ExpandProperty ValidValues)
        foreach ($value in @('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')) { ($validValues -contains $value) | Should Be $true }
        ($validValues -contains 'ManagedIdentity') | Should Be $false
        ($validValues -contains 'DeviceCode') | Should Be $false
    }

    It 'makes the entry script support WhatIf and secure token sources' {
        $command = Get-Command $setupScriptPath
        ($command.Parameters.Keys -contains 'WhatIf') | Should Be $true
        ($command.Parameters.Keys -contains 'RegistrationToken') | Should Be $true
        ($command.Parameters.Keys -contains 'RegistrationTokenEnvironmentVariableName') | Should Be $true
        $command.Parameters['RegistrationToken'].ParameterType.FullName | Should Be 'System.Security.SecureString'
        ($command.Parameters.Keys -contains 'PublisherThumbprint') | Should Be $false
        ($command.Parameters.Keys -contains 'LabAllowUnsigned') | Should Be $false
    }

    It 'uses a nonsecret six-phase resume state machine' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        foreach ($phase in @('Preflight', 'PackageStaged', 'RegisteredStopped', 'KeyValidated', 'ClusterInstalled', 'Complete')) { $source | Should Match ("'" + $phase + "'") }
        $source | Should Match '\.setup\.json'
        $source | Should Not Match 'registrationToken\s*='
        $source | Should Not Match 'servicePassword\s*='
    }

    It 'uses child environment variables and never puts credentials in config.cmd arguments' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        $source | Should Match 'VSTS_AGENT_INPUT_TOKEN'
        $source | Should Match 'VSTS_AGENT_INPUT_WINDOWSLOGONPASSWORD'
        $source | Should Match '--preventServiceStart'
        $source | Should Not Match "--token\s+\$"
        $source | Should Not Match "--windowsLogonPassword\s+\$"
    }

    It 'removes a token environment variable when it is consumed' {
        $global:AdoSetupTokenVariable = 'ADO_SETUP_PESTER_TOKEN'
        [Environment]::SetEnvironmentVariable($global:AdoSetupTokenVariable, 'sentinel-secret-value', 'Process')
        InModuleScope AdoAgentClusterKey {
            $value = Get-AdoRegistrationSecret -RegistrationTokenEnvironmentVariableName $global:AdoSetupTokenVariable
            $value | Should Be 'sentinel-secret-value'
            [Environment]::GetEnvironmentVariable($global:AdoSetupTokenVariable, 'Process') | Should BeNullOrEmpty
            $value = $null
        }
    }

    It 'preserves a token environment variable for WhatIf inspection' {
        $global:AdoSetupTokenVariable = 'ADO_SETUP_PESTER_WHATIF_TOKEN'
        [Environment]::SetEnvironmentVariable($global:AdoSetupTokenVariable, 'whatif-sentinel', 'Process')
        InModuleScope AdoAgentClusterKey {
            $value = Get-AdoRegistrationSecret -RegistrationTokenEnvironmentVariableName $global:AdoSetupTokenVariable -PreserveEnvironmentVariable
            $value | Should Be 'whatif-sentinel'
            [Environment]::GetEnvironmentVariable($global:AdoSetupTokenVariable, 'Process') | Should Be 'whatif-sentinel'
            $value = $null
        }
        [Environment]::SetEnvironmentVariable($global:AdoSetupTokenVariable, $null, 'Process')
    }

    It 'rejects invalid authentication combinations' {
        $secure = ConvertTo-SecureString 'sentinel' -AsPlainText -Force
        $global:AdoSetupSecure = $secure
        InModuleScope AdoAgentClusterKey {
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth Integrated -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should Throw
            { Assert-AdoSetupParameters -ServerType Server -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should Throw
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -RegistrationTokenEnvironmentVariableName 'TOKEN' -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should Throw
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '..\work' } | Should Throw
        }
    }

    It 'accepts the production OAuth-token combination' {
        $secure = ConvertTo-SecureString 'sentinel' -AsPlainText -Force
        $global:AdoSetupSecure = $secure
        InModuleScope AdoAgentClusterKey {
            { Assert-AdoSetupParameters -ServerType Services -RegistrationAuth OAuthToken -RegistrationToken $global:AdoSetupSecure -ServiceAccount 'NT AUTHORITY\SYSTEM' -WorkDirectory '_work' } | Should Not Throw
        }
    }

    It 'uses Bearer for OAuth and Basic for PAT API requests' {
        InModuleScope AdoAgentClusterKey {
            $oauth = Get-AdoAuthorizationHeaderValue -RegistrationAuth OAuthToken -RegistrationSecret 'oauth-sentinel'
            $oauth.Scheme | Should Be 'Bearer'
            $oauth.Parameter | Should Be 'oauth-sentinel'
            $pat = Get-AdoAuthorizationHeaderValue -RegistrationAuth PersonalAccessToken -RegistrationSecret 'pat-sentinel'
            $pat.Scheme | Should Be 'Basic'
            [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($pat.Parameter)) | Should Be ':pat-sentinel'
        }
    }

    It 'restricts service URLs and external package hosts' {
        InModuleScope AdoAgentClusterKey {
            $base = Get-AdoNormalizedServerUri -AzureDevOpsUrl 'https://dev.azure.com/example' -ServerType Services
            { Assert-AdoHttpUri -Uri ([Uri]'https://dev.azure.com/example/_apis/test') -BaseUri $base -ServerType Services } | Should Not Throw
            { Assert-AdoHttpUri -Uri ([Uri]'https://vstsagentpackage.azureedge.net/agent/test.zip') -BaseUri $base -ServerType Services -PackageDownload } | Should Not Throw
            { Assert-AdoHttpUri -Uri ([Uri]'https://example.invalid/agent.zip') -BaseUri $base -ServerType Services -PackageDownload } | Should Throw
            { Get-AdoNormalizedServerUri -AzureDevOpsUrl 'http://dev.azure.com/example' -ServerType Services } | Should Throw
        }
    }

    It 'stores a download URL without a reusable query string' {
        $source = Get-Content -LiteralPath $setupModulePath -Raw
        $source | Should Match 'GetLeftPart\(\[UriPartial\]::Path\)'
    }

    It 'normalizes the LocalSystem service alias for Windows APIs' {
        InModuleScope AdoAgentClusterKey {
            (Get-AdoServiceIdentityForWindows -Identity 'LocalSystem') | Should Be 'NT AUTHORITY\SYSTEM'
        }
    }
}

Describe 'Agent package extraction security' {
    BeforeEach {
        $global:AdoSetupExtractionRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $global:AdoSetupExtractionRoot | Out-Null
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
            (Get-AdoAgentRegistrationState -AgentRoot $global:AdoSetupTarget) | Should Be 'PackageStaged'
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
            { Expand-AdoAgentArchive -ArchivePath $global:AdoSetupArchive -AgentRoot $global:AdoSetupTarget } | Should Throw
        }
        (Test-Path -LiteralPath (Join-Path $global:AdoSetupExtractionRoot 'escape.txt')) | Should Be $false
    }
}
