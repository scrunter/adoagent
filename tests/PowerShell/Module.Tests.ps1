BeforeAll {
    $here = Split-Path -Parent $PSCommandPath
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
    $manifestPath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1'
    $modulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1'
    $setupModulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.Setup.ps1'
    $setupScriptPath = Join-Path $repositoryRoot 'setup\Initialize-AdoAgentCluster.ps1'
    $installScriptPath = Join-Path $repositoryRoot 'setup\Install-AdoAgentCluster.ps1'
    $vbsPath = Join-Path $repositoryRoot 'cluster\AdoAgentClusterKey.vbs'
    $buildPath = Join-Path $repositoryRoot 'build\Build.ps1'
    $releaseVerifierPath = Join-Path $repositoryRoot 'build\Test-Release.ps1'
    $vbsSource = Get-Content -LiteralPath $vbsPath -Raw
    Import-Module $manifestPath -Force
}

Describe 'AdoAgentClusterKey module contract' {
    It 'parses without PowerShell syntax errors' {
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors) | Out-Null
        @($parseErrors).Count | Should -Be 0
    }

    It 'exports all eight documented commands' {
        Import-Module $manifestPath -Force
        $expected = @(
            'Initialize-AdoAgentCluster',
            'Test-AdoAgentClusterPrerequisite', 'Install-AdoAgentCluster', 'Add-AdoAgentClusterNode',
            'Repair-AdoAgentCluster', 'Remove-AdoAgentClusterNode', 'Uninstall-AdoAgentCluster',
            'Invoke-AdoAgentClusterEvaluation'
        )
        $actual = @(Get-Command -Module AdoAgentClusterKey | Select-Object -ExpandProperty Name)
        foreach ($name in $expected) { ($actual -contains $name) | Should -Be $true }
    }

    It 'uses ShouldProcess for every mutating public command' {
        Import-Module $manifestPath -Force
        foreach ($name in @('Initialize-AdoAgentCluster', 'Install-AdoAgentCluster', 'Add-AdoAgentClusterNode', 'Repair-AdoAgentCluster', 'Remove-AdoAgentClusterNode', 'Uninstall-AdoAgentCluster', 'Invoke-AdoAgentClusterEvaluation')) {
            ((Get-Command $name).Parameters.Keys -contains 'WhatIf') | Should -Be $true
        }
    }

    It 'parses the setup implementation and entry script' {
        foreach ($path in @($setupModulePath, $setupScriptPath, $installScriptPath)) {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors) | Out-Null
            @($parseErrors).Count | Should -Be 0
        }
    }

    It 'adds dependencies without using the overwrite operation during install' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should -Match 'Add-ClusterResourceDependency'
        $source | Should -Match 'Get-ClusterResourceDependency'
    }

    It 'persists UTF-8 runtime JSON without a BOM' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should -Match 'UTF8Encoding\(\$false\)'
    }

    It 'preserves matching node artifacts for idempotent install and add-node retries' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should -Match 'PreserveExisting'
        $source | Should -Match 'Existing ConfigId artifacts do not match'
        $source | Should -Match 'writeRollbackSnapshot'
    }

    It 'passes an explicit quoted empty recovery-action value to sc.exe' {
        $moduleSource = Get-Content -LiteralPath $modulePath -Raw
        $setupSource = Get-Content -LiteralPath $setupModulePath -Raw
        foreach ($source in @($moduleSource, $setupSource)) {
            $source | Should -Match "'actions='\s+'\x22\x22'"
            $source | Should -Not -Match "'actions='\s+''"
        }
    }

    It 'makes reseal and purge explicit and restores rollback state' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should -Match 'if \(\$Reseal\)'
        $source | Should -Match 'PurgeSealedKeys'
        $source | Should -Match 'Set-ClusterResourceDependency'
        $source | Should -Match 'FailureActionsBase64'
    }

    It 'extracts possible owners from the ClusterOwnerNodeList OwnerNodes collection' {
        $ownerNodes = New-Object System.Collections.Specialized.StringCollection
        [void]$ownerNodes.Add('node-b')
        [void]$ownerNodes.Add('node-a')
        [void]$ownerNodes.Add('node-a')
        $global:AdoOwnerNodeList = [pscustomobject]@{
            ClusterObject = 'Cluster Virtual Disk (ADOT)'
            OwnerNodes = $ownerNodes
        }
        try {
            InModuleScope AdoAgentClusterKey {
                $actual = @(ConvertFrom-AdoClusterOwnerNodeList -OwnerNodeList $global:AdoOwnerNodeList)
                $actual | Should -Be @('node-a', 'node-b')
            }
        }
        finally {
            Remove-Variable -Name AdoOwnerNodeList -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'normalizes object-shaped possible owners to CLR strings' {
        $global:AdoOwnerNodeList = [pscustomobject]@{
            ClusterObject = 'Cluster Virtual Disk (ADOT)'
            OwnerNodes = @(
                [pscustomobject]@{ Name = 'node-b' },
                [pscustomobject]@{ Name = 'node-a' }
            )
        }
        try {
            InModuleScope AdoAgentClusterKey {
                $actual = @(ConvertFrom-AdoClusterOwnerNodeList -OwnerNodeList $global:AdoOwnerNodeList)
                $actual | Should -Be @('node-a', 'node-b')
                foreach ($name in $actual) { $name.GetType() | Should -Be ([string]) }
            }
        }
        finally {
            Remove-Variable -Name AdoOwnerNodeList -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Package integrity policy' {
    It 'accepts an unsigned package when all required files are present' {
        $global:AdoPackageTestPath = Join-Path $TestDrive 'complete-package'
        New-Item -ItemType Directory -Path $global:AdoPackageTestPath | Out-Null
        foreach ($name in @('AdoAgent.ClusterKey.exe','AdoAgentClusterKey.vbs','AdoAgentClusterKey.psm1','AdoAgentClusterKey.psd1','AdoAgentClusterKey.Setup.ps1','Install-AdoAgentCluster.ps1','Initialize-AdoAgentCluster.ps1')) {
            Set-Content -LiteralPath (Join-Path $global:AdoPackageTestPath $name) -Value 'unsigned-test-file'
        }
        InModuleScope AdoAgentClusterKey {
            { Get-AdoPackageFiles -PackagePath $global:AdoPackageTestPath | Out-Null } | Should -Not -Throw
        }
    }

    It 'rejects a package that is missing a required file' {
        $global:AdoPackageTestPath = Join-Path $TestDrive 'incomplete-package'
        New-Item -ItemType Directory -Path $global:AdoPackageTestPath | Out-Null
        Set-Content -LiteralPath (Join-Path $global:AdoPackageTestPath 'AdoAgent.ClusterKey.exe') -Value 'test-file'
        InModuleScope AdoAgentClusterKey {
            { Get-AdoPackageFiles -PackagePath $global:AdoPackageTestPath | Out-Null } | Should -Throw
        }
    }

    It 'does not expose Authenticode policy parameters on public commands' {
        foreach ($name in @('Initialize-AdoAgentCluster', 'Test-AdoAgentClusterPrerequisite', 'Install-AdoAgentCluster', 'Add-AdoAgentClusterNode', 'Repair-AdoAgentCluster')) {
            $parameters = (Get-Command $name).Parameters.Keys
            ($parameters -contains 'PublisherThumbprint') | Should -Be $false
            ($parameters -contains 'LabAllowUnsigned') | Should -Be $false
        }
    }

    It 'builds one hash-manifest package type without signing inputs' {
        $source = Get-Content -LiteralPath $buildPath -Raw
        $source | Should -Match 'RELEASE-MANIFEST\.json'
        $source | Should -Match '\.sha256'
        $source | Should -Not -Match 'CertificateThumbprint'
        $source | Should -Not -Match 'LabUnsigned'
        $source | Should -Not -Match 'Sign-Release'
    }

    It 'detects changed and unlisted release files' {
        $package = Join-Path $TestDrive 'release-package'
        New-Item -ItemType Directory -Path $package | Out-Null
        $file = Join-Path $package 'payload.txt'
        Set-Content -LiteralPath $file -Value 'approved payload' -Encoding Ascii
        $entry = [ordered]@{
            path = 'payload.txt'
            sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
            length = (Get-Item -LiteralPath $file).Length
        }
        $manifest = [ordered]@{ schemaVersion = 1; product = 'AdoAgentClusterKey'; version = 'test'; files = @($entry) }
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'RELEASE-MANIFEST.json') -Encoding UTF8

        { & $releaseVerifierPath -PackagePath $package | Out-Null } | Should -Not -Throw
        Set-Content -LiteralPath $file -Value 'changed payload' -Encoding Ascii
        { & $releaseVerifierPath -PackagePath $package | Out-Null } | Should -Throw
        Set-Content -LiteralPath $file -Value 'approved payload' -Encoding Ascii
        Set-Content -LiteralPath (Join-Path $package 'unlisted.txt') -Value 'unlisted' -Encoding Ascii
        { & $releaseVerifierPath -PackagePath $package | Out-Null } | Should -Throw
    }
}

Describe 'Generic Script callback contract' {
    It 'implements every required entry point' {
        foreach ($entryPoint in @('Open', 'Online', 'LooksAlive', 'IsAlive', 'Offline', 'Close')) {
            $vbsSource | Should -Match ("Function " + $entryPoint + "\(\)")
        }
        $vbsSource | Should -Match 'Function Terminate\(\)'
    }

    It 'uses only the fixed helper path and ConfigId as resource input' {
        $vbsSource | Should -Match 'C:\\Program Files\\AdoAgentClusterKey\\AdoAgent.ClusterKey.exe'
        $vbsSource | Should -Match 'Resource.ConfigId'
        $vbsSource | Should -Not -Match 'GetObject\("winmgmts'
        $vbsSource | Should -Not -Match 'OpenCluster'
    }

    It 'does not test Azure DevOps network connectivity' {
        $vbsSource | Should -Not -Match 'https://'
        $vbsSource | Should -Not -Match 'Invoke-WebRequest'
    }

    It 'uses stable sanitized resource-log message prefixes' {
        foreach ($code in @('ADOCK1000','ADOCK1100','ADOCK1200','ADOCK1300','ADOCK1400','ADOCK1500','ADOCK1901','ADOCK1902')) {
            $vbsSource | Should -Match $code
        }
    }
}
