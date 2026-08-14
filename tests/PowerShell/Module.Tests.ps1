$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
$manifestPath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1'
$modulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1'
$setupModulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.Setup.ps1'
$setupScriptPath = Join-Path $repositoryRoot 'setup\Initialize-AdoAgentCluster.ps1'
$vbsPath = Join-Path $repositoryRoot 'cluster\AdoAgentClusterKey.vbs'
Import-Module $manifestPath -Force

Describe 'AdoAgentClusterKey module contract' {
    It 'parses without PowerShell syntax errors' {
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors) | Out-Null
        @($parseErrors).Count | Should Be 0
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
        foreach ($name in $expected) { ($actual -contains $name) | Should Be $true }
    }

    It 'uses ShouldProcess for every mutating public command' {
        Import-Module $manifestPath -Force
        foreach ($name in @('Initialize-AdoAgentCluster', 'Install-AdoAgentCluster', 'Add-AdoAgentClusterNode', 'Repair-AdoAgentCluster', 'Remove-AdoAgentClusterNode', 'Uninstall-AdoAgentCluster', 'Invoke-AdoAgentClusterEvaluation')) {
            ((Get-Command $name).Parameters.Keys -contains 'WhatIf') | Should Be $true
        }
    }

    It 'parses the setup implementation and signed entry script' {
        foreach ($path in @($setupModulePath, $setupScriptPath)) {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors) | Out-Null
            @($parseErrors).Count | Should Be 0
        }
    }

    It 'adds dependencies without using the overwrite operation during install' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should Match 'Add-ClusterResourceDependency'
        $source | Should Match 'Get-ClusterResourceDependency'
    }

    It 'persists UTF-8 runtime JSON without a BOM' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should Match 'UTF8Encoding\(\$false\)'
    }

    It 'preserves matching node artifacts for idempotent install and add-node retries' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should Match 'PreserveExisting'
        $source | Should Match 'Existing ConfigId artifacts do not match'
        $source | Should Match 'writeRollbackSnapshot'
    }

    It 'makes reseal and purge explicit and restores rollback state' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should Match 'if \(\$Reseal\)'
        $source | Should Match 'PurgeSealedKeys'
        $source | Should Match 'Set-ClusterResourceDependency'
        $source | Should Match 'FailureActionsBase64'
    }
}

Describe 'Package signature policy' {
    It 'rejects unsigned artifacts in production mode' {
        $global:AdoSignatureTestPath = Join-Path $TestDrive 'package'
        New-Item -ItemType Directory -Path $global:AdoSignatureTestPath | Out-Null
        foreach ($name in @('AdoAgent.ClusterKey.exe','AdoAgentClusterKey.vbs','AdoAgentClusterKey.psm1','AdoAgentClusterKey.psd1','AdoAgentClusterKey.Setup.ps1','Initialize-AdoAgentCluster.ps1')) {
            Set-Content -LiteralPath (Join-Path $global:AdoSignatureTestPath $name) -Value 'unsigned-test-file'
        }
        InModuleScope AdoAgentClusterKey {
            $threw = $false
            try { Assert-AdoSignatures -PackagePath $global:AdoSignatureTestPath -PublisherThumbprint '0000000000000000000000000000000000000000' } catch { $threw = $true }
            $threw | Should Be $true
        }
    }

    It 'requires an explicit lab switch to accept unsigned artifacts' {
        InModuleScope AdoAgentClusterKey {
            { Assert-AdoSignatures -PackagePath $global:AdoSignatureTestPath -LabAllowUnsigned } | Should Not Throw
        }
    }
}

Describe 'Generic Script callback contract' {
    $source = Get-Content -LiteralPath $vbsPath -Raw

    It 'implements every required entry point' {
        foreach ($entryPoint in @('Open', 'Online', 'LooksAlive', 'IsAlive', 'Offline', 'Close')) {
            $source | Should Match ("Function " + $entryPoint + "\(\)")
        }
        $source | Should Match 'Function Terminate\(\)'
    }

    It 'uses only the fixed helper path and ConfigId as resource input' {
        $source | Should Match 'C:\\Program Files\\AdoAgentClusterKey\\AdoAgent.ClusterKey.exe'
        $source | Should Match 'Resource.ConfigId'
        $source | Should Not Match 'GetObject\("winmgmts'
        $source | Should Not Match 'OpenCluster'
    }

    It 'does not test Azure DevOps network connectivity' {
        $source | Should Not Match 'https://'
        $source | Should Not Match 'Invoke-WebRequest'
    }

    It 'uses stable sanitized resource-log message prefixes' {
        foreach ($code in @('ADOCK1000','ADOCK1100','ADOCK1200','ADOCK1300','ADOCK1400','ADOCK1500','ADOCK1901','ADOCK1902')) {
            $source | Should Match $code
        }
    }
}
