BeforeAll {
    $here = Split-Path -Parent $PSCommandPath
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
    $workflowPath = Join-Path $repositoryRoot '.github\workflows\release.yml'
    $dependenciesPath = Join-Path $repositoryRoot 'build\Build.Dependencies.psd1'
}

Describe 'GitHub release workflow contract' {
    It 'publishes only for version tags or an explicit manual run' {
        Test-Path -LiteralPath $workflowPath -PathType Leaf | Should -Be $true
        $source = Get-Content -LiteralPath $workflowPath -Raw
        $source | Should -Match '(?m)^\s{2}push:'
        $source | Should -Match '(?m)^\s{4}tags:'
        $source | Should -Match '(?m)^\s{2}workflow_dispatch:'
        $source | Should -Not -Match '(?m)^\s{2}pull_request:'
    }

    It 'uses a Windows 2025 runner, the pinned SDK, and current official actions' {
        $source = Get-Content -LiteralPath $workflowPath -Raw
        $dependencies = Import-PowerShellDataFile -LiteralPath $dependenciesPath
        $source | Should -Match 'runs-on: windows-2025'
        $source | Should -Match 'actions/checkout@v7'
        $source | Should -Match 'actions/setup-dotnet@v6'
        $source | Should -Match 'global-json-file: global\.json'
        $source | Should -Match 'actions/upload-artifact@v7'
        $dependencies.Pester | Should -Be '5.7.1'
        $source | Should -Match 'Install-Module -Name Pester -RequiredVersion \$dependencies\.Pester'
    }

    It 'runs the complete package build and verifies both integrity layers' {
        $source = Get-Content -LiteralPath $workflowPath -Raw
        $source | Should -Match '\.\\build\\Build\.ps1 -Version'
        $source | Should -Match '\.\\build\\Test-Release\.ps1 -PackagePath'
        $source | Should -Match 'Get-FileHash -LiteralPath \$zipPath -Algorithm SHA256'
    }

    It 'publishes the zip, checksum, release manifest, and SBOM without overwrite behavior' {
        $source = Get-Content -LiteralPath $workflowPath -Raw
        foreach ($name in @('.zip', '.zip.sha256', 'RELEASE-MANIFEST.json', 'sbom.spdx.json')) {
            $source | Should -Match ([regex]::Escape($name))
        }
        $source | Should -Match "'release', 'create'"
        $source | Should -Match '& gh @arguments'
        $source | Should -Match "'--verify-tag'"
        $source | Should -Not -Match '(?i)--clobber|overwrite:\s*true'
    }

    It 'limits its token request to release contents and does not persist checkout credentials' {
        $source = Get-Content -LiteralPath $workflowPath -Raw
        $source | Should -Match '(?ms)^permissions:\s+contents: write'
        $source | Should -Match 'persist-credentials: false'
        $source | Should -Match 'GH_TOKEN: \$\{\{ github\.token \}\}'
    }
}
