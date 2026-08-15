BeforeAll {
    $here = Split-Path -Parent $PSCommandPath
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
    $manifestPath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psd1'
    $modulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1'
    $resetScriptPath = Join-Path $repositoryRoot 'setup\Reset-AdoAgentCluster.ps1'
    $buildPath = Join-Path $repositoryRoot 'build\Build.ps1'
    Import-Module $manifestPath -Force
}

Describe 'Permanent cluster-agent reset contract' {
    It 'exposes a high-impact module command and package entry point' {
        foreach ($command in @((Get-Command Reset-AdoAgentCluster), (Get-Command $resetScriptPath))) {
            ($command.Parameters.Keys -contains 'WhatIf') | Should -Be $true
            ($command.Parameters.Keys -contains 'Confirm') | Should -Be $true
            ($command.Parameters.Keys -contains 'Node') | Should -Be $false
            $command.Parameters['RegistrationToken'].ParameterType.FullName | Should -Be 'System.Security.SecureString'
            foreach ($name in @('ConfigId','AgentRoot','EscrowPath','ClusterRoleName','SharedDiskResourceName','KeyResourceName','ServiceResourceName','ConfirmAgentIdle','ConfirmPermanentReset')) {
                @($command.Parameters[$name].Attributes | Where-Object { $_ -is [Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count | Should -BeGreaterThan 0
            }
        }
    }

    It 'validates every supported removal-authentication combination' {
        $global:AdoResetToken = ConvertTo-SecureString 'placeholder-secret' -AsPlainText -Force
        $global:AdoResetCredential = New-Object Management.Automation.PSCredential('CONTOSO\operator', $global:AdoResetToken)
        try {
            InModuleScope AdoAgentClusterKey {
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth PersonalAccessToken -RegistrationToken $global:AdoResetToken } | Should -Not -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth OAuthToken -RegistrationTokenEnvironmentVariableName 'ADO_RESET_TOKEN' } | Should -Not -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth Integrated } | Should -Not -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth Negotiate -RegistrationCredential $global:AdoResetCredential } | Should -Not -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth PersonalAccessToken } | Should -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth PersonalAccessToken -RegistrationToken $global:AdoResetToken -RegistrationTokenEnvironmentVariableName 'ADO_RESET_TOKEN' } | Should -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth Negotiate } | Should -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth PersonalAccessToken -RegistrationToken $global:AdoResetToken -SkipAzureDevOpsUnregister } | Should -Throw
                { Assert-AdoResetAuthenticationParameters -RegistrationAuth PersonalAccessToken -SkipAzureDevOpsUnregister } | Should -Not -Throw
            }
        }
        finally {
            $global:AdoResetToken.Dispose()
            Remove-Variable AdoResetToken,AdoResetCredential -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It 'keeps credentials out of process arguments and consumes them only after approval' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $resetStart = $source.IndexOf('function Reset-AdoAgentCluster')
        $resetEnd = $source.IndexOf('function Invoke-AdoAgentClusterEvaluation')
        $resetSource = $source.Substring($resetStart, $resetEnd - $resetStart)
        $removalStart = $source.IndexOf('function Invoke-AdoAgentRegistrationRemoval')
        $removalEnd = $source.IndexOf('function Reset-AdoAgentCluster')
        $removalSource = $source.Substring($removalStart, $removalEnd - $removalStart)

        $removalSource | Should -Match 'remove --unattended'
        $removalSource | Should -Match 'VSTS_AGENT_INPUT_TOKEN'
        $removalSource | Should -Match 'VSTS_AGENT_INPUT_PASSWORD'
        $removalSource | Should -Not -Match '--token\s+'
        $removalSource | Should -Not -Match '--password\s+'
        $resetSource.IndexOf('Get-AdoRegistrationSecret') | Should -BeGreaterThan $resetSource.IndexOf('$PSCmdlet.ShouldProcess')
    }

    It 'accepts rollback entries for nodes where the service did not previously exist' {
        InModuleScope AdoAgentClusterKey {
            $snapshot = [pscustomobject]@{
                ServiceName = 'vstsagent.contoso.pool.cluster'
                Services = @(
                    [pscustomobject]@{ Node = 'NODE-A'; Existed = $true; Name = 'vstsagent.contoso.pool.cluster' }
                    [pscustomobject]@{ Node = 'NODE-B'; Existed = $false }
                    $null
                )
            }

            $names = @(Get-AdoRollbackServiceNames -RollbackSnapshot $snapshot)

            $names.Count | Should -Be 1
            $names[0] | Should -Be 'vstsagent.contoso.pool.cluster'
        }
    }

    It 'fails closed when a rollback snapshot identifies no service' {
        InModuleScope AdoAgentClusterKey {
            $snapshot = [pscustomobject]@{
                Services = @([pscustomobject]@{ Node = 'NODE-B'; Existed = $false })
            }

            @(Get-AdoRollbackServiceNames -RollbackSnapshot $snapshot).Count | Should -Be 0
        }
    }

    It 'binds deletion to runtime configuration and preserves role and disk' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $resetStart = $source.IndexOf('function Reset-AdoAgentCluster')
        $resetEnd = $source.IndexOf('function Invoke-AdoAgentClusterEvaluation')
        $resetSource = $source.Substring($resetStart, $resetEnd - $resetStart)

        $resetSource | Should -Match 'Runtime configuration does not bind the requested ConfigId, key resource, and AgentRoot'
        $resetSource | Should -Match 'AgentRoot must not be a volume root'
        $resetSource | Should -Match 'Refusing unexpected runtime purge path'
        $resetSource | Should -Match 'Refusing an unexpected escrow purge path'
        $resetSource | Should -Match 'Refusing to purge a runtime reparse point'
        $resetSource | Should -Match 'ClusterRolePreserved'
        $resetSource | Should -Match 'SharedDiskPreserved'
        $resetSource | Should -Match 'RemoveToolkitBinaries'
    }

    It 'packages the reset entry point' {
        (Get-Content -LiteralPath $buildPath -Raw) | Should -Match "setup\\Reset-AdoAgentCluster\.ps1"
        (Get-Content -LiteralPath $resetScriptPath -Raw) | Should -Match 'Reset-AdoAgentCluster @invoke'
    }
}
