$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $here)
$installScriptPath = Join-Path $repositoryRoot 'setup\Install-AdoAgentCluster.ps1'
$modulePath = Join-Path $repositoryRoot 'module\AdoAgentClusterKey\AdoAgentClusterKey.psm1'

Describe 'Full cluster-node installation entry point' {
    It 'parses and exposes the required safe operator interface' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($installScriptPath, [ref]$null, [ref]$errors) | Out-Null
        @($errors).Count | Should Be 0

        $command = Get-Command $installScriptPath
        ($command.Parameters.Keys -contains 'WhatIf') | Should Be $true
        ($command.Parameters.Keys -contains 'Confirm') | Should Be $true
        ($command.Parameters.Keys -contains 'Node') | Should Be $false
        foreach ($name in @('AgentRoot','ClusterRoleName','SharedDiskResourceName','ProtectorGroup','EscrowPath','ConfirmAgentIdle')) {
            $parameter = $command.Parameters[$name]
            $parameter | Should Not BeNullOrEmpty
            @($parameter.Attributes | Where-Object { $_ -is [Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count | Should BeGreaterThan 0
        }
    }

    It 'discovers every owner from the shared disk and requires each node to be Up' {
        $source = Get-Content -LiteralPath $installScriptPath -Raw
        $source | Should Match '\$disk \| Get-ClusterOwnerNode'
        $source | Should Match '\$disk\.State -ne ''Online'''
        $source | Should Match 'Get-ClusterNode -Name \$nodeName'
        $source | Should Match '\$clusterNode\.State -ne ''Up'''
        $source | Should Not Match '\[string\[\]\]\$Node'
    }

    It 'passes the complete owner set to the module installer and leaves the role Offline' {
        $source = Get-Content -LiteralPath $installScriptPath -Raw
        $source | Should Match 'Node = \$nodes'
        $source | Should Match "Get-Command -Name 'Install-AdoAgentCluster' -Module 'AdoAgentClusterKey'"
        $source | Should Match 'Stop-ClusterGroup -Name \$ClusterRoleName -Wait 60'
        $source | Should Match '\$group\.State -ne ''Offline'''
    }

    It 'requires full release-manifest validation and service-identity preflight before install' {
        $source = Get-Content -LiteralPath $modulePath -Raw
        $source | Should Match 'function Test-AdoReleasePackage'
        $source | Should Match "Test-Release\.ps1"
        $source | Should Match 'RELEASE-MANIFEST\.json'
        $source | Should Match '-ServiceIdentity \$service\.StartName'
    }
}
