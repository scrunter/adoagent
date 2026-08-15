@{
    RootModule = 'AdoAgentClusterKey.psm1'
    ModuleVersion = '0.3.0'
    GUID = 'e9684e0b-d7a5-4ba9-a18f-ab23ebfd9f04'
    Author = 'AdoAgentClusterKey maintainers'
    CompanyName = 'Community'
    Copyright = '(c) AdoAgentClusterKey maintainers. All rights reserved.'
    Description = 'Installs and operates a node-local DPAPI key selector for clustered Azure DevOps agents.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop')
    FunctionsToExport = @(
        'Initialize-AdoAgentCluster',
        'Test-AdoAgentClusterPrerequisite',
        'Install-AdoAgentCluster',
        'Add-AdoAgentClusterNode',
        'Repair-AdoAgentCluster',
        'Remove-AdoAgentClusterNode',
        'Uninstall-AdoAgentCluster',
        'Reset-AdoAgentCluster',
        'Invoke-AdoAgentClusterEvaluation'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{ Tags = @('AzureDevOps', 'WSFC', 'DPAPI', 'Windows') }
    }
}
