param(
    [Parameter(Mandatory = $true)][Guid]$ConfigId,
    [Parameter(Mandatory = $true)][string]$ClusterRoleName,
    [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
    [Parameter(Mandatory = $true)][string]$KeyResourceName,
    [Parameter(Mandatory = $true)][string]$ServiceResourceName,
    [Parameter(Mandatory = $true)][string[]]$Node,
    [Parameter(Mandatory = $true)][string]$PackagePath
)

BeforeAll {
    Import-Module FailoverClusters -ErrorAction Stop
    $releaseManifest = Get-Content -LiteralPath (Join-Path $PackagePath 'RELEASE-MANIFEST.json') -Raw | ConvertFrom-Json
    $expectedPackageHashes = @($releaseManifest.files | Where-Object { ([string]$_.path) -notmatch '/' } | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.path; Sha256 = [string]$_.sha256 }
    })
}

Describe 'AdoAgentClusterKey WSFC installation' {
    It 'uses the required resource types and role' {
        $key = Get-ClusterResource -Name $KeyResourceName
        $service = Get-ClusterResource -Name $ServiceResourceName
        $key.ResourceType | Should -Be 'Generic Script'
        $service.ResourceType | Should -Be 'Generic Service'
        $key.OwnerGroup.Name | Should -Be $ClusterRoleName
        $service.OwnerGroup.Name | Should -Be $ClusterRoleName
    }

    It 'has additive dependency ordering' {
        $keyDependency = [string](Get-ClusterResourceDependency -Resource $KeyResourceName)
        $serviceDependency = [string](Get-ClusterResourceDependency -Resource $ServiceResourceName)
        $keyDependency | Should -Match ([regex]::Escape("[$SharedDiskResourceName]"))
        $serviceDependency | Should -Match ([regex]::Escape("[$KeyResourceName]"))
    }

    It 'has required timing properties' {
        $key = Get-ClusterResource -Name $KeyResourceName
        $key.PendingTimeout | Should -Be 60000
        $key.LooksAlivePollInterval | Should -Be 15000
        $key.IsAlivePollInterval | Should -Be 60000
    }

    It 'binds the canonical ConfigId and fixed script path' {
        $key = Get-ClusterResource -Name $KeyResourceName
        ($key | Get-ClusterParameter -Name ConfigId).Value | Should -Be $ConfigId.ToString('D')
        ($key | Get-ClusterParameter -Name ScriptFilePath).Value | Should -Be 'C:\Program Files\AdoAgentClusterKey\AdoAgentClusterKey.vbs'
    }

    It 'aligns possible owners with the requested nodes' {
        foreach ($resourceName in @($KeyResourceName, $ServiceResourceName)) {
            $owners = @((Get-ClusterResource -Name $resourceName | Get-ClusterOwnerNode).OwnerNodes | ForEach-Object { [string]$_ })
            @($owners | Sort-Object) -join ',' | Should -Be (@($Node | Sort-Object) -join ',')
        }
    }

    It 'has the expected package bytes and protected node-local material on every node' {
        $results = Invoke-Command -ComputerName $Node -ScriptBlock {
            param($id, $hashes)
            $root = 'C:\Program Files\AdoAgentClusterKey'
            $configRoot = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id
            $hashesValid = $true
            foreach ($expected in $hashes) {
                $path = Join-Path $root ([string]$expected.Name)
                $hashesValid = $hashesValid -and
                    (Test-Path -LiteralPath $path -PathType Leaf) -and
                    ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq [string]$expected.Sha256)
            }
            $acl = Get-Acl -LiteralPath $configRoot
            [pscustomobject]@{
                Node = $env:COMPUTERNAME
                HashesValid = $hashesValid
                ConfigExists = Test-Path -LiteralPath (Join-Path $configRoot 'config.json') -PathType Leaf
                SealedExists = Test-Path -LiteralPath (Join-Path $configRoot 'sealed.credentials_rsaparams') -PathType Leaf
                ProtectedInheritance = $acl.AreAccessRulesProtected
            }
        } -ArgumentList $ConfigId.ToString('D'), $expectedPackageHashes
        foreach ($result in $results) {
            $result.HashesValid | Should -Be $true
            $result.ConfigExists | Should -Be $true
            $result.SealedExists | Should -Be $true
            $result.ProtectedInheritance | Should -Be $true
        }
    }

    It 'keeps passive-node services stopped' {
        $owner = (Get-ClusterGroup -Name $ClusterRoleName).OwnerNode.Name
        $serviceName = (Get-ClusterResource -Name $ServiceResourceName | Get-ClusterParameter -Name ServiceName).Value
        foreach ($passive in @($Node | Where-Object { $_ -ne $owner })) {
            (Invoke-Command -ComputerName $passive -ScriptBlock { param($name) (Get-Service -Name $name).Status } -ArgumentList $serviceName) | Should -Be 'Stopped'
        }
    }

    It 'passes a full cryptographic probe on the storage owner' {
        $owner = (Get-ClusterGroup -Name $ClusterRoleName).OwnerNode.Name
        $exitCode = Invoke-Command -ComputerName $owner -ScriptBlock {
            param($id)
            & 'C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe' probe --config-id $id --mode full --json | Out-Null
            return $LASTEXITCODE
        } -ArgumentList $ConfigId.ToString('D')
        $exitCode[-1] | Should -Be 0
    }
}
