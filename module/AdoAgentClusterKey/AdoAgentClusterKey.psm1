Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:InstallRoot = 'C:\Program Files\AdoAgentClusterKey'
$script:ConfigRoot = 'C:\ProgramData\AdoAgentClusterKey'
$script:HelperPath = Join-Path $script:InstallRoot 'AdoAgent.ClusterKey.exe'
$script:ScriptPath = Join-Path $script:InstallRoot 'AdoAgentClusterKey.vbs'
$script:SchemaVersion = 1

. (Join-Path $PSScriptRoot 'AdoAgentClusterKey.Setup.ps1')

function Assert-AdoElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this operation from an elevated Windows PowerShell 5.1 session.'
    }
}

function Resolve-AdoGroupSid {
    param([Parameter(Mandatory = $true)][string]$Identity)
    try {
        $account = New-Object Security.Principal.NTAccount($Identity)
        return $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Unable to resolve ProtectorGroup '$Identity'. Use a domain-qualified Active Directory security-group name such as 'CONTOSO\AdoAgentKeyRecoveryOperators'. $($_.Exception.Message)"
    }
}

function Test-AdoCurrentTokenSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $securityIdentifier = New-Object Security.Principal.SecurityIdentifier($Sid)
    return $principal.IsInRole($securityIdentifier)
}

function Assert-AdoSecurityGroupSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        $entry = [ADSI]("LDAP://<SID=$Sid>")
        $classes = @($entry.Properties['objectClass'])
        if ($classes -notcontains 'group') { throw 'The protector SID does not identify an Active Directory group.' }
        $groupType = [int]$entry.Properties['groupType'].Value
        if ($groupType -ge 0) { throw 'The protector group is not security-enabled.' }
    }
    catch {
        throw "Unable to validate the protector as a security-enabled Active Directory group. Local groups and distribution groups are not supported. $($_.Exception.Message)"
    }
}

function Get-AdoProtectorGroupValidation {
    param([Parameter(Mandatory = $true)][string]$Identity)
    $sid = Resolve-AdoGroupSid -Identity $Identity
    Assert-AdoSecurityGroupSid -Sid $sid
    if (-not (Test-AdoCurrentTokenSid -Sid $sid)) {
        throw "The current logon token does not contain ProtectorGroup '$Identity' ($sid). Add the provisioning administrator to the group, then sign out and sign back in before retrying."
    }
    return [pscustomobject]@{ Identity = $Identity; Sid = $sid; InCurrentToken = $true }
}

function Get-AdoPackageFiles {
    param([Parameter(Mandatory = $true)][string]$PackagePath)
    $required = @(
        'AdoAgent.ClusterKey.exe',
        'AdoAgentClusterKey.vbs',
        'AdoAgentClusterKey.psm1',
        'AdoAgentClusterKey.psd1',
        'AdoAgentClusterKey.Setup.ps1',
        'Install-AdoAgentCluster.ps1',
        'Initialize-AdoAgentCluster.ps1',
        'Reset-AdoAgentCluster.ps1'
    )
    foreach ($name in $required) {
        $path = Join-Path $PackagePath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Package file '$name' is missing from '$PackagePath'."
        }
    }
    return Get-ChildItem -LiteralPath $PackagePath -File | Where-Object { $_.Extension -in @('.exe', '.dll', '.ps1', '.psm1', '.psd1', '.vbs') }
}

function Test-AdoReleasePackage {
    param([Parameter(Mandatory = $true)][string]$PackagePath)
    Get-AdoPackageFiles -PackagePath $PackagePath | Out-Null
    $verifier = Join-Path $PackagePath 'Test-Release.ps1'
    $manifest = Join-Path $PackagePath 'RELEASE-MANIFEST.json'
    if (-not (Test-Path -LiteralPath $verifier -PathType Leaf) -or -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw 'The package must contain Test-Release.ps1 and RELEASE-MANIFEST.json.'
    }
    $verification = & $verifier -PackagePath $PackagePath
    if ($null -eq $verification -or -not [bool]$verification.Valid) {
        throw 'Release package SHA-256 verification did not return a valid result.'
    }
    return $verification
}

function Invoke-AdoKeyHelper {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )
    $output = & $Executable @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    $parsed = $null
    if ($text) {
        try { $parsed = $text | ConvertFrom-Json } catch { }
    }
    if ($AllowedExitCodes -notcontains $exitCode) {
        $message = if ($null -ne $parsed -and $parsed.message) { $parsed.message } else { 'The key helper failed without a parseable sanitized response.' }
        throw "AdoAgent.ClusterKey exited with code $exitCode. $message"
    }
    return $parsed
}

function Get-AdoAgentServiceDefinition {
    param([Parameter(Mandatory = $true)][string]$AgentRoot)
    $marker = Join-Path $AgentRoot '.service'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw "The ADO agent service marker was not found at '$marker'."
    }
    $raw = (Get-Content -LiteralPath $marker -Raw).Trim()
    $serviceName = $raw
    try {
        $json = $raw | ConvertFrom-Json
        foreach ($property in @('serviceName', 'ServiceName', 'name', 'Name')) {
            if ($json.PSObject.Properties.Name -contains $property -and $json.$property) {
                $serviceName = [string]$json.$property
                break
            }
        }
    }
    catch { }
    $serviceName = $serviceName.Trim('"', "'", ' ')
    $escaped = $serviceName.Replace("'", "''")
    $service = Get-CimInstance Win32_Service -Filter "Name='$escaped'"
    if ($null -eq $service) {
        $rootPattern = [WildcardPattern]::Escape((Resolve-Path -LiteralPath $AgentRoot).Path)
        $service = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*$rootPattern*" -and $_.Name -like 'vstsagent*' } | Select-Object -First 1
    }
    if ($null -eq $service) {
        throw "Windows service '$serviceName' could not be discovered on the current owner."
    }
    $sidTypeLine = & sc.exe qsidtype $service.Name | Where-Object { $_ -match 'SERVICE_SID_TYPE' } | Select-Object -First 1
    $sidType = if ($sidTypeLine -match ':\s*(\S+)') { $Matches[1].ToUpperInvariant() } else { 'NONE' }
    [pscustomobject]@{
        Name = [string]$service.Name
        DisplayName = [string]$service.DisplayName
        PathName = [string]$service.PathName
        StartName = [string]$service.StartName
        StartMode = [string]$service.StartMode
        State = [string]$service.State
        ServiceSidType = $sidType
    }
}

function Get-AdoResourceOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)
    return Get-ClusterResource -Name $Name -ErrorAction SilentlyContinue
}

function Get-AdoPossibleOwners {
    param([Parameter(Mandatory = $true)]$Resource)
    $ownerNodeList = $Resource | Get-ClusterOwnerNode
    if ($null -eq $ownerNodeList) { return @() }
    return @(ConvertFrom-AdoClusterOwnerNodeList -OwnerNodeList $ownerNodeList)
}

function ConvertFrom-AdoClusterOwnerNodeList {
    param([Parameter(Mandatory = $true)]$OwnerNodeList)
    $ownerNodesProperty = $OwnerNodeList.PSObject.Properties['OwnerNodes']
    if ($null -eq $ownerNodesProperty) {
        throw 'Get-ClusterOwnerNode returned an unexpected result without an OwnerNodes property.'
    }

    [string[]]$names = @(
        foreach ($ownerNode in @($ownerNodesProperty.Value)) {
            if ($null -eq $ownerNode) { continue }
            $nameProperty = $ownerNode.PSObject.Properties['Name']
            $candidate = if ($null -ne $nameProperty) { $nameProperty.Value } else { $ownerNode }
            $name = [Convert]::ToString($candidate, [Globalization.CultureInfo]::InvariantCulture)
            if (-not [string]::IsNullOrWhiteSpace($name)) { $name }
        }
    )
    return @($names | Sort-Object -Unique)
}

function Assert-AdoRoleIdle {
    param(
        [Parameter(Mandatory = $true)][string]$RoleName,
        [string]$ServiceResourceName,
        [string]$KeyResourceName,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle
    )
    if (-not $ConfirmAgentIdle) {
        throw '-ConfirmAgentIdle is required: it confirms that no job is running and the clustered agent service may be changed.'
    }
    $group = Get-ClusterGroup -Name $RoleName
    if ($group.State -ne 'Offline') {
        foreach ($resourceName in @($ServiceResourceName, $KeyResourceName)) {
            if (-not $resourceName) { continue }
            $resource = Get-AdoResourceOrNull -Name $resourceName
            if ($null -ne $resource -and $resource.State -ne 'Offline') {
                throw "Clustered resource '$resourceName' must be Offline while the shared disk remains accessible."
            }
        }
    }
    return $group
}

function New-AdoRollbackSnapshot {
    param(
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$RoleName,
        [Parameter(Mandatory = $true)][string[]]$Node,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName
    )
    $clusterResources = @()
    foreach ($name in @($KeyResourceName, $ServiceResourceName)) {
        $resource = Get-AdoResourceOrNull -Name $name
        if ($null -eq $resource) {
            $clusterResources += [pscustomobject]@{ Name = $name; Existed = $false }
        }
        else {
            $parameters = @{}
            foreach ($parameter in @($resource | Get-ClusterParameter -ErrorAction SilentlyContinue)) { $parameters[$parameter.Name] = $parameter.Value }
            $dependency = $resource | Get-ClusterResourceDependency -ErrorAction SilentlyContinue
            $dependencyExpression = if ($null -ne $dependency -and $null -ne $dependency.PSObject.Properties['DependencyExpression']) { [string]$dependency.DependencyExpression } else { [string]$dependency }
            $clusterResources += [pscustomobject]@{
                Name = $name
                Existed = $true
                Type = [string]$resource.ResourceType
                Owners = @(Get-AdoPossibleOwners -Resource $resource)
                Parameters = $parameters
                DependencyExpression = $dependencyExpression
                RestartAction = [int]$resource.RestartAction
                PendingTimeout = [int]$resource.PendingTimeout
                LooksAlivePollInterval = [int]$resource.LooksAlivePollInterval
                IsAlivePollInterval = [int]$resource.IsAlivePollInterval
            }
        }
    }
    $services = Invoke-Command -ComputerName $Node -ScriptBlock {
        param($name)
        $escaped = $name.Replace("'", "''")
        $service = Get-CimInstance Win32_Service -Filter "Name='$escaped'"
        if ($null -eq $service) { return [pscustomobject]@{ Node = $env:COMPUTERNAME; Existed = $false } }
        $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $service.Name
        $registry = Get-ItemProperty -LiteralPath $registryPath
        $serviceSddl = (& sc.exe sdshow $service.Name | Where-Object { $_ -match '^[OGDS]:' } | Select-Object -First 1)
        $sidTypeLine = & sc.exe qsidtype $service.Name | Where-Object { $_ -match 'SERVICE_SID_TYPE' } | Select-Object -First 1
        $sidType = if ($sidTypeLine -match ':\s*(\S+)') { $Matches[1].ToUpperInvariant() } else { 'NONE' }
        [pscustomobject]@{
            Node = $env:COMPUTERNAME
            Existed = $true
            Name = $service.Name
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            StartName = $service.StartName
            StartMode = $service.StartMode
            FailureActionsBase64 = if ($null -ne $registry.FailureActions) { [Convert]::ToBase64String([byte[]]$registry.FailureActions) } else { $null }
            FailureActionsOnNonCrashFailures = if ($null -ne $registry.FailureActionsOnNonCrashFailures) { [int]$registry.FailureActionsOnNonCrashFailures } else { $null }
            DelayedAutostart = if ($null -ne $registry.DelayedAutostart) { [int]$registry.DelayedAutostart } else { $null }
            ServiceSddl = [string]$serviceSddl
            ServiceSidType = $sidType
        }
    } -ArgumentList $ServiceName
    [pscustomobject]@{
        SchemaVersion = 1
        ConfigId = $ConfigId.ToString('D')
        CreatedUtc = [DateTime]::UtcNow.ToString('o')
        ClusterName = (Get-Cluster).Name
        RoleName = $RoleName
        Nodes = $Node
        ServiceName = $ServiceName
        Services = @($services)
        ClusterResources = $clusterResources
    }
}

function Install-AdoPackageOnNode {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][string]$PackagePath
    )
    $expectedHashes = @(Get-AdoPackageFiles -PackagePath $PackagePath | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } })
    $session = $null
    $staging = $null
    $session = New-PSSession -ComputerName $Node
    try {
        $staging = Invoke-Command -Session $session -ScriptBlock {
            $path = Join-Path $env:TEMP ('AdoAgentClusterKey-' + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            return $path
        }
        Copy-Item -Path (Join-Path $PackagePath '*') -Destination $staging -Recurse -Force -ToSession $session
        Invoke-Command -Session $session -ScriptBlock {
            param($stagingPath, $installRoot, $hashes)
            New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
            Copy-Item -Path (Join-Path $stagingPath '*') -Destination $installRoot -Recurse -Force
            foreach ($expectedFile in $hashes) {
                $installedPath = Join-Path $installRoot ([string]$expectedFile.Name)
                if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf) -or (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash -ne [string]$expectedFile.Sha256) {
                    throw "Installed package hash mismatch for '$($expectedFile.Name)' on $env:COMPUTERNAME."
                }
            }
            & icacls.exe $installRoot '/inheritance:r' '/grant:r' 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Unable to protect the toolkit Program Files ACL.' }
            $warningPath = Join-Path $installRoot 'UNSIGNED-LAB-ONLY.txt'
            if (Test-Path -LiteralPath $warningPath) { Remove-Item -LiteralPath $warningPath -Force }
        } -ArgumentList $staging, $script:InstallRoot, $expectedHashes
    }
    finally {
        if ($null -ne $session) {
            if ($staging) { Invoke-Command -Session $session -ScriptBlock { param($path) if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } } -ArgumentList $staging -ErrorAction SilentlyContinue }
            Remove-PSSession -Session $session
        }
    }
}

function Set-AdoNodeService {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)]$Definition,
        [System.Management.Automation.PSCredential]$ServiceCredential
    )
    Invoke-Command -ComputerName $Node -ScriptBlock {
        param($definition, $credential)
        $escaped = $definition.Name.Replace("'", "''")
        $service = Get-CimInstance Win32_Service -Filter "Name='$escaped'"
        $account = [string]$definition.StartName
        $password = $null
        if ($null -ne $credential) {
            if ($credential.UserName -ne $account) { throw 'ServiceCredential user name does not match the discovered service identity.' }
            $password = $credential.GetNetworkCredential().Password
        }
        $isPasswordless = $account -in @('LocalSystem', 'NT AUTHORITY\SYSTEM', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE') -or $account.EndsWith('$')
        if ($null -eq $service) {
            if (-not $isPasswordless -and $null -eq $credential) { throw "A PSCredential is required to create '$($definition.Name)' as '$account' on $env:COMPUTERNAME." }
            $arguments = @{
                Name = [string]$definition.Name
                DisplayName = [string]$definition.DisplayName
                PathName = [string]$definition.PathName
                ServiceType = [byte]16
                ErrorControl = [byte]1
                StartMode = 'Manual'
                DesktopInteract = $false
                StartName = $account
                StartPassword = $password
            }
            $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments $arguments
            if ($result.ReturnValue -ne 0) { throw "Win32_Service.Create returned $($result.ReturnValue) on $env:COMPUTERNAME." }
        }
        else {
            if ([string]$service.StartName -ne $account) { throw "Existing service '$($definition.Name)' uses '$($service.StartName)' instead of '$account'. Standardize it under separate change control before installation." }
            $arguments = @{ PathName = [string]$definition.PathName; StartMode = 'Manual' }
            $result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments $arguments
            if ($result.ReturnValue -ne 0) { throw "Win32_Service.Change returned $($result.ReturnValue) on $env:COMPUTERNAME." }
        }
        & sc.exe failure $definition.Name 'reset=' '0' 'actions=' '""' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to disable SCM recovery for '$($definition.Name)' on $env:COMPUTERNAME." }
        & sc.exe config $definition.Name 'start=' 'demand' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to set Manual start for '$($definition.Name)' on $env:COMPUTERNAME." }
        if ($definition.ServiceSidType -in @('NONE','UNRESTRICTED','RESTRICTED')) {
            & sc.exe sidtype $definition.Name $definition.ServiceSidType.ToLowerInvariant() | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Unable to set service SID type for '$($definition.Name)' on $env:COMPUTERNAME." }
        }
        Stop-Service -Name $definition.Name -Force -ErrorAction SilentlyContinue
        $password = $null
    } -ArgumentList $Definition, $ServiceCredential
}

function Test-AdoNodeIsLocal {
    param([Parameter(Mandatory = $true)][string]$Node)
    $shortName = $Node.Trim().TrimEnd('.').Split('.')[0]
    return $shortName.Equals($env:COMPUTERNAME, [StringComparison]::OrdinalIgnoreCase)
}

function Test-AdoNodeKeyMaterialPresent {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [string]$ConfigRoot = 'C:\ProgramData\AdoAgentClusterKey'
    )
    $check = {
        param($id, $root)
        $directory = Join-Path $root $id
        $config = Join-Path $directory 'config.json'
        $sealed = Join-Path $directory 'sealed.credentials_rsaparams'
        $configItem = Get-Item -LiteralPath $config -Force -ErrorAction SilentlyContinue
        $sealedItem = Get-Item -LiteralPath $sealed -Force -ErrorAction SilentlyContinue
        return $null -ne $configItem -and -not $configItem.PSIsContainer -and
            $null -ne $sealedItem -and -not $sealedItem.PSIsContainer -and
            $sealedItem.Length -gt 0
    }
    if (Test-AdoNodeIsLocal -Node $Node) { return [bool](& $check $ConfigId.ToString('D') $ConfigRoot) }
    return [bool](Invoke-Command -ComputerName $Node -ScriptBlock $check -ArgumentList $ConfigId.ToString('D'), $ConfigRoot)
}

function Set-AdoPreservedNodeConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)]$Inspection,
        [Parameter(Mandatory = $true)][string]$ResourceName,
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$RollbackJson
    )
    $writeConfiguration = {
        param($configId, $resourceName, $agentRoot, $inspectionData, $rollback)
        $configDirectory = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $configId
        $sealedPath = Join-Path $configDirectory 'sealed.credentials_rsaparams'
        $configPath = Join-Path $configDirectory 'config.json'
        $sealedItem = Get-Item -LiteralPath $sealedPath -Force -ErrorAction SilentlyContinue
        if ($null -eq $sealedItem -or $sealedItem.PSIsContainer -or $sealedItem.Length -eq 0 -or
            -not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            throw "Matching node-sealed key material is incomplete on '$env:COMPUTERNAME'."
        }

        $existing = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $same = [string]$existing.configId -eq $configId -and
            [string]$existing.resourceName -eq $resourceName -and
            [string]$existing.agentRoot -eq $agentRoot -and
            [string]$existing.expectedAgentId -eq [string]$inspectionData.agentId -and
            [string]$existing.expectedPublicKeySha256 -eq [string]$inspectionData.publicKeySha256
        if (-not $same) { throw "Existing ConfigId artifacts do not match the requested installation on '$env:COMPUTERNAME'." }

        # Preserve only the sealed ciphertext. Regenerate every derived runtime
        # field so malformed paths from older releases cannot survive repair.
        $configuration = [ordered]@{
            schemaVersion = 1
            configId = $configId
            resourceName = $resourceName
            agentRoot = $agentRoot
            activeKeyPath = [IO.Path]::Combine($agentRoot, '.credentials_rsaparams')
            sealedKeyPath = $sealedPath
            expectedAgentId = [string]$inspectionData.agentId
            expectedPublicKeySha256 = [string]$inspectionData.publicKeySha256
            targetFileSddl = [string]$inspectionData.targetFileSddl
        }
        $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($configPath, ($configuration | ConvertTo-Json -Depth 5), $utf8WithoutBom)
        $rollbackPath = Join-Path $configDirectory 'rollback.json'
        if (-not (Test-Path -LiteralPath $rollbackPath -PathType Leaf)) {
            [IO.File]::WriteAllText($rollbackPath, $rollback, $utf8WithoutBom)
        }
        & icacls.exe $configDirectory '/inheritance:r' '/grant:r' 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to protect the ConfigId directory ACL on '$env:COMPUTERNAME'." }
    }

    $arguments = @($ConfigId.ToString('D'), $ResourceName, $AgentRoot, $Inspection.data, $RollbackJson)
    if (Test-AdoNodeIsLocal -Node $Node) {
        & $writeConfiguration @arguments
        return
    }
    Invoke-Command -ComputerName $Node -ScriptBlock $writeConfiguration -ArgumentList $arguments
}

function Set-AdoNodeKeyMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$EnvelopePath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)]$Inspection,
        [Parameter(Mandatory = $true)][string]$ResourceName,
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$RollbackJson,
        [System.Management.Automation.PSCredential]$ProvisioningCredential,
        [switch]$PreserveExisting
    )
    $session = $null
    $temporary = $null
    $localExecution = Test-AdoNodeIsLocal -Node $Node
    if ($PreserveExisting -and (Test-AdoNodeKeyMaterialPresent -Node $Node -ConfigId $ConfigId)) {
        Set-AdoPreservedNodeConfiguration -Node $Node -ConfigId $ConfigId -Inspection $Inspection -ResourceName $ResourceName -AgentRoot $AgentRoot -RollbackJson $RollbackJson
        return
    }
    $configureNode = {
        param($configId, $temporaryPath, $resourceName, $agentRoot, $inspectionData, $rollback, $isLocalExecution, $credential)
        $configDirectory = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $configId
        New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
        $sealedPath = Join-Path $configDirectory 'sealed.credentials_rsaparams'
        $configPath = Join-Path $configDirectory 'config.json'
        # Only the sealed ciphertext is immutable node key material. Rebuild the
        # runtime configuration on every install/repair so derived paths cannot
        # remain stale after upgrading from an older toolkit release.
        $configuration = [ordered]@{
            schemaVersion = 1
            configId = $configId
            resourceName = $resourceName
            agentRoot = $agentRoot
            # The shared cluster disk is not mounted on a passive node. Build the
            # Windows path lexically instead of asking the PowerShell drive provider
            # to resolve it while node-local configuration is being installed.
            activeKeyPath = [IO.Path]::Combine($agentRoot, '.credentials_rsaparams')
            sealedKeyPath = $sealedPath
            expectedAgentId = [string]$inspectionData.agentId
            expectedPublicKeySha256 = [string]$inspectionData.publicKeySha256
            targetFileSddl = [string]$inspectionData.targetFileSddl
        }
        $arguments = @('seal', '--envelope', (Join-Path $temporaryPath 'escrow.bin'), '--manifest', (Join-Path $temporaryPath 'manifest.json'), '--config-id', $configId, '--force', '--json')
        $helperPath = 'C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe'
        if ($isLocalExecution) {
            $output = & $helperPath @arguments 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Local node sealing failed on '$env:COMPUTERNAME' with sanitized helper response: $(($output | Out-String).Trim())" }
        }
        else {
            if ($null -eq $credential) {
                throw "ProvisioningCredential is required to seal the DPAPI-NG envelope on remote node '$env:COMPUTERNAME' without enabling credential delegation."
            }
            $process = $null
            $standardInput = $null
            $passwordPointer = [IntPtr]::Zero
            try {
                if (((Get-Item -LiteralPath $temporaryPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "The temporary sealing directory is a reparse point on '$env:COMPUTERNAME'."
                }
                $stagedSealedPath = Join-Path $temporaryPath 'staged.sealed.credentials_rsaparams'
                $argumentString = 'seal-delegated --envelope "{0}" --manifest "{1}" --config-id {2} --output "{3}" --force --json' -f
                    (Join-Path $temporaryPath 'escrow.bin'), (Join-Path $temporaryPath 'manifest.json'), $configId, $stagedSealedPath

                $startInfo = New-Object Diagnostics.ProcessStartInfo
                $startInfo.FileName = $helperPath
                $startInfo.Arguments = $argumentString
                $startInfo.WorkingDirectory = $temporaryPath
                $startInfo.UseShellExecute = $false
                $startInfo.CreateNoWindow = $true
                $startInfo.RedirectStandardInput = $true
                $startInfo.RedirectStandardOutput = $true
                $startInfo.RedirectStandardError = $true
                $process = New-Object Diagnostics.Process
                $process.StartInfo = $startInfo
                if (-not $process.Start()) { throw 'Windows did not start the delegated sealing helper.' }
                $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
                $standardErrorTask = $process.StandardError.ReadToEndAsync()
                $standardInput = $process.StandardInput.BaseStream

                [byte[]]$protocolMagic = @(65, 67, 75, 49)
                $standardInput.Write($protocolMagic, 0, $protocolMagic.Length)
                [Array]::Clear($protocolMagic, 0, $protocolMagic.Length)

                $userNameBytes = [Text.Encoding]::UTF8.GetBytes($credential.UserName)
                try {
                    $lengthBytes = [BitConverter]::GetBytes([int]$userNameBytes.Length)
                    $standardInput.Write($lengthBytes, 0, $lengthBytes.Length)
                    $standardInput.Write($userNameBytes, 0, $userNameBytes.Length)
                    [Array]::Clear($lengthBytes, 0, $lengthBytes.Length)
                }
                finally { [Array]::Clear($userNameBytes, 0, $userNameBytes.Length) }

                $passwordCharacterCount = [int]$credential.Password.Length
                $passwordByteCount = [int]($passwordCharacterCount * 2)
                $lengthBytes = [BitConverter]::GetBytes($passwordByteCount)
                $standardInput.Write($lengthBytes, 0, $lengthBytes.Length)
                [Array]::Clear($lengthBytes, 0, $lengthBytes.Length)
                $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($credential.Password)
                [byte[]]$passwordCodeUnit = @(0, 0)
                try {
                    for ($index = 0; $index -lt $passwordCharacterCount; $index++) {
                        $value = [int][Runtime.InteropServices.Marshal]::ReadInt16($passwordPointer, $index * 2)
                        $passwordCodeUnit[0] = [byte]($value -band 255)
                        $passwordCodeUnit[1] = [byte](($value -shr 8) -band 255)
                        $standardInput.Write($passwordCodeUnit, 0, 2)
                    }
                    $standardInput.Flush()
                }
                finally { [Array]::Clear($passwordCodeUnit, 0, $passwordCodeUnit.Length) }
                $standardInput.Close()
                $standardInput = $null
                $process.WaitForExit()
                $outputText = @($standardOutputTask.Result, $standardErrorTask.Result) -join [Environment]::NewLine
                if ($process.ExitCode -ne 0) {
                    throw "Node sealing failed on '$env:COMPUTERNAME' with sanitized helper response: $($outputText.Trim())"
                }
            }
            catch {
                throw "Delegated node sealing failed on '$env:COMPUTERNAME'. $($_.Exception.Message)"
            }
            finally {
                if ($passwordPointer -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($passwordPointer)
                }
                if ($null -ne $standardInput) { try { $standardInput.Dispose() } catch { } }
                if ($null -ne $process) {
                    try { if (-not $process.HasExited) { $process.Kill() } } catch { }
                    $process.Dispose()
                }
                $credential = $null
            }
            $installArguments = @('install-sealed', '--sealed', $stagedSealedPath, '--manifest', (Join-Path $temporaryPath 'manifest.json'), '--config-id', $configId, '--force', '--json')
            $installOutput = & $helperPath @installArguments 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Unable to install the staged sealed key on '$env:COMPUTERNAME' with sanitized helper response: $(($installOutput | Out-String).Trim())" }
        }
        $sealedItem = Get-Item -LiteralPath $sealedPath -Force -ErrorAction SilentlyContinue
        if ($null -eq $sealedItem -or $sealedItem.PSIsContainer -or $sealedItem.Length -eq 0) {
            throw "Node sealing did not create a nonempty sealed key on '$env:COMPUTERNAME'."
        }

        $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($configPath, ($configuration | ConvertTo-Json -Depth 5), $utf8WithoutBom)
        [IO.File]::WriteAllText((Join-Path $configDirectory 'rollback.json'), $rollback, $utf8WithoutBom)
        & icacls.exe $configDirectory '/inheritance:r' '/grant:r' 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to protect the ConfigId directory ACL on '$env:COMPUTERNAME'." }
    }
    try {
        if ($localExecution) {
            $temporary = Join-Path $env:TEMP ('AdoAgentClusterKey-Escrow-' + [Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $temporary -Force | Out-Null
            Copy-Item -LiteralPath $EnvelopePath -Destination (Join-Path $temporary 'escrow.bin')
            Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $temporary 'manifest.json')
            & $configureNode $ConfigId.ToString('D') $temporary $ResourceName $AgentRoot $Inspection.data $RollbackJson $true $null
        }
        else {
            $session = New-PSSession -ComputerName $Node
            $temporary = Invoke-Command -Session $session -ScriptBlock {
                $path = Join-Path $env:TEMP ('AdoAgentClusterKey-Escrow-' + [Guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $path -Force | Out-Null
                return $path
            }
            Copy-Item -LiteralPath $EnvelopePath -Destination (Join-Path $temporary 'escrow.bin') -ToSession $session
            Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $temporary 'manifest.json') -ToSession $session
            Invoke-Command -Session $session -ScriptBlock $configureNode -ArgumentList $ConfigId.ToString('D'), $temporary, $ResourceName, $AgentRoot, $Inspection.data, $RollbackJson, $false, $ProvisioningCredential
        }
    }
    finally {
        if ($localExecution) {
            if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
        }
        elseif ($null -ne $session) {
            if ($temporary) { Invoke-Command -Session $session -ScriptBlock { param($path) if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } } -ArgumentList $temporary -ErrorAction SilentlyContinue }
            Remove-PSSession -Session $session
        }
    }
}

function Remove-AdoLegacySigningStateOnNode {
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][Guid]$ConfigId
    )
    Invoke-Command -ComputerName $Node -ScriptBlock {
        param($id)
        $configDirectory = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id
        $configPath = Join-Path $configDirectory 'config.json'
        if (Test-Path -LiteralPath $configPath -PathType Leaf) {
            $configuration = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            $changed = $false
            foreach ($propertyName in @('publisherThumbprint', 'allowUnsigned')) {
                if ($configuration.PSObject.Properties.Name -contains $propertyName) {
                    $configuration.PSObject.Properties.Remove($propertyName)
                    $changed = $true
                }
            }
            if ($changed) {
                $temporary = $configPath + '.tmp.' + [Guid]::NewGuid().ToString('N')
                try {
                    [IO.File]::WriteAllText($temporary, ($configuration | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
                    Move-Item -LiteralPath $temporary -Destination $configPath -Force
                }
                finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
            }
        }
        $warningPath = Join-Path $configDirectory 'UNSIGNED-LAB-ONLY.txt'
        if (Test-Path -LiteralPath $warningPath) { Remove-Item -LiteralPath $warningPath -Force }
    } -ArgumentList $ConfigId.ToString('D')
}

function Set-AdoClusterPrivateParameter {
    param($Resource, [string]$Name, $Value)
    $updateFailure = $null
    try { $Resource | Set-ClusterParameter -Name $Name -Value $Value -ErrorAction Stop | Out-Null }
    catch {
        $updateFailure = $_.Exception.Message
        try { $Resource | Set-ClusterParameter -Name $Name -Value $Value -Create -ErrorAction Stop | Out-Null }
        catch {
            throw "Unable to set private cluster property '$Name' on '$($Resource.Name)'. Update failed: $updateFailure Create failed: $($_.Exception.Message)"
        }
    }
    try {
        $saved = $Resource | Get-ClusterParameter -Name $Name -ErrorAction Stop
        if ([string]$saved.Value -cne [string]$Value) {
            throw 'WSFC returned a different value after the update.'
        }
    }
    catch {
        throw "Unable to verify private cluster property '$Name' on '$($Resource.Name)'. $($_.Exception.Message)"
    }
}

function Set-AdoClusterCommonProperty {
    param(
        [Parameter(Mandatory = $true)]$Resource,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][uint32]$Value
    )
    try {
        if ($null -eq $Resource.PSObject.Properties[$Name]) {
            throw 'The installed FailoverClusters module does not expose this common property.'
        }
        $Resource.$Name = $Value
        $refreshed = Get-ClusterResource -Name ([string]$Resource.Name) -ErrorAction Stop
        if ([uint32]$refreshed.$Name -ne $Value) {
            throw "WSFC returned '$($refreshed.$Name)' after the update."
        }
    }
    catch {
        throw "Unable to set common cluster property '$Name' to '$Value' on '$($Resource.Name)'. $($_.Exception.Message)"
    }
}

function Ensure-AdoDependency {
    param($Resource, $Provider)
    $dependency = $Resource | Get-ClusterResourceDependency -ErrorAction SilentlyContinue
    $expression = if ($null -ne $dependency -and $null -ne $dependency.PSObject.Properties['DependencyExpression']) { [string]$dependency.DependencyExpression } else { [string]$dependency }
    if ($expression -notmatch [regex]::Escape("[$($Provider.Name)]")) {
        Add-ClusterResourceDependency -Resource $Resource -Provider $Provider | Out-Null
    }
}

function Set-AdoClusterResources {
    param(
        [Parameter(Mandatory = $true)][string]$RoleName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string[]]$Node
    )
    $disk = Get-ClusterResource -Name $SharedDiskResourceName
    if ($disk.OwnerGroup.Name -ne $RoleName) { throw "Shared disk '$SharedDiskResourceName' is not in role '$RoleName'." }
    $key = Get-AdoResourceOrNull -Name $KeyResourceName
    if ($null -eq $key) { $key = Add-ClusterResource -Name $KeyResourceName -ResourceType 'Generic Script' -Group $RoleName -SeparateMonitor }
    if ($key.ResourceType -ne 'Generic Script') { throw "'$KeyResourceName' exists but is not a Generic Script resource." }
    Set-AdoClusterPrivateParameter -Resource $key -Name 'ScriptFilePath' -Value $script:ScriptPath
    Set-AdoClusterPrivateParameter -Resource $key -Name 'ConfigId' -Value $ConfigId.ToString('D')
    Set-AdoClusterCommonProperty -Resource $key -Name 'PendingTimeout' -Value 60000
    Set-AdoClusterCommonProperty -Resource $key -Name 'LooksAlivePollInterval' -Value 15000
    Set-AdoClusterCommonProperty -Resource $key -Name 'IsAlivePollInterval' -Value 60000
    Set-AdoClusterCommonProperty -Resource $key -Name 'RestartAction' -Value 1

    $service = Get-AdoResourceOrNull -Name $ServiceResourceName
    if ($null -eq $service) { $service = Add-ClusterResource -Name $ServiceResourceName -ResourceType 'Generic Service' -Group $RoleName -SeparateMonitor }
    if ($service.ResourceType -ne 'Generic Service') { throw "'$ServiceResourceName' exists but is not a Generic Service resource." }
    Set-AdoClusterPrivateParameter -Resource $service -Name 'ServiceName' -Value $ServiceName
    Set-AdoClusterCommonProperty -Resource $service -Name 'PendingTimeout' -Value 60000
    Set-AdoClusterCommonProperty -Resource $service -Name 'RestartAction' -Value 1

    Ensure-AdoDependency -Resource $key -Provider $disk
    Ensure-AdoDependency -Resource $service -Provider $key
    Set-ClusterOwnerNode -Resource $key -Owners $Node | Out-Null
    Set-ClusterOwnerNode -Resource $service -Owners $Node | Out-Null
    return [pscustomobject]@{ Key = $key; Service = $service; Disk = $disk }
}

function Test-AdoAgentClusterPrerequisite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$ProtectorGroup,
        [string[]]$Node,
        [string]$PackagePath,
        [string]$ServiceIdentity,
        [string]$WorkDirectory = '_work',
        [switch]$ThrowOnFailure
    )
    $checks = New-Object System.Collections.Generic.List[object]
    function Add-Check([string]$name, [bool]$passed, [string]$detail) { $checks.Add([pscustomobject]@{ Name = $name; Passed = $passed; Detail = $detail }) }
    try { Assert-AdoElevated; Add-Check 'Elevated' $true 'The current session is elevated.' } catch { Add-Check 'Elevated' $false $_.Exception.Message }
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Check 'OperatingSystem' ([Environment]::Is64BitOperatingSystem -and [version]$os.Version -ge [version]'10.0.17763') "$($os.Caption) $($os.Version)"
    $computer = Get-CimInstance Win32_ComputerSystem
    Add-Check 'DomainJoined' ([bool]$computer.PartOfDomain) "Domain=$($computer.Domain)"
    Add-Check 'PowerShell51' ($PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion -ge [version]'5.1') "Edition=$($PSVersionTable.PSEdition) PowerShell=$($PSVersionTable.PSVersion)"
    $clusterModule = Get-Module -ListAvailable FailoverClusters | Select-Object -First 1
    Add-Check 'FailoverClusters' ($null -ne $clusterModule) $(if ($clusterModule) { $clusterModule.Version.ToString() } else { 'Module not installed.' })
    $sid = $null
    $protectorIsSecurityGroup = $false
    try {
        $sid = Resolve-AdoGroupSid -Identity $ProtectorGroup
        Add-Check 'ProtectorSid' $true "Identity=$ProtectorGroup SID=$sid"
    }
    catch { Add-Check 'ProtectorSid' $false $_.Exception.Message }
    if ($sid) {
        try {
            Assert-AdoSecurityGroupSid -Sid $sid
            $protectorIsSecurityGroup = $true
            Add-Check 'ProtectorSecurityGroup' $true 'The protector is a security-enabled Active Directory group.'
        }
        catch { Add-Check 'ProtectorSecurityGroup' $false $_.Exception.Message }
    }
    if ($protectorIsSecurityGroup) {
        $inCurrentToken = Test-AdoCurrentTokenSid -Sid $sid
        $tokenDetail = if ($inCurrentToken) { 'The current logon token contains the protector group SID.' } else { "The current logon token does not contain '$ProtectorGroup' ($sid). Add the administrator to the group, then sign out and sign back in." }
        Add-Check 'ProvisioningIdentity' $inCurrentToken $tokenDetail
    }
    foreach ($file in @('.agent', '.credentials', '.credentials_rsaparams', '.service')) { Add-Check "AgentFile:$file" (Test-Path -LiteralPath (Join-Path $AgentRoot $file) -PathType Leaf) (Join-Path $AgentRoot $file) }
    try {
        $group = Get-ClusterGroup -Name $ClusterRoleName
        $disk = Get-ClusterResource -Name $SharedDiskResourceName
        Add-Check 'ClusterRole' $true "State=$($group.State) Owner=$($group.OwnerNode)"
        Add-Check 'SharedDisk' ($disk.OwnerGroup.Name -eq $ClusterRoleName) "State=$($disk.State) Role=$($disk.OwnerGroup.Name)"
        if (-not $Node) { $Node = @(Get-AdoPossibleOwners -Resource $disk) }
    }
    catch { Add-Check 'ClusterRole' $false $_.Exception.Message }
    foreach ($clusterNode in @($Node)) {
        try { Test-WSMan -ComputerName $clusterNode -ErrorAction Stop | Out-Null; Add-Check "Remoting:$clusterNode" $true 'WSMan reachable.' } catch { Add-Check "Remoting:$clusterNode" $false $_.Exception.Message }
    }
    if (-not [string]::IsNullOrWhiteSpace($ServiceIdentity) -and @($Node).Count -gt 0) {
        if ([IO.Path]::IsPathRooted($WorkDirectory) -or $WorkDirectory -match '(^|[\\/])\.\.([\\/]|$)') {
            Add-Check 'ServiceWorkDirectory' $false 'WorkDirectory must remain beneath AgentRoot.'
        }
        else {
            foreach ($identityCheck in @(Get-AdoServiceIdentityChecks -ServiceIdentity $ServiceIdentity -Node $Node -AgentRoot $AgentRoot)) {
                Add-Check ([string]$identityCheck.Name) ([bool]$identityCheck.Passed) ([string]$identityCheck.Detail)
            }
        }
    }
    if ($PackagePath) {
        try {
            $verification = Test-AdoReleasePackage -PackagePath $PackagePath
            Add-Check 'PackageIntegrity' $true "Version=$($verification.Version) Files=$($verification.FileCount)"
            $inspection = Invoke-AdoKeyHelper -Executable (Join-Path $PackagePath 'AdoAgent.ClusterKey.exe') -Arguments @('inspect', '--agent-root', $AgentRoot, '--json')
            Add-Check 'FileBackedRsa' ($inspection.data.keyStorage -eq 'file') "Storage=$($inspection.data.keyStorage)"
            Add-Check 'AdditionalCredentials' (@($inspection.data.additionalCredentialStores).Count -eq 0) "Detected=$($inspection.data.additionalCredentialStores -join ',')"
        }
        catch {
            Add-Check 'PackageFilesOrInspection' $false $_.Exception.Message
        }
    }
    $passed = @($checks | Where-Object { -not $_.Passed }).Count -eq 0
    $result = [pscustomobject]@{ Passed = $passed; Checks = $checks.ToArray(); Nodes = @($Node) }
    if ($ThrowOnFailure -and -not $passed) { throw "Prerequisite checks failed: $((@($checks | Where-Object { -not $_.Passed } | ForEach-Object { $_.Name })) -join ', ')" }
    return $result
}

function Install-AdoAgentCluster {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$ProtectorGroup,
        [Parameter(Mandatory = $true)][string]$EscrowPath,
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
        [string[]]$Node,
        [Guid]$ConfigId = [Guid]::Empty,
        [string]$KeyResourceName,
        [string]$ServiceResourceName,
        [System.Management.Automation.PSCredential]$ServiceCredential,
        [System.Management.Automation.PSCredential]$ProvisioningCredential
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    Test-AdoReleasePackage -PackagePath $PackagePath | Out-Null
    if ($ConfigId -eq [Guid]::Empty) { $ConfigId = [Guid]::NewGuid() }
    if (-not $KeyResourceName) { $KeyResourceName = "$ClusterRoleName - Key Selector" }
    if (-not $ServiceResourceName) { $ServiceResourceName = "$ClusterRoleName - ADO Agent" }
    $group = Assert-AdoRoleIdle -RoleName $ClusterRoleName -ServiceResourceName $ServiceResourceName -KeyResourceName $KeyResourceName -ConfirmAgentIdle:$ConfirmAgentIdle
    if ($group.OwnerNode.Name -ne $env:COMPUTERNAME) { throw "Run initial migration on current role owner '$($group.OwnerNode.Name)' so classic DPAPI can decrypt the existing key." }
    $disk = Get-ClusterResource -Name $SharedDiskResourceName
    if (-not $Node) { $Node = @(Get-AdoPossibleOwners -Resource $disk) }
    $diskOwners = @(Get-AdoPossibleOwners -Resource $disk)
    foreach ($name in $Node) { if ($diskOwners -notcontains $name) { throw "Node '$name' is not a possible owner of '$SharedDiskResourceName'." } }
    $service = Get-AdoAgentServiceDefinition -AgentRoot $AgentRoot
    $prerequisite = Test-AdoAgentClusterPrerequisite -AgentRoot $AgentRoot -ClusterRoleName $ClusterRoleName -SharedDiskResourceName $SharedDiskResourceName -ProtectorGroup $ProtectorGroup -Node $Node -PackagePath $PackagePath -ServiceIdentity $service.StartName -ThrowOnFailure
    $sid = Resolve-AdoGroupSid -Identity $ProtectorGroup
    $helper = Join-Path $PackagePath 'AdoAgent.ClusterKey.exe'
    $inspection = Invoke-AdoKeyHelper -Executable $helper -Arguments @('inspect', '--agent-root', $AgentRoot, '--json')
    if ($inspection.data.keyStorage -ne 'file') { throw 'The agent uses a named CSP/CNG container. Perform the documented one-time file-mode re-registration first.' }
    if (@($inspection.data.additionalCredentialStores).Count -gt 0) { throw "Unsupported credential stores detected: $($inspection.data.additionalCredentialStores -join ', ')." }
    if (-not (Test-Path -LiteralPath $EscrowPath -PathType Container)) { throw 'EscrowPath must be a pre-created administrator-controlled directory.' }
    $resolvedEscrow = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $EscrowPath).Path).TrimEnd('\')
    $resolvedAgentRoot = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $AgentRoot).Path).TrimEnd('\')
    if ($resolvedEscrow.StartsWith($resolvedAgentRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or $resolvedEscrow -eq $resolvedAgentRoot) { throw 'EscrowPath must be outside the shared agent root and runtime filesystem.' }
    $envelope = Join-Path $EscrowPath ($ConfigId.ToString('D') + '.envelope.bin')
    $manifest = Join-Path $EscrowPath ($ConfigId.ToString('D') + '.manifest.json')
    $rollbackFile = Join-Path $EscrowPath ($ConfigId.ToString('D') + '.rollback.json')
    $writeRollbackSnapshot = $false
    if (Test-Path -LiteralPath $rollbackFile -PathType Leaf) {
        $rollbackJson = Get-Content -LiteralPath $rollbackFile -Raw
        $saved = $rollbackJson | ConvertFrom-Json
        if ([string]$saved.ConfigId -ne $ConfigId.ToString('D') -or [string]$saved.RoleName -ne $ClusterRoleName) { throw 'Existing rollback snapshot does not match this ConfigId and role.' }
    }
    else {
        $snapshot = New-AdoRollbackSnapshot -ConfigId $ConfigId -RoleName $ClusterRoleName -Node $Node -ServiceName $service.Name -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName
        $rollbackJson = $snapshot | ConvertTo-Json -Depth 10
        $writeRollbackSnapshot = $true
    }
    $escrowExists = (Test-Path -LiteralPath $envelope -PathType Leaf) -and (Test-Path -LiteralPath $manifest -PathType Leaf)
    if ((Test-Path -LiteralPath $envelope -PathType Leaf) -xor (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Only one escrow artifact exists; restore the matching pair before retrying.' }
    if ($escrowExists) {
        $existingManifest = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        if ([string]$existingManifest.agentId -ne [string]$inspection.data.agentId -or
            [string]$existingManifest.publicKeySha256 -ne [string]$inspection.data.publicKeySha256 -or
            [string]$existingManifest.protectorSid -ne $sid) {
            throw 'Existing escrow manifest does not match the inspected agent key or protector SID.'
        }
    }
    $remoteNodesNeedingSeal = @($Node | Where-Object {
        -not (Test-AdoNodeIsLocal -Node $_) -and -not (Test-AdoNodeKeyMaterialPresent -Node $_ -ConfigId $ConfigId)
    })
    if ($remoteNodesNeedingSeal.Count -gt 0 -and $null -eq $ProvisioningCredential) {
        throw "ProvisioningCredential is required for DPAPI-NG sealing on remote nodes: $($remoteNodesNeedingSeal -join ', '). Supply an in-memory credential for an account authorized by ProtectorGroup."
    }
    if (-not $PSCmdlet.ShouldProcess($ClusterRoleName, "install clustered ADO key selector ConfigId $ConfigId on $($Node -join ', ')")) { return }
    if ($writeRollbackSnapshot) { [IO.File]::WriteAllText($rollbackFile, $rollbackJson, (New-Object Text.UTF8Encoding($false))) }
    if (-not $escrowExists) {
        Invoke-AdoKeyHelper -Executable $helper -Arguments @('export', '--agent-root', $AgentRoot, '--protector-sid', $sid, '--envelope', $envelope, '--manifest', $manifest, '--json') | Out-Null
    }
    foreach ($clusterNode in $Node) {
        Install-AdoPackageOnNode -Node $clusterNode -PackagePath $PackagePath
        Set-AdoNodeService -Node $clusterNode -Definition $service -ServiceCredential $ServiceCredential
        Set-AdoNodeKeyMaterial -Node $clusterNode -ConfigId $ConfigId -EnvelopePath $envelope -ManifestPath $manifest -Inspection $inspection -ResourceName $KeyResourceName -AgentRoot $AgentRoot -RollbackJson $rollbackJson -ProvisioningCredential $ProvisioningCredential -PreserveExisting
    }
    $resources = Set-AdoClusterResources -RoleName $ClusterRoleName -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName -SharedDiskResourceName $SharedDiskResourceName -ServiceName $service.Name -ConfigId $ConfigId -Node $Node
    [pscustomobject]@{ ConfigId = $ConfigId; EnvelopePath = $envelope; ManifestPath = $manifest; Nodes = $Node; KeyResource = $resources.Key.Name; ServiceResource = $resources.Service.Name }
}

function Add-AdoAgentClusterNode {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [Parameter(Mandatory = $true)][string]$EnvelopePath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
        [System.Management.Automation.PSCredential]$ServiceCredential,
        [System.Management.Automation.PSCredential]$ProvisioningCredential
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    Test-AdoReleasePackage -PackagePath $PackagePath | Out-Null
    Assert-AdoRoleIdle -RoleName $ClusterRoleName -ServiceResourceName $ServiceResourceName -KeyResourceName $KeyResourceName -ConfirmAgentIdle:$ConfirmAgentIdle | Out-Null
    $disk = Get-ClusterResource -Name $SharedDiskResourceName
    if ((Get-AdoPossibleOwners -Resource $disk) -notcontains $Node) { throw "Node '$Node' must first be a possible owner of '$SharedDiskResourceName'." }
    $currentConfigPath = Join-Path (Join-Path $script:ConfigRoot $ConfigId.ToString('D')) 'config.json'
    $configuration = Get-Content -LiteralPath $currentConfigPath -Raw | ConvertFrom-Json
    $inspection = [pscustomobject]@{ data = [pscustomobject]@{ agentId = $configuration.expectedAgentId; publicKeySha256 = $configuration.expectedPublicKeySha256; targetFileSddl = $configuration.targetFileSddl } }
    $service = Get-AdoAgentServiceDefinition -AgentRoot $AgentRoot
    $rollbackPath = Join-Path (Join-Path $script:ConfigRoot $ConfigId.ToString('D')) 'rollback.json'
    $rollbackJson = Get-Content -LiteralPath $rollbackPath -Raw
    if (-not (Test-AdoNodeIsLocal -Node $Node) -and -not (Test-AdoNodeKeyMaterialPresent -Node $Node -ConfigId $ConfigId) -and $null -eq $ProvisioningCredential) {
        throw "ProvisioningCredential is required for DPAPI-NG sealing on remote node '$Node'."
    }
    if (-not $PSCmdlet.ShouldProcess($Node, "enroll as a possible owner for ConfigId $ConfigId")) { return }
    Install-AdoPackageOnNode -Node $Node -PackagePath $PackagePath
    Set-AdoNodeService -Node $Node -Definition $service -ServiceCredential $ServiceCredential
    Set-AdoNodeKeyMaterial -Node $Node -ConfigId $ConfigId -EnvelopePath $EnvelopePath -ManifestPath $ManifestPath -Inspection $inspection -ResourceName $KeyResourceName -AgentRoot $AgentRoot -RollbackJson $rollbackJson -ProvisioningCredential $ProvisioningCredential -PreserveExisting
    $owners = @((Get-AdoPossibleOwners -Resource (Get-ClusterResource -Name $KeyResourceName)) + $Node | Select-Object -Unique)
    Set-AdoClusterResources -RoleName $ClusterRoleName -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName -SharedDiskResourceName $SharedDiskResourceName -ServiceName $service.Name -ConfigId $ConfigId -Node $owners | Out-Null
}

function Repair-AdoAgentCluster {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
        [string[]]$Node,
        [string]$EnvelopePath,
        [string]$ManifestPath,
        [switch]$Reseal,
        [System.Management.Automation.PSCredential]$ServiceCredential,
        [System.Management.Automation.PSCredential]$ProvisioningCredential
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    Assert-AdoRoleIdle -RoleName $ClusterRoleName -ServiceResourceName $ServiceResourceName -KeyResourceName $KeyResourceName -ConfirmAgentIdle:$ConfirmAgentIdle | Out-Null
    Test-AdoReleasePackage -PackagePath $PackagePath | Out-Null
    if (-not $Node) { $Node = @(Get-AdoPossibleOwners -Resource (Get-ClusterResource -Name $SharedDiskResourceName)) }
    $configPath = Join-Path (Join-Path $script:ConfigRoot $ConfigId.ToString('D')) 'config.json'
    $configuration = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $inspection = [pscustomobject]@{ data = [pscustomobject]@{ agentId = $configuration.expectedAgentId; publicKeySha256 = $configuration.expectedPublicKeySha256; targetFileSddl = $configuration.targetFileSddl } }
    $service = Get-AdoAgentServiceDefinition -AgentRoot $AgentRoot
    $rollbackJson = Get-Content -LiteralPath (Join-Path (Join-Path $script:ConfigRoot $ConfigId.ToString('D')) 'rollback.json') -Raw
    if ($Reseal -and (-not $EnvelopePath -or -not $ManifestPath)) { throw '-EnvelopePath and -ManifestPath are required with -Reseal.' }
    $remoteResealNodes = @($Node | Where-Object { -not (Test-AdoNodeIsLocal -Node $_) })
    if ($Reseal -and $remoteResealNodes.Count -gt 0 -and $null -eq $ProvisioningCredential) {
        throw "ProvisioningCredential is required to reseal remote nodes: $($remoteResealNodes -join ', ')."
    }
    if (-not $PSCmdlet.ShouldProcess($ClusterRoleName, "repair ConfigId $ConfigId on $($Node -join ', ')")) { return }
    foreach ($clusterNode in $Node) {
        Install-AdoPackageOnNode -Node $clusterNode -PackagePath $PackagePath
        Set-AdoNodeService -Node $clusterNode -Definition $service -ServiceCredential $ServiceCredential
        if ($Reseal) {
            Set-AdoNodeKeyMaterial -Node $clusterNode -ConfigId $ConfigId -EnvelopePath $EnvelopePath -ManifestPath $ManifestPath -Inspection $inspection -ResourceName $KeyResourceName -AgentRoot $AgentRoot -RollbackJson $rollbackJson -ProvisioningCredential $ProvisioningCredential
        }
        else {
            Set-AdoPreservedNodeConfiguration -Node $clusterNode -ConfigId $ConfigId -Inspection $inspection -ResourceName $KeyResourceName -AgentRoot $AgentRoot -RollbackJson $rollbackJson
        }
        Remove-AdoLegacySigningStateOnNode -Node $clusterNode -ConfigId $ConfigId
        $nodeReady = Invoke-Command -ComputerName $clusterNode -ScriptBlock {
            param($id)
            $directory = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id
            return (Test-Path -LiteralPath (Join-Path $directory 'config.json') -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $directory 'sealed.credentials_rsaparams') -PathType Leaf)
        } -ArgumentList $ConfigId.ToString('D')
        if (-not $nodeReady) { throw "Runtime configuration or sealed key is missing on '$clusterNode' after repair." }
    }
    Set-AdoClusterResources -RoleName $ClusterRoleName -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName -SharedDiskResourceName $SharedDiskResourceName -ServiceName $service.Name -ConfigId $ConfigId -Node $Node | Out-Null
    if ((Get-ClusterGroup -Name $ClusterRoleName).OwnerNode.Name -eq $env:COMPUTERNAME -and (Get-ClusterResource -Name $KeyResourceName).State -eq 'Online') {
        Invoke-AdoKeyHelper -Executable $script:HelperPath -Arguments @('probe', '--config-id', $ConfigId.ToString('D'), '--mode', 'full', '--json') | Out-Null
    }
}

function Remove-AdoAgentClusterNode {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][string]$Node,
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [switch]$PurgeSealedKey
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    $group = Get-ClusterGroup -Name $ClusterRoleName
    if ($group.OwnerNode.Name -eq $Node) { throw "Move '$ClusterRoleName' away from '$Node' before removing it." }
    $owners = @(Get-AdoPossibleOwners -Resource (Get-ClusterResource -Name $KeyResourceName) | Where-Object { $_ -ne $Node })
    if ($owners.Count -eq 0) { throw 'Removing the last possible owner is not allowed.' }
    if (-not $PSCmdlet.ShouldProcess($Node, "remove as possible owner; PurgeSealedKey=$PurgeSealedKey")) { return }
    Set-ClusterOwnerNode -Resource $KeyResourceName -Owners $owners | Out-Null
    Set-ClusterOwnerNode -Resource $ServiceResourceName -Owners $owners | Out-Null
    if ($PurgeSealedKey) {
        Invoke-Command -ComputerName $Node -ScriptBlock {
            param($id)
            $directory = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id
            $resolved = [IO.Path]::GetFullPath($directory)
            if (-not $resolved.StartsWith('C:\ProgramData\AdoAgentClusterKey\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing an unexpected purge path.' }
            if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
        } -ArgumentList $ConfigId.ToString('D')
    }
}

function Uninstall-AdoAgentCluster {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
        [switch]$PurgeSealedKeys,
        [switch]$PurgeEscrow,
        [string]$EnvelopePath,
        [string]$ManifestPath
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    Assert-AdoRoleIdle -RoleName $ClusterRoleName -ServiceResourceName $ServiceResourceName -KeyResourceName $KeyResourceName -ConfirmAgentIdle:$ConfirmAgentIdle | Out-Null
    $snapshotPath = Join-Path (Join-Path $script:ConfigRoot $ConfigId.ToString('D')) 'rollback.json'
    if (-not (Test-Path -LiteralPath $snapshotPath)) { throw "Rollback snapshot '$snapshotPath' is missing." }
    $snapshot = Get-Content -LiteralPath $snapshotPath -Raw | ConvertFrom-Json
    if ($PurgeEscrow -and (-not $EnvelopePath -or -not $ManifestPath)) { throw '-EnvelopePath and -ManifestPath are required with -PurgeEscrow.' }
    if (-not $PSCmdlet.ShouldProcess($ClusterRoleName, "restore snapshot and uninstall ConfigId $ConfigId")) { return }
    foreach ($resourceSnapshot in $snapshot.ClusterResources) {
        $resource = Get-AdoResourceOrNull -Name $resourceSnapshot.Name
        if (-not $resourceSnapshot.Existed) {
            if ($null -ne $resource) { Remove-ClusterResource -InputObject $resource -Force }
        }
        elseif ($null -ne $resource) {
            if (@($resourceSnapshot.Owners).Count -gt 0) { Set-ClusterOwnerNode -Resource $resource -Owners @($resourceSnapshot.Owners) | Out-Null }
            foreach ($entry in $resourceSnapshot.Parameters.PSObject.Properties) { Set-AdoClusterPrivateParameter -Resource $resource -Name $entry.Name -Value $entry.Value }
            $resource.RestartAction = [int]$resourceSnapshot.RestartAction
            $resource.PendingTimeout = [int]$resourceSnapshot.PendingTimeout
            $resource.LooksAlivePollInterval = [int]$resourceSnapshot.LooksAlivePollInterval
            $resource.IsAlivePollInterval = [int]$resourceSnapshot.IsAlivePollInterval
            if ($null -ne $resourceSnapshot.PSObject.Properties['DependencyExpression']) {
                Set-ClusterResourceDependency -Resource $resource.Name -Dependency ([string]$resourceSnapshot.DependencyExpression) | Out-Null
            }
        }
    }
    foreach ($serviceSnapshot in $snapshot.Services) {
        Invoke-Command -ComputerName $serviceSnapshot.Node -ScriptBlock {
            param($saved, $defaultName)
            $name = if ($saved.Name) { [string]$saved.Name } else { [string]$defaultName }
            $escaped = $name.Replace("'", "''")
            $service = Get-CimInstance Win32_Service -Filter "Name='$escaped'"
            if (-not $saved.Existed) {
                if ($null -ne $service) {
                    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                    Invoke-CimMethod -InputObject $service -MethodName Delete | Out-Null
                }
                return
            }
            if ($null -ne $service) {
                $savedMode = if ([string]$saved.StartMode -eq 'Auto') { 'Automatic' } else { [string]$saved.StartMode }
                Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{ PathName = [string]$saved.PathName; StartMode = $savedMode } | Out-Null
                $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
                if ($saved.FailureActionsBase64) { Set-ItemProperty -LiteralPath $registryPath -Name FailureActions -Value ([Convert]::FromBase64String([string]$saved.FailureActionsBase64)) }
                else { Remove-ItemProperty -LiteralPath $registryPath -Name FailureActions -ErrorAction SilentlyContinue }
                if ($null -ne $saved.FailureActionsOnNonCrashFailures) { Set-ItemProperty -LiteralPath $registryPath -Name FailureActionsOnNonCrashFailures -Value ([int]$saved.FailureActionsOnNonCrashFailures) }
                else { Remove-ItemProperty -LiteralPath $registryPath -Name FailureActionsOnNonCrashFailures -ErrorAction SilentlyContinue }
                if ($null -ne $saved.DelayedAutostart) { Set-ItemProperty -LiteralPath $registryPath -Name DelayedAutostart -Value ([int]$saved.DelayedAutostart) }
                else { Remove-ItemProperty -LiteralPath $registryPath -Name DelayedAutostart -ErrorAction SilentlyContinue }
                if ($saved.ServiceSddl) {
                    & sc.exe sdset $name ([string]$saved.ServiceSddl) | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "Unable to restore service SDDL for '$name'." }
                }
                if ($saved.ServiceSidType -in @('NONE','UNRESTRICTED','RESTRICTED')) {
                    & sc.exe sidtype $name ([string]$saved.ServiceSidType).ToLowerInvariant() | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "Unable to restore service SID type for '$name'." }
                }
            }
        } -ArgumentList $serviceSnapshot, $snapshot.ServiceName
    }
    if ($PurgeSealedKeys) {
        foreach ($node in $snapshot.Nodes) {
            Invoke-Command -ComputerName $node -ScriptBlock {
                param($id)
                $directory = [IO.Path]::GetFullPath((Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id))
                if (-not $directory.StartsWith('C:\ProgramData\AdoAgentClusterKey\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing an unexpected purge path.' }
                if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
            } -ArgumentList $ConfigId.ToString('D')
        }
    }
    if ($PurgeEscrow) {
        Remove-Item -LiteralPath $EnvelopePath, $ManifestPath -Force
    }
}

function Assert-AdoResetAuthenticationParameters {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth,
        [Security.SecureString]$RegistrationToken,
        [string]$RegistrationTokenEnvironmentVariableName,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [switch]$SkipAzureDevOpsUnregister
    )
    $hasToken = $null -ne $RegistrationToken
    $hasEnvironmentToken = -not [string]::IsNullOrWhiteSpace($RegistrationTokenEnvironmentVariableName)
    if ($hasToken -and $hasEnvironmentToken) { throw 'Specify either RegistrationToken or RegistrationTokenEnvironmentVariableName, not both.' }
    if ($SkipAzureDevOpsUnregister) {
        if ($hasToken -or $hasEnvironmentToken -or $null -ne $RegistrationCredential) {
            throw 'Registration credentials must not be supplied with SkipAzureDevOpsUnregister.'
        }
        return
    }
    if ($RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
        if (($hasToken -or $hasEnvironmentToken) -eq $false -or ($hasToken -and $hasEnvironmentToken)) {
            throw 'Token-based removal requires exactly one secure token source.'
        }
        if ($null -ne $RegistrationCredential) { throw 'RegistrationCredential is valid only with Negotiate.' }
        return
    }
    if ($hasToken -or $hasEnvironmentToken) { throw 'Token input is valid only with OAuthToken or PersonalAccessToken.' }
    if ($RegistrationAuth -eq 'Negotiate' -and $null -eq $RegistrationCredential) {
        throw 'Negotiate removal requires RegistrationCredential.'
    }
    if ($RegistrationAuth -eq 'Integrated' -and $null -ne $RegistrationCredential) {
        throw 'Integrated removal uses the current Windows identity and does not accept RegistrationCredential.'
    }
}

function Invoke-AdoAgentRegistrationRemoval {
    param(
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential
    )
    $configCommand = Join-Path $AgentRoot 'config.cmd'
    if (-not (Test-Path -LiteralPath $configCommand -PathType Leaf)) {
        throw "Microsoft agent config.cmd was not found at '$configCommand'."
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $env:ComSpec
    $start.Arguments = '/D /S /C ""{0}" remove --unattended"' -f $configCommand
    $start.WorkingDirectory = $AgentRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['VSO_AGENT_IGNORE'] = 'VSTS_AGENT_INPUT_TOKEN,VSTS_AGENT_INPUT_PASSWORD'
    if ($RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_AUTH'] = 'PAT'
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_TOKEN'] = $RegistrationSecret
    }
    elseif ($RegistrationAuth -eq 'Integrated') {
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_AUTH'] = 'Integrated'
    }
    else {
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_AUTH'] = 'Negotiate'
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_USERNAME'] = $RegistrationCredential.UserName
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_PASSWORD'] = $RegistrationCredential.GetNetworkCredential().Password
    }
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($start)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        if ($process.ExitCode -ne 0) {
            throw "Microsoft agent removal failed with exit code $($process.ExitCode). Protected key material was retained; review the agent's sanitized _diag log."
        }
        $stdout = $null
        $stderr = $null
    }
    finally {
        foreach ($name in @('VSTS_AGENT_INPUT_TOKEN', 'VSTS_AGENT_INPUT_PASSWORD')) {
            if ($start.EnvironmentVariables.ContainsKey($name)) { $start.EnvironmentVariables[$name] = '' }
        }
        if ($null -ne $process) { $process.Dispose() }
        $RegistrationSecret = $null
        $RegistrationCredential = $null
    }
}

function Get-AdoRollbackServiceNames {
    param(
        [Parameter(Mandatory = $true)][object]$RollbackSnapshot
    )
    $names = @()
    $servicesProperty = $RollbackSnapshot.PSObject.Properties['Services']
    if ($null -ne $servicesProperty) {
        foreach ($serviceSnapshot in @($servicesProperty.Value)) {
            if ($null -eq $serviceSnapshot) { continue }
            $nameProperty = $serviceSnapshot.PSObject.Properties['Name']
            if ($null -ne $nameProperty -and -not [string]::IsNullOrWhiteSpace([string]$nameProperty.Value)) {
                $names += [string]$nameProperty.Value
            }
        }
    }
    $serviceNameProperty = $RollbackSnapshot.PSObject.Properties['ServiceName']
    if ($null -ne $serviceNameProperty -and -not [string]::IsNullOrWhiteSpace([string]$serviceNameProperty.Value)) {
        $names += [string]$serviceNameProperty.Value
    }
    @($names | Sort-Object -Unique)
}

function Reset-AdoAgentCluster {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][string]$EscrowPath,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth = 'PersonalAccessToken',
        [Security.SecureString]$RegistrationToken,
        [string]$RegistrationTokenEnvironmentVariableName,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
        [Parameter(Mandatory = $true)][switch]$ConfirmPermanentReset,
        [switch]$SkipAzureDevOpsUnregister,
        [switch]$RemoveToolkitBinaries
    )
    Assert-AdoElevated
    if (-not $ConfirmAgentIdle) { throw '-ConfirmAgentIdle is required and must be true.' }
    if (-not $ConfirmPermanentReset) { throw '-ConfirmPermanentReset is required and must be true.' }
    Assert-AdoResetAuthenticationParameters -RegistrationAuth $RegistrationAuth -RegistrationToken $RegistrationToken -RegistrationTokenEnvironmentVariableName $RegistrationTokenEnvironmentVariableName -RegistrationCredential $RegistrationCredential -SkipAzureDevOpsUnregister:$SkipAzureDevOpsUnregister
    Import-Module FailoverClusters -ErrorAction Stop

    $resolvedAgentRoot = Get-AdoCanonicalPath -Path $AgentRoot -MustExist
    $resolvedEscrow = Get-AdoCanonicalPath -Path $EscrowPath -MustExist
    Assert-AdoNoReparsePoint -Path $resolvedAgentRoot
    Assert-AdoNoReparsePoint -Path $resolvedEscrow
    $agentVolumeRoot = [IO.Path]::GetPathRoot($resolvedAgentRoot).TrimEnd('\')
    if ($resolvedAgentRoot.TrimEnd('\') -eq $agentVolumeRoot) { throw 'AgentRoot must not be a volume root.' }

    $disk = Get-ClusterResource -Name $SharedDiskResourceName -ErrorAction Stop
    $role = Get-ClusterGroup -Name $ClusterRoleName -ErrorAction Stop
    if ([string]$disk.OwnerGroup.Name -ne $ClusterRoleName) { throw 'The shared disk is not owned by the requested cluster role.' }
    if ([string]$disk.State -ne 'Online') { throw 'The shared disk must remain Online during reset.' }
    if ([string]$disk.OwnerNode.Name -ne $env:COMPUTERNAME) {
        throw "Run reset on shared-disk owner '$($disk.OwnerNode.Name)'."
    }
    [string[]]$nodes = @(Get-AdoPossibleOwners -Resource $disk)
    if ($nodes.Count -eq 0) { throw 'The shared disk has no possible owner nodes.' }
    $runtimeDirectory = Join-Path $script:ConfigRoot $ConfigId.ToString('D')
    $rollbackPath = Join-Path $runtimeDirectory 'rollback.json'
    $runtimeConfigPath = Join-Path $runtimeDirectory 'config.json'
    if (-not (Test-Path -LiteralPath $rollbackPath -PathType Leaf)) { throw "Rollback snapshot '$rollbackPath' is missing." }
    if (-not (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf)) { throw "Runtime configuration '$runtimeConfigPath' is missing." }
    $rollbackSnapshot = Get-Content -LiteralPath $rollbackPath -Raw | ConvertFrom-Json
    [string[]]$serviceNames = @(Get-AdoRollbackServiceNames -RollbackSnapshot $rollbackSnapshot)
    if ($serviceNames.Count -eq 0) { throw 'Rollback snapshot does not identify the agent service to remove.' }
    $serviceNamePayload = [pscustomobject]@{ Names = $serviceNames }
    $runtimeConfig = Get-Content -LiteralPath $runtimeConfigPath -Raw | ConvertFrom-Json
    $configuredAgentRoot = Get-AdoCanonicalPath -Path ([string]$runtimeConfig.agentRoot)
    if ([string]$runtimeConfig.configId -ne $ConfigId.ToString('D') -or
        [string]$runtimeConfig.resourceName -ne $KeyResourceName -or
        $configuredAgentRoot -ne $resolvedAgentRoot) {
        throw 'Runtime configuration does not bind the requested ConfigId, key resource, and AgentRoot.'
    }
    if (-not $SkipAzureDevOpsUnregister -and -not (Test-Path -LiteralPath (Join-Path $resolvedAgentRoot 'config.cmd') -PathType Leaf)) {
        throw 'Microsoft agent config.cmd is required to unregister the Azure DevOps agent before purge.'
    }

    $action = "permanently unregister and purge ConfigId $($ConfigId.ToString('D')) from $($nodes -join ', ')"
    if (-not $PSCmdlet.ShouldProcess($ClusterRoleName, $action)) {
        return [pscustomobject]@{ ConfigId = $ConfigId; Planned = $true; Nodes = $nodes; AgentRoot = $resolvedAgentRoot; EscrowPath = $resolvedEscrow }
    }

    $registrationSecret = $null
    try {
        foreach ($resourceName in @($ServiceResourceName, $KeyResourceName)) {
            $resource = Get-AdoResourceOrNull -Name $resourceName
            if ($null -ne $resource -and [string]$resource.State -ne 'Offline') {
                Stop-ClusterResource -InputObject $resource -Wait 60 | Out-Null
            }
        }
        Uninstall-AdoAgentCluster -ConfigId $ConfigId -ClusterRoleName $ClusterRoleName -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName -ConfirmAgentIdle -Confirm:$false

        foreach ($resourceName in @($ServiceResourceName, $KeyResourceName)) {
            $resource = Get-AdoResourceOrNull -Name $resourceName
            if ($null -ne $resource) { Remove-ClusterResource -InputObject $resource -Force }
        }

        if (-not $SkipAzureDevOpsUnregister) {
            if ($RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
                $registrationSecret = Get-AdoRegistrationSecret -RegistrationToken $RegistrationToken -RegistrationTokenEnvironmentVariableName $RegistrationTokenEnvironmentVariableName
            }
            Invoke-AdoAgentRegistrationRemoval -AgentRoot $resolvedAgentRoot -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential
        }

        $nodeResults = @(Invoke-Command -ComputerName $nodes -ScriptBlock {
            param($id, $agentRoot, $expectedServiceNames, $removeToolkit)
            $escapedAgentRoot = [WildcardPattern]::Escape($agentRoot.TrimEnd('\') + '\')
            $servicePathPattern = '*' + $escapedAgentRoot + '*'
            $services = @(
                foreach ($serviceName in @($expectedServiceNames.Names)) {
                    $escapedServiceName = ([string]$serviceName).Replace("'", "''")
                    $service = Get-CimInstance Win32_Service -Filter "Name='$escapedServiceName'" -ErrorAction SilentlyContinue
                    if ($null -ne $service) {
                        if ($service.Name -notlike 'vstsagent*' -or $service.PathName -notlike $servicePathPattern) {
                            throw "Refusing to delete service '$($service.Name)' because it is not bound beneath the requested AgentRoot."
                        }
                        $service
                    }
                }
            )
            foreach ($service in $services) {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                Invoke-CimMethod -InputObject $service -MethodName Delete | Out-Null
            }

            $runtimeRoot = [IO.Path]::GetFullPath('C:\ProgramData\AdoAgentClusterKey').TrimEnd('\')
            $target = [IO.Path]::GetFullPath((Join-Path $runtimeRoot $id))
            if (-not $target.StartsWith($runtimeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing unexpected runtime purge path '$target'."
            }
            if (Test-Path -LiteralPath $target) {
                if (((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to purge a runtime reparse point.' }
                Remove-Item -LiteralPath $target -Recurse -Force
            }

            $binariesRemoved = $false
            if ($removeToolkit) {
                $remaining = @(Get-ChildItem -LiteralPath $runtimeRoot -Force -ErrorAction SilentlyContinue)
                if ($remaining.Count -eq 0) {
                    $installRoot = [IO.Path]::GetFullPath('C:\Program Files\AdoAgentClusterKey').TrimEnd('\')
                    if ($installRoot -ne 'C:\Program Files\AdoAgentClusterKey') { throw 'Refusing an unexpected toolkit installation path.' }
                    if (Test-Path -LiteralPath $installRoot) {
                        if (((Get-Item -LiteralPath $installRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to purge a toolkit reparse point.' }
                        Remove-Item -LiteralPath $installRoot -Recurse -Force
                    }
                    if (Test-Path -LiteralPath $runtimeRoot) { Remove-Item -LiteralPath $runtimeRoot -Force }
                    $binariesRemoved = $true
                }
            }
            [pscustomobject]@{ Node = $env:COMPUTERNAME; RemovedServices = @($services.Name); RuntimeRemoved = -not (Test-Path -LiteralPath $target); BinariesRemoved = $binariesRemoved }
        } -ArgumentList $ConfigId.ToString('D'), $resolvedAgentRoot, $serviceNamePayload, ([bool]$RemoveToolkitBinaries))

        $removedEscrow = @()
        foreach ($suffix in @('.envelope.bin', '.manifest.json', '.rollback.json', '.setup.json')) {
            $artifact = Join-Path $resolvedEscrow ($ConfigId.ToString('D') + $suffix)
            $resolvedArtifact = [IO.Path]::GetFullPath($artifact)
            if (-not $resolvedArtifact.StartsWith($resolvedEscrow + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing an unexpected escrow purge path.' }
            if (Test-Path -LiteralPath $resolvedArtifact) {
                Remove-Item -LiteralPath $resolvedArtifact -Force
                $removedEscrow += $resolvedArtifact
            }
        }

        Assert-AdoNoReparsePoint -Path $resolvedAgentRoot
        if (Test-Path -LiteralPath $resolvedAgentRoot) { Remove-Item -LiteralPath $resolvedAgentRoot -Recurse -Force }
        [pscustomobject]@{
            ConfigId = $ConfigId
            Reset = $true
            AzureDevOpsUnregistered = -not $SkipAzureDevOpsUnregister
            Nodes = $nodes
            NodeResults = $nodeResults
            RemovedEscrowArtifacts = $removedEscrow
            AgentRootRemoved = -not (Test-Path -LiteralPath $resolvedAgentRoot)
            ClusterRolePreserved = $null -ne (Get-ClusterGroup -Name $role.Name -ErrorAction SilentlyContinue)
            SharedDiskPreserved = $null -ne (Get-ClusterResource -Name $disk.Name -ErrorAction SilentlyContinue)
        }
    }
    finally {
        $registrationSecret = $null
        $RegistrationCredential = $null
    }
}

function Invoke-AdoAgentClusterEvaluation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][Guid]$ConfigId,
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName,
        [Parameter(Mandatory = $true)][string[]]$Node,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [scriptblock]$PoolStatusProbe,
        [scriptblock]$CanaryPipeline,
        [switch]$IncludeNegativeTests,
        [switch]$IncludeServiceRecoveryTest,
        [switch]$IncludeRepairTest,
        [hashtable]$RepairParameters,
        [switch]$IncludeRollbackTest,
        [hashtable]$RollbackParameters
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    if ($Node.Count -ne 2) { throw 'Evaluation requires exactly two possible-owner nodes.' }
    if ($IncludeRepairTest -and $null -eq $RepairParameters) { throw '-RepairParameters is required with -IncludeRepairTest.' }
    if ($IncludeRollbackTest -and $null -eq $RollbackParameters) { throw '-RollbackParameters is required with -IncludeRollbackTest.' }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $records = New-Object System.Collections.Generic.List[object]
    function Add-Evidence([string]$test, [bool]$passed, [datetime]$started, [string]$detail, $measurements) {
        $records.Add([pscustomobject]@{ Test = $test; Passed = $passed; StartedUtc = $started.ToUniversalTime().ToString('o'); FinishedUtc = [DateTime]::UtcNow.ToString('o'); Detail = $detail; Measurements = $measurements })
    }
    if (-not $PSCmdlet.ShouldProcess($ClusterRoleName, "run two-node failover evaluation for ConfigId $ConfigId")) { return }
    foreach ($clusterNode in $Node) {
        $started = Get-Date
        try {
            $ready = Invoke-Command -ComputerName $clusterNode -ScriptBlock {
                param($id)
                $directory = Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id
                $config = Join-Path $directory 'config.json'
                $sealed = Join-Path $directory 'sealed.credentials_rsaparams'
                $configItem = Get-Item -LiteralPath $config -Force -ErrorAction SilentlyContinue
                $sealedItem = Get-Item -LiteralPath $sealed -Force -ErrorAction SilentlyContinue
                return $null -ne $configItem -and -not $configItem.PSIsContainer -and
                    $null -ne $sealedItem -and -not $sealedItem.PSIsContainer -and
                    $sealedItem.Length -gt 0
            } -ArgumentList $ConfigId.ToString('D')
            Add-Evidence "Preflight:$clusterNode" ([bool]$ready) $started 'Node-local configuration and sealed key are present; cryptographic validation follows when this node owns storage.' @{ Node = $clusterNode }
        }
        catch { Add-Evidence "Preflight:$clusterNode" $false $started $_.Exception.Message @{ Node = $clusterNode } }
    }
    foreach ($target in @($Node[1], $Node[0])) {
        $started = Get-Date
        try {
            Move-ClusterGroup -Name $ClusterRoleName -Node $target -Wait 300 | Out-Null
            $elapsed = ((Get-Date) - $started).TotalSeconds
            $keyOnline = (Get-ClusterResource -Name $KeyResourceName).State -eq 'Online'
            $serviceOnline = (Get-ClusterResource -Name $ServiceResourceName).State -eq 'Online'
            $fullProbe = $false
            if ($keyOnline) {
                $probeResult = Invoke-Command -ComputerName $target -ScriptBlock { param($id) & 'C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe' probe --config-id $id --mode full --json | Out-Null; return $LASTEXITCODE } -ArgumentList $ConfigId.ToString('D')
                $fullProbe = $probeResult[-1] -eq 0
            }
            $passiveNode = ($Node | Where-Object { $_ -ne $target })[0]
            $passiveStopped = Invoke-Command -ComputerName $passiveNode -ScriptBlock { param($name) (Get-Service -Name $name).Status -eq 'Stopped' } -ArgumentList ((Get-ClusterResource -Name $ServiceResourceName | Get-ClusterParameter -Name ServiceName).Value)
            $poolOnline = if ($PoolStatusProbe) { [bool](& $PoolStatusProbe $target) } else { $null }
            $canary = if ($CanaryPipeline) { [bool](& $CanaryPipeline $target) } else { $null }
            $passed = $keyOnline -and $serviceOnline -and $fullProbe -and $passiveStopped -and $elapsed -le 300 -and ($null -eq $poolOnline -or $poolOnline) -and ($null -eq $canary -or $canary)
            Add-Evidence "PlannedMove:$target" $passed $started 'Planned ownership move and owner-side cryptographic probe completed.' @{ MoveSeconds = $elapsed; KeyOnline = $keyOnline; ServiceOnline = $serviceOnline; FullProbe = $fullProbe; PassiveServiceStopped = $passiveStopped; PoolOnline = $poolOnline; CanaryPassed = $canary }
        }
        catch { Add-Evidence "PlannedMove:$target" $false $started $_.Exception.Message @{} }
    }
    if ($IncludeServiceRecoveryTest) {
        $started = Get-Date
        try {
            $owner = (Get-ClusterGroup -Name $ClusterRoleName).OwnerNode.Name
            $serviceName = (Get-ClusterResource -Name $ServiceResourceName | Get-ClusterParameter -Name ServiceName).Value
            Invoke-Command -ComputerName $owner -ScriptBlock {
                param($name)
                $escaped = $name.Replace("'", "''")
                $service = Get-CimInstance Win32_Service -Filter "Name='$escaped'"
                if ($null -eq $service -or [int]$service.ProcessId -le 0) { throw 'The clustered service process is not running.' }
                Stop-Process -Id ([int]$service.ProcessId) -Force
            } -ArgumentList $serviceName
            $deadline = (Get-Date).AddSeconds(180)
            do {
                Start-Sleep -Seconds 2
                $resource = Get-ClusterResource -Name $ServiceResourceName
            } until ($resource.State -eq 'Online' -or (Get-Date) -ge $deadline)
            Add-Evidence 'ServiceRecovery' ($resource.State -eq 'Online') $started 'The service process was terminated and WSFC-controlled recovery was observed.' @{ Owner = $owner; State = [string]$resource.State; RecoverySeconds = ((Get-Date) - $started).TotalSeconds }
        }
        catch { Add-Evidence 'ServiceRecovery' $false $started $_.Exception.Message @{} }
    }
    if ($IncludeNegativeTests) {
        $passive = ($Node | Where-Object { $_ -ne (Get-ClusterGroup -Name $ClusterRoleName).OwnerNode.Name })[0]
        foreach ($case in @('missing', 'corrupt')) {
            $started = Get-Date
            $result = $false
            $detail = ''
            try {
                Invoke-Command -ComputerName $passive -ScriptBlock {
                    param($id, $mode)
                    $path = Join-Path (Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id) 'sealed.credentials_rsaparams'
                    $backup = $path + '.evaluation-backup'
                    Copy-Item -LiteralPath $path -Destination $backup -Force
                    if ($mode -eq 'missing') { Remove-Item -LiteralPath $path -Force }
                    else {
                        [IO.File]::SetAttributes($path, ([IO.File]::GetAttributes($path) -band (-bnot [IO.FileAttributes]::Hidden)))
                        [IO.File]::WriteAllBytes($path, [byte[]](1,2,3,4,5,6,7,8))
                    }
                } -ArgumentList $ConfigId.ToString('D'), $case
                try { Move-ClusterGroup -Name $ClusterRoleName -Node $passive -Wait 90 -ErrorAction Stop | Out-Null } catch { }
                $serviceOffline = (Get-ClusterResource -Name $ServiceResourceName).State -ne 'Online'
                $result = $serviceOffline
                $detail = 'Selector failed closed and the service did not start.'
            }
            catch { $detail = $_.Exception.Message }
            finally {
                Invoke-Command -ComputerName $passive -ScriptBlock {
                    param($id)
                    $path = Join-Path (Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id) 'sealed.credentials_rsaparams'
                    $backup = $path + '.evaluation-backup'
                    if (Test-Path -LiteralPath $backup) { Move-Item -LiteralPath $backup -Destination $path -Force }
                } -ArgumentList $ConfigId.ToString('D') -ErrorAction SilentlyContinue
                try { Start-ClusterGroup -Name $ClusterRoleName -Wait 300 | Out-Null } catch { }
            }
            Add-Evidence "NegativeKey:$case" $result $started $detail @{ PassiveNode = $passive }
        }
    }
    if ($IncludeRepairTest) {
        $started = Get-Date
        try {
            Stop-ClusterResource -Name $ServiceResourceName -Wait 120 | Out-Null
            Stop-ClusterResource -Name $KeyResourceName -Wait 120 | Out-Null
            Repair-AdoAgentCluster @RepairParameters -Confirm:$false
            Start-ClusterGroup -Name $ClusterRoleName -Wait 300 | Out-Null
            $target = ($Node | Where-Object { $_ -ne (Get-ClusterGroup -Name $ClusterRoleName).OwnerNode.Name })[0]
            Move-ClusterGroup -Name $ClusterRoleName -Node $target -Wait 300 | Out-Null
            $passed = (Get-ClusterResource -Name $KeyResourceName).State -eq 'Online' -and (Get-ClusterResource -Name $ServiceResourceName).State -eq 'Online'
            Add-Evidence 'RepairAndMove' $passed $started 'Repair completed and the role moved to the other owner.' @{ Target = $target; Seconds = ((Get-Date) - $started).TotalSeconds }
        }
        catch { Add-Evidence 'RepairAndMove' $false $started $_.Exception.Message @{} }
    }
    if ($IncludeRollbackTest) {
        $started = Get-Date
        try {
            Stop-ClusterResource -Name $ServiceResourceName -Wait 120 | Out-Null
            Stop-ClusterResource -Name $KeyResourceName -Wait 120 | Out-Null
            Uninstall-AdoAgentCluster @RollbackParameters -Confirm:$false
            $sealedPreserved = $true
            foreach ($clusterNode in $Node) {
                $present = Invoke-Command -ComputerName $clusterNode -ScriptBlock {
                    param($id)
                    Test-Path -LiteralPath (Join-Path (Join-Path 'C:\ProgramData\AdoAgentClusterKey' $id) 'sealed.credentials_rsaparams') -PathType Leaf
                } -ArgumentList $ConfigId.ToString('D')
                $sealedPreserved = $sealedPreserved -and [bool]$present
            }
            $escrowPreserved = $true
            if ($RollbackParameters.ContainsKey('EnvelopePath')) { $escrowPreserved = $escrowPreserved -and (Test-Path -LiteralPath $RollbackParameters.EnvelopePath -PathType Leaf) }
            if ($RollbackParameters.ContainsKey('ManifestPath')) { $escrowPreserved = $escrowPreserved -and (Test-Path -LiteralPath $RollbackParameters.ManifestPath -PathType Leaf) }
            Add-Evidence 'DefaultUninstallRollback' ($sealedPreserved -and $escrowPreserved) $started 'Rollback ran without purge and protected material remained.' @{ SealedPreserved = $sealedPreserved; EscrowPreserved = $escrowPreserved }
        }
        catch { Add-Evidence 'DefaultUninstallRollback' $false $started $_.Exception.Message @{} }
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath = Join-Path $OutputPath "evaluation-$timestamp.json"
    $markdownPath = Join-Path $OutputPath "evaluation-$timestamp.md"
    $summary = [pscustomobject]@{ SchemaVersion = 1; ConfigId = $ConfigId.ToString('D'); GeneratedUtc = [DateTime]::UtcNow.ToString('o'); Passed = @($records | Where-Object { -not $_.Passed }).Count -eq 0; Evidence = $records.ToArray() }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    $lines = @('# ADO Agent Cluster Evaluation', '', "- ConfigId: ``$ConfigId``", "- Generated UTC: $($summary.GeneratedUtc)", "- Overall: $(if ($summary.Passed) { 'GO' } else { 'NO-GO' })", '', '| Test | Result | Detail |', '|---|---:|---|')
    foreach ($record in $records) { $lines += "| $($record.Test) | $(if ($record.Passed) { 'PASS' } else { 'FAIL' }) | $($record.Detail -replace '\|','/') |" }
    $lines += @('', '## Gate interpretation', '', 'GO requires every selected test to pass, each planned move to complete within 300 seconds, the key and service resources to be Online, and any supplied pool/canary probes to pass. In-flight jobs are not resumable.')
    Set-Content -LiteralPath $markdownPath -Value $lines -Encoding UTF8
    [pscustomobject]@{ Passed = $summary.Passed; JsonPath = $jsonPath; MarkdownPath = $markdownPath; Evidence = $records.ToArray() }
}

Export-ModuleMember -Function @(
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
