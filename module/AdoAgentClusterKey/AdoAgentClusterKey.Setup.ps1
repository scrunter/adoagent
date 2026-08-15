Set-StrictMode -Version 2.0

$script:AdoSetupSchemaVersion = 1
$script:AdoSetupPhases = @('Preflight', 'PackageStaged', 'RegisteredStopped', 'KeyValidated', 'ClusterInstalled', 'Complete')

function Get-AdoSetupPhaseIndex {
    param([Parameter(Mandatory = $true)][string]$Phase)
    $index = [Array]::IndexOf($script:AdoSetupPhases, $Phase)
    if ($index -lt 0) { throw "Unknown setup phase '$Phase'." }
    return $index
}

function ConvertFrom-AdoSecureString {
    param([Parameter(Mandatory = $true)][Security.SecureString]$SecureValue)
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Get-AdoRegistrationSecret {
    param(
        [Security.SecureString]$RegistrationToken,
        [string]$RegistrationTokenEnvironmentVariableName,
        [switch]$PreserveEnvironmentVariable
    )
    if ($null -ne $RegistrationToken -and -not [string]::IsNullOrWhiteSpace($RegistrationTokenEnvironmentVariableName)) {
        throw 'Specify either RegistrationToken or RegistrationTokenEnvironmentVariableName, not both.'
    }
    if ($null -ne $RegistrationToken) { return ConvertFrom-AdoSecureString -SecureValue $RegistrationToken }
    if ([string]::IsNullOrWhiteSpace($RegistrationTokenEnvironmentVariableName)) { return $null }
    if ($RegistrationTokenEnvironmentVariableName -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$') {
        throw 'RegistrationTokenEnvironmentVariableName is invalid.'
    }
    $value = [Environment]::GetEnvironmentVariable($RegistrationTokenEnvironmentVariableName, 'Process')
    if (-not $PreserveEnvironmentVariable) { [Environment]::SetEnvironmentVariable($RegistrationTokenEnvironmentVariableName, $null, 'Process') }
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "The requested registration-token environment variable is missing or empty."
    }
    return $value
}

function Test-AdoPasswordlessServiceIdentity {
    param([Parameter(Mandatory = $true)][string]$Identity)
    return $Identity -in @(
        'LocalSystem',
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\LOCAL SERVICE',
        'NT AUTHORITY\NETWORK SERVICE'
    ) -or $Identity.EndsWith('$')
}

function Get-AdoServiceIdentityForWindows {
    param([Parameter(Mandatory = $true)][string]$Identity)
    if ($Identity -eq 'LocalSystem') { return 'NT AUTHORITY\SYSTEM' }
    return $Identity
}

function Assert-AdoSetupParameters {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Services', 'Server')][string]$ServerType,
        [Parameter(Mandatory = $true)][ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth,
        [Security.SecureString]$RegistrationToken,
        [string]$RegistrationTokenEnvironmentVariableName,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [System.Management.Automation.PSCredential]$ServiceCredential,
        [Parameter(Mandatory = $true)][string]$WorkDirectory,
        [switch]$AllowInsecureServerUrl,
        [switch]$TokenOptional
    )
    if ($null -ne $RegistrationToken -and -not [string]::IsNullOrWhiteSpace($RegistrationTokenEnvironmentVariableName)) {
        throw 'Specify either RegistrationToken or RegistrationTokenEnvironmentVariableName, not both.'
    }
    if ($ServerType -eq 'Services' -and $RegistrationAuth -notin @('OAuthToken', 'PersonalAccessToken')) {
        throw 'Azure DevOps Services supports OAuthToken or PersonalAccessToken in this setup workflow.'
    }
    if ($ServerType -eq 'Server' -and $RegistrationAuth -eq 'OAuthToken') {
        throw 'OAuthToken registration is supported only for Azure DevOps Services.'
    }
    if ($RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
        if ($null -ne $RegistrationCredential) { throw 'RegistrationCredential is valid only with Negotiate.' }
        if (-not $TokenOptional) {
            $sourceCount = 0
            if ($null -ne $RegistrationToken) { $sourceCount++ }
            if (-not [string]::IsNullOrWhiteSpace($RegistrationTokenEnvironmentVariableName)) { $sourceCount++ }
            if ($sourceCount -ne 1) { throw 'Token authentication requires exactly one secure token source.' }
        }
    }
    else {
        if ($null -ne $RegistrationToken -or -not [string]::IsNullOrWhiteSpace($RegistrationTokenEnvironmentVariableName)) {
            throw 'Token input is valid only with OAuthToken or PersonalAccessToken.'
        }
        if ($RegistrationAuth -eq 'Negotiate' -and $null -eq $RegistrationCredential) {
            throw 'Negotiate registration requires RegistrationCredential.'
        }
        if ($RegistrationAuth -eq 'Integrated' -and $null -ne $RegistrationCredential) {
            throw 'Integrated registration uses the current Windows identity and does not accept RegistrationCredential.'
        }
    }
    if ($AllowInsecureServerUrl -and $ServerType -ne 'Server') {
        throw 'AllowInsecureServerUrl is valid only for Azure DevOps Server.'
    }
    if ([string]::IsNullOrWhiteSpace($WorkDirectory)) { throw 'WorkDirectory must not be empty.' }
    if ([IO.Path]::IsPathRooted($WorkDirectory) -or $WorkDirectory -match '(^|[\\/])\.\.([\\/]|$)' -or $WorkDirectory.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) {
        throw 'WorkDirectory must be a relative path beneath AgentRoot without traversal.'
    }
    if ($null -ne $ServiceCredential -and -not $ServiceCredential.UserName.Equals($ServiceAccount, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ServiceCredential user name must match ServiceAccount.'
    }
    if (-not (Test-AdoPasswordlessServiceIdentity -Identity $ServiceAccount) -and $null -eq $ServiceCredential) {
        throw 'A regular domain ServiceAccount requires an in-memory ServiceCredential.'
    }
}

function Get-AdoCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$MustExist)
    if ($MustExist) { return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path).TrimEnd('\') }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Assert-AdoNoReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$AllowMissingLeaf)
    $candidate = Get-AdoCanonicalPath -Path $Path
    if ($AllowMissingLeaf -and -not (Test-Path -LiteralPath $candidate)) { $candidate = Split-Path -Parent $candidate }
    while (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Path '$Path' contains a reparse point."
        }
        $root = [IO.Path]::GetPathRoot($candidate)
        if ($candidate.TrimEnd('\') -eq $root.TrimEnd('\')) { break }
        $parent = [IO.Path]::GetDirectoryName($candidate.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Get-AdoNormalizedServerUri {
    param(
        [Parameter(Mandatory = $true)][string]$AzureDevOpsUrl,
        [Parameter(Mandatory = $true)][ValidateSet('Services', 'Server')][string]$ServerType,
        [switch]$AllowInsecureServerUrl
    )
    $uri = $null
    if (-not [Uri]::TryCreate($AzureDevOpsUrl, [UriKind]::Absolute, [ref]$uri)) { throw 'AzureDevOpsUrl must be an absolute URL.' }
    if ($uri.UserInfo -or $uri.Fragment -or $uri.Query) { throw 'AzureDevOpsUrl must not contain credentials, a query, or a fragment.' }
    if ($uri.Scheme -ne 'https') {
        if ($ServerType -ne 'Server' -or -not $AllowInsecureServerUrl -or $uri.Scheme -ne 'http') {
            throw 'AzureDevOpsUrl must use HTTPS unless Azure DevOps Server is explicitly allowed to use HTTP.'
        }
    }
    if ($ServerType -eq 'Services' -and $uri.Host -ne 'dev.azure.com' -and -not $uri.Host.EndsWith('.visualstudio.com', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Azure DevOps Services URL must use dev.azure.com or an organization.visualstudio.com host.'
    }
    return [Uri]($uri.AbsoluteUri.TrimEnd('/') + '/')
}

function Test-AdoMicrosoftDownloadHost {
    param([Parameter(Mandatory = $true)][string]$HostName)
    $hostValue = $HostName.ToLowerInvariant()
    foreach ($suffix in @('dev.azure.com', 'visualstudio.com', 'azureedge.net', 'microsoft.com')) {
        if ($hostValue -eq $suffix -or $hostValue.EndsWith('.' + $suffix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Assert-AdoHttpUri {
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][ValidateSet('Services', 'Server')][string]$ServerType,
        [switch]$AllowInsecureServerUrl,
        [switch]$PackageDownload
    )
    if ($Uri.UserInfo -or $Uri.Fragment) { throw 'A request URI contained prohibited user information or a fragment.' }
    $sameHost = $Uri.Host.Equals($BaseUri.Host, [StringComparison]::OrdinalIgnoreCase) -and $Uri.Port -eq $BaseUri.Port
    if ($Uri.Scheme -ne 'https') {
        if (-not ($sameHost -and $ServerType -eq 'Server' -and $AllowInsecureServerUrl -and $Uri.Scheme -eq 'http')) {
            throw 'An Azure DevOps request or redirect attempted to use an insecure URI.'
        }
    }
    if (-not $sameHost) {
        if (-not $PackageDownload -or -not (Test-AdoMicrosoftDownloadHost -HostName $Uri.Host)) {
            throw 'An Azure DevOps request or redirect targeted an unapproved host.'
        }
    }
}

function New-AdoHttpClient {
    param(
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [switch]$UseCredentials
    )
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    if ($UseCredentials -and $RegistrationAuth -eq 'Integrated') { $handler.UseDefaultCredentials = $true }
    elseif ($UseCredentials -and $RegistrationAuth -eq 'Negotiate') { $handler.Credentials = $RegistrationCredential.GetNetworkCredential() }
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(5)
    return $client
}

function Get-AdoAuthorizationHeaderValue {
    param(
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret
    )
    Add-Type -AssemblyName System.Net.Http
    if ($RegistrationAuth -eq 'OAuthToken') {
        return New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $RegistrationSecret)
    }
    if ($RegistrationAuth -eq 'PersonalAccessToken') {
        $bytes = [Text.Encoding]::ASCII.GetBytes(':' + $RegistrationSecret)
        try {
            $encoded = [Convert]::ToBase64String($bytes)
            return New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Basic', $encoded)
        }
        finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    return $null
}

function Invoke-AdoHttpGet {
    param(
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][ValidateSet('Services', 'Server')][string]$ServerType,
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [string]$OutputPath,
        [switch]$AllowInsecureServerUrl,
        [switch]$PackageDownload
    )
    $current = $Uri
    for ($redirect = 0; $redirect -le 5; $redirect++) {
        Assert-AdoHttpUri -Uri $current -BaseUri $BaseUri -ServerType $ServerType -AllowInsecureServerUrl:$AllowInsecureServerUrl -PackageDownload:$PackageDownload
        $sameHost = $current.Host.Equals($BaseUri.Host, [StringComparison]::OrdinalIgnoreCase) -and $current.Port -eq $BaseUri.Port
        $client = New-AdoHttpClient -RegistrationAuth $RegistrationAuth -RegistrationCredential $RegistrationCredential -UseCredentials:$sameHost
        $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $current)
        $response = $null
        try {
            if ($sameHost -and $RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
                $request.Headers.Authorization = Get-AdoAuthorizationHeaderValue -RegistrationAuth $RegistrationAuth -RegistrationSecret $RegistrationSecret
            }
            $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                if ($null -eq $response.Headers.Location) { throw 'An HTTP redirect did not include a Location header.' }
                $current = if ($response.Headers.Location.IsAbsoluteUri) { $response.Headers.Location } else { New-Object Uri($current, $response.Headers.Location) }
                continue
            }
            if (-not $response.IsSuccessStatusCode) { throw "Azure DevOps returned HTTP status $status." }
            if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                return [pscustomobject]@{ Uri = $current; Content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult(); StatusCode = $status }
            }
            $stream = $null
            $file = $null
            try {
                $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $file = New-Object IO.FileStream($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $stream.CopyTo($file)
                $file.Flush($true)
            }
            finally {
                if ($null -ne $file) { $file.Dispose() }
                if ($null -ne $stream) { $stream.Dispose() }
            }
            return [pscustomobject]@{ Uri = $current; Content = $null; StatusCode = $status }
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
            $request.Dispose()
            $client.Dispose()
        }
    }
    throw 'Azure DevOps exceeded the maximum permitted redirect count.'
}

function ConvertFrom-AdoJsonResponse {
    param([Parameter(Mandatory = $true)][string]$Content, [Parameter(Mandatory = $true)][string]$Operation)
    try { return $Content | ConvertFrom-Json }
    catch { throw "Azure DevOps returned malformed JSON while $Operation." }
}

function Get-AdoManagedAgentPool {
    param(
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][string]$PoolName,
        [Parameter(Mandatory = $true)][string]$ServerType,
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [switch]$AllowInsecureServerUrl
    )
    $escaped = [Uri]::EscapeDataString($PoolName)
    $uri = New-Object Uri($BaseUri, "_apis/distributedtask/pools?poolName=$escaped&actionFilter=manage&api-version=5.0")
    $response = Invoke-AdoHttpGet -Uri $uri -BaseUri $BaseUri -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $RegistrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
    $json = ConvertFrom-AdoJsonResponse -Content $response.Content -Operation 'validating agent-pool administration'
    [object[]]$items = @()
    if ($null -ne $json.PSObject.Properties['value']) { $items = [object[]]@($json.value) }
    else { $items = [object[]]@($json) }
    $matches = @($items | Where-Object { [string]$_.name -eq $PoolName })
    if ($matches.Count -ne 1) { throw 'The deployment identity cannot manage the exact requested agent pool, or the pool is ambiguous.' }
    return $matches[0]
}

function Get-AdoExistingAgent {
    param(
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][int]$PoolId,
        [Parameter(Mandatory = $true)][string]$AgentName,
        [Parameter(Mandatory = $true)][string]$ServerType,
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [switch]$AllowInsecureServerUrl
    )
    $escaped = [Uri]::EscapeDataString($AgentName)
    $uri = New-Object Uri($BaseUri, "_apis/distributedtask/pools/$PoolId/agents?agentName=$escaped&api-version=5.0")
    $response = Invoke-AdoHttpGet -Uri $uri -BaseUri $BaseUri -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $RegistrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
    $json = ConvertFrom-AdoJsonResponse -Content $response.Content -Operation 'checking the requested agent name'
    [object[]]$items = @()
    if ($null -ne $json.PSObject.Properties['value']) { $items = [object[]]@($json.value) }
    else { $items = [object[]]@($json) }
    $matches = @($items | Where-Object { [string]$_.name -eq $AgentName })
    if ($matches.Count -gt 1) { throw 'Azure DevOps returned more than one exact agent-name match.' }
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Get-AdoAgentPackageMetadata {
    param(
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][string]$ServerType,
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [switch]$AllowInsecureServerUrl
    )
    $uri = New-Object Uri($BaseUri, '_apis/distributedtask/packages/agent?platform=win-x64&%24top=1')
    $response = Invoke-AdoHttpGet -Uri $uri -BaseUri $BaseUri -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $RegistrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
    $json = ConvertFrom-AdoJsonResponse -Content $response.Content -Operation 'selecting a compatible agent package'
    [object[]]$items = @()
    if ($null -ne $json.PSObject.Properties['value']) { $items = [object[]]@($json.value) }
    else { $items = [object[]]@($json) }
    if ($items.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$items[0].downloadUrl)) {
        throw 'Azure DevOps did not return exactly one compatible win-x64 agent package.'
    }
    $downloadUri = $null
    if (-not [Uri]::TryCreate([string]$items[0].downloadUrl, [UriKind]::Absolute, [ref]$downloadUri)) {
        throw 'Azure DevOps returned an invalid agent-package URL.'
    }
    Assert-AdoHttpUri -Uri $downloadUri -BaseUri $BaseUri -ServerType $ServerType -AllowInsecureServerUrl:$AllowInsecureServerUrl -PackageDownload
    return [pscustomobject]@{ Version = [string]$items[0].version; DownloadUri = $downloadUri }
}

function Get-AdoSetupAgentMetadata {
    param([Parameter(Mandatory = $true)][string]$AgentRoot)
    $path = Join-Path $AgentRoot '.agent'
    try { $agent = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    catch { throw 'The configured .agent file is missing or malformed.' }
    $id = $null
    foreach ($name in @('agentId', 'id')) {
        if ($agent.PSObject.Properties.Name -contains $name -and $null -ne $agent.$name) { $id = [string]$agent.$name; break }
    }
    $nameValue = $null
    foreach ($name in @('agentName', 'name')) {
        if ($agent.PSObject.Properties.Name -contains $name -and $agent.$name) { $nameValue = [string]$agent.$name; break }
    }
    if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($nameValue)) { throw 'The configured .agent identity is incomplete.' }
    return [pscustomobject]@{ Id = $id; Name = $nameValue }
}

function Get-AdoAgentRegistrationState {
    param([Parameter(Mandatory = $true)][string]$AgentRoot)
    $packageFiles = @('config.cmd', 'run.cmd', 'bin\Agent.Listener.exe')
    $registrationFiles = @('.agent', '.credentials', '.credentials_rsaparams', '.service')
    $packageCount = @($packageFiles | Where-Object { Test-Path -LiteralPath (Join-Path $AgentRoot $_) -PathType Leaf }).Count
    $registrationCount = @($registrationFiles | Where-Object { Test-Path -LiteralPath (Join-Path $AgentRoot $_) -PathType Leaf }).Count
    if ($packageCount -eq 0 -and $registrationCount -eq 0) { return 'Empty' }
    if ($packageCount -eq $packageFiles.Count -and $registrationCount -eq 0) { return 'PackageStaged' }
    if ($packageCount -eq $packageFiles.Count -and $registrationCount -eq $registrationFiles.Count) { return 'Registered' }
    return 'Partial'
}

function Expand-AdoAgentArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$AgentRoot
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $target = Get-AdoCanonicalPath -Path $AgentRoot
    $parent = Split-Path -Parent $target
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'AgentRoot parent directory must already exist.' }
    Assert-AdoNoReparsePoint -Path $parent
    if (Test-Path -LiteralPath $target) {
        Assert-AdoNoReparsePoint -Path $target
        $item = Get-Item -LiteralPath $target -Force
        if (-not $item.PSIsContainer -or @(Get-ChildItem -LiteralPath $target -Force).Count -ne 0) { throw 'AgentRoot must be absent or empty before package staging.' }
    }
    $stage = Join-Path $parent ('.adoagent-stage-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $archive = $null
    try {
        $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
        foreach ($entry in $archive.Entries) {
            $relative = ([string]$entry.FullName).Replace('/', '\')
            if ([string]::IsNullOrWhiteSpace($relative)) { continue }
            if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':')) { throw 'The agent archive contains an unsafe absolute or alternate-stream path.' }
            $destination = [IO.Path]::GetFullPath((Join-Path $stage $relative))
            if (-not $destination.StartsWith($stage + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'The agent archive contains a traversal path.' }
            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            if ($unixType -eq 0xA000) { throw 'The agent archive contains a symbolic-link entry.' }
            if ($relative.EndsWith('\')) { [IO.Directory]::CreateDirectory($destination) | Out-Null; continue }
            $destinationParent = Split-Path -Parent $destination
            [IO.Directory]::CreateDirectory($destinationParent) | Out-Null
            $input = $null
            $output = $null
            try {
                $input = $entry.Open()
                $output = New-Object IO.FileStream($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $input.CopyTo($output)
                $output.Flush($true)
            }
            finally {
                if ($null -ne $output) { $output.Dispose() }
                if ($null -ne $input) { $input.Dispose() }
            }
        }
        foreach ($required in @('config.cmd', 'run.cmd', 'bin\Agent.Listener.exe')) {
            if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw "The agent archive is missing '$required'." }
        }
        foreach ($item in Get-ChildItem -LiteralPath $stage -Force -Recurse) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The extracted agent package contains a reparse point.' }
        }
        if (Test-Path -LiteralPath $target) { [IO.Directory]::Delete($target, $false) }
        [IO.Directory]::Move($stage, $target)
        $stage = $null
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}

function Get-AdoAgentConfigArguments {
    param([switch]$ReplaceExistingAgent)
    $arguments = '/D /S /C ""{0}" --unattended --runAsService --preventServiceStart{1}"'
    return $arguments
}

function Invoke-AdoAgentConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][string]$PoolName,
        [Parameter(Mandatory = $true)][string]$AgentName,
        [Parameter(Mandatory = $true)][string]$WorkDirectory,
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [System.Management.Automation.PSCredential]$ServiceCredential,
        [switch]$ReplaceExistingAgent
    )
    $configPath = Join-Path $AgentRoot 'config.cmd'
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $env:ComSpec
    $replace = if ($ReplaceExistingAgent) { ' --replace' } else { '' }
    $template = Get-AdoAgentConfigArguments -ReplaceExistingAgent:$ReplaceExistingAgent
    $start.Arguments = $template -f $configPath, $replace
    $start.WorkingDirectory = $AgentRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['VSTS_AGENT_INPUT_URL'] = $BaseUri.AbsoluteUri.TrimEnd('/')
    $start.EnvironmentVariables['VSTS_AGENT_INPUT_POOL'] = $PoolName
    $start.EnvironmentVariables['VSTS_AGENT_INPUT_AGENT'] = $AgentName
    $start.EnvironmentVariables['VSTS_AGENT_INPUT_WORK'] = $WorkDirectory
    $start.EnvironmentVariables['VSTS_AGENT_INPUT_WINDOWSLOGONACCOUNT'] = Get-AdoServiceIdentityForWindows -Identity $ServiceAccount
    $start.EnvironmentVariables['VSO_AGENT_IGNORE'] = 'VSTS_AGENT_INPUT_TOKEN,VSTS_AGENT_INPUT_PASSWORD,VSTS_AGENT_INPUT_WINDOWSLOGONPASSWORD'
    if ($RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_AUTH'] = 'PAT'
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_TOKEN'] = $RegistrationSecret
    }
    elseif ($RegistrationAuth -eq 'Integrated') { $start.EnvironmentVariables['VSTS_AGENT_INPUT_AUTH'] = 'Integrated' }
    else {
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_AUTH'] = 'Negotiate'
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_USERNAME'] = $RegistrationCredential.UserName
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_PASSWORD'] = $RegistrationCredential.GetNetworkCredential().Password
    }
    if ($null -ne $ServiceCredential) {
        $start.EnvironmentVariables['VSTS_AGENT_INPUT_WINDOWSLOGONPASSWORD'] = $ServiceCredential.GetNetworkCredential().Password
    }
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Microsoft agent configuration failed with exit code $($process.ExitCode). Review the agent's sanitized _diag log." }
        $stdout = $null
        $stderr = $null
    }
    finally {
        foreach ($name in @('VSTS_AGENT_INPUT_TOKEN', 'VSTS_AGENT_INPUT_PASSWORD', 'VSTS_AGENT_INPUT_WINDOWSLOGONPASSWORD')) {
            if ($start.EnvironmentVariables.ContainsKey($name)) { $start.EnvironmentVariables[$name] = '' }
        }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Set-AdoSetupServiceStopped {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe config $ServiceName 'start=' 'demand' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to set the newly configured agent service to Manual.' }
    & sc.exe failure $ServiceName 'reset=' '0' 'actions=' '""' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to disable independent recovery for the newly configured agent service.' }
    $service = Get-Service -Name $ServiceName
    if ($service.Status -ne 'Stopped') { throw 'The newly configured agent service is not stopped.' }
}

function Test-AdoAgentOffline {
    param(
        [Parameter(Mandatory = $true)][Uri]$BaseUri,
        [Parameter(Mandatory = $true)][int]$PoolId,
        [Parameter(Mandatory = $true)][string]$AgentName,
        [Parameter(Mandatory = $true)][string]$ServerType,
        [Parameter(Mandatory = $true)][string]$RegistrationAuth,
        [string]$RegistrationSecret,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [switch]$AllowInsecureServerUrl
    )
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $agent = Get-AdoExistingAgent -BaseUri $BaseUri -PoolId $PoolId -AgentName $AgentName -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $RegistrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
        if ($null -ne $agent -and [string]$agent.status -eq 'offline') { return $true }
        if ($attempt -lt 9) { Start-Sleep -Seconds 2 }
    }
    throw 'Azure DevOps did not report the newly registered agent as Offline.'
}

function Test-AdoPathAclForIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Identity,
        [switch]$UsingParent
    )
    $windowsIdentity = Get-AdoServiceIdentityForWindows -Identity $Identity
    $sid = (New-Object Security.Principal.NTAccount($windowsIdentity)).Translate([Security.Principal.SecurityIdentifier])
    $acl = Get-Acl -LiteralPath $Path
    $allow = [Security.AccessControl.FileSystemRights]0
    $deny = [Security.AccessControl.FileSystemRights]0
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ne $sid.Value) { continue }
        if ($UsingParent -and (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -eq 0)) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) { $deny = $deny -bor $rule.FileSystemRights }
        else { $allow = $allow -bor $rule.FileSystemRights }
    }
    $effective = $allow -band (-bnot $deny)
    $required = [Security.AccessControl.FileSystemRights]::Modify
    return (($effective -band $required) -eq $required)
}

function Get-AdoServiceIdentityChecks {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceIdentity,
        [Parameter(Mandatory = $true)][string[]]$Node,
        [Parameter(Mandatory = $true)][string]$AgentRoot
    )
    $checks = New-Object System.Collections.Generic.List[object]
    $passwordlessBuiltin = $ServiceIdentity -in @('LocalSystem', 'NT AUTHORITY\SYSTEM', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
    $windowsIdentity = Get-AdoServiceIdentityForWindows -Identity $ServiceIdentity
    foreach ($targetNode in $Node) {
        try {
            $result = Invoke-Command -ComputerName $targetNode -ScriptBlock {
                param($identity, $skipUserRight)
                $sid = (New-Object Security.Principal.NTAccount($identity)).Translate([Security.Principal.SecurityIdentifier]).Value
                if ($skipUserRight) { return [pscustomobject]@{ Sid = $sid; HasLogonRight = $true } }
                $temporary = Join-Path $env:TEMP ('AdoAgentClusterKey-rights-' + [Guid]::NewGuid().ToString('N') + '.inf')
                try {
                    & secedit.exe /export /areas USER_RIGHTS /cfg $temporary /quiet | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'secedit export failed.' }
                    $line = Get-Content -LiteralPath $temporary | Where-Object { $_ -match '^SeServiceLogonRight\s*=' } | Select-Object -First 1
                    $hasRight = $false
                    if ($line) {
                        $values = @(($line -split '=', 2)[1] -split ',' | ForEach-Object { $_.Trim() })
                        $hasRight = $values -contains ('*' + $sid) -or $values -contains $identity
                    }
                    return [pscustomobject]@{ Sid = $sid; HasLogonRight = $hasRight }
                }
                finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
            } -ArgumentList $windowsIdentity, $passwordlessBuiltin
            $checks.Add([pscustomobject]@{ Name = "ServiceIdentity:$targetNode"; Passed = $true; Detail = "SID=$($result.Sid)" })
            $checks.Add([pscustomobject]@{ Name = "ServiceLogonRight:$targetNode"; Passed = [bool]$result.HasLogonRight; Detail = 'SeServiceLogonRight must be assigned by policy.' })
        }
        catch { $checks.Add([pscustomobject]@{ Name = "ServiceIdentity:$targetNode"; Passed = $false; Detail = $_.Exception.Message }) }
    }
    try {
        $aclPath = if (Test-Path -LiteralPath $AgentRoot -PathType Container) { $AgentRoot } else { Split-Path -Parent (Get-AdoCanonicalPath -Path $AgentRoot) }
        $usingParent = -not (Test-Path -LiteralPath $AgentRoot -PathType Container)
        $hasAccess = Test-AdoPathAclForIdentity -Path $aclPath -Identity $ServiceIdentity -UsingParent:$usingParent
        $checks.Add([pscustomobject]@{ Name = 'ServiceAgentRootAccess'; Passed = $hasAccess; Detail = "An explicit inheritable Modify ACE for '$ServiceIdentity' is required on '$aclPath'." })
    }
    catch { $checks.Add([pscustomobject]@{ Name = 'ServiceAgentRootAccess'; Passed = $false; Detail = $_.Exception.Message }) }
    return $checks.ToArray()
}

function Get-AdoSetupImmutableData {
    param($Bound)
    $nodes = @($Bound.Node | Sort-Object -Unique)
    return [ordered]@{
        schemaVersion = $script:AdoSetupSchemaVersion
        configId = $Bound.ConfigId.ToString('D')
        serverType = $Bound.ServerType
        azureDevOpsUrl = $Bound.BaseUri.AbsoluteUri.TrimEnd('/')
        registrationAuth = $Bound.RegistrationAuth
        poolName = $Bound.PoolName
        agentName = $Bound.AgentName
        agentRoot = $Bound.AgentRoot
        workDirectory = $Bound.WorkDirectory
        clusterRoleName = $Bound.ClusterRoleName
        sharedDiskResourceName = $Bound.SharedDiskResourceName
        node = $nodes
        protectorGroup = $Bound.ProtectorGroup
        escrowPath = $Bound.EscrowPath
        toolkitPackagePath = $Bound.ToolkitPackagePath
        agentPackagePath = $Bound.AgentPackagePath
        agentPackageSha256 = $Bound.AgentPackageSha256
        serviceAccount = $Bound.ServiceAccount
        allowInsecureServerUrl = [bool]$Bound.AllowInsecureServerUrl
    }
}

function Get-AdoObjectSha256 {
    param([Parameter(Mandatory = $true)]$InputObject)
    $json = $InputObject | ConvertTo-Json -Depth 10 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') }
        finally { $sha.Dispose() }
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Test-AdoSetupToolkitPathOnlyChange {
    param(
        [Parameter(Mandatory = $true)]$SavedImmutable,
        [Parameter(Mandatory = $true)]$RequestedImmutable
    )
    $savedCopy = $SavedImmutable | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $requestedCopy = $RequestedImmutable | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    if ($savedCopy.PSObject.Properties.Name -notcontains 'toolkitPackagePath' -or
        $requestedCopy.PSObject.Properties.Name -notcontains 'toolkitPackagePath') {
        return $false
    }
    $savedCopy.toolkitPackagePath = [string]$requestedCopy.toolkitPackagePath
    return (Get-AdoObjectSha256 -InputObject $savedCopy) -eq (Get-AdoObjectSha256 -InputObject $requestedCopy)
}

function Test-AdoSetupPermittedResumeChange {
    param(
        [Parameter(Mandatory = $true)]$SavedImmutable,
        [Parameter(Mandatory = $true)]$RequestedImmutable,
        [switch]$AllowProtectorGroupChange
    )
    $savedCopy = $SavedImmutable | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $requestedCopy = $RequestedImmutable | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    foreach ($property in @('toolkitPackagePath', 'protectorGroup')) {
        if ($savedCopy.PSObject.Properties.Name -notcontains $property -or
            $requestedCopy.PSObject.Properties.Name -notcontains $property) {
            return $false
        }
    }
    $savedCopy.toolkitPackagePath = [string]$requestedCopy.toolkitPackagePath
    if ($AllowProtectorGroupChange) {
        $savedCopy.protectorGroup = [string]$requestedCopy.protectorGroup
    }
    return (Get-AdoObjectSha256 -InputObject $savedCopy) -eq (Get-AdoObjectSha256 -InputObject $requestedCopy)
}

function Test-AdoSetupKeyArtifactsExist {
    param(
        [Parameter(Mandatory = $true)][string]$EscrowPath,
        [Parameter(Mandatory = $true)][Guid]$ConfigId
    )
    $stem = $ConfigId.ToString('D')
    foreach ($suffix in @('.envelope.bin', '.manifest.json', '.rollback.json')) {
        if (Test-Path -LiteralPath (Join-Path $EscrowPath ($stem + $suffix)) -PathType Leaf) { return $true }
    }
    return $false
}

function Write-AdoSetupState {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$State)
    $operationId = [Guid]::NewGuid().ToString('N')
    $temporary = $Path + '.tmp.' + $operationId
    $backup = $Path + '.bak.' + $operationId
    $utf8 = New-Object Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText($temporary, ($State | ConvertTo-Json -Depth 12), $utf8)
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, $backup, $true) }
        else { [IO.File]::Move($temporary, $Path) }
    }
    finally {
        foreach ($artifact in @($temporary, $backup)) {
            try { if (Test-Path -LiteralPath $artifact) { [IO.File]::Delete($artifact) } }
            catch { }
        }
    }
}

function New-AdoSetupState {
    param([Parameter(Mandatory = $true)]$Immutable, [Parameter(Mandatory = $true)][string]$Hash)
    return [pscustomobject][ordered]@{
        schemaVersion = $script:AdoSetupSchemaVersion
        configId = [string]$Immutable.configId
        immutableSha256 = $Hash
        immutable = $Immutable
        phase = 'Preflight'
        createdUtc = [DateTime]::UtcNow.ToString('o')
        updatedUtc = [DateTime]::UtcNow.ToString('o')
        packageVersion = $null
        packageDownloadUrl = $null
        packageSha256 = $null
        poolId = $null
        agentId = $null
        serviceName = $null
        registrationOfflineVerified = $false
        lastFailurePhase = $null
        lastFailureOperation = $null
    }
}

function Set-AdoSetupPhase {
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$Phase, [Parameter(Mandatory = $true)][string]$StatePath)
    [void](Get-AdoSetupPhaseIndex -Phase $Phase)
    $State.phase = $Phase
    $State.updatedUtc = [DateTime]::UtcNow.ToString('o')
    $State.lastFailurePhase = $null
    if ($null -eq $State.PSObject.Properties['lastFailureOperation']) {
        $State | Add-Member -NotePropertyName lastFailureOperation -NotePropertyValue $null
    }
    else { $State.lastFailureOperation = $null }
    Write-AdoSetupState -Path $StatePath -State $State
}

function Assert-AdoSetupClusterContext {
    param(
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string[]]$Node,
        [Parameter(Mandatory = $true)][string]$KeyResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceResourceName
    )
    $group = Get-ClusterGroup -Name $ClusterRoleName
    $disk = Get-ClusterResource -Name $SharedDiskResourceName
    if ($disk.OwnerGroup.Name -ne $ClusterRoleName) { throw 'SharedDiskResourceName does not belong to ClusterRoleName.' }
    if ($disk.State -ne 'Online' -or $disk.OwnerNode.Name -ne $env:COMPUTERNAME) { throw 'The shared disk must be Online on the current cluster owner during setup.' }
    $diskOwners = @(Get-AdoPossibleOwners -Resource $disk)
    foreach ($name in $Node) { if ($diskOwners -notcontains $name) { throw "Node '$name' is not a possible owner of the shared disk." } }
    foreach ($resourceName in @($KeyResourceName, $ServiceResourceName)) {
        $resource = Get-AdoResourceOrNull -Name $resourceName
        if ($null -ne $resource -and $resource.State -ne 'Offline') { throw "Cluster resource '$resourceName' must be Offline during setup." }
    }
    return [pscustomobject]@{ Group = $group; Disk = $disk; Nodes = $Node }
}

function Initialize-AdoAgentCluster {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Services', 'Server')][string]$ServerType,
        [Parameter(Mandatory = $true)][string]$AzureDevOpsUrl,
        [Parameter(Mandatory = $true)][ValidateSet('OAuthToken', 'PersonalAccessToken', 'Integrated', 'Negotiate')][string]$RegistrationAuth,
        [Security.SecureString]$RegistrationToken,
        [string]$RegistrationTokenEnvironmentVariableName,
        [System.Management.Automation.PSCredential]$RegistrationCredential,
        [Parameter(Mandatory = $true)][string]$PoolName,
        [Parameter(Mandatory = $true)][string]$AgentName,
        [Parameter(Mandatory = $true)][string]$AgentRoot,
        [string]$WorkDirectory = '_work',
        [Parameter(Mandatory = $true)][string]$ClusterRoleName,
        [Parameter(Mandatory = $true)][string]$SharedDiskResourceName,
        [Parameter(Mandatory = $true)][string]$ProtectorGroup,
        [Parameter(Mandatory = $true)][string]$EscrowPath,
        [Parameter(Mandatory = $true)][string]$ToolkitPackagePath,
        [string]$AgentPackagePath,
        [string]$AgentPackageSha256,
        [string[]]$Node,
        [Guid]$ConfigId = [Guid]::Empty,
        [string]$KeyResourceName,
        [string]$ServiceResourceName,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [System.Management.Automation.PSCredential]$ServiceCredential,
        [Parameter(Mandatory = $true)][switch]$ConfirmAgentIdle,
        [switch]$Resume,
        [switch]$ReplaceExistingAgent,
        [switch]$AllowInsecureServerUrl
    )
    Assert-AdoElevated
    Import-Module FailoverClusters -ErrorAction Stop
    if (-not $ConfirmAgentIdle) { throw '-ConfirmAgentIdle is required and must be true.' }
    foreach ($requiredValue in @($PoolName, $AgentName, $AgentRoot, $ClusterRoleName, $SharedDiskResourceName, $ProtectorGroup, $EscrowPath, $ToolkitPackagePath, $ServiceAccount)) {
        if ([string]::IsNullOrWhiteSpace([string]$requiredValue)) { throw 'A required setup string is empty.' }
    }
    if ($ConfigId -eq [Guid]::Empty) { $ConfigId = [Guid]::NewGuid() }
    if (-not $KeyResourceName) { $KeyResourceName = "$ClusterRoleName - Key Selector" }
    if (-not $ServiceResourceName) { $ServiceResourceName = "$ClusterRoleName - ADO Agent" }
    if (-not $Node) {
        $diskForOwners = Get-ClusterResource -Name $SharedDiskResourceName
        $Node = @(Get-AdoPossibleOwners -Resource $diskForOwners)
    }
    $Node = @($Node | Sort-Object -Unique)
    if ($Node.Count -eq 0) { throw 'At least one possible owner node is required.' }
    $baseUri = Get-AdoNormalizedServerUri -AzureDevOpsUrl $AzureDevOpsUrl -ServerType $ServerType -AllowInsecureServerUrl:$AllowInsecureServerUrl
    $resolvedAgentRoot = Get-AdoCanonicalPath -Path $AgentRoot
    $resolvedEscrow = Get-AdoCanonicalPath -Path $EscrowPath -MustExist
    $resolvedToolkit = Get-AdoCanonicalPath -Path $ToolkitPackagePath -MustExist
    if (-not (Test-Path -LiteralPath $resolvedEscrow -PathType Container)) { throw 'EscrowPath must be a pre-created directory.' }
    $agentRootVolume = [IO.Path]::GetPathRoot($resolvedAgentRoot).TrimEnd('\')
    if ($resolvedAgentRoot -eq $agentRootVolume) { throw 'AgentRoot must not be a volume root.' }
    if ($resolvedEscrow -eq $resolvedAgentRoot -or
        $resolvedEscrow.StartsWith($resolvedAgentRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $resolvedAgentRoot.StartsWith($resolvedEscrow + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'EscrowPath must be outside AgentRoot.'
    }
    Assert-AdoNoReparsePoint -Path $resolvedAgentRoot -AllowMissingLeaf
    Assert-AdoNoReparsePoint -Path $resolvedEscrow
    Assert-AdoNoReparsePoint -Path $resolvedToolkit
    Test-AdoReleasePackage -PackagePath $resolvedToolkit | Out-Null
    try { Get-AdoProtectorGroupValidation -Identity $ProtectorGroup | Out-Null }
    catch { throw "ProtectorGroup prerequisite failed. $($_.Exception.Message)" }
    if ([string]::IsNullOrWhiteSpace($AgentPackagePath) -ne [string]::IsNullOrWhiteSpace($AgentPackageSha256)) {
        throw 'AgentPackagePath and AgentPackageSha256 must be supplied together.'
    }
    if ($AgentPackageSha256 -and $AgentPackageSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'AgentPackageSha256 must contain exactly 64 hexadecimal characters.' }
    $statePath = Join-Path $resolvedEscrow ($ConfigId.ToString('D') + '.setup.json')
    $state = $null
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        Assert-AdoNoReparsePoint -Path $statePath
        if (-not $Resume) { throw 'Setup state already exists. Use -Resume with the same ConfigId.' }
        try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }
        catch { throw 'The setup-state file is malformed.' }
        if ([int]$state.schemaVersion -ne $script:AdoSetupSchemaVersion -or [string]$state.configId -ne $ConfigId.ToString('D')) { throw 'The setup-state identity or schema is invalid.' }
        if ([string]$state.immutableSha256 -ne (Get-AdoObjectSha256 -InputObject $state.immutable)) { throw 'The setup-state immutable input hash is invalid.' }
    }
    elseif ($Resume) { throw 'Resume was requested but the setup-state file does not exist.' }
    $phase = if ($null -eq $state) { 'Preflight' } else { [string]$state.phase }
    $phaseIndex = Get-AdoSetupPhaseIndex -Phase $phase
    $tokenOptional = $phaseIndex -ge (Get-AdoSetupPhaseIndex -Phase 'RegisteredStopped') -and [bool]$state.registrationOfflineVerified
    Assert-AdoSetupParameters -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationToken $RegistrationToken -RegistrationTokenEnvironmentVariableName $RegistrationTokenEnvironmentVariableName -RegistrationCredential $RegistrationCredential -ServiceAccount $ServiceAccount -ServiceCredential $ServiceCredential -WorkDirectory $WorkDirectory -AllowInsecureServerUrl:$AllowInsecureServerUrl -TokenOptional:$tokenOptional
    $context = Assert-AdoSetupClusterContext -ClusterRoleName $ClusterRoleName -SharedDiskResourceName $SharedDiskResourceName -Node $Node -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName
    $identityChecks = @(Get-AdoServiceIdentityChecks -ServiceIdentity $ServiceAccount -Node $Node -AgentRoot $resolvedAgentRoot)
    $failedIdentityChecks = @($identityChecks | Where-Object { -not $_.Passed })
    if ($failedIdentityChecks.Count -gt 0) {
        $failedNames = @($failedIdentityChecks | ForEach-Object { $_.Name }) -join ', '
        throw "Service identity prerequisite failed: $failedNames."
    }
    $bound = [pscustomobject]@{
        ConfigId = $ConfigId; ServerType = $ServerType; BaseUri = $baseUri; RegistrationAuth = $RegistrationAuth
        PoolName = $PoolName; AgentName = $AgentName; AgentRoot = $resolvedAgentRoot; WorkDirectory = $WorkDirectory
        ClusterRoleName = $ClusterRoleName; SharedDiskResourceName = $SharedDiskResourceName; Node = $Node
        ProtectorGroup = $ProtectorGroup; EscrowPath = $resolvedEscrow; ToolkitPackagePath = $resolvedToolkit
        AgentPackagePath = if ($AgentPackagePath) { Get-AdoCanonicalPath -Path $AgentPackagePath -MustExist } else { $null }
        AgentPackageSha256 = if ($AgentPackageSha256) { $AgentPackageSha256.ToUpperInvariant() } else { $null }
        ServiceAccount = $ServiceAccount; AllowInsecureServerUrl = [bool]$AllowInsecureServerUrl
    }
    if ($bound.AgentPackagePath) { Assert-AdoNoReparsePoint -Path $bound.AgentPackagePath }
    $immutable = Get-AdoSetupImmutableData -Bound $bound
    $immutableHash = Get-AdoObjectSha256 -InputObject $immutable
    $rebindToolkitPackage = $false
    $rebindProtectorGroup = $false
    if ($null -ne $state -and [string]$state.immutableSha256 -ne $immutableHash) {
        $protectorChanged = [string]$state.immutable.protectorGroup -cne [string]$immutable.protectorGroup
        $keyArtifactsExist = Test-AdoSetupKeyArtifactsExist -EscrowPath $resolvedEscrow -ConfigId $ConfigId
        $allowProtectorGroupChange = $phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'ClusterInstalled') -and -not $keyArtifactsExist
        if (-not $Resume -or -not (Test-AdoSetupPermittedResumeChange -SavedImmutable $state.immutable -RequestedImmutable $immutable -AllowProtectorGroupChange:$allowProtectorGroupChange)) {
            if ($protectorChanged -and $keyArtifactsExist) {
                throw 'ProtectorGroup cannot change because escrow or rollback key artifacts already exist for this ConfigId.'
            }
            throw 'Resume inputs do not match the immutable setup state.'
        }
        $rebindToolkitPackage = [string]$state.immutable.toolkitPackagePath -cne [string]$immutable.toolkitPackagePath
        $rebindProtectorGroup = $protectorChanged
    }
    $registrationSecret = $null
    $pool = $null
    $packageMetadata = $null
    $existingAgent = $null
    $serviceNameForFailure = if ($null -ne $state) { [string]$state.serviceName } else { $null }
    $currentOperation = 'Authorization'
    try {
        $needsAuthorization = $phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'RegisteredStopped') -or ($null -ne $state -and -not [bool]$state.registrationOfflineVerified)
        if ($needsAuthorization -and $RegistrationAuth -in @('OAuthToken', 'PersonalAccessToken')) {
            $registrationSecret = Get-AdoRegistrationSecret -RegistrationToken $RegistrationToken -RegistrationTokenEnvironmentVariableName $RegistrationTokenEnvironmentVariableName -PreserveEnvironmentVariable:$WhatIfPreference
        }
        if ($needsAuthorization) {
            $currentOperation = 'ValidatePoolAuthorization'
            $pool = Get-AdoManagedAgentPool -BaseUri $baseUri -PoolName $PoolName -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
            if ($phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'PackageStaged') -and -not $AgentPackagePath) {
                $currentOperation = 'SelectAgentPackage'
                $packageMetadata = Get-AdoAgentPackageMetadata -BaseUri $baseUri -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
            }
            $currentOperation = 'CheckExistingAgent'
            $existingAgent = Get-AdoExistingAgent -BaseUri $baseUri -PoolId ([int]$pool.id) -AgentName $AgentName -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl
            $canResumeLocalRegistration = $Resume -and (Get-AdoAgentRegistrationState -AgentRoot $resolvedAgentRoot) -eq 'Registered'
            if ($null -ne $existingAgent -and $phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'RegisteredStopped') -and [string]$existingAgent.status -ne 'offline') {
                throw 'The existing exact-name agent is not Offline; replacement is prohibited.'
            }
            if ($null -ne $existingAgent -and $phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'RegisteredStopped') -and -not $ReplaceExistingAgent -and -not $canResumeLocalRegistration) {
                throw 'An agent with the requested name already exists. Use -ReplaceExistingAgent only after confirming it is the intended stopped registration.'
            }
        }
        if (-not $PSCmdlet.ShouldProcess($ClusterRoleName, "download, register, and cluster Azure DevOps agent '$AgentName' as ConfigId $ConfigId")) {
            return [pscustomobject]@{ ConfigId = $ConfigId; Planned = $true; StatePath = $statePath; Nodes = $Node; AgentRoot = $resolvedAgentRoot }
        }
        if ($rebindToolkitPackage -or $rebindProtectorGroup) {
            $currentOperation = if ($rebindProtectorGroup) { 'RebindProtectorGroup' } else { 'RebindToolkitPackage' }
            $state.immutable = $immutable
            $state.immutableSha256 = $immutableHash
            $state.updatedUtc = [DateTime]::UtcNow.ToString('o')
            Write-AdoSetupState -Path $statePath -State $state
        }
        if ($null -eq $state) {
            $currentOperation = 'CreateSetupState'
            $state = New-AdoSetupState -Immutable $immutable -Hash $immutableHash
            if ($null -ne $pool) { $state.poolId = [int]$pool.id }
            Write-AdoSetupState -Path $statePath -State $state
            $phaseIndex = Get-AdoSetupPhaseIndex -Phase 'Preflight'
        }
        $currentOperation = 'InspectAgentRoot'
        $rootState = Get-AdoAgentRegistrationState -AgentRoot $resolvedAgentRoot
        if ($phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'PackageStaged')) {
            if ($rootState -eq 'Partial') { throw 'AgentRoot contains a partial package or registration. Preserve it and follow the documented explicit recovery procedure.' }
            if ($rootState -in @('PackageStaged', 'Registered')) {
                if (-not $Resume -or [string]::IsNullOrWhiteSpace([string]$state.packageSha256)) {
                    throw 'AgentRoot is not empty and cannot be safely bound to this new setup state.'
                }
                Set-AdoSetupPhase -State $state -Phase 'PackageStaged' -StatePath $statePath
                $phaseIndex = Get-AdoSetupPhaseIndex -Phase 'PackageStaged'
            }
            else {
            $archivePath = $null
            $deleteArchive = $false
            try {
                if ($AgentPackagePath) {
                    $currentOperation = 'ValidateOfflinePackage'
                    $archivePath = $bound.AgentPackagePath
                    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
                    if ($actualHash -ne $bound.AgentPackageSha256) { throw 'Offline agent-package SHA-256 does not match AgentPackageSha256.' }
                    $state.packageVersion = 'offline'
                    $state.packageDownloadUrl = $null
                    $state.packageSha256 = $actualHash
                }
                else {
                    if ($null -eq $packageMetadata) { throw 'Compatible agent-package metadata is unavailable.' }
                    $archivePath = Join-Path ([IO.Path]::GetTempPath()) ('ado-agent-' + [Guid]::NewGuid().ToString('N') + '.zip')
                    $deleteArchive = $true
                    $currentOperation = 'DownloadAgentPackage'
                    $download = Invoke-AdoHttpGet -Uri $packageMetadata.DownloadUri -BaseUri $baseUri -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential -OutputPath $archivePath -AllowInsecureServerUrl:$AllowInsecureServerUrl -PackageDownload
                    $state.packageVersion = $packageMetadata.Version
                    $state.packageDownloadUrl = $download.Uri.GetLeftPart([UriPartial]::Path)
                    $state.packageSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
                }
                $state.updatedUtc = [DateTime]::UtcNow.ToString('o')
                $currentOperation = 'PersistPackageMetadata'
                Write-AdoSetupState -Path $statePath -State $state
                $currentOperation = 'ExtractAgentPackage'
                Expand-AdoAgentArchive -ArchivePath $archivePath -AgentRoot $resolvedAgentRoot
            }
            finally { if ($deleteArchive -and $archivePath -and (Test-Path -LiteralPath $archivePath)) { Remove-Item -LiteralPath $archivePath -Force } }
            $currentOperation = 'PersistPackageStaged'
            Set-AdoSetupPhase -State $state -Phase 'PackageStaged' -StatePath $statePath
            $phaseIndex = Get-AdoSetupPhaseIndex -Phase 'PackageStaged'
            }
        }
        $currentOperation = 'InspectRegistrationState'
        $rootState = Get-AdoAgentRegistrationState -AgentRoot $resolvedAgentRoot
        if ($phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'RegisteredStopped')) {
            if ($rootState -eq 'Partial') { throw 'AgentRoot contains a partial registration. Preserve it and follow the documented explicit recovery procedure.' }
            if ($rootState -eq 'Registered') {
                if (-not $Resume) { throw 'AgentRoot is already registered. Use the existing-agent migration path or resume its recorded setup.' }
            }
            elseif ($rootState -eq 'PackageStaged') {
                $currentOperation = 'ConfigureAgent'
                Invoke-AdoAgentConfiguration -AgentRoot $resolvedAgentRoot -BaseUri $baseUri -PoolName $PoolName -AgentName $AgentName -WorkDirectory $WorkDirectory -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential -ServiceAccount $ServiceAccount -ServiceCredential $ServiceCredential -ReplaceExistingAgent:$ReplaceExistingAgent
            }
            else { throw 'AgentRoot does not contain the expected staged Microsoft agent package.' }
            $currentOperation = 'ValidateRegisteredAgent'
            $metadata = Get-AdoSetupAgentMetadata -AgentRoot $resolvedAgentRoot
            if (-not $metadata.Name.Equals($AgentName, [StringComparison]::Ordinal)) { throw 'The configured agent name does not match AgentName.' }
            if ($null -ne $existingAgent -and $null -ne $existingAgent.PSObject.Properties['id'] -and [string]$existingAgent.id -ne $metadata.Id) {
                throw 'The local resumed registration does not match the exact server-side agent ID.'
            }
            $currentOperation = 'DiscoverAgentService'
            $definition = Get-AdoAgentServiceDefinition -AgentRoot $resolvedAgentRoot
            $serviceNameForFailure = $definition.Name
            $currentOperation = 'StopAgentService'
            Set-AdoSetupServiceStopped -ServiceName $definition.Name
            $state.agentId = $metadata.Id
            $state.serviceName = $definition.Name
            $state.poolId = [int]$pool.id
            $state.registrationOfflineVerified = $false
            Set-AdoSetupPhase -State $state -Phase 'RegisteredStopped' -StatePath $statePath
            $phaseIndex = Get-AdoSetupPhaseIndex -Phase 'RegisteredStopped'
        }
        if (-not [bool]$state.registrationOfflineVerified) {
            if ($null -eq $pool) { throw 'A registration credential is required to verify that the newly registered agent remained Offline.' }
            $currentOperation = 'VerifyAgentOffline'
            Test-AdoAgentOffline -BaseUri $baseUri -PoolId ([int]$state.poolId) -AgentName $AgentName -ServerType $ServerType -RegistrationAuth $RegistrationAuth -RegistrationSecret $registrationSecret -RegistrationCredential $RegistrationCredential -AllowInsecureServerUrl:$AllowInsecureServerUrl | Out-Null
            $state.registrationOfflineVerified = $true
            $state.updatedUtc = [DateTime]::UtcNow.ToString('o')
            Write-AdoSetupState -Path $statePath -State $state
        }
        if ((Get-AdoAgentRegistrationState -AgentRoot $resolvedAgentRoot) -ne 'Registered') { throw 'The stopped agent registration is incomplete.' }
        $currentOperation = 'StopAgentService'
        Set-AdoSetupServiceStopped -ServiceName ([string]$state.serviceName)
        if ($phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'KeyValidated')) {
            $currentOperation = 'InspectAgentKey'
            $inspection = Invoke-AdoKeyHelper -Executable (Join-Path $resolvedToolkit 'AdoAgent.ClusterKey.exe') -Arguments @('inspect', '--agent-root', $resolvedAgentRoot, '--json')
            if ($inspection.data.keyStorage -ne 'file') { throw 'The new agent uses a named key container; file-backed RSA is required.' }
            if (@($inspection.data.additionalCredentialStores).Count -gt 0) { throw 'The new agent created an unsupported additional protected credential store.' }
            if ([string]$inspection.data.agentId -ne [string]$state.agentId) { throw 'The inspected agent identity does not match setup state.' }
            Set-AdoSetupPhase -State $state -Phase 'KeyValidated' -StatePath $statePath
            $phaseIndex = Get-AdoSetupPhaseIndex -Phase 'KeyValidated'
        }
        if ($phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'ClusterInstalled')) {
            $currentOperation = 'ValidateClusterPrerequisites'
            Test-AdoAgentClusterPrerequisite -AgentRoot $resolvedAgentRoot -ClusterRoleName $ClusterRoleName -SharedDiskResourceName $SharedDiskResourceName -ProtectorGroup $ProtectorGroup -Node $Node -PackagePath $resolvedToolkit -ServiceIdentity $ServiceAccount -WorkDirectory $WorkDirectory -ThrowOnFailure | Out-Null
            $currentOperation = 'InstallClusterResources'
            Install-AdoAgentCluster -AgentRoot $resolvedAgentRoot -ClusterRoleName $ClusterRoleName -SharedDiskResourceName $SharedDiskResourceName -ProtectorGroup $ProtectorGroup -EscrowPath $resolvedEscrow -PackagePath $resolvedToolkit -ConfirmAgentIdle -Node $Node -ConfigId $ConfigId -KeyResourceName $KeyResourceName -ServiceResourceName $ServiceResourceName -ServiceCredential $ServiceCredential -Confirm:$false | Out-Null
            Set-AdoSetupPhase -State $state -Phase 'ClusterInstalled' -StatePath $statePath
            $phaseIndex = Get-AdoSetupPhaseIndex -Phase 'ClusterInstalled'
        }
        if ($phaseIndex -lt (Get-AdoSetupPhaseIndex -Phase 'Complete')) {
            $currentOperation = 'OfflineClusterRole'
            Stop-ClusterGroup -Name $ClusterRoleName -Wait 60 | Out-Null
            $group = Get-ClusterGroup -Name $ClusterRoleName
            if ($group.State -ne 'Offline') { throw 'The clustered role did not reach Offline after setup.' }
            Set-AdoSetupPhase -State $state -Phase 'Complete' -StatePath $statePath
        }
        return [pscustomobject]@{
            ConfigId = $ConfigId
            State = 'Complete'
            StatePath = $statePath
            AgentId = [string]$state.agentId
            AgentName = $AgentName
            ServiceName = [string]$state.serviceName
            AgentRoot = $resolvedAgentRoot
            ClusterRoleName = $ClusterRoleName
            Nodes = $Node
        }
    }
    catch {
        $originalError = $_
        if (-not [string]::IsNullOrWhiteSpace($serviceNameForFailure)) { Stop-Service -Name $serviceNameForFailure -Force -ErrorAction SilentlyContinue }
        if ($null -ne $state -and (Test-Path -LiteralPath $statePath)) {
            $state.lastFailurePhase = [string]$state.phase
            if ($null -eq $state.PSObject.Properties['lastFailureOperation']) {
                $state | Add-Member -NotePropertyName lastFailureOperation -NotePropertyValue $currentOperation
            }
            else { $state.lastFailureOperation = $currentOperation }
            $state.updatedUtc = [DateTime]::UtcNow.ToString('o')
            try { Write-AdoSetupState -Path $statePath -State $state }
            catch { Write-Warning 'Unable to persist sanitized setup failure metadata; the original setup error follows.' }
        }
        $message = "Setup failed during '$currentOperation'. $($originalError.Exception.Message)"
        $exception = [InvalidOperationException]::new($message, $originalError.Exception)
        $errorRecord = [Management.Automation.ErrorRecord]::new($exception, "AdoAgentClusterSetup.$currentOperation", [Management.Automation.ErrorCategory]::InvalidOperation, $null)
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
    finally { $registrationSecret = $null }
}
