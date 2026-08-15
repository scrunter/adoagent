[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Executable)

$ErrorActionPreference = 'Stop'
$sentinel = 'DO-NOT-LOG-9f76dc83-private-value'
function Invoke-TestProcess([string]$arguments, [byte[]]$standardInputBytes) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = $arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $null -ne $standardInputBytes
    $process = [Diagnostics.Process]::Start($start)
    if ($null -ne $standardInputBytes) {
        $process.StandardInput.BaseStream.Write($standardInputBytes, 0, $standardInputBytes.Length)
        $process.StandardInput.Close()
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Text = ($stdout + $stderr).Trim() }
}

$result = Invoke-TestProcess "$sentinel --json"
$exitCode = $result.ExitCode
$text = $result.Text
if ($exitCode -ne 2) { throw "Unknown command returned $exitCode instead of 2." }
if ($text -match [regex]::Escape($sentinel)) { throw 'Unknown command output disclosed the command-line sentinel.' }
$errorObject = $text | ConvertFrom-Json
if ($errorObject.ok -ne $false -or $errorObject.code -ne 2) { throw 'Unknown command JSON contract is invalid.' }

$result = Invoke-TestProcess "inspect $sentinel --json"
$exitCode = $result.ExitCode
$text = $result.Text
if ($exitCode -ne 2) { throw "Unexpected positional argument returned $exitCode instead of 2." }
if ($text -match [regex]::Escape($sentinel)) { throw 'Argument parser output disclosed the command-line sentinel.' }

$result = Invoke-TestProcess "help --unsupported $sentinel --json"
$exitCode = $result.ExitCode
$text = $result.Text
if ($exitCode -ne 2) { throw "Unsupported option returned $exitCode instead of 2." }
if ($text -match [regex]::Escape($sentinel)) { throw 'Unsupported-option output disclosed the command-line sentinel.' }

$result = Invoke-TestProcess 'help --json'
$help = $result.Text
if ($result.ExitCode -ne 0) { throw 'Helper JSON help failed.' }
if ($help -match 'privateExponent|inverseQ|"d"\s*:|protectedBlob|envelopeContents|password') { throw 'Helper help output contains a prohibited secret-field term.' }

$delegatedUser = 'no-such-user-9f76dc83@invalid.example'
$userBytes = [Text.Encoding]::UTF8.GetBytes($delegatedUser)
$passwordBytes = [Text.Encoding]::Unicode.GetBytes($sentinel)
$wire = New-Object IO.MemoryStream
try {
    $wire.Write([byte[]]@(65, 67, 75, 49), 0, 4)
    $length = [BitConverter]::GetBytes([int]$userBytes.Length)
    $wire.Write($length, 0, $length.Length)
    $wire.Write($userBytes, 0, $userBytes.Length)
    $length = [BitConverter]::GetBytes([int]$passwordBytes.Length)
    $wire.Write($length, 0, $length.Length)
    $wire.Write($passwordBytes, 0, $passwordBytes.Length)
    $delegatedInput = $wire.ToArray()
}
finally {
    $wire.Dispose()
    [Array]::Clear($userBytes, 0, $userBytes.Length)
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
}
$result = Invoke-TestProcess -arguments 'seal-delegated --envelope missing --manifest missing --config-id 11111111-2222-3333-4444-555555555555 --output missing --json' -standardInputBytes $delegatedInput
[Array]::Clear($delegatedInput, 0, $delegatedInput.Length)
if ($result.ExitCode -ne 14) { throw "Delegated credential failure returned $($result.ExitCode) instead of 14: $($result.Text)" }
if ($result.Text -match [regex]::Escape($sentinel)) { throw 'Delegated credential failure disclosed the password sentinel.' }
$delegatedError = $result.Text | ConvertFrom-Json
if ($delegatedError.ok -ne $false -or $delegatedError.code -ne 14) { throw 'Delegated credential JSON contract is invalid.' }

Write-Output 'CLI sanitized-output tests passed.'
