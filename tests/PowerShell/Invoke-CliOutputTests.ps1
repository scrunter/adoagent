[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Executable)

$ErrorActionPreference = 'Stop'
$sentinel = 'DO-NOT-LOG-9f76dc83-private-value'
function Invoke-TestProcess([string]$arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = $arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
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

Write-Output 'CLI sanitized-output tests passed.'
