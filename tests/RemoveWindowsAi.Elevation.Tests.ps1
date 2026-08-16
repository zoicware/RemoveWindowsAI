$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (!$Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        $Expected,
        $Actual,
        [string]$Message
    )

    if ($Expected -ne $Actual) {
        throw "$Message Expected: [$Expected] Actual: [$Actual]"
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repositoryRoot 'RemoveWindowsAi.ps1'
$tokens = $null
$parseErrors = $null
$sourceAst = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)

Assert-Equal 0 $parseErrors.Count 'RemoveWindowsAi.ps1 must parse before testing its elevation helper.'

$functionAst = $sourceAst.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-ElevatedScript'
    }, $true)

Assert-True ($null -ne $functionAst) 'Start-ElevatedScript was not found in RemoveWindowsAi.ps1.'
Invoke-Expression $functionAst.Extent.Text

$script:startProcessCall = $null
function Start-Process {
    [CmdletBinding()]
    param(
        [string]$FilePath,
        [object[]]$ArgumentList,
        [string]$Verb
    )

    $script:startProcessCall = [PSCustomObject]@{
        FilePath      = $FilePath
        ArgumentList  = $ArgumentList
        Verb          = $Verb
        ErrorAction   = $PSBoundParameters['ErrorAction']
    }
}

$script:startProcessCall = $null
$inMemoryError = $null
try {
    Start-ElevatedScript -ScriptPath '' -BoundParameters @{}
}
catch {
    $inMemoryError = $_.Exception.Message
}

Assert-True ($inMemoryError -like '*requires a saved script file*') 'In-memory invocation must fail with explicit saved-file guidance.'
Assert-True ($null -eq $script:startProcessCall) 'In-memory invocation must not start another process.'
Write-Host 'PASS: in-memory invocation fails closed without a download or elevation attempt'

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "RemoveWindowsAI elevation tests $([Guid]::NewGuid())"
$fixturePath = Join-Path $tempRoot 'saved script with spaces.ps1'
[void][IO.Directory]::CreateDirectory($tempRoot)

$fixtureContent = @'
param(
    [switch]$EnableLogging,
    [switch]$nonInteractive,
    [array]$Options,
    [switch]$AllOptions,
    [switch]$revertMode,
    [switch]$backupMode,
    [array]$InstallClassicApps,
    [switch]$RunWinUpdateRepair,
    [switch]$ExcludeOptions
)

[PSCustomObject]@{
    ScriptPath          = $PSCommandPath
    EnableLogging       = [bool]$EnableLogging
    nonInteractive      = [bool]$nonInteractive
    Options             = @($Options)
    AllOptions          = [bool]$AllOptions
    revertMode          = [bool]$revertMode
    backupMode          = [bool]$backupMode
    InstallClassicApps  = @($InstallClassicApps)
    RunWinUpdateRepair  = [bool]$RunWinUpdateRepair
    ExcludeOptions      = [bool]$ExcludeOptions
    BoundKeys           = @($PSBoundParameters.Keys | Sort-Object)
} | ConvertTo-Json -Compress
'@

try {
    [IO.File]::WriteAllText($fixturePath, $fixtureContent, [Text.UTF8Encoding]::new($false))

    function Invoke-RelaunchCapture {
        param(
            [switch]$EnableLogging,
            [switch]$nonInteractive,
            [array]$Options,
            [switch]$AllOptions,
            [switch]$revertMode,
            [switch]$backupMode,
            [array]$InstallClassicApps,
            [switch]$RunWinUpdateRepair,
            [switch]$ExcludeOptions
        )

        Start-ElevatedScript -ScriptPath $fixturePath -BoundParameters $MyInvocation.BoundParameters
    }

    $script:startProcessCall = $null
    Invoke-RelaunchCapture `
        -EnableLogging `
        -nonInteractive `
        -Options @('DisableRegKeys', 'RemoveAIFiles') `
        -AllOptions:$false `
        -revertMode:$false `
        -backupMode `
        -InstallClassicApps @('mspaint', 'snippingtool') `
        -RunWinUpdateRepair `
        -ExcludeOptions:$false

    Assert-True ($null -ne $script:startProcessCall) 'Saved-file invocation must request one elevated process.'
    Assert-Equal (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') $script:startProcessCall.FilePath 'The relaunch must use Windows PowerShell 5.1.'
    Assert-Equal 'RunAs' $script:startProcessCall.Verb 'The relaunch must request UAC elevation.'
    Assert-Equal 'Stop' ([string]$script:startProcessCall.ErrorAction) 'Elevation failures must be surfaced.'
    Assert-Equal 5 $script:startProcessCall.ArgumentList.Count 'The relaunch argument list has an unexpected shape.'
    Assert-Equal '-NoProfile' $script:startProcessCall.ArgumentList[0] 'The relaunch must disable profile loading.'
    Assert-Equal '-ExecutionPolicy' $script:startProcessCall.ArgumentList[1] 'The relaunch must set a process-only execution policy.'
    Assert-Equal 'Bypass' $script:startProcessCall.ArgumentList[2] 'The relaunch must use process-only Bypass.'
    Assert-Equal '-EncodedCommand' $script:startProcessCall.ArgumentList[3] 'The relaunch must use a safely encoded bootstrap.'

    $decodedCommand = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($script:startProcessCall.ArgumentList[4]))
    Assert-True ($decodedCommand -notmatch '(?i)invoke-restmethod|invoke-webrequest|raw\.githubusercontent|https?://|\birm\b') 'The elevation bootstrap must not fetch code from the network.'
    Write-Host 'PASS: saved-file elevation is mocked and the bootstrap contains no network fetch'

    $childArguments = $script:startProcessCall.ArgumentList
    $childOutput = & $script:startProcessCall.FilePath @childArguments 2>&1
    Assert-Equal 0 $LASTEXITCODE "The non-elevated child-process simulation failed: $($childOutput -join [Environment]::NewLine)"
    $received = ($childOutput -join [Environment]::NewLine) | ConvertFrom-Json

    Assert-Equal ([IO.Path]::GetFullPath($fixturePath)) $received.ScriptPath 'The exact saved script path, including spaces, was not preserved.'
    Assert-True $received.EnableLogging 'EnableLogging was not preserved.'
    Assert-True $received.nonInteractive 'nonInteractive was not preserved.'
    Assert-Equal 'DisableRegKeys|RemoveAIFiles' ($received.Options -join '|') 'Options array values were not preserved.'
    Assert-True (!$received.AllOptions) 'An explicitly false AllOptions switch was not preserved.'
    Assert-True (!$received.revertMode) 'An explicitly false revertMode switch was not preserved.'
    Assert-True $received.backupMode 'backupMode was not preserved.'
    Assert-Equal 'mspaint|snippingtool' ($received.InstallClassicApps -join '|') 'InstallClassicApps array values were not preserved.'
    Assert-True $received.RunWinUpdateRepair 'RunWinUpdateRepair was not preserved.'
    Assert-True (!$received.ExcludeOptions) 'An explicitly false ExcludeOptions switch was not preserved.'

    $expectedKeys = 'AllOptions|backupMode|EnableLogging|ExcludeOptions|InstallClassicApps|nonInteractive|Options|revertMode|RunWinUpdateRepair'
    Assert-Equal $expectedKeys ($received.BoundKeys -join '|') 'The set of explicitly bound parameters was not preserved.'
    Write-Host 'PASS: spaces, switches, false switches, arrays and all current bound parameters survive relaunch'
}
finally {
    if ([IO.File]::Exists($fixturePath)) {
        [IO.File]::Delete($fixturePath)
    }
    if ([IO.Directory]::Exists($tempRoot)) {
        [IO.Directory]::Delete($tempRoot, $false)
    }
}

Write-Host 'All RemoveWindowsAI elevation tests passed.'
