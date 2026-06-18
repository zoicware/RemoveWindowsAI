<#
.SYNOPSIS
    Audit + targeted uninstall of Windows AI components (Copilot, Recall, Click to Do, Office/Paint/Photos AI, Copilot+ AI).

.DESCRIPTION
    Local layer on top of zoicware/RemoveWindowsAI.
    "foundation" mode: KEEPS the base environment + local LLM (for 3rd-party / Windows ML),
    REMOVES only Microsoft's product AI features (Copilot, Click to Do, AI search, Office AI, Paint AI,
    Photos AI, Voice Access, Gaming Copilot, Input Insights, AI Actions...).

    The script is written so that it also DETECTS and HANDLES things that are NOT on this PC
    right now but Windows Update can bring back at any time (Recall, CBS packages, scheduled
    tasks, services, policy keys). Anything missing is reported as "not present / ready to be
    handled", and in removal mode it pre-emptively blocks / sets the disable values, so the
    feature will not come up if it returns.

    1) Lists what is INSTALLED -> splits into TO REMOVE vs KEPT (foundation/LLM).
    2) Lists AI FILES, SERVICES, REGISTRY (disable+leftover+protective), CBS packages,
       Recall+scheduled TASKS, region-policy JSON and "Hide AI Components".
    3) At the end offers removal / disable (incl. TrustedInstaller for non-removable packages).
    4) Honors restore-high-risk.reg (keeps app access to local AI models ENABLED).

.PARAMETER Remove        After the audit, offer / perform the removal.
.PARAMETER Yes           No interactive confirmation (with -Remove = fully non-interactive).
.PARAMETER AuditOnly     Audit only, remove nothing, do not prompt.
.PARAMETER RemoveAllAI   IGNORES the foundation keep-list and removes EVERYTHING incl. runtime/LLM.
.PARAMETER NoTrustedInstaller  Do not use the TrustedInstaller trick (standard uninstall only).
.PARAMETER SkipProtect   Do not turn on the protective values from restore-high-risk.reg.
.PARAMETER SkipCBS       Skip scanning/removing hidden AI packages in the CBS store.
.PARAMETER SkipServices  Skip disabling AI services (WSAIFabricSvc, Copilot elevation).
.PARAMETER SkipRegionPolicy  Do not edit IntegratedServicesRegionPolicySet.json.
.PARAMETER SkipHide      Do not hide the "AI Components" page in Settings.
.PARAMETER Report        Path to the text report (default next to the script).

.NOTES
    Requires Windows PowerShell 5.1 + admin. When launched in pwsh 7 / without admin it
    relaunches itself correctly (via UAC).
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Yes,
    [switch]$AuditOnly,
    [switch]$RemoveAllAI,
    [switch]$NoTrustedInstaller,
    [switch]$SkipProtect,
    [switch]$SkipCBS,
    [switch]$SkipServices,
    [switch]$SkipRegionPolicy,
    [switch]$SkipHide,
    [string]$Report
)

# ============================================================================
#  0) Ensure Windows PowerShell 5.1 + admin (otherwise relaunch via UAC)
# ============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$inPwsh7 = $PSVersionTable.PSVersion.Major -ge 6

if ($inPwsh7 -or -not $isAdmin) {
    $reason = @()
    if ($inPwsh7)        { $reason += 'PowerShell 7 (Appx cmdlets are not native)' }
    if (-not $isAdmin)   { $reason += 'missing administrator rights' }
    Write-Host "This script must be run in Windows PowerShell 5.1 as admin." -ForegroundColor Yellow
    Write-Host "Reason: $($reason -join ', '). Relaunching via UAC..." -ForegroundColor Yellow

    $ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path $ps51)) {
        Write-Host "ERROR: powershell.exe (5.1) not found at $ps51" -ForegroundColor Red
        return
    }
    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }

    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$scriptPath`"")
    if ($Remove)             { $argList += '-Remove' }
    if ($Yes)                { $argList += '-Yes' }
    if ($AuditOnly)          { $argList += '-AuditOnly' }
    if ($RemoveAllAI)        { $argList += '-RemoveAllAI' }
    if ($NoTrustedInstaller) { $argList += '-NoTrustedInstaller' }
    if ($SkipProtect)        { $argList += '-SkipProtect' }
    if ($SkipCBS)            { $argList += '-SkipCBS' }
    if ($SkipServices)       { $argList += '-SkipServices' }
    if ($SkipRegionPolicy)   { $argList += '-SkipRegionPolicy' }
    if ($SkipHide)           { $argList += '-SkipHide' }
    if ($Report)             { $argList += @('-Report', "`"$Report`"") }

    try { Start-Process -FilePath $ps51 -ArgumentList $argList -Verb RunAs }
    catch { Write-Host "ERROR: UAC denied or launch failed: $($_.Exception.Message)" -ForegroundColor Red }
    return
}

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$Global:psversion = 5
$tempDir = "$env:TEMP\"
$scriptDir = Split-Path $PSCommandPath -Parent

if (-not $Report) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Report = Join-Path $scriptDir "AI-Audit-$stamp.txt"
}
$Global:ReportLines = New-Object System.Collections.Generic.List[string]

function Out-Both {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    $Global:ReportLines.Add($Text)
}
function Out-Head {
    param([string]$Text)
    $bar = '=' * 76
    Out-Both ''
    Out-Both $bar 'Cyan'
    Out-Both "  $Text" 'Cyan'
    Out-Both $bar 'Cyan'
}
function Save-Report {
    try { $Global:ReportLines | Set-Content -Path $Report -Encoding UTF8 } catch {}
}

# Convert a PS provider path (HKLM:\...) to reg.exe form (HKLM\...)
function ConvertTo-RegExe {
    param([string]$Path)
    $p = $Path -replace '^Registry::', ''
    $p = $p -replace '^HKLM:\\', 'HKLM\' -replace '^HKCU:\\', 'HKCU\' -replace '^HKCR:\\', 'HKCR\' -replace '^HKU:\\', 'HKU\'
    $p = $p -replace '^HKEY_CLASSES_ROOT\\', 'HKCR\' -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\' -replace '^HKEY_CURRENT_USER\\', 'HKCU\'
    return $p
}
function Get-RegVal {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}
function Set-RegValForced {
    param([string]$Path, [string]$Name, [string]$Type, $Value)
    $rp = ConvertTo-RegExe $Path
    & reg.exe add "$rp" /v "$Name" /t $Type /d "$Value" /f *>$null
}

# ============================================================================
#  TrustedInstaller engine (port from RemoveWindowsAi.ps1, sc.exe binPath method)
#  Runs the given command in the context of the TrustedInstaller service (SYSTEM/TI rights).
# ============================================================================
function Run-Trusted {
    param([string]$command)
    $psexe = 'PowerShell.exe'
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)

    try { Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop }
    catch { & taskkill.exe /im trustedinstaller.exe /f *>$null }

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
    if ($DefaultBinPath -ne $trustedInstallerPath) { $DefaultBinPath = $trustedInstallerPath }

    & sc.exe config TrustedInstaller binPath= "cmd.exe /c $psexe -encodedcommand $base64Command" | Out-Null
    & sc.exe start TrustedInstaller | Out-Null
    & sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null

    try { Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop }
    catch { & taskkill.exe /im trustedinstaller.exe /f *>$null }
}

# ============================================================================
#  1) Definitions: master AI list + keep-list (foundation / local LLM)
# ============================================================================

# All AI Appx patterns (Name -like). Source: $aipackages in RemoveWindowsAi.ps1
# (extended with specific product WindowsWorkload.* features for a clearer report).
$appxPatterns = @(
    'MicrosoftWindows.Client.AIX'
    'MicrosoftWindows.Client.CoPilot'
    'Microsoft.Windows.Ai.Copilot.Provider'
    'Microsoft.Copilot'
    'Microsoft.MicrosoftOfficeHub'
    'MicrosoftWindows.Client.CoreAI'
    'Microsoft.Edge.GameAssist'
    'Microsoft.Office.ActionsServer'
    'aimgr'
    'Microsoft.WritingAssistant'
    'Clipchamp.Clipchamp'
    'Microsoft.AIFabric.CBS*'
    'MicrosoftWindows.*.Voiess'
    'MicrosoftWindows.*.Speion'
    'MicrosoftWindows.*.Livtop'
    'MicrosoftWindows.*.InpApp'
    'MicrosoftWindows.*.Filons'
    # specific product WindowsWorkload features (AI search / Photos / Click to Do)
    'WindowsWorkload.SemanticText.*'
    'WindowsWorkload.QueryProcessor.*'
    'WindowsWorkload.QueryBlockList.*'
    'WindowsWorkload.ImageSearch.*'
    'WindowsWorkload.ImageTextSearch.*'
    'WindowsWorkload.Data.ImageSearch.*'
    # catch-all (everything else under WindowsWorkload except the keep-list below)
    'WindowsWorkload.*'
)

# === KEEP-LIST (foundation + local LLM) - these are NOT removed (except with -RemoveAllAI) ===
# Base environment and models that a 3rd-party app can call (Windows ML / Windows AI Foundry).
$keepPatterns = @(
    'WindowsWorkload.OnnxRuntime.*'            # ONNX runtime
    'WindowsWorkload.PSOnnxRuntime.*'          # ONNX runtime (per-skill)
    'WindowsWorkload.WinMLShared.*'            # Windows ML shared
    'WindowsWorkload.EP.Intel.*'               # Intel OpenVINO NPU execution provider
    'WindowsWorkload.LanguageModel.*'          # Phi Silica - local LLM
    'WindowsWorkload.Data.PhiSilica.*'         # Phi Silica data
    'WindowsWorkload.PSTokenizer.*'            # tokenizer for the LLM
    'WindowsWorkload.PSTokenizerShared.*'      # tokenizer shared
    'WindowsWorkload.Manager.*'                # model orchestration
    'WindowsWorkload.SessionManager.*'         # session manager
    'WindowsWorkload.Data.Analysis.*'          # runtime analysis
    'WindowsWorkload.TextRecognition.*'        # OCR (dev API)
    'WindowsWorkload.ScrRegDetection.*'        # screen region detection for OCR
    'WindowsWorkload.Data.ContentExtraction.*' # content extraction (recognition primitives)
    'WindowsWorkload.ContentExtraction.*'
    'WindowsWorkload.ImageDescription.*'       # image description (dev API)
    'WindowsWorkload.ImageLLMAdapter.*'        # image+LLM adapter
    'WindowsWorkload.TextContentModeration.*'  # safety layer for the LLM
    'WindowsWorkload.ImageContentModeration.*' # safety layer for images
)

function Test-Keep {
    param([string]$Name)
    if ($RemoveAllAI) { return $false }
    foreach ($k in $keepPatterns) { if ($Name -like $k) { return $true } }
    return $false
}

# Package/file description for the mini-table (order matters - more specific first)
function Get-PkgDesc {
    param([string]$Name)
    switch -Wildcard ($Name) {
        # --- foundation / local LLM (kept) ---
        '*PSOnnxRuntime*'          { return 'ONNX Runtime (per-skill) - runs AI models' }
        '*OnnxRuntime*'            { return 'ONNX Runtime - runs AI models (incl. 3rd-party)' }
        '*WinMLShared*'            { return 'Windows ML - shared inference layer' }
        '*EP.Intel.OpenVINO*'      { return 'Intel OpenVINO - model acceleration on the NPU' }
        '*LanguageModel*'          { return 'Phi Silica - local language model (LLM)' }
        '*Data.PhiSilica*'         { return 'Phi Silica - model data/weights' }
        '*PSTokenizerShared*'      { return 'Tokenizer - shared part (for the LLM)' }
        '*PSTokenizer*'            { return 'Tokenizer for the language model' }
        '*SessionManager*'         { return 'Manages running AI sessions' }
        '*Manager.*'               { return 'AI model orchestration / management' }
        '*Data.Analysis*'          { return 'Runtime input analysis' }
        '*TextRecognition*'        { return 'OCR - text recognition (dev API)' }
        '*ScrRegDetection*'        { return 'Screen region detection for OCR' }
        '*ContentExtraction*'      { return 'Content extraction (recognition primitives)' }
        '*ImageDescription*'       { return 'AI image description (accessibility, dev API)' }
        '*ImageLLMAdapter*'        { return 'Image -> LLM adapter (vision)' }
        '*TextContentModeration*'  { return 'Text safety filter (safety for the LLM)' }
        '*ImageContentModeration*' { return 'Image safety filter (safety)' }
        '*Windows.AI.MachineLearning*' { return 'Legacy WinML inbox API (called by 3rd-party apps)' }
        # --- product features (removed) ---
        'Microsoft.Copilot'        { return 'Microsoft Copilot app' }
        '*Ai.Copilot.Provider*'    { return 'Copilot provider (Edge integration)' }
        '*Client.CoPilot'          { return 'Copilot host in the shell' }
        '*Client.AIX*'             { return 'AI eXperience host in the shell' }
        '*Client.CoreAI*'          { return 'Windows AI host in the shell (Click to Do)' }
        '*MicrosoftOfficeHub*'     { return 'Office Hub - launcher + AI integration' }
        '*Edge.GameAssist*'        { return 'Gaming Copilot (game assistant)' }
        '*Office.ActionsServer*'   { return 'Office Actions Server (AI actions)' }
        'aimgr'                    { return 'Office AI manager' }
        '*WritingAssistant*'       { return 'Writing assistant (Office AI)' }
        '*Clipchamp*'              { return 'Clipchamp (video editor)' }
        '*SemanticText*'           { return 'Semantic search (Windows Search AI)' }
        '*QueryProcessor*'         { return 'Query processing for AI search' }
        '*QueryBlockList*'         { return 'Block list for AI search' }
        '*ImageTextSearch*'        { return 'Text-in-image search (Photos/Explorer)' }
        '*ImageSearch*'            { return 'Search photos by content' }
        '*SettingsModel*'          { return 'AI agent in Settings' }
        '*AIFabric*'               { return 'AI Fabric (CBS component)' }
        '*SettingsHandlers_Copilot*' { return 'Copilot tile in Settings' }
        '*SettingsHandlers_A9*'    { return 'Copilot/AI settings handler' }
        default                    { return 'AI component' }
    }
}

function Out-Table {
    param([array]$Rows, [ConsoleColor]$Color = 'Gray')
    # Rows = array of hashtables @{ Name=..; Desc=.. }
    $w = 0
    foreach ($r in $Rows) { if ($r.Name.Length -gt $w) { $w = $r.Name.Length } }
    if ($w -gt 52) { $w = 52 }
    foreach ($r in $Rows) {
        $n = $r.Name
        if ($n.Length -gt $w) { $n = $n.Substring(0, $w) }
        Out-Both ("  {0}  {1}" -f $n.PadRight($w), $r.Desc) $Color
    }
}

# Fixed files: Copilot settings handlers (always remove)
$copilotDlls = @(
    "$env:SystemRoot\System32\SettingsHandlers_Copilot.dll"
    "$env:SystemRoot\System32\SettingsHandlers_A9.dll"
)
# Windows ML inbox DLL (legacy, dev API) - removed only with -RemoveAllAI
$winmlDlls = @(
    "$env:SystemRoot\System32\Windows.AI.MachineLearning.dll"
    "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.dll"
    "$env:SystemRoot\System32\Windows.AI.MachineLearning.Preview.dll"
    "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.Preview.dll"
)

# App Actions / Visual Assist binaries inside the shell CBS package (product AI actions)
$appActionsFiles = @(
    "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionUI"
    "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssist"
    "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AppActions.exe"
    "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AppActions.dll"
    "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssistExe.exe"
    "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssistExe.dll"
)
# ActionsMcpHost (MCP host for AI actions)
$actionsMcpHostFiles = @(
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\ActionsMcpHost.exe"
    "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\ActionsMcpHost.exe"
    "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionsMcpHost.exe"
    "$env:LOCALAPPDATA\Microsoft\WindowsApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionsMcpHost.exe"
)

# Office AI paths (product AI - always remove)
$officeAiPaths = @(
    "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\AI"
    "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\AI"
    "$env:ProgramFiles\Microsoft Office\root\Office16\AI"
    "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\ActionsServer"
    "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\aimgr.msix"
    "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\WritingAssistant.msix"
    "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\ActionsServer.msix"
)

# Registry leftover keys / values of specific AI apps (safe to delete)
$appRegKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Copilot_8wekyb3d8bbwe'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe'
    'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Copilot_8wekyb3d8bbwe'
    'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe'
    'HKCU:\Software\Microsoft\Windows\Shell\Copilot'
    'HKCU:\Software\Microsoft\Copilot'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy'
    # AI URI handlers (ms-copilot:, ms-office-ai:, ms-clicktodo:)
    'Registry::HKEY_CLASSES_ROOT\ms-copilot'
    'Registry::HKEY_CLASSES_ROOT\ms-office-ai'
    'Registry::HKEY_CLASSES_ROOT\ms-clicktodo'
    # .copilot file association (blocks server communication)
    'HKCU:\Software\Classes\.copilot'
    'Registry::HKEY_CLASSES_ROOT\.copilot'
)

# === REGISTRY: DISABLE keys (turn off product AI) ===
# Foundation-safe: does NOT include app access to AI models (generativeAI/systemAIModels/
# LetAppsAccess*) - those are held at "Allow"/1 by $keepRegKeys below. Everything here is set
# to its disable value in removal mode, even if the key does not currently exist (a guard
# against the feature coming back).
$disableRegKeys = @(
    # --- Recall / WindowsAI policy ---
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableAIDataAnalysis'; Type = 'REG_DWORD'; Want = 1; Note = 'Recall - AI data analysis' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'AllowRecallEnablement'; Type = 'REG_DWORD'; Want = 0; Note = 'Recall - block enablement' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'TurnOffSavingSnapshots'; Type = 'REG_DWORD'; Want = 1; Note = 'Recall - turn off snapshots' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableClickToDo'; Type = 'REG_DWORD'; Want = 1; Note = 'Click to Do' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableSettingsAgent'; Type = 'REG_DWORD'; Want = 1; Note = 'AI agent in Settings' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableAgentConnectors'; Type = 'REG_DWORD'; Want = 1; Note = 'AI agent connectors' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableAgentWorkspaces'; Type = 'REG_DWORD'; Want = 1; Note = 'AI agent workspaces' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableRemoteAgentConnectors'; Type = 'REG_DWORD'; Want = 1; Note = 'Remote AI agent connectors' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableAIDataAnalysis'; Type = 'REG_DWORD'; Want = 1; Note = 'Recall - AI data analysis (user)' }
    @{ G = 'Recall/WindowsAI'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableClickToDo'; Type = 'REG_DWORD'; Want = 1; Note = 'Click to Do (user)' }

    # --- Copilot ---
    @{ G = 'Copilot'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name = 'TurnOffWindowsCopilot'; Type = 'REG_DWORD'; Want = 1; Note = 'Windows Copilot turned off' }
    @{ G = 'Copilot'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat'; Name = 'IsUserEligible'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot/BingChat eligibility' }
    @{ G = 'Copilot'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\Shell\Copilot'; Name = 'IsCopilotAvailable'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot availability' }
    @{ G = 'Copilot'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\Shell\Copilot'; Name = 'CopilotDisabledReason'; Type = 'REG_SZ'; Want = 'FeatureIsDisabled'; Note = 'Copilot disabled reason' }
    @{ G = 'Copilot'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat'; Name = 'IsUserEligible'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot/BingChat eligibility (user)' }
    @{ G = 'Copilot'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Copilot'; Name = 'IsCopilotAvailable'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot availability (user)' }
    @{ G = 'Copilot'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot'; Name = 'AllowCopilotRuntime'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot runtime' }
    @{ G = 'Copilot'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'ShowCopilotButton'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot taskbar button' }
    @{ G = 'Copilot'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'TaskbarCompanion'; Type = 'REG_DWORD'; Want = 0; Note = 'Ask Copilot in search' }
    @{ G = 'Copilot'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins'; Name = 'CopilotPWAPin'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot taskbar pin' }
    @{ G = 'Copilot'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins'; Name = 'RecallPin'; Type = 'REG_DWORD'; Want = 0; Note = 'Recall taskbar pin' }
    @{ G = 'Copilot'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'; Name = 'AutoOpenCopilotLargeScreens'; Type = 'REG_DWORD'; Want = 0; Note = 'Auto-open Copilot on large screens' }
    @{ G = 'Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableConsumerAccountStateContent'; Type = 'REG_DWORD'; Want = 1; Note = 'Hide Copilot ads in Settings' }

    # --- Search / input / privacy ---
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'DisableSearchBoxSuggestions'; Type = 'REG_DWORD'; Want = 1; Note = 'Copilot/suggestions in search' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\input\Settings'; Name = 'InsightsEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Input Insights / typing data harvesting' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps'; Name = 'AgentActivationEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Voice agent activation' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\InputPersonalization'; Name = 'RestrictImplicitInkCollection'; Type = 'REG_DWORD'; Want = 1; Note = 'Ink collection for AI training' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\InputPersonalization'; Name = 'RestrictImplicitTextCollection'; Type = 'REG_DWORD'; Want = 1; Note = 'Text collection for AI training' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore'; Name = 'HarvestContacts'; Type = 'REG_DWORD'; Want = 0; Note = 'Contact harvesting' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization'; Name = 'Value'; Type = 'REG_DWORD'; Want = 0; Note = 'Inking & typing personalization' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\Windows\Shell\ClickToDo'; Name = 'DisableClickToDo'; Type = 'REG_DWORD'; Want = 1; Note = 'Click to Do (user shell)' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers'; Name = 'A9HomeContentEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Recall customized home page' }
    @{ G = 'Search/Input/Privacy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels'; Name = 'RecordUsageData'; Type = 'REG_DWORD'; Want = 0; Note = 'AI model usage telemetry' }

    # --- Voice Access ---
    @{ G = 'Voice Access'; Path = 'HKCU:\Software\Microsoft\VoiceAccess'; Name = 'RunningState'; Type = 'REG_DWORD'; Want = 0; Note = 'Voice Access running state' }
    @{ G = 'Voice Access'; Path = 'HKCU:\Software\Microsoft\VoiceAccess'; Name = 'TextCorrection'; Type = 'REG_DWORD'; Want = 1; Note = 'Voice Access text correction' }

    # --- AI Actions (Feature Management Overrides) ---
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1853569164'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'AI Actions' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\4098520719'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'AI Actions' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\929719951'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'AI Actions' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1646260367'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 2; Note = 'Hide AI actions in context menu' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\3389499533'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'Copilot in systray' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\4027803789'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'Copilot in systray' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\450471565'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'Copilot in systray' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\2283032206'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'Core AI / Click to Do' }
    @{ G = 'AI Actions'; Path = 'HKLM:\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\502943886'; Name = 'EnabledState'; Type = 'REG_DWORD'; Want = 1; Note = 'Core AI / Click to Do' }

    # --- Paint AI ---
    @{ G = 'Paint AI'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'; Name = 'DisableImageCreator'; Type = 'REG_DWORD'; Want = 1; Note = 'Paint Image Creator' }
    @{ G = 'Paint AI'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View'; Name = 'IsSignedUpForTargetingService'; Type = 'REG_DWORD'; Want = 0; Note = 'Paint AI experiment program' }
    @{ G = 'Paint AI'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View'; Name = 'IsNotInterestedInTargetingService'; Type = 'REG_DWORD'; Want = 1; Note = 'Paint AI experiment - opt out' }
    @{ G = 'Paint AI'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View'; Name = 'LeftTargetingService'; Type = 'REG_DWORD'; Want = 1; Note = 'Paint AI experiment - left' }

    # --- Edge Copilot ---
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'HubsSidebarEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Edge sidebar (Copilot)' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'CopilotPageContext'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot reads the page' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'CopilotCDPPageContext'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot reads the page (CDP)' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'EdgeEntraCopilotPageContext'; Type = 'REG_DWORD'; Want = 0; Note = 'Entra Copilot reads the page' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ComposeInlineEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'AI Compose' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'AllowBrowsingWithCopilot'; Type = 'REG_DWORD'; Want = 0; Note = 'Browsing with Copilot' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'CopilotNewTabPageEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot on the new tab page' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'EdgeHistoryAISearchEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'AI search in history' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'AIGenThemesEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'AI themes' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'BuiltInAIAPIsEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Built-in AI APIs' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ShareBrowsingHistoryWithCopilotSearchAllowed'; Type = 'REG_DWORD'; Want = 0; Note = 'Share history with Copilot Search' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'M365LinksAutoOpenCopilotEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'M365 links auto-open Copilot' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'Microsoft365CopilotChatIconEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'M365 Copilot Chat icon' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'GenAILocalFoundationalModelSettings'; Type = 'REG_DWORD'; Want = 1; Note = 'Edge local GenAI model (1=off)' }
    @{ G = 'Edge Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'DevToolsGenAiSettings'; Type = 'REG_DWORD'; Want = 2; Note = 'DevTools GenAI (2=off)' }

    # --- Office Copilot ---
    @{ G = 'Office Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\training\general'; Name = 'disabletraining'; Type = 'REG_DWORD'; Want = 1; Note = 'Office AI training' }
    @{ G = 'Office Copilot'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\training\specific\adaptivefloatie'; Name = 'disabletrainingofadaptivefloatie'; Type = 'REG_DWORD'; Want = 1; Note = 'Office AI training (floatie)' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Policies\Microsoft\office\16.0\common\privacy'; Name = 'controllerconnectedservicesenabled'; Type = 'REG_DWORD'; Want = 2; Note = 'Office connected experiences' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Policies\Microsoft\office\16.0\common\privacy'; Name = 'usercontentdisabled'; Type = 'REG_DWORD'; Want = 2; Note = 'Office content analysis' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Microsoft\Office\16.0\Word\Options'; Name = 'EnableCopilot'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot in Word' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Microsoft\Office\16.0\Excel\Options'; Name = 'EnableCopilot'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot in Excel' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Microsoft\Office\16.0\OneNote\Options\Copilot'; Name = 'CopilotEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot in OneNote' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Microsoft\Office\16.0\OneNote\Options\Copilot'; Name = 'CopilotNotebooksEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot Notebooks (OneNote)' }
    @{ G = 'Office Copilot'; Path = 'HKCU:\Software\Microsoft\Office\16.0\OneNote\Options\Copilot'; Name = 'CopilotSkittleEnabled'; Type = 'REG_DWORD'; Want = 0; Note = 'Copilot Skittle (OneNote)' }

    # --- Notepad ---
    @{ G = 'Notepad'; Path = 'HKLM:\SOFTWARE\Policies\WindowsNotepad'; Name = 'DisableAIFeatures'; Type = 'REG_DWORD'; Want = 1; Note = 'Notepad AI (Rewrite) disabled' }
)

# === REGISTRY: PROTECTIVE keep keys (foundation) - DO NOT DELETE, hold at "Allow"/1 ===
# App access to local AI models = required for 3rd-party / local LLM (restore-high-risk.reg).
$keepRegKeys = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI'; Name = 'Value'; Type = 'REG_SZ'; Want = 'Allow'; Note = 'restore-high-risk: 3rd-party generativeAI' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'; Name = 'Value'; Type = 'REG_SZ'; Want = 'Allow'; Note = 'restore-high-risk: 3rd-party systemAIModels' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name = 'LetAppsAccessGenerativeAI'; Type = 'REG_DWORD'; Want = 1; Note = 'restore-high-risk: app access generativeAI' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name = 'LetAppsAccessSystemAIModels'; Type = 'REG_DWORD'; Want = 1; Note = 'restore-high-risk: app access systemAIModels' }
)

# === AI services (product) - stop + disable (Start=4), reversible ===
$aiServices = @(
    @{ Name = 'WSAIFabricSvc'; Note = 'Windows AI Fabric (on-device AI orchestration)' }
    @{ Name = 'MicrosoftCopilotElevationService'; Note = 'Copilot elevation service' }
)
# Services for reporting only (shared, not touched in foundation mode)
$reportServicePatterns = @('AarSvc*', 'AgentActivationRuntime*')

# CBS keywords for hidden AI packages
$cbsKeywords = 'AIX|Recall|Copilot|CoreAI'
$cbsRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'

# IntegratedServicesRegionPolicySet.json - path + targeted policies (match on $comment)
$regionPolicyJson = "$env:windir\System32\IntegratedServicesRegionPolicySet.json"
# Hide AI Components - page in Settings
$hidePolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$hideValueName = 'SettingsPageVisibility'

# ============================================================================
#  2) AUDIT
# ============================================================================
Out-Head 'AUDIT OF WINDOWS AI COMPONENTS'
$mode = if ($RemoveAllAI) { 'RemoveAllAI (remove EVERYTHING incl. runtime/LLM)' } else { 'foundation (keep runtime + local LLM)' }
$os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Out-Both ("Date:         {0}" -f (Get-Date))
Out-Both ("Computer:     {0}" -f $env:COMPUTERNAME)
Out-Both ("Windows:      {0} (build {1}.{2})" -f $os.DisplayVersion, $os.CurrentBuildNumber, $os.UBR)
Out-Both ("Mode:         {0}" -f $mode) 'White'
$marker = Get-ItemProperty 'HKLM:\SOFTWARE\RemoveWindowsAI' -ErrorAction SilentlyContinue
if ($marker) {
    Out-Both ("RemoveWindowsAI has run before. CachedBuild = {0}, current = {1}.{2}" -f $marker.CachedBuild, $os.CurrentBuildNumber, $os.UBR) 'Yellow'
    if ("$($os.CurrentBuildNumber).$($os.UBR)" -ne "$($marker.CachedBuild)") {
        Out-Both "  -> Build changed since the last run: Windows Update may have brought AI packages back." 'Yellow'
    }
}
else {
    Out-Both "RemoveWindowsAI has not run yet (marker HKLM\SOFTWARE\RemoveWindowsAI missing)." 'Yellow'
}

# --- 2a) Appx packages: split REMOVE / KEEP ---
Out-Head 'APPX PACKAGES'
$allAppx = Get-AppxPackage -AllUsers
$allProv = Get-AppxProvisionedPackage -Online

$matchedAppx = @()
$matchedPatterns = @()
foreach ($pat in $appxPatterns) {
    $hits = $allAppx | Where-Object { $_.Name -like $pat }
    if ($hits) { $matchedPatterns += $pat; $matchedAppx += $hits }
}
$matchedAppx = $matchedAppx | Sort-Object Name -Unique

$removeAppx = @($matchedAppx | Where-Object { -not (Test-Keep $_.Name) })
$keepAppx = @($matchedAppx | Where-Object { Test-Keep $_.Name })

if ($removeAppx.Count -gt 0) {
    Out-Both ("TO REMOVE ({0}):" -f $removeAppx.Count) 'Red'
    Out-Table (@($removeAppx | ForEach-Object { @{ Name = $_.Name; Desc = (Get-PkgDesc $_.Name) } })) 'Red'
}
else { Out-Both "To remove: nothing." 'Green' }

if ($keepAppx.Count -gt 0) {
    Out-Both ''
    Out-Both ("INTENTIONALLY KEPT - foundation/LLM ({0}):" -f $keepAppx.Count) 'Green'
    Out-Table (@($keepAppx | ForEach-Object { @{ Name = $_.Name; Desc = (Get-PkgDesc $_.Name) } })) 'Green'
}

$missingPatterns = $appxPatterns | Where-Object { $matchedPatterns -notcontains $_ -and $keepPatterns -notcontains $_ }
if ($missingPatterns) {
    Out-Both ''
    Out-Both ("NOT FOUND / already removed patterns ({0}) - the script will catch them if they return:" -f $missingPatterns.Count) 'DarkGray'
    foreach ($m in $missingPatterns) { Out-Both ("  [ ] {0}" -f $m) 'DarkGray' }
}

# --- 2b) Provisioned packages ---
Out-Head 'PROVISIONED PACKAGES'
$matchedProv = @()
foreach ($pat in $appxPatterns) { $matchedProv += $allProv | Where-Object { $_.DisplayName -like $pat } }
$matchedProv = $matchedProv | Sort-Object PackageName -Unique
$removeProv = @($matchedProv | Where-Object { -not (Test-Keep $_.DisplayName) })
$keepProv = @($matchedProv | Where-Object { Test-Keep $_.DisplayName })

if ($removeProv.Count -gt 0) {
    Out-Both ("TO REMOVE ({0}):" -f $removeProv.Count) 'Red'
    foreach ($p in $removeProv) { Out-Both ("  [x] {0}" -f $p.PackageName) 'Red' }
}
else { Out-Both "To remove: nothing." 'Green' }
if ($keepProv.Count -gt 0) {
    Out-Both ("KEPT ({0}):" -f $keepProv.Count) 'Green'
    foreach ($p in $keepProv) { Out-Both ("  [keep] {0}" -f $p.PackageName) 'DarkGreen' }
}

# --- 2c) Files (only for packages to remove + product installers) ---
Out-Head 'FILES ON DISK'

$installLocations = @()
foreach ($p in $removeAppx) {
    if ($p.InstallLocation -and (Test-Path $p.InstallLocation)) { $installLocations += $p.InstallLocation }
}
$localAppDataDirs = @()
foreach ($p in $removeAppx) {
    if ($p.PackageFamilyName) {
        $d = Join-Path "$env:LOCALAPPDATA\Packages" $p.PackageFamilyName
        if (Test-Path $d) { $localAppDataDirs += $d }
    }
}
# Edge copilot installers
$edgeFiles = @()
$edgeBase = "${env:ProgramFiles(x86)}\Microsoft"
foreach ($folder in @('Edge', 'EdgeCore', 'EdgeWebView')) {
    if ($folder -eq 'EdgeCore') {
        $edgeFiles += (Get-ChildItem -Path "$edgeBase\$folder\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
    }
    else {
        $edgeFiles += (Get-ChildItem -Path "$edgeBase\$folder\Application\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
    }
}
$edgeFiles += (Get-ChildItem "$edgeBase\EdgeUpdate" -Recurse -Filter '*CopilotUpdate.exe*' -ErrorAction SilentlyContinue).FullName
$edgeFiles += (Get-ChildItem $edgeBase -Recurse -Filter '*Copilot_setup*' -ErrorAction SilentlyContinue).FullName
$inboxCopilot = (Get-ChildItem 'C:\Windows\InboxApps' -Filter '*Copilot*' -ErrorAction SilentlyContinue).FullName

# Recall / CoreAI user data
$coreAiData = (Get-ChildItem -Path "$env:LOCALAPPDATA\CoreAIPlatform*" -ErrorAction SilentlyContinue).FullName
$copilotChat = @()
if ($env:OneDrive) {
    $cc = Join-Path $env:OneDrive 'Microsoft Copilot Chat Files'
    if (Test-Path $cc) { $copilotChat += $cc }
}

$dllList = $copilotDlls
if ($RemoveAllAI) { $dllList = $copilotDlls + $winmlDlls }

$fileGroups = [ordered]@{
    'Copilot settings DLL'      = ($dllList | Where-Object { Test-Path $_ })
    'App Actions binaries'      = ($appActionsFiles | Where-Object { Test-Path $_ })
    'ActionsMcpHost'            = ($actionsMcpHostFiles | Where-Object { Test-Path $_ })
    'Office AI'                 = ($officeAiPaths | Where-Object { Test-Path $_ })
    'Edge Copilot installers'   = ($edgeFiles | Where-Object { $_ -and (Test-Path $_) })
    'InboxApps Copilot'         = ($inboxCopilot | Where-Object { $_ -and (Test-Path $_) })
    'Recall/CoreAI data'        = ($coreAiData | Where-Object { $_ -and (Test-Path $_) })
    'Copilot Chat (OneDrive)'   = ($copilotChat | Where-Object { Test-Path $_ })
    'AppX install locations'    = $installLocations
    'LocalAppData\Packages'     = $localAppDataDirs
}

$Global:FilesToRemove = New-Object System.Collections.Generic.List[string]
foreach ($g in $fileGroups.Keys) {
    $items = @($fileGroups[$g] | Sort-Object -Unique)
    if ($items.Count -gt 0) {
        Out-Both ("{0} ({1}):" -f $g, $items.Count) 'Red'
        foreach ($i in $items) { Out-Both ("  [x] $i") 'Red'; $Global:FilesToRemove.Add($i) }
    }
    else { Out-Both ("{0}: nothing" -f $g) 'Green' }
}
if (-not $RemoveAllAI) {
    $keptDlls = @($winmlDlls | Where-Object { Test-Path $_ })
    if ($keptDlls.Count -gt 0) {
        Out-Both ''
        Out-Both ("INTENTIONALLY KEPT DLLs ({0}):" -f $keptDlls.Count) 'Green'
        Out-Table (@($keptDlls | ForEach-Object { @{ Name = (Split-Path $_ -Leaf); Desc = (Get-PkgDesc $_) } })) 'Green'
    }
}

# --- 2d) AI services ---
Out-Head 'AI SERVICES'
$Global:ServicesToDisable = @()
foreach ($svc in $aiServices) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($s) {
        $start = (Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" 'Start')
        $disabled = ($start -eq 4)
        $col = if ($disabled) { 'Green' } else { 'Red' }
        $tag = if ($disabled) { 'already disabled' } else { 'to disable' }
        Out-Both ("  [{0}] {1} ({2}) - status {3}, start={4}" -f $tag, $svc.Name, $svc.Note, $s.Status, $start) $col
        if (-not $disabled) { $Global:ServicesToDisable += $svc }
    }
    else {
        Out-Both ("  [ ] {0} ({1}) - not present" -f $svc.Name, $svc.Note) 'DarkGray'
    }
}
$reportSvcs = @()
foreach ($pat in $reportServicePatterns) { $reportSvcs += Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $pat } }
$reportSvcs = $reportSvcs | Sort-Object Name -Unique
if ($reportSvcs) {
    Out-Both ''
    Out-Both 'Shared services (info only, not touched in foundation mode):' 'White'
    foreach ($s in $reportSvcs) { Out-Both ("  [info] {0} ({1})" -f $s.Name, $s.Status) 'DarkGray' }
}

# --- 2e) Registry: DISABLE keys ---
Out-Head 'REGISTRY - DISABLE KEYS (turn off product AI)'
$Global:DisableKeysToFix = New-Object System.Collections.Generic.List[object]
$groups = $disableRegKeys | ForEach-Object { $_.G } | Select-Object -Unique
foreach ($grp in $groups) {
    Out-Both ("[{0}]" -f $grp) 'White'
    foreach ($k in ($disableRegKeys | Where-Object { $_.G -eq $grp })) {
        $cur = Get-RegVal $k.Path $k.Name
        if ($null -eq $cur) {
            Out-Both ("  [missing] {0}\{1} -> want {2}  ({3})" -f (ConvertTo-RegExe $k.Path), $k.Name, $k.Want, $k.Note) 'Yellow'
            $Global:DisableKeysToFix.Add($k)
        }
        elseif ("$cur" -eq "$($k.Want)") {
            Out-Both ("  [OK]      {0}\{1} = {2}  ({3})" -f (ConvertTo-RegExe $k.Path), $k.Name, $cur, $k.Note) 'DarkGray'
        }
        else {
            Out-Both ("  [!!diff]  {0}\{1} = {2} -> want {3}  ({4})" -f (ConvertTo-RegExe $k.Path), $k.Name, $cur, $k.Want, $k.Note) 'Yellow'
            $Global:DisableKeysToFix.Add($k)
        }
    }
}

# --- 2f) Registry: leftover keys to delete + protective keep ---
Out-Head 'REGISTRY - LEFTOVER + PROTECTIVE'
Out-Both 'Leftover keys of AI apps (to delete):' 'White'
$Global:RegToRemove = New-Object System.Collections.Generic.List[string]
foreach ($k in $appRegKeys) {
    if (Test-Path $k) { Out-Both ("  [x] $k") 'Red'; $Global:RegToRemove.Add($k) }
    else { Out-Both ("  [ ] $k") 'DarkGray' }
}
Out-Both ''
Out-Both 'Protective / desired values (DO NOT DELETE, the script keeps them on):' 'White'
foreach ($pk in $keepRegKeys) {
    $val = Get-RegVal $pk.Path $pk.Name
    if ($null -ne $val) {
        $ok = ("$val" -eq "$($pk.Want)")
        $state = if ($ok) { 'OK' } else { '!! different value (want ' + $pk.Want + ')' }
        $col = if ($ok) { 'Gray' } else { 'Yellow' }
        Out-Both ("  [{0}] {1}\{2} = {3}  ({4})" -f $state, (ConvertTo-RegExe $pk.Path), $pk.Name, $val, $pk.Note) $col
    }
    else {
        Out-Both ("  [missing] {0}\{1} = (not set) -> want {2}  ({3})" -f (ConvertTo-RegExe $pk.Path), $pk.Name, $pk.Want, $pk.Note) 'Yellow'
    }
}

# --- 2g) CBS hidden AI packages ---
Out-Head 'CBS - HIDDEN AI PACKAGES (Component Based Servicing)'
$Global:CbsToRemove = @()
if ($SkipCBS) {
    Out-Both 'Skipped (-SkipCBS).' 'DarkGray'
}
else {
    $cbsMatches = @(Get-ChildItem $cbsRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $cbsKeywords })
    if ($cbsMatches.Count -gt 0) {
        Out-Both ("Found {0} CBS packages matching AI ({1}):" -f $cbsMatches.Count, $cbsKeywords) 'Red'
        foreach ($c in $cbsMatches) {
            $vis = (Get-RegVal "registry::$($c.Name)" 'Visibility')
            Out-Both ("  [x] {0}  (Visibility={1})" -f $c.PSChildName, $vis) 'Red'
        }
        $Global:CbsToRemove = $cbsMatches
    }
    else { Out-Both 'No hidden AI CBS packages found.' 'Green' }
}

# --- 2h) Recall optional feature + scheduled tasks + taskcache ---
Out-Head 'RECALL + SCHEDULED TASKS'
$recall = Get-WindowsOptionalFeature -Online -FeatureName 'Recall' -ErrorAction SilentlyContinue
$Global:RecallFeaturePresent = $false
if ($recall) {
    $payloadRemoved = ($recall.State -match 'DisabledWithPayloadRemoved')
    $col = if ($recall.State -match 'Disabled') { 'Green' } else { 'Red' }
    Out-Both ("Recall optional feature: {0}" -f $recall.State) $col
    if (-not $payloadRemoved) { $Global:RecallFeaturePresent = $true }
}
else { Out-Both 'Recall optional feature: not found' 'Green' }

$Global:TasksToRemove = @()
$aiTasks = @()
$aiTasks += Get-ScheduledTask -TaskPath '*WindowsAI*' -ErrorAction SilentlyContinue
$aiTasks += Get-ScheduledTask -TaskName '*Office Actions Server*' -ErrorAction SilentlyContinue
$aiTasks = $aiTasks | Sort-Object TaskPath, TaskName -Unique
if ($aiTasks) {
    Out-Both ("AI scheduled tasks ({0}):" -f $aiTasks.Count) 'Red'
    foreach ($t in $aiTasks) { Out-Both ("  [x] {0}{1}  ({2})" -f $t.TaskPath, $t.TaskName, $t.State) 'Red' }
    $Global:TasksToRemove = $aiTasks
}
else { Out-Both 'No AI scheduled tasks found.' 'Green' }

# TaskCache Tree leftovers (even when the tasks are not visible via Get-ScheduledTask)
$taskTreeKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI'
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Office\Office Actions Server'
)
$Global:TaskTreeToRemove = @($taskTreeKeys | Where-Object { Test-Path $_ })
if ($Global:TaskTreeToRemove.Count -gt 0) {
    Out-Both ("TaskCache Tree leftovers ({0}):" -f $Global:TaskTreeToRemove.Count) 'Red'
    foreach ($k in $Global:TaskTreeToRemove) { Out-Both ("  [x] $k") 'Red' }
}

# --- 2i) IntegratedServicesRegionPolicySet.json (Copilot region policy) ---
Out-Head 'REGION POLICY (IntegratedServicesRegionPolicySet.json)'
$Global:RegionPolicyNeedsFix = $false
if ($SkipRegionPolicy) {
    Out-Both 'Skipped (-SkipRegionPolicy).' 'DarkGray'
}
elseif (Test-Path $regionPolicyJson) {
    try {
        $rp = Get-Content $regionPolicyJson -Raw | ConvertFrom-Json
        $cop = @($rp.policies | Where-Object { $_.'$comment' -like '*CoPilot*' -or $_.'$comment' -like '*Manage Recall*' })
        $a9 = @($rp.policies | Where-Object { $_.'$comment' -like '*A9*' -or $_.'$comment' -like '*Settings Agent*' })
        $copBad = @($cop | Where-Object { $_.defaultState -ne 'disabled' })
        $a9Bad = @($a9 | Where-Object { $_.defaultState -ne 'enabled' })
        Out-Both ("Copilot/Recall policies: {0} (not set to disabled: {1})" -f $cop.Count, $copBad.Count) (@('Green', 'Red')[[int]($copBad.Count -gt 0)])
        Out-Both ("A9/Settings Agent policies: {0} (not set to enabled: {1})" -f $a9.Count, $a9Bad.Count) (@('Green', 'Red')[[int]($a9Bad.Count -gt 0)])
        if ($copBad.Count -gt 0 -or $a9Bad.Count -gt 0) { $Global:RegionPolicyNeedsFix = $true }
    }
    catch { Out-Both ("Cannot read JSON: {0}" -f $_.Exception.Message) 'Yellow' }
}
else { Out-Both 'File does not exist (no region policy on this build).' 'Green' }

# --- 2j) Hide AI Components page in Settings ---
Out-Head 'HIDE AI COMPONENTS (page in Settings)'
$Global:HideNeedsFix = $false
if ($SkipHide) {
    Out-Both 'Skipped (-SkipHide).' 'DarkGray'
}
else {
    $curVis = Get-RegVal $hidePolicyPath $hideValueName
    if ($curVis -like '*aicomponents*') {
        Out-Both ("Already hidden: {0} = {1}" -f $hideValueName, $curVis) 'Green'
    }
    elseif ($curVis -like '*showonly*') {
        Out-Both ("SettingsPageVisibility contains 'showonly' -> skipping (manual setting): {0}" -f $curVis) 'Yellow'
    }
    else {
        $disp = if ($null -eq $curVis) { '(not set)' } else { $curVis }
        Out-Both ("AI Components page is NOT hidden: {0} = {1}" -f $hideValueName, $disp) 'Yellow'
        $Global:HideNeedsFix = $true
    }
}

# ============================================================================
#  3) Summary
# ============================================================================
Out-Head 'SUMMARY'
$cntAppx = $removeAppx.Count
$cntProv = $removeProv.Count
$cntFiles = $Global:FilesToRemove.Count
$cntSvc = ($Global:ServicesToDisable | Measure-Object).Count
$cntDisable = $Global:DisableKeysToFix.Count
$cntReg = $Global:RegToRemove.Count
$cntCbs = ($Global:CbsToRemove | Measure-Object).Count
$cntTasks = ($Global:TasksToRemove | Measure-Object).Count
$cntTree = ($Global:TaskTreeToRemove | Measure-Object).Count
$cntKeep = $keepAppx.Count
Out-Both ("Appx to uninstall:            {0}" -f $cntAppx) (@('Green', 'Red')[[int]($cntAppx -gt 0)])
Out-Both ("Provisioned to remove:        {0}" -f $cntProv) (@('Green', 'Red')[[int]($cntProv -gt 0)])
Out-Both ("Files/folders to delete:      {0}" -f $cntFiles) (@('Green', 'Red')[[int]($cntFiles -gt 0)])
Out-Both ("AI services to disable:       {0}" -f $cntSvc) (@('Green', 'Red')[[int]($cntSvc -gt 0)])
Out-Both ("Disable reg keys to set:      {0}" -f $cntDisable) (@('Green', 'Red')[[int]($cntDisable -gt 0)])
Out-Both ("Leftover reg keys to delete:  {0}" -f $cntReg) (@('Green', 'Red')[[int]($cntReg -gt 0)])
Out-Both ("CBS packages to remove:       {0}" -f $cntCbs) (@('Green', 'Red')[[int]($cntCbs -gt 0)])
Out-Both ("Scheduled tasks:              {0}" -f $cntTasks) (@('Green', 'Red')[[int]($cntTasks -gt 0)])
Out-Both ("TaskCache Tree leftovers:     {0}" -f $cntTree) (@('Green', 'Red')[[int]($cntTree -gt 0)])
Out-Both ("Recall feature active:        {0}" -f $(if ($Global:RecallFeaturePresent) { 'YES' } else { 'no' })) (@('Green', 'Red')[[int]$Global:RecallFeaturePresent])
Out-Both ("Region policy to edit:        {0}" -f $(if ($Global:RegionPolicyNeedsFix) { 'YES' } else { 'no' })) (@('Green', 'Red')[[int]$Global:RegionPolicyNeedsFix])
Out-Both ("Hide AI Components:           {0}" -f $(if ($Global:HideNeedsFix) { 'to set' } else { 'OK' })) (@('Green', 'Red')[[int]$Global:HideNeedsFix])
Out-Both ("Kept (foundation/LLM):        {0}" -f $cntKeep) 'Green'

$totalFound = $cntAppx + $cntProv + $cntFiles + $cntSvc + $cntDisable + $cntReg + $cntCbs + $cntTasks + $cntTree `
    + [int]$Global:RecallFeaturePresent + [int]$Global:RegionPolicyNeedsFix + [int]$Global:HideNeedsFix
Save-Report
Out-Both ''
Out-Both ("Report saved: {0}" -f $Report) 'Cyan'

# ============================================================================
#  4) Removal offer
# ============================================================================
if ($AuditOnly) {
    Out-Both "`nDone (audit-only). To remove, run without -AuditOnly." 'Cyan'
    if (-not $Yes) { Read-Host "`nPress Enter to exit" | Out-Null }
    return
}
if ($totalFound -eq 0) {
    Out-Both "`nNothing to remove / set." 'Green'
    if (-not $Yes) { Read-Host "`nPress Enter to exit" | Out-Null }
    return
}

$proceed = $false
if ($Remove -and $Yes) { $proceed = $true }
else {
    Write-Host ''
    $ans = Read-Host "Perform removal + disable ($totalFound items, foundation/LLM stays)? [Y/N]"
    $proceed = $ans -match '^(a|A|y|Y|ano|yes)$'
}
if (-not $proceed) {
    Out-Both "`nRemoval cancelled. Nothing changed." 'Yellow'
    if (-not $Yes) { Read-Host "Press Enter to exit" | Out-Null }
    return
}

Out-Head 'REMOVING'
$fail = New-Object System.Collections.Generic.List[string]

function Remove-FileForced {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $true }
    try { Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop; return $true } catch {}
    & takeown.exe /f "$Path" /r /d Y *>$null
    & icacls.exe "$Path" /grant "*S-1-5-32-544:F" /t /c *>$null
    try { Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop; return $true } catch {}
    if (-not $NoTrustedInstaller) {
        Run-Trusted -command "Remove-Item -Path `"$Path`" -Recurse -Force -ErrorAction SilentlyContinue"
        Start-Sleep 1
        if (-not (Test-Path $Path)) { return $true }
    }
    return $false
}

# --- 4a) Appx: standard uninstall ---
foreach ($p in $removeAppx) {
    Write-Host ("Uninstalling Appx: {0}" -f $p.Name) -ForegroundColor Gray
    try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop } catch {}
}
foreach ($p in $removeProv) {
    Write-Host ("Removing provisioned: {0}" -f $p.DisplayName) -ForegroundColor Gray
    try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -AllUsers -ErrorAction Stop } catch {}
}

# --- 4b) Appx: TrustedInstaller finish-off for non-removable ---
$leftover = @(Get-AppxPackage -AllUsers | Where-Object {
        $n = $_.Name
        ($removeAppx.Name -contains $n)
    })
if ($leftover.Count -gt 0 -and -not $NoTrustedInstaller) {
    Out-Both ("TrustedInstaller: finishing off {0} non-removable packages..." -f $leftover.Count) 'Yellow'

    $removeNames = @($removeAppx.Name) + @($removeProv.DisplayName) | Sort-Object -Unique
    $pkgArrayText = ($removeNames | ForEach-Object { "    '$_'" }) -join "`n"

    $payloadBody = @'
$provisioned = get-appxprovisionedpackage -online
$appxpackage = get-appxpackage -allusers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }
foreach ($choice in $aipackages) {
    foreach ($appx in $($provisioned | Where-Object { $_.DisplayName -eq $choice })) {
        $PackageName = $appx.PackageName
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
        if ($PackageFamilyName) {
            New-Item "$store\Deprovisioned\$PackageFamilyName" -force | Out-Null
            try { Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0 } catch {}
        }
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers
    }
    foreach ($appx in $($appxpackage | Where-Object { $_.Name -eq $choice })) {
        $PackageFullName = $appx.PackageFullName
        $PackageFamilyName = $appx.PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force | Out-Null
        try { Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0 } catch {}
        Remove-Item -Path "$store\InboxApplications\$PackageFullName" -Force -ErrorAction SilentlyContinue
        foreach ($user in $appx.PackageUserInformation) {
            $sid = $user.UserSecurityID.SID
            New-Item "$store\EndOfLife\$sid\$PackageFullName" -force | Out-Null
            remove-appxpackage -package $PackageFullName -User $sid
        }
        remove-appxpackage -package $PackageFullName -allusers
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force | Out-Null }
    }
}
'@
    $removalScript = "`$aipackages = @(`n$pkgArrayText`n)`n`n" + $payloadBody
    $removalPath = "$($tempDir)aiPackageRemoval.ps1"
    Set-Content -Path $removalPath -Value $removalScript -Encoding UTF8 -Force

    $attempts = 0
    do {
        $cmd = "Set-ExecutionPolicy Bypass -Scope Process -Force; &`"$removalPath`""
        Run-Trusted -command $cmd
        Start-Sleep 2
        $leftover = @(Get-AppxPackage -AllUsers | Where-Object { $removeAppx.Name -contains $_.Name })
        $attempts++
    } while ($leftover.Count -gt 0 -and $attempts -lt 8)

    Remove-Item $removalPath -Force -ErrorAction SilentlyContinue
    foreach ($lo in $leftover) { $fail.Add("APPX  $($lo.Name)  [non-removable - failed even via TI]") }
}
elseif ($leftover.Count -gt 0) {
    foreach ($lo in $leftover) { $fail.Add("APPX  $($lo.Name)  [non-removable - TI disabled by switch]") }
}

# --- 4c) AI services: stop + disable (Start=4) ---
if (-not $SkipServices) {
    foreach ($svc in $Global:ServicesToDisable) {
        Write-Host ("Disabling service: {0}" -f $svc.Name) -ForegroundColor Gray
        try { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue } catch {}
        try { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop }
        catch { & sc.exe config $svc.Name start= disabled *>$null }
        $start = (Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" 'Start')
        if ($start -ne 4) { $fail.Add("SVC   $($svc.Name)  [could not disable]") }
    }
}

# --- 4d) Files ---
# Kill App Actions processes first
& taskkill.exe /im AppActions.exe /f *>$null
& taskkill.exe /im VisualAssist.exe /f *>$null
& taskkill.exe /im ActionsMcpHost.exe /f *>$null
foreach ($f in $Global:FilesToRemove) {
    Write-Host ("Deleting: {0}" -f $f) -ForegroundColor Gray
    if (-not (Remove-FileForced -Path $f)) { $fail.Add("FILE  $f  [locked]") }
}
& reg.exe delete 'HKLM\SOFTWARE\Microsoft\EdgeUpdate' /v 'CopilotUpdatePath' /f *>$null
& reg.exe delete 'HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate' /v 'CopilotUpdatePath' /f *>$null
# Shell Update Packages\Components - AI values
& reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIX' /f *>$null
& reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'CopilotNudges' /f *>$null
& reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIContext' /f *>$null

# --- 4e) Registry: DISABLE keys (set even if missing - a guard) ---
Out-Both ("Setting {0} disable reg keys..." -f $Global:DisableKeysToFix.Count) 'Cyan'
foreach ($k in $Global:DisableKeysToFix) {
    Set-RegValForced -Path $k.Path -Name $k.Name -Type $k.Type -Value $k.Want
    $cur = Get-RegVal $k.Path $k.Name
    if ("$cur" -ne "$($k.Want)") { $fail.Add("REGSET $((ConvertTo-RegExe $k.Path))\$($k.Name)") }
}

# --- 4f) Registry leftover (delete) ---
foreach ($k in $Global:RegToRemove) {
    Write-Host ("Deleting registry: {0}" -f $k) -ForegroundColor Gray
    try { Remove-Item -Path $k -Recurse -Force -ErrorAction Stop }
    catch {
        $rp = ConvertTo-RegExe $k
        & reg.exe delete "$rp" /f *>$null
        if (Test-Path $k) {
            if (-not $NoTrustedInstaller) {
                Run-Trusted -command "Remove-Item -Path `"$k`" -Recurse -Force -ErrorAction SilentlyContinue; reg.exe delete `"$rp`" /f"
                Start-Sleep 1
            }
            if (Test-Path $k) { $fail.Add("REG   $k") }
        }
    }
}

# --- 4g) CBS hidden packages: unhide + remove ---
if (-not $SkipCBS -and $Global:CbsToRemove.Count -gt 0) {
    Out-Both ("Removing {0} CBS packages..." -f $Global:CbsToRemove.Count) 'Cyan'
    foreach ($c in $Global:CbsToRemove) {
        $pkgName = $c.PSChildName
        Write-Host ("CBS: {0}" -f $pkgName) -ForegroundColor Gray
        $key = "registry::$($c.Name)"
        try {
            Set-ItemProperty $key -Name Visibility -Value 1 -Force -ErrorAction SilentlyContinue
            New-ItemProperty $key -Name DefVis -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item "$key\Owners" -Force -ErrorAction SilentlyContinue
            Remove-Item "$key\Updates" -Force -ErrorAction SilentlyContinue
        }
        catch {}
        $removed = $false
        try { Remove-WindowsPackage -Online -PackageName $pkgName -NoRestart -ErrorAction Stop *>$null; $removed = $true } catch {}
        if (-not $removed) {
            & dism.exe /Online /Remove-Package /PackageName:$pkgName /NoRestart /Quiet *>$null
            if ($LASTEXITCODE -eq 0) { $removed = $true }
        }
        if ($removed) {
            Get-ChildItem "$env:windir\servicing\Packages" -Filter "*$pkgName*" -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        else { $fail.Add("CBS   $pkgName") }
    }
}

# --- 4h) Recall optional feature ---
if ($Global:RecallFeaturePresent) {
    Out-Both 'Removing Recall optional feature...' 'Cyan'
    try { Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -Remove -NoRestart -ErrorAction Stop *>$null }
    catch { & dism.exe /Online /Disable-Feature /FeatureName:Recall /Remove /NoRestart /Quiet *>$null }
}

# --- 4i) Scheduled tasks ---
foreach ($t in $Global:TasksToRemove) {
    Write-Host ("Removing task: {0}{1}" -f $t.TaskPath, $t.TaskName) -ForegroundColor Gray
    try { Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop }
    catch { $fail.Add("TASK  $($t.TaskPath)$($t.TaskName)") }
}
# TaskCache Tree + Tasks (resolve GUID Id) + on-disk folders
$taskCacheTasks = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
$recallTreeBranches = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration'
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration'
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Office\Office Actions Server'
)
foreach ($b in $recallTreeBranches) {
    $id = Get-RegVal $b 'Id'
    if ($id) {
        $tk = Join-Path $taskCacheTasks $id
        try { Remove-Item -Path $tk -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
}
foreach ($k in $Global:TaskTreeToRemove) {
    try { Remove-Item -Path $k -Recurse -Force -ErrorAction Stop }
    catch {
        if (-not $NoTrustedInstaller) {
            Run-Trusted -command "Remove-Item -Path `"$k`" -Recurse -Force -ErrorAction SilentlyContinue"
        }
    }
}
foreach ($tf in @("$env:Systemroot\System32\Tasks\Microsoft\Windows\WindowsAI", "$env:Systemroot\System32\Tasks\Microsoft\Office\Office Actions Server")) {
    if (Test-Path $tf) { Remove-FileForced -Path $tf | Out-Null }
}

# --- 4j) Region policy JSON (Copilot/Recall -> disabled, A9/Settings Agent -> enabled) ---
if (-not $SkipRegionPolicy -and $Global:RegionPolicyNeedsFix -and (Test-Path $regionPolicyJson)) {
    Out-Both 'Editing IntegratedServicesRegionPolicySet.json...' 'Cyan'
    & takeown.exe /f "$regionPolicyJson" *>$null
    & icacls.exe "$regionPolicyJson" /grant "*S-1-5-32-544:F" /t /c *>$null
    try {
        $rp = Get-Content $regionPolicyJson -Raw | ConvertFrom-Json
        foreach ($pol in $rp.policies) {
            $c = $pol.'$comment'
            if ($c -like '*CoPilot*' -or $c -like '*Manage Recall*') { $pol.defaultState = 'disabled' }
            elseif ($c -like '*A9*' -or $c -like '*Settings Agent*') { $pol.defaultState = 'enabled' }
        }
        ($rp | ConvertTo-Json -Depth 100) | Set-Content -Path $regionPolicyJson -Force -Encoding UTF8
    }
    catch { $fail.Add("JSON  $regionPolicyJson") }
}

# --- 4k) Hide AI Components ---
if (-not $SkipHide -and $Global:HideNeedsFix) {
    $curVis = Get-RegVal $hidePolicyPath $hideValueName
    if ($curVis -notlike '*showonly*') {
        if ($null -eq $curVis) { $new = 'hide:aicomponents;appactions;' }
        elseif ($curVis -notlike '*aicomponents*') {
            $sep = if ($curVis.EndsWith(';')) { '' } else { ';' }
            $new = "$curVis$sep" + 'aicomponents;appactions;'
        }
        else { $new = $curVis }
        Set-RegValForced -Path $hidePolicyPath -Name $hideValueName -Type 'REG_SZ' -Value $new
    }
}

# --- 4l) Anti-reinstall guard (only for product apps, not foundation) ---
& reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' /v 'CopilotPWAPreinstallCompleted' /t REG_DWORD /d '1' /f *>$null
& reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' /v 'Microsoft.Copilot_8wekyb3d8bbwe' /t REG_DWORD /d '1' /f *>$null
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' /v 'Enabled' /t REG_DWORD /d '1' /f *>$null
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Copilot_8wekyb3d8bbwe' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Clipchamp.Clipchamp_yxz26nhyzhsrt' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null

# Apply policy changes
& gpupdate.exe /force /wait:0 *>$null

# --- 4m) Protection: re-enable app access to local AI models (restore-high-risk.reg) ---
if (-not $SkipProtect) {
    $regFile = Join-Path $scriptDir 'restore-high-risk.reg'
    if (Test-Path $regFile) {
        Out-Both 'Applying restore-high-risk.reg (app access to local AI models)...' 'Cyan'
        & reg.exe import "$regFile" *>$null
    }
    else {
        # fallback - set the key values directly
        & reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI' /v 'Value' /t REG_SZ /d 'Allow' /f *>$null
        & reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels' /v 'Value' /t REG_SZ /d 'Allow' /f *>$null
        & reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessGenerativeAI' /t REG_DWORD /d '1' /f *>$null
        & reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessSystemAIModels' /t REG_DWORD /d '1' /f *>$null
    }
}

# ============================================================================
#  5) Result
# ============================================================================
Out-Head 'RESULT'
if ($fail.Count -eq 0) { Out-Both 'Everything removed / set without errors.' 'Green' }
else {
    Out-Both ("Not removed / not set ({0}):" -f $fail.Count) 'Yellow'
    foreach ($x in $fail) { Out-Both ("  - $x") 'Yellow' }
}
Out-Both ''
Out-Both 'Kept the base environment + local LLM (Phi Silica, ONNX/WinML, OpenVINO).' 'Green'
Out-Both 'App access to local AI models stays ENABLED.' 'Green'
Out-Both 'Recommendation: restart the PC.' 'Cyan'
Save-Report
if (-not $Yes) { Read-Host "`nPress Enter to exit" | Out-Null }
