param(
    [switch]$EnableLogging,
    [switch]$nonInteractive,
    [ValidateSet('DisableRegKeys',          
        'PreventAIPackageReinstall',     
        'DisableCopilotPolicies',       
        'RemoveAppxPackages',        
        'RemoveRecallFeature', 
        'RemoveCBSPackages',         
        'RemoveAIFiles',               
        'HideAIComponents',            
        'DisableRewrite',       
        'RemoveWindowsAITasks',
        'UpdateCleanupCheck')]
    [array]$Options,
    [switch]$AllOptions,
    [switch]$revertMode,
    [switch]$backupMode,
    [ValidateSet('photoviewer', 'mspaint', 'snippingtool', 'notepad', 'photoslegacy')]
    [array]$InstallClassicApps,
    [switch]$RunWinUpdateRepair,
    [switch]$ExcludeOptions
)

if ($nonInteractive) {
    if (!($AllOptions) -and (!$Options -or $Options.Count -eq 0) -and !($InstallClassicApps)) {
        throw 'Non-Interactive mode was supplied without any options... Please use -Options or -AllOptions when using Non-Interactive Mode'
        exit
    }
}


#get powershell version to ensure run-trusted doesnt enter an infinite loop
$version = $PSVersionTable.PSVersion
if ($version -like '7*') {
    $Global:psversion = 7
}
else {
    $Global:psversion = 5
}

if ($psversion -ge 7) {
    Write-Host 'ERROR: This script requires Windows PowerShell 5.1 (powershell.exe).' -ForegroundColor Red
    Write-Host "You are currently running PowerShell version $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)." -ForegroundColor Red
    Write-Host 'PowerShell 7+ (pwsh.exe) is not supported. Please run the script using the classic Windows PowerShell 5.1.' -ForegroundColor Red
    if (-not $nonInteractive) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show(
                "This script must be run in Windows PowerShell 5.1.`n`nCurrent version: $($PSVersionTable.PSVersion)`n`nPlease use powershell.exe instead of pwsh.exe.",
                'PowerShell Version Error',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        catch { }
    }
    exit 1
}

#check if powershell is being "locked down" aka in ConstrainedLangauge mode
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host 'ERROR: PowerShell is running in ' -NoNewline -ForegroundColor Red
    Write-Host "[$($ExecutionContext.SessionState.LanguageMode) Mode]!" -ForegroundColor Yellow
    Write-Host 'In order for this script to run PowerShell needs to be in FullLanguage Mode!' -ForegroundColor Red
    Write-Host "`nYou may be able to fix this by running the following command: reg delete `"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`" /v `"__PSLockdownPolicy`" /f" -ForegroundColor Red
    Write-Host "`nPress Any Key to Exit..."
    [System.Console]::ReadKey() >$null
    exit 1
}

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    #rebuild params from $MyInvocation.BoundParameters
    $paramStr = $MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object {
        $val = $_.Value
        $key = $_.Key
        switch ($val) {
            { $val -is [switch] -or $val -is [bool] } { "-$Key"; break }
            { $val -is [array] } { "-$key $($val -join ',')"; break }
            default { "-$key $val" }
        }
        
    }

    $arglist = "-NoProfile -ExecutionPolicy Bypass -C `"& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1'))) $($paramStr -join ' ')`""
    Start-Process PowerShell.exe -ArgumentList $arglist -Verb RunAs
    Exit	
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

#check if a third party av has replaced defender
$productNames = (Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct).displayName
$thirdPartyAvName = $null
if ($productNames.count -gt 1) {
    $thirdPartyAvName = $productNames | Where-Object { $_ -ne 'Windows Defender' }
}
elseif ($productNames -ne 'Windows Defender') {
    $thirdPartyAvName = $productNames
}

if ($thirdPartyAvName) {
    Write-Host 'WARNING: A third-party anti-virus has been detected!' -ForegroundColor Yellow
    Write-Host "The anti-virus: $thirdPartyAvName, may falsely block/break this script!" -ForegroundColor Yellow
    Write-Host 'Please disable or uninstall this anti-virus temporarily or proceed with caution!' -ForegroundColor Yellow
    Write-Host "`nPress Any Key to Continue..."
    [System.Console]::ReadKey() >$null
}

function Run-Trusted([String]$command, $psversion) {

    #run as ti by aveyo refactored for powershell use only
    #no powershell window flash
    #removed reg sym link as its not needed
    #fixed some issues with reflection methods
    function Invoke-AsTrustedInstaller {
        param(
            [string]$Code
        )

        $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $regKey = "Registry::HKU\$userSid\Volatile Environment"
        $userCodeValue = 'TI_Code'
        $payloadValue = 'TI_Payload'
        $bootstrapValue = 'TI_Bootstrap'

        Set-ItemProperty $regKey $userCodeValue $Code -Type 1 # REG_SZ

        #Bootstrap to run payload
        $bootstrap = @"
`$env:R = (Get-Item 'Registry::HKU\$userSid\Volatile Environment' -EA 0).GetValue('$($payloadValue)') -join `"``n`";
iex `$env:R
"@
        Set-ItemProperty $regKey $bootstrapValue $bootstrap -Type 1 # REG_SZ

        #Reflection / P-Invoke payload 
        $payload = @'
$I=[int32];$M=$I.module.gettype("System.Runtime.InteropServices.Marshal")
$P=[IntPtr];$S=[string];$Z=[uintptr]::size
$D=@();$T=@()
$DM=[AppDomain]::CurrentDomain.DefineDynamicAssembly(1,1).DefineDynamicModule(1)
0..5 | ForEach-Object { $D += $DM.DefineType("AveYo_$_", 265, [ValueType]) }
$D += [uintptr]
4..6 | ForEach-Object { $D += $D[$_].MakeByRefType() }
$F = 'kernel','advapi','advapi',
     ([string],[string],[int32],[int32],[int32],[int32],[int32],[string],$D[7],$D[8]),
     ([uintptr],[string],[int32],[int32],$D[9]),
     ([uintptr],[string],[int32],[int32],[byte[]],[int32])
0..2 | ForEach-Object {
    $D[0].DefinePInvokeMethod(
        ('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],
        $F[$_]+'32', 8214, 1, $S, $F[$_+3], 1, 4
    )
}
$DF = ($P,$I,$P),
      ($I,$I,$I,$I,$P,$D[1]),
      ($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),
      ($D[3],$P),
      ($P,$P,$I,$I)
1..5 | ForEach-Object {
    $k = $_; $n = 1
    $DF[$_-1] | ForEach-Object { $D[$k].DefineField('f'+$n++, $_, 6) }
}
0..5 | ForEach-Object { $T += $D[$_].CreateType() }
0..5 | ForEach-Object { New-Variable "A$_" ([Activator]::CreateInstance($T[$_])) -Force }
function Invoke-NativeMethod($Name, $MethodArgs) {
    $T[0].GetMethod($Name).Invoke($null, [object[]]$MethodArgs)
}
function Invoke-MarshalMethod($Name, [type[]]$Types, $MethodArgs) {
    $M.GetMethod($Name, [type[]]$Types).Invoke($null, [object[]]$MethodArgs)
}
$privMethod = [Diagnostics.Process].GetMember('SetPrivilege', 42)[0]
'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |
    ForEach-Object { $privMethod.Invoke($null, @("$_", 2)) }
$targetProcess = $null
'TrustedInstaller','lsass','winlogon' | ForEach-Object {
    if (!$targetProcess) {
        sc.exe start $_ 2>$null
        Start-Sleep -Milliseconds 500
        $targetProcess = @(Get-Process -Name $_ -EA 0)[0]
    }
}
$handles = @()
$Z, (4*$Z+16) | ForEach-Object {
    $handles += Invoke-MarshalMethod 'AllocHGlobal' @([int32]) @([int32]$_)
}
Invoke-MarshalMethod 'WriteIntPtr' @([IntPtr],[IntPtr]) @($handles[0], $targetProcess.Handle)
$A1.f1 = 131072; $A1.f2 = $Z; $A1.f3 = $handles[0]
$A2.f1 = 1; $A2.f2 = 1; $A2.f3 = 1; $A2.f4 = 1; $A2.f6 = $A1
$A3.f1 = 10*$Z+32
$A4.f1 = $A3; $A4.f2 = $handles[1]
Invoke-MarshalMethod 'StructureToPtr' @([object],[IntPtr],[bool]) @(($A2 -as $D[2]), $A4.f2, $false)
$HKU     = [uintptr][uint32]2147483651
$NT      = 'S-1-5-18'
$regArgs = @($HKU, $NT, 8, 2, ($HKU -as $D[9]))
Invoke-NativeMethod 'RegOpenKeyEx' $regArgs
$hkuLink = $regArgs[4]
# Retrieve the SID that was appended to the payload by the outer function
$currentSid = ($env:R -split '###SID###')[2].trim()
# Read TI_Code and base64-encode it to pass safely into CreateProcess command line
$rawCode = (Get-Item 'HKCU:\Volatile Environment' -EA 0).GetValue('TI_Code')
$encodedCode = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rawCode))
$createResult = Invoke-NativeMethod 'CreateProcess' @(
    $null,
    "powershell -win hidden -nop -ep bypass -enc $encodedCode",
    0, 0, 0, 0x0E080600, 0, $null,
    ($A4 -as $T[4]),
    ($A5 -as $T[5])
)
$childInfo = $A5 -as $T[5]
if ($childInfo.f1 -ne [IntPtr]::Zero) {
    $childProc = [Diagnostics.Process]::GetProcessById(
        [Runtime.InteropServices.Marshal]::ReadInt32($childInfo.f2)
    )
    if ($childProc) { $childProc.WaitForExit() }
}
$env:R = ''
'@

        #add user sid in comment to get later
        Set-ItemProperty $regKey $payloadValue "$payload`n###SID###$userSid" -Type 1 # REG_SZ
    
        #run payload
        $wshell = New-Object -ComObject WScript.Shell
        $wshell.Run(
            "powershell.exe -win hidden -nop -ep bypass -c iex((gi 'Registry::HKU\$userSid\Volatile Environment').GetValue('TI_Bootstrap'))",
            0,
            $true
        ) | Out-Null
     
        #Cleanup 
        Remove-ItemProperty $regKey $userCodeValue  -Force -EA 0
        Remove-ItemProperty $regKey $payloadValue   -Force -EA 0
        Remove-ItemProperty $regKey $bootstrapValue -Force -EA 0
        $env:B = ''
    }


    $psexe = 'PowerShell.exe'

    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)


    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    
    # trusted installer proc not found (128) or access denied (1)
    if ($LASTEXITCODE -eq 128 -or $LASTEXITCODE -eq 1) {
        Write-Status -msg 'Failed to stop TrustedInstaller.exe... Using fallback method!' -warningOutput
        Invoke-AsTrustedInstaller -Code $command
        Start-Sleep 1
        return 
    }

    #get bin path to revert later
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    #make sure path is valid and the correct location
    $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
    if ($DefaultBinPath -ne $trustedInstallerPath) {
        $DefaultBinPath = $trustedInstallerPath
    }
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c $psexe -encodedcommand $base64Command" | Out-Null
    #run the command
    sc.exe start TrustedInstaller | Out-Null
    #set bin back to default
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    
}


function Write-Status {
    param(
        [string]$msg,
        [switch]$errorOutput,
        [switch]$warningOutput
    )
    if ($errorOutput) {
        Write-Host "[ ! ERROR ] $msg" -ForegroundColor Red
    }
    elseif ($warningOutput) {
        Write-Host "[ * WARNING ] $msg" -ForegroundColor Yellow
    }
    else {
        Write-Host "[ + ] $msg" -ForegroundColor Cyan
    }
   
    
}

# Source - https://stackoverflow.com/a/42792718
# Posted by Krisz, modified by community. See post 'Timeline' for change history
# Retrieved 2026-03-24, License - CC BY-SA 4.0

$QuickEditCodeSnippet = @'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

 
public static class DisableConsoleQuickEdit{
 
const uint ENABLE_QUICK_EDIT = 0x0040;

// STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
const int STD_INPUT_HANDLE = -10;

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetStdHandle(int nStdHandle);

[DllImport("kernel32.dll")]
static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

[DllImport("kernel32.dll")]
static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

public static bool SetQuickEdit(bool SetEnabled){

    IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

    // get current console mode
    uint consoleMode;
    if (!GetConsoleMode(consoleHandle, out consoleMode)){
        // ERROR: Unable to get console mode.
        return false;
    }

    // Clear the quick edit bit in the mode flags
    if (SetEnabled){
        consoleMode &= ~ENABLE_QUICK_EDIT;
    }
    else{
        consoleMode |= ENABLE_QUICK_EDIT;
    }

    // set the new mode
    if (!SetConsoleMode(consoleHandle, consoleMode)){
        // ERROR: Unable to set console mode
        return false;
    }

    return true;
}
}
'@

Add-Type -TypeDefinition $QuickEditCodeSnippet -Language CSharp


function Set-QuickEdit {
    [CmdletBinding()]
    param(
        [switch]$DisableQuickEdit = $false
    )

    if ([DisableConsoleQuickEdit]::SetQuickEdit($DisableQuickEdit)) {
        Write-Output 'QuickEdit settings has been updated.'
    }
    else {
        Write-Output 'Something went wrong.'
    }
}

#some users have messed with the system envrioment variables (for some reason) this breaks inline cmdlets like Reg.exe 
#to fix this we can ensure the enviroment variable for this powershell session is set properly
if ($env:PATH -notlike "*$env:SystemRoot\system32;*") {
    Write-Status -msg "System Envrioment Variable 'PATH' is corrupted! Fixing for script session..." -errorOutput
    $env:PATH = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;" + $env:PATH
}


#setup script
#=====================================================================================
Write-Host '~ ~ ~ Remove Windows AI by @zoicware ~ ~ ~' -ForegroundColor DarkCyan

#disables quick edit just for this session 
#since the quick edit setting is stored in the powershell shortcut file when ran from startmenu its not really possible to do it any other way
#why: quick edit allows for highlighting the console text while a script is running causing it to pause until the user presses some key 
#this is not clearly stated to the user causing confusion for some 
Set-QuickEdit -DisableQuickEdit | Out-Null

if ($EnableLogging) {
    $date = (Get-Date).ToString('MM-dd-yyyy-HH:mm') -replace ':'
    $Global:logPath = "$env:USERPROFILE\RemoveWindowsAI$date.log"
    New-Item $logPath -Force | Out-Null
    Write-Status -msg "Starting Log at [$logPath]"
    #start and stop the transcript to get the header
    Start-Transcript -Path $logPath -IncludeInvocationHeader | Out-Null
    Stop-Transcript | Out-Null

    #create info object
    $Global:logInfo = [PSCustomObject]@{
        Line   = $null
        Result = $null
    }
}

if ($revertMode) {
    $Global:revert = 1
}
else {
    $Global:revert = 0
}

if ($backupMode) {
    $Global:backup = 1
}
else {
    $Global:backup = 0
}

$Global:tempDir = ([System.IO.Path]::GetTempPath())

#=====================================================================================

function Add-LogInfo {
    param(
        [string]$logPath,
        $info
    )

    $content = @"
    ====================================
    Line: $($info.Line)
    Result: $($info.Result)
"@

    Add-Content $logPath -Value $content | Out-Null
}


function Create-RestorePoint {
    param(
        [switch]$nonInteractive
    )

    #check vss service first
    $vssService = Get-Service -Name 'VSS' -ErrorAction SilentlyContinue
    if ($vssService -and $vssService.StartType -eq 'Disabled') {
        try {
            Write-Status -msg 'Enabling VSS Service...'
            Set-Service -Name 'VSS' -StartupType Manual -ErrorAction Stop
            Start-Service -Name 'VSS' -ErrorAction Stop
        }
        catch {
            Write-Status -msg 'Unable to Start VSS Service... Can not create restore point!' -errorOutput
            return
        }
        
    }
    #enable system protection to allow restore points
    $restoreEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if (!$restoreEnabled) {
        Write-Status -msg 'Enabling Restore Points on System...'
        Enable-ComputerRestore -Drive "$env:SystemDrive\" 
    }

    
    if ($nonInteractive) {
        #allow restore point to be created even if one was just made
        $restoreFreqPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $restoreFreqKey = 'SystemRestorePointCreationFrequency'
        $currentValue = (Get-ItemProperty -Path $restoreFreqPath -Name $restoreFreqKey -ErrorAction SilentlyContinue).$restoreFreqKey
        if ($currentValue -ne 0) {
            Set-ItemProperty -Path $restoreFreqPath -Name $restoreFreqKey -Value 0 -Force
        }

        $restorePointName = "RemoveWindowsAI-$(Get-Date -Format 'yyyy-MM-dd')"
        Write-Status -msg "Creating Restore Point: [$restorePointName]"
        Write-Status -msg 'This may take a moment...please wait'
        Checkpoint-Computer -Description $restorePointName -RestorePointType 'MODIFY_SETTINGS' 
    }
    else {
        Write-Status -msg 'Opening Restore Point Dialog...'
        try {
            $proc = Start-Process 'SystemPropertiesProtection.exe' -ErrorAction Stop -PassThru
        }
        catch {
            $proc = Start-Process 'C:\Windows\System32\control.exe' -ArgumentList 'sysdm.cpl ,4' -PassThru
        }
        #click configure on the window
        Start-Sleep 1
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait('%c') 
        Wait-Process -Id $proc.Id
    }

}

function Set-UwpAppRegistryEntry {
    # modified to work in windows powershell from https://github.com/agadiffe/WindowsMize/blob/fe78912ccb1c83d440bd2123f5e43a6156fab31a/src/modules/applications/settings/public/Set-UwpAppSetting.ps1
    <# 
    .SYNOPSIS
        Modifies UWP app registry entries in the settings.dat file.
    
    .EXAMPLE
        PS> $setting = [PSCustomObject]@{
                Name  = 'VideoAutoplay'
                Value = '0'
                Type  = '5f5e10b'
            }
        PS> $setting | Set-UwpAppRegistryEntry -FilePath $FilePath
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline)]
        $InputObject,
        [string] $FilePath
    )

    begin {
        $script:abort = $false
        $AppSettingsRegPath = 'HKEY_USERS\APP_SETTINGS'
        $RegContent = "Windows Registry Editor Version 5.00`n"

        reg.exe UNLOAD $AppSettingsRegPath 2>&1 | Out-Null

        $max = 30
        $attempts = 0
        $ProcessToStop = @(
            'AppActions'
            'SearchHost'
            'FESearchHost'
            'msedgewebview2'
            'TextInputHost'
            'VisualAssistExe'
            'WebExperienceHostApp'
            'WindowsMigration'
            'WindowsBackupClient'
            'SoftLandingTask'
            'DesktopStickerEditorWin32Exe'
            'CrossDeviceResume'
            'DiscoveryHubApp'
        )
        Stop-Process -Name $ProcessToStop -Force -ErrorAction SilentlyContinue 
        # do while is needed here because wait-process in this case is not working maybe cause its just a trash function lol
        # using microsofts own example found in the docs does not work 
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/wait-process?view=powershell-7.5#example-1-stop-a-process-and-wait

        # since we are trying multiple times while the processes are stopping this will work as soon as the file is freed 
        do {
            reg.exe LOAD $AppSettingsRegPath $FilePath *>$null
            $attempts++
        } while ($LASTEXITCODE -ne 0 -and $attempts -lt $max)
    
        if ($LASTEXITCODE -ne 0) {
            Write-Status -msg 'Unable to load settings.dat' -errorOutput
            $script:abort = $true
            return 2
        }
      
    }

    process {
        if ($script:abort) {
            return 2
        }
        $Value = $InputObject.Value
        $Value = switch ($InputObject.Type) {
            '5f5e10b' { 
                # Single byte for boolean
                '{0:x2}' -f [byte][int]$Value
            }
            '5f5e10c' { 
                # Unicode string 
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value + "`0")
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' ' 
            }
            '5f5e104' { 
                # Int32
                $bytes = [BitConverter]::GetBytes([int]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
            '5f5e105' { 
                # UInt32
                $bytes = [BitConverter]::GetBytes([uint32]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
            '5f5e106' { 
                # Int64
                $bytes = [BitConverter]::GetBytes([int64]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
        }

        $Value = $Value -replace '\s+', ','
    
        # create timestamp for remaining bytes
        $timestampBytes = [BitConverter]::GetBytes([int64](Get-Date).ToFileTime())
        $Timestamp = ($timestampBytes | ForEach-Object { '{0:x2}' -f $_ }) -join ','
    
        # build registry content
        if ($InputObject.Path) {
            $RegKey = "$($AppSettingsRegPath)\$($InputObject.Path)"
        }
        else {
            try {
                $RegKey = (Get-ChildItem "registry::$AppSettingsRegPath" -Recurse -ErrorAction Stop | Where-Object { $_.pschildname -like '*Evoke' }).Name
                if (!$RegKey) {
                    #go to catch when regkey is empty too
                    throw
                }
            }
            catch {
                #early return when user has older version of photos app that doesnt have ai features
                [gc]::Collect()
                reg.exe UNLOAD $AppSettingsRegPath *>$null
                $script:abort = $true
                return 1
            }
            
        }
        $RegContent += "`n[$RegKey]
        ""$($InputObject.Name)""=hex($($InputObject.Type)):$Value,$Timestamp`n" -replace '(?m)^ *'
    }

    end {
        if ($script:abort) {
            return 1
        }
        [gc]::Collect()
        $SettingRegFilePath = "$($tempDir)uwp_app_settings.reg"
        $RegContent | Out-File -FilePath $SettingRegFilePath

        reg.exe IMPORT $SettingRegFilePath 2>&1 | Out-Null
        reg.exe UNLOAD $AppSettingsRegPath | Out-Null

        Remove-Item -Path $SettingRegFilePath
    }
}

#function to edit group policies's pol file that contains all policies found in group policy editor 
#this will update the ui to properly reflect what policies have been set to via reg  
function Edit-PolFile {
    param(
        [ValidateSet('HKLM', 'HKCU')]
        [string]$Hive,
        [ValidateSet('Add', 'Delete')]
        [string]$Action,
        [string]$Key,
        [string]$ValueName,
        [ValidateSet('DWORD', 'SZ')]
        [string]$Type,
        [string]$Value
    )

    if ($Hive -eq 'HKLM') {
        $PolPath = "$env:SYSTEMROOT\System32\GroupPolicy\Machine\Registry.pol"
    }
    else {
        $PolPath = "$env:SYSTEMROOT\System32\GroupPolicy\User\Registry.pol"
    }

    #C# pol file reader/writer 
    if (-not ([System.Management.Automation.PSTypeName]'PolHandler').Type) {
        Add-Type -Language CSharp @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public class PolRec {
    public string Key;
    public string ValueName;
    public uint   Type;
    public byte[] Data;
}

public static class PolHandler {

    public static List<PolRec> Read(string f) {
        var l = new List<PolRec>();
        if (!File.Exists(f) || new FileInfo(f).Length < 8) return l;
        try {
            using (var br = new BinaryReader(File.OpenRead(f), Encoding.Unicode)) {
                if (br.ReadUInt32() != 0x67655250 || br.ReadUInt32() != 1) return l;
                while (br.BaseStream.Position < br.BaseStream.Length) {
                    if (br.ReadChar() != '[') continue;
                    var r = new PolRec { Key = RS(br) };
                    if (br.ReadChar() != ';') break;
                    r.ValueName = RS(br);
                    if (br.ReadChar() != ';') break;
                    r.Type = br.ReadUInt32();
                    if (br.ReadChar() != ';') break;
                    uint sz = br.ReadUInt32();
                    if (br.ReadChar() != ';') break;
                    if (br.BaseStream.Position + sz > br.BaseStream.Length) break;
                    r.Data = br.ReadBytes((int)sz);
                    if (br.ReadChar() != ']') break;
                    l.Add(r);
                }
            }
        } catch {}
        return l;
    }

    public static void Write(string f, ICollection<PolRec> d) {
        Directory.CreateDirectory(Path.GetDirectoryName(f));
        using (var bw = new BinaryWriter(File.Open(f, FileMode.Create), Encoding.Unicode)) {
            bw.Write((uint)0x67655250);
            bw.Write((uint)1);
            foreach (var r in d) {
                bw.Write('[');
                SS(bw, r.Key);       bw.Write(';');
                SS(bw, r.ValueName); bw.Write(';');
                bw.Write(r.Type);    bw.Write(';');
                bw.Write((uint)r.Data.Length); bw.Write(';');
                bw.Write(r.Data);
                bw.Write(']');
            }
        }
    }

    private static string RS(BinaryReader br) {
        var sb = new StringBuilder(); char c;
        while ((c = br.ReadChar()) != 0) sb.Append(c);
        return sb.ToString();
    }

    private static void SS(BinaryWriter bw, string v) {
        bw.Write(v.ToCharArray());
        bw.Write((char)0);
    }
}
'@
    }

    #Load existing records into a dictionary to edit 
    $policies = [System.Collections.Generic.Dictionary[string, PolRec]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [PolHandler]::Read($PolPath) | ForEach-Object {
        $policies["$($_.Key);$($_.ValueName)"] = $_
    }

    $dictKey = "$Key;$ValueName"

    switch ($Action) {

        'Add' {
            if (-not $Type) { throw "'-Type' is required when Action is 'Add'" }
            if (-not $Value -and $Value -ne '0') { throw "'-Value' is required when Action is 'Add'" }

            $rec = [PolRec]::new()
            $rec.Key = $Key
            $rec.ValueName = $ValueName

            if ($Type -eq 'DWORD') {
                $rec.Type = 4
                $rec.Data = [BitConverter]::GetBytes([uint32]::Parse($Value))
            }
            else {
                $rec.Type = 1
                $rec.Data = [Text.Encoding]::Unicode.GetBytes($Value + [char]0)
            }

            $policies[$dictKey] = $rec
            Write-Verbose "Added/updated: $dictKey"
        }

        'Delete' {
            if ($policies.Remove($dictKey)) {
                Write-Verbose "Deleted: $dictKey"
            }
            else {
                Write-Warning "Entry not found in .pol file: $dictKey"
            }
        }
    }

    #add updated dictionary back to pol file
    $final = [System.Collections.Generic.List[PolRec]]::new($policies.Values)
    [PolHandler]::Write($PolPath, $final)
}

function Disable-Registry-Keys {
    #maybe add params for particular parts

    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Copilot and Recall..."
    <#
    keys related to windows ai schedled task 
'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration'  
    #>
    if (!$revert) {
        #removing it does not get remade on restart so we will just remove it for now 
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAI\LastConfiguration' /f *>$null

        Reg.exe delete 'HKCU\Software\Microsoft\Windows\Shell\Copilot' /v 'CopilotLogonTelemetryTime' /f *>$null
        Reg.exe delete 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Copilot_8wekyb3d8bbwe\Copilot.StartupTaskId' /f *>$null
        Reg.exe delete 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId' /f *>$null
        Reg.exe delete 'HKCU\Software\Microsoft\Copilot' /v 'WakeApp' /f *>$null

        #remove copilot run auto launch
        $runNotiKey = (Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification').property | Where-Object { $_ -like '*MicrosoftCopilotAutoLaunch*' }
        if ($runNotiKey) {
            Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification' -Name $runNotiKey -Force
        }
    }

    $aiPolicies = @()
    $valueNamesHKLM = @(
        'DisableAIDataAnalysis'
        'AllowRecallEnablement'
        'DisableClickToDo'
        'TurnOffSavingSnapshots'
        'DisableSettingsAgent'
        'DisableAgentConnectors'
        'DisableAgentWorkspaces'
        'DisableRemoteAgentConnectors'
    )
    foreach ($name in $valueNamesHKLM) {
        $obj = [PSCustomObject]@{
            Name  = $name
            Hive  = 'HKLM'
            Key   = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Value = if ($name -eq 'AllowRecallEnablement') { @('0', '1')[$revert] }else { @('1', '0')[$revert] } #value needs to be 0 for AllowRecallEnablement but 1 for the rest
        }
        $aiPolicies += $obj
    }

    $valueNamesHKCU = @(
        'DisableAIDataAnalysis'
        'DisableClickToDo'
    )
    foreach ($name in $valueNamesHKCU) {
        $obj = [PSCustomObject]@{
            Name  = $name
            Hive  = 'HKCU'
            Key   = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Value = @('1', '0')[$revert]
        }
        $aiPolicies += $obj
    }

    $obj = [PSCustomObject]@{
        Name  = 'TurnOffWindowsCopilot'
        Hive  = 'HKCU'
        Key   = 'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        Value = @('1', '0')[$revert]
    }
    $aiPolicies += $obj
  
    foreach ($policy in $aiPolicies) {
        #apply each policy to registry and pol file (reflects exact behavior when doing these manually through gpedit)
        Reg.exe add "$($policy.Hive)\$($policy.Key)" /v "$($policy.Name)" /t REG_DWORD /d $policy.Value /f *>$null
        Edit-PolFile -Hive $policy.Hive -Key $policy.Key -Action Add -ValueName $policy.Name -Type DWORD -Value $policy.Value
    }

    #set for local machine and current user to be sure
    $hives = @('HKLM', 'HKCU')
    foreach ($hive in $hives) {
        #only for insiders using enterprise or education as of right now (12/23/25)
        #Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableRecallDataProviders' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat" /v 'IsUserEligible' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v 'IsCopilotAvailable' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v 'CopilotDisabledReason' /t REG_SZ /d @('FeatureIsDisabled', ' ')[$revert] /f *>$null
    }
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Copilot_8wekyb3d8bbwe' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\systemAIModels' /v 'RecordUsageData' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps' /v 'AgentActivationEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCopilotButton' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\input\Settings' /v 'InsightsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\Shell\ClickToDo' /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\M365Copilot' /v 'AutoStartDelayEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\M365Copilot' /v 'IsCompanionWindowAvailable' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #remove copilot from search
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Copilot In Windows Search..."
    Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchBoxSuggestions' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable copilot in edge
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Copilot In Edge..."
    #keeping depreciated policies incase user has older versions of edge
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotCDPPageContext' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null #depreciated shows Unknown policy in edge://policy
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'HubsSidebarEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeEntraCopilotPageContext' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'Microsoft365CopilotChatIconEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null #depreciated shows Unknown policy in edge://policy
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeHistoryAISearchEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ComposeInlineEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'GenAILocalFoundationalModelSettings' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'BuiltInAIAPIsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AIGenThemesEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'DevToolsGenAiSettings' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'ShareBrowsingHistoryWithCopilotSearchAllowed' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'AllowBrowsingWithCopilot' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotNewTabPageEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'M365LinksAutoOpenCopilotEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotAddressBarSuggestionsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable edge copilot mode 
    # "enabled_labs_experiments":["edge-copilot-mode@2"]
    # view flags at edge://flags
    taskkill.exe /im msedge.exe /f *>$null
    $config = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
    if (Test-Path $config) {
        #powershell core bug where json that has empty strings will error
        try {
            $jsonContent = (Get-Content $config).Replace('""', '"_empty"') | ConvertFrom-Json -ErrorAction Stop
            $fail = $false
        }
        catch {
            Write-Status -msg 'Unable to set Edge flags to disable Copilot due to a different langauge being used' -errorOutput 
            Write-Status -msg 'You can manually disable the Copilot flags at [edge://flags] in the browser' -errorOutput 
            $fail = $true
        }
        
        if (!$fail) {
            try {
                if (($jsonContent.browser | Get-Member -MemberType NoteProperty enabled_labs_experiments -ErrorAction Stop) -eq $null) {
                    $jsonContent.browser | Add-Member -MemberType NoteProperty -Name enabled_labs_experiments -Value @()
                }
                $flags = @(
                    'edge-copilot-mode@2', 
                    'edge-ntp-composer@2', #disables the copilot search in new tab page 
                    'edge-compose@2' #disables the ai writing help 
                )
                if ($revert) {
                    $jsonContent.browser.enabled_labs_experiments = $jsonContent.browser.enabled_labs_experiments | Where-Object { $_ -notin $flags }
                }
                else {
                    foreach ($flag in $flags) {
                        if ($jsonContent.browser.enabled_labs_experiments -notcontains $flag) {
                            $jsonContent.browser.enabled_labs_experiments += $flag
                        }
                    }
                }
        
                $newContent = $jsonContent | ConvertTo-Json -Compress -Depth 10 
                #add back the empty strings 
                $newContent = $newContent.replace('"_empty"', '""')
                Set-Content $config -Value $newContent -Encoding UTF8 -Force
            }
            catch {
                Write-Status -msg 'Edge Browser has never been opened on this machine unable to set flags...' -errorOutput 
                Write-Status -msg 'Open Edge once and run this tweak again' -errorOutput 
            }
        }
        
    }
   
    #disable office ai with group policy
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\training\general' /v 'disabletraining' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\training\specific\adaptivefloatie' /v 'disabletrainingofadaptivefloatie' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable connected experiences in office should prevent copilot from working 
    Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\common\privacy' /v 'controllerconnectedservicesenabled' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Policies\Microsoft\office\16.0\common\privacy' /v 'usercontentdisabled' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    #disable copilot in word
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\Word\Options' /v 'EnableCopilot' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot in excel
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\Excel\Options' /v 'EnableCopilot' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot in onenote
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\OneNote\Options\Copilot' /v 'CopilotEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\OneNote\Options\Copilot' /v 'CopilotNotebooksEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\OneNote\Options\Copilot' /v 'CopilotSkittleEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot in power point
    Reg.exe add 'HKCU\Software\Microsoft\Office\16.0\PowerPoint\Options' /v 'Enable Copilot in Settings' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable office ai content safety
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\general' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\alternativetext' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\imagequestionandanswering' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\promptassistance' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\rewrite' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\summarization' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\summarizationwithreferences' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\ai\contentsafety\specific\texttotable' /v 'disablecontentsafety' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable additional keys
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'AutoOpenCopilotLargeScreens' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI' /v 'Value' /t REG_SZ /d @('Deny', 'Allow')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels' /v 'Value' /t REG_SZ /d @('Deny', 'Allow')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessGenerativeAI' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessSystemAIModels' /t REG_DWORD /d @('2', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot' /v 'AllowCopilotRuntime' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'CopilotPWAPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'RecallPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable copilot background app access 
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe' /v 'DisabledByUser' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe' /v 'Disabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Copilot_8wekyb3d8bbwe' /v 'SleepDisabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'DisabledByUser' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'Disabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'SleepDisabled' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable for all users
    $sids = (Get-ChildItem 'registry::HKEY_USERS').Name | Where-Object { $_ -like 'HKEY_USERS\S-1-5-21*' -and $_ -notlike '*Classes*' } 
    foreach ($sid in $sids) {
        Reg.exe add "$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v 'CopilotPWAPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add "$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v 'RecallPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    }
    #disable ask copilot (taskbar search)
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarCompanion' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #this branded key is blocked by the user choice driver too bad ms was very lazy and hardcoded a list of exe's not allowed to edit this key
    #workaround for any key blocked by user choice driver: rename reg.exe to something else
    Copy-Item (Get-Command reg.exe).Source .\reg1.exe -Force -ErrorAction SilentlyContinue
    & .\reg1.exe add 'HKCU\Software\Microsoft\Windows\Shell\BrandedKey' /v 'BrandedKeyChoiceType' /t REG_SZ /d @('Search', 'App')[$revert] /f *>$null
    & .\reg1.exe add 'HKCU\Software\Microsoft\Windows\Shell\BrandedKey' /v 'AppAumid' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
    Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CopilotKey' /v 'SetCopilotHardwareKey' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
    Remove-Item .\reg1.exe -Force -ErrorAction SilentlyContinue
    #disable recall customized homepage 
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers' /v 'A9HomeContentEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #disable typing data harvesting for ai training 
    Reg.exe add 'HKCU\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization' /v 'Value' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    #hide copilot ads in settings home page 
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableConsumerAccountStateContent' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #disable office hub startup
    Reg.exe add 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe\WebViewHostStartupId' /v 'State' /t REG_DWORD /d @('1', '2')[$revert] /f *>$null
    #disable ai image creator in paint
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) Image Creator In Paint..."

    #applying this policy causes paint to not open and none of the other policies actually do anything, nice one ms
    #additonal context: when the disable image creator policy is enabled mspaint.exe checks this policy and produces an event log error then exits...
    #seems to be fixed in 26200.8328
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableImageCreator' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null

    #these still do nothing
    #Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableCocreator' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableGenerativeFill' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    
    # disable experimental agentic features
    # Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IsoEnvBroker" /v "Enabled" /t REG_DWORD /d "0" /f
    # Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\IsoEnvBroker" /v "Enabled" /t REG_DWORD /d "0" /f
    # leaving commented since its still only in preview builds

    #disable paint ai experiment program
    Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) AI Experiment Program In Paint..."
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'IsSignedUpForTargetingService' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'LeftTargetingService' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'IsNotInterestedInTargetingService' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    #additionals
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedWelcomePageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedStickerGeneratorPageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedGenerativeImageEditPageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedGenerativeErasePageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedGenerativeFillPageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedImageCreatorPageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\View' /v 'GettingStartedCocreatorPageViewed' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null

    #disable ai context menu extensions
    #these clsids are not always the same despite what most people seem to think when using this method so we need to get them for the user
    if ($revert) {
        $keys = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' -ErrorAction SilentlyContinue  | Get-Member -ErrorAction SilentlyContinue | Where-Object { $_.Definition -like '*copilot*' -or $_.Definition -like '*designer*' }
        if ($keys) {
            foreach ($key in $keys) {
                Reg.exe delete 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v "$($key.Name)" /f *>$null
            }
        }
    }
    else {
        $aiContextMenus = @(
            'AskM365Copilot'
            'AskCopilot'
            'CreateWithDesigner'
        )
        #some packages wont have a manifest file so check before getting its info
        $packages = Get-AppxPackage -AllUsers | Where-Object { (Test-Path "$($_.InstallLocation)\AppXManifest.xml") -eq $true }
        $contextMenuExtensions = ($packages | Get-AppxPackageManifest) | ForEach-Object { $_.package.Applications.Application.Extensions.Extension.FileExplorerContextMenus.itemtype.verb } | Select-Object  Id, Clsid -unique
        foreach ($ext in $contextMenuExtensions) {
            if ($aiContextMenus -contains $ext.Id) {
                Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v "{$($ext.Clsid)}" /t REG_SZ /d "$($ext.Id)" /f *>$null
            }
        }
    }

    #Albacore.ViVe.ObfuscationHelpers (ViveTool) in powershell
    #only need feature id -> obfuscated id for registry 
    function SwapBytes32 {
        param([uint32]$x)
        $x = (($x -shr 16) -band 0xFFFFFFFF) -bor (($x -shl 16) -band 0xFFFFFFFF)
        return ((($x -band 0xFF00FF00) -shr 8) -bor (($x -band 0x00FF00FF) -shl 8)) -band 0xFFFFFFFF
    }

    function RotateRight32 {
        param([uint32]$value, [int]$shift)
        #masks the shift amount to 0-31 for uint operands (shift & 31)
        $s = (($shift % 32) + 32) % 32
        if ($s -eq 0) { return $value }
        return ((($value -shr $s) -bor ($value -shl (32 - $s))) -band 0xFFFFFFFF)
    }

    function ObfuscateFeatureId {
        param([uint32]$FeatureId)
        $step1 = ($FeatureId -bxor 0x74161A4E) -band 0xFFFFFFFF
        $step2 = SwapBytes32 $step1
        $step3 = ($step2 -bxor 0x8FB23D4F) -band 0xFFFFFFFF
        $step4 = RotateRight32 -value $step3 -shift -1   # -1 & 31 = 31 -> rotate right 31 == rotate left 1
        $step5 = ($step4 -bxor 0x833EA8FF) -band 0xFFFFFFFF
        return [uint32]$step5
    }


    $settingsJSON = (Get-ChildItem -Path "$env:windir\SystemApps" -Recurse).FullName | Where-Object { $_ -like '*wsxpacks\Account\SettingsExtensions.json' }

    $jsonContent = Get-Content $settingsJSON | ConvertFrom-Json
    $list = 'CopilotSubscriptionCard', 'CopilotSubscriptionCard_Enterprise'

    if ($jsonContent.addedHomeCards) {
        Write-Status -msg 'Removing Copilot Cards from Settings...'
        #grab the velocity id and apply it to registry
        #if this file gets repaired or replaced the feature management should prevent it from coming back
        $veloIDs = $jsonContent.addedHomeCards | Where-Object { $list -contains $_.cardID } | ForEach-Object { $_.conditions.velocityKey } 
        if ($veloIDs) {
            foreach ($veloID in $veloIDs) {
                #convert feature id to obfuscated reg id
                $regID = ObfuscateFeatureId $veloID.id
                #tested using vivetool /disable sets enabledstate to 1
                Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\$regID" /v 'EnabledState' /t REG_DWORD /d '1' /f *>$null
            }
        }

        #remove the cards from the json
        $jsonContent.addedHomeCards = $jsonContent.addedHomeCards | Where-Object { $list -notcontains $_.cardId }

        takeown /f $settingsJSON *>$null
        icacls $settingsJSON /grant *S-1-5-32-544:F /t *>$null

        $newContent = $jsonContent | ConvertTo-Json -Depth 100
        Set-Content -Path $settingsJSON -Value $newContent -Force
    }



    #unpin copilot 365 based on similar method from here: https://github.com/Freenitial/Pin-Taskbar
    #since this is 'SystemPinned' theres no actual lnk file associated with the pin so we can just remove the AUMID
    $Aumid = 'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub'

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class TaskbarUnpinByAumid {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindow(string c, string w);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindowEx(IntPtr p, IntPtr a, string c, string w);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public static int FindEntry(byte[] blob, string needleStr) {
        byte[] needle = System.Text.Encoding.Unicode.GetBytes(needleStr);
        int pos = 0; int idx = 0;
        while (pos < blob.Length && blob[pos] != 0xFF) {
            if (pos + 5 > blob.Length) break;
            int pidlStart = pos + 5;
            int pidlEnd = pidlStart + (int)BitConverter.ToUInt32(blob, pos + 1);
            if (pidlEnd > blob.Length) break;
            for (int b = pidlStart; b + needle.Length <= pidlEnd; b++) {
                bool match = true;
                for (int c = 0; c < needle.Length; c++) { if (blob[b + c] != needle[c]) { match = false; break; } }
                if (match) return idx;
            }
            pos = pidlEnd; idx++;
        }
        return -1;
    }

    public static byte[] RemoveFavEntry(byte[] blob, int removeIdx) {
        System.IO.MemoryStream ms = new System.IO.MemoryStream();
        int pos = 0; int idx = 0;
        while (pos < blob.Length && blob[pos] != 0xFF) {
            if (pos + 5 > blob.Length) break;
            int total = 5 + (int)BitConverter.ToUInt32(blob, pos + 1);
            if (pos + total > blob.Length) break;
            if (idx != removeIdx) ms.Write(blob, pos, total);
            pos += total; idx++;
        }
        ms.WriteByte(0xFF);
        return ms.ToArray();
    }

    public static byte[] RemoveResEntry(byte[] blob, int removeIdx) {
        System.IO.MemoryStream ms = new System.IO.MemoryStream();
        int pos = 0; int idx = 0;
        while (pos + 4 <= blob.Length) {
            uint linkSize = BitConverter.ToUInt32(blob, pos);
            if (linkSize == 0 || pos + 4 + (int)linkSize > blob.Length) break;
            if (idx != removeIdx) ms.Write(blob, pos, 4 + (int)linkSize);
            pos += 4 + (int)linkSize; idx++;
        }
        return ms.ToArray();
    }

    public static void SendPinNotify() {
        IntPtr reBar = FindWindowEx(FindWindow("Shell_TrayWnd", null), IntPtr.Zero, "ReBarWindow32", null);
        IntPtr band  = FindWindowEx(reBar, IntPtr.Zero, "MSTaskSwWClass", null);
        if (band != IntPtr.Zero) PostMessage(band, 0x446, IntPtr.Zero, IntPtr.Zero);
    }
}
'@

    Write-Status -msg 'Unpinning Copilot 365 from Taskbar...'
    $TaskBand = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband', $true)
    $Favorites = $TaskBand.GetValue('Favorites', $null, 'DoNotExpandEnvironmentNames')
    $FavoritesResolve = $TaskBand.GetValue('FavoritesResolve', $null, 'DoNotExpandEnvironmentNames')

    try {
        $Idx = [TaskbarUnpinByAumid]::FindEntry($Favorites, $Aumid)
    }
    catch {}
    if ($Idx -lt 0 -or $Idx -eq $null) {
        Write-Status -msg 'Copilot 365 is already unpinned...'
        $TaskBand.Close()
    }
    else {
        $Favorites = [TaskbarUnpinByAumid]::RemoveFavEntry($Favorites, $Idx)
        if ($FavoritesResolve) { 
            $FavoritesResolve = [TaskbarUnpinByAumid]::RemoveResEntry($FavoritesResolve, $Idx) 
        }

        $Changes = [int]$TaskBand.GetValue('FavoritesChanges', 0, 'DoNotExpandEnvironmentNames')
        $TaskBand.SetValue('Favorites', $Favorites, 'Binary')
        if ($FavoritesResolve) { 
            $TaskBand.SetValue('FavoritesResolve', $FavoritesResolve, 'Binary') 
        }
        $TaskBand.SetValue('FavoritesVersion', 3, 'DWord')
        $TaskBand.SetValue('FavoritesChanges', $Changes + 1, 'DWord')
        $TaskBand.Close()
        #refresh taskbar
        [TaskbarUnpinByAumid]::SendPinNotify()
    }

    
    
    #apply reg keys for default user to disable for any new users created
    #unload just incase
    [GC]::Collect()
    reg.exe unload 'HKU\DefaultUser' *>$null
    try {
        reg.exe load 'HKU\DefaultUser' "$env:SystemDrive\Users\Default\NTUSER.DAT" >$null
        $hiveloaded = $true
    }
    catch {
        Write-Status -msg 'Unable to Load Default User Hive...' -errorOutput 
        $hiveloaded = $false
    }

    if ($hiveloaded) {
        Write-Status -msg "$(@('Disabling', 'Enabling')[$revert]) AI for new users..." 
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' /v 'TurnOffWindowsCopilot' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAIDataAnalysis' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'AllowRecallEnablement' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'TurnOffSavingSnapshots' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableSettingsAgent' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAgentConnectors' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAgentWorkspaces' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableRemoteAgentConnectors' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat' /v 'IsUserEligible' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\Shell\Copilot' /v 'IsCopilotAvailable' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\Shell\Copilot' /v 'CopilotDisabledReason' /t REG_SZ /d @('FeatureIsDisabled', ' ')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Copilot_8wekyb3d8bbwe' /v 'Value' /t REG_SZ /d @('Deny', 'Prompt')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps' /v 'AgentActivationEnabled' /t REG_DWORD /d @('0', '1')[$revert]  /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCopilotButton' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\input\Settings' /v 'InsightsEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\Shell\ClickToDo' /v 'DisableClickToDo' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchBoxSuggestions' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot' /v 'AllowCopilotRuntime' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'CopilotPWAPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins' /v 'RecallPin' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarCompanion' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\Shell\BrandedKey' /v 'BrandedKeyChoiceType' /t REG_SZ /d @('Search', 'App')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\Shell\BrandedKey' /v 'AppAumid' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\CopilotKey' /v 'SetCopilotHardwareKey' /t REG_SZ /d @(' ', 'Microsoft.Copilot_8wekyb3d8bbwe!App')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers' /v 'A9HomeContentEnabled' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        Reg.exe add 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization' /v 'Value' /t REG_DWORD /d @('0', '1')[$revert] /f *>$null
        
        reg.exe unload 'HKU\DefaultUser' *>$null
    }


    #Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WSAIFabricSvc' /v 'Start' /t REG_DWORD /d @('4', '2')[$revert] /f *>$null
    try {
        Stop-Service -Name WSAIFabricSvc -Force -ErrorAction Stop
    }
    catch {
        #ignore error when svc is already removed
    }
    
    $backupPath = "$env:USERPROFILE\RemoveWindowsAI\Backup"
    $backupFileWSAI = 'WSAIFabricSvc.reg'
    $backupFileAAR = 'AARSVC.reg'
    if ($revert) {
        if (Test-Path "$backupPath\$backupFileWSAI") {
            Reg.exe import "$backupPath\$backupFileWSAI" *>$null
            sc.exe create WSAIFabricSvc binPath= "$env:windir\System32\svchost.exe -k WSAIFabricSvcGroup -p" *>$null
        }
        else {
            Write-Status -msg "Path Not Found: $backupPath\$backupFileWSAI" -errorOutput 
        }
        
    }
    else {
        if ($backup) {
            Write-Status -msg 'Backing up WSAIFabricSvc...'
            #export the service to a reg file before removing it 
            if (!(Test-Path $backupPath)) {
                New-Item $backupPath -Force -ItemType Directory | Out-Null
            }
            #this will hang if the service has already been exported
            # if (!(Test-Path "$backupPath\$backupFileWSAI")) {
            Reg.exe export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSAIFabricSvc' "$backupPath\$backupFileWSAI" /y | Out-Null #add overwrite file /y switch
            # }
        }
        Write-Status -msg 'Removing WSAIFabricSvc...'
        #delete the service
        sc.exe delete WSAIFabricSvc *>$null
    }
    if (!$revert) {
        #remove conversational agent service (used to be used for cortana, prob going to be updated for new ai agents and copilot)
        try {
            $aarSVCName = (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.name -like '*aarsvc*' }).Name
        }
        catch {
            #aarsvc already removed
        }
        

        if ($aarSVCName) {
            if ($backup) {
                Write-Status -msg 'Backing up Agent Activation Runtime Service...'
                #export the service to a reg file before removing it 
                if (!(Test-Path $backupPath)) {
                    New-Item $backupPath -Force -ItemType Directory | Out-Null
                }
                #this will hang if the service has already been exported
                # if (!(Test-Path "$backupPath\$backupFileAAR")) {
                Reg.exe export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc' "$backupPath\$backupFileAAR" /y | Out-Null
                # }
            }
            Write-Status -msg 'Removing Agent Activation Runtime Service...'
            #delete the service
            try {
                Stop-Service -Name $aarSVCName -Force -ErrorAction Stop
            }
            catch {
                try {
                    Stop-Service -Name AarSvc -Force -ErrorAction Stop
                }
                catch {
                    #neither are running
                }
                
            }
            
            sc.exe delete AarSvc *>$null
        }
    }
    else {
        Write-Status 'Restoring Agent Activation Runtime Service...'

        if (Test-Path "$backupPath\$backupFileAAR") {
            Reg.exe import "$backupPath\$backupFileAAR" *>$null
            sc.exe create AarSvc binPath= "$env:windir\system32\svchost.exe -k AarSvcGroup -p" *>$null
        }
        else {
            Write-Status -msg "Path Not Found: $backupPath\$backupFileAAR" -errorOutput 
        }
    }
  
    #remove copilot elevation service
    try {
        Stop-Service -Name MicrosoftCopilotElevationService -Force -ErrorAction Stop
    }
    catch {
        #ignore error when svc is already removed
    }
    
    $backupPath = "$env:USERPROFILE\RemoveWindowsAI\Backup"
    $backupFileCopilotSvc = 'CopilotSvc.reg'
    if ($revert) {
        if (Test-Path "$backupPath\$backupFileCopilotSvc") {
            Reg.exe import "$backupPath\$backupFileCopilotSvc" *>$null
            #sc.exe create WSAIFabricSvc binPath= "$env:windir\System32\svchost.exe -k WSAIFabricSvcGroup -p" *>$null
        }
        else {
            Write-Status -msg "Path Not Found: $backupPath\$backupFileCopilotSvc" -errorOutput 
        }
        
    }
    else {
        if ($backup) {
            Write-Status -msg 'Backing up MicrosoftCopilotElevationService...'
            #export the service to a reg file before removing it 
            if (!(Test-Path $backupPath)) {
                New-Item $backupPath -Force -ItemType Directory | Out-Null
            }
            Reg.exe export 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftCopilotElevationService' "$backupPath\$backupFileCopilotSvc" /y | Out-Null #add overwrite file /y switch
            
        }
        Write-Status -msg 'Removing MicrosoftCopilotElevationService...'
        #delete the service
        sc.exe delete MicrosoftCopilotElevationService *>$null
    }


    #block copilot from communicating with server
    if ($revert) {
        if ((Test-Path "$backupPath\HKCR_Copilot.reg") -or (Test-Path "$backupPath\HKCU_Copilot.reg")) {
            Reg.exe import "$backupPath\HKCR_Copilot.reg" *>$null
            Reg.exe import "$backupPath\HKCU_Copilot.reg" *>$null
        }
        else {
            Write-Status -msg "Unable to Find HKCR_Copilot.reg or HKCU_Copilot.reg in [$backupPath]" -errorOutput 
        }
    }
    else {
        if ($backup) {
            #backup .copilot file extension
            Reg.exe export 'HKEY_CLASSES_ROOT\.copilot' "$backupPath\HKCR_Copilot.reg" /y *>$null
            Reg.exe export 'HKEY_CURRENT_USER\Software\Classes\.copilot' "$backupPath\HKCU_Copilot.reg" /y *>$null
        }
        Write-Status -msg 'Removing .copilot File Extension...' 
        Reg.exe delete 'HKCU\Software\Classes\.copilot' /f *>$null
        Reg.exe delete 'HKCR\.copilot' /f *>$null
    }

    #disabling and removing voice access, recently added ai powered
    Reg.exe add 'HKCU\Software\Microsoft\VoiceAccess' /v 'RunningState' /t REG_DWORD /d @('0', '1')[$revert] /f >$null
    Reg.exe add 'HKCU\Software\Microsoft\VoiceAccess' /v 'TextCorrection' /t REG_DWORD /d @('1', '2')[$revert] /f >$null
    Reg.exe add 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp' /v @('0', '1')[$revert] /t REG_DWORD /d '0' /f >$null
    $startMenu = "$env:appdata\Microsoft\Windows\Start Menu\Programs\Accessibility"
    $voiceExe = "$env:windir\System32\voiceaccess.exe"
    if ($backup) {
        Write-Status -msg 'Backing up Voice Access...'
        if (!(Test-Path $backupPath)) {
            New-Item $backupPath -Force -ItemType Directory | Out-Null
        }
        Copy-Item $voiceExe -Destination $backupPath -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item "$startMenu\VoiceAccess.lnk" -Destination $backupPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    if ($revert) {
        if ((Test-Path "$backupPath\VoiceAccess.exe") -and (Test-Path "$backupPath\VoiceAccess.lnk")) {
            Write-Status -msg 'Restoring Voice Access...'
            Move-Item "$backupPath\VoiceAccess.exe" -Destination "$env:windir\System32" -Force | Out-Null
            Move-Item "$backupPath\VoiceAccess.lnk" -Destination $startMenu -Force | Out-Null
        }
        else {
            Write-Status -msg 'Voice Access Backup NOT Found!' -errorOutput 
        }
    }
    else {
        Write-Status -msg 'Removing Voice Access...'
        $command = "Remove-item -path $env:windir\System32\voiceaccess.exe -force"
        Run-Trusted -command $command -psversion $psversion
        Start-Sleep 1
        Remove-Item "$startMenu\VoiceAccess.lnk" -Force -ErrorAction SilentlyContinue
    }

    
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture'
    $allFX = (Get-ChildItem $root -Recurse).Name | Where-Object { $_ -like '*FxProperties' }
    #search the fx props for VocalEffectPack and add {1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5 = 1
    foreach ($fxPath in $allFX) {
        $keys = Get-ItemProperty "registry::$fxPath"
        foreach ($key in $keys) {
            if ($key | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -like '{*},*' } | Where-Object { $_.Definition -like '*#VocaEffectPack*' }) {
                Write-Status -msg "$(@('Disabling','Enabling')[$revert]) AI Voice Effects..."
                $regPath = Convert-Path $key.PSPath
                if ($revert) {
                    #enable
                    $command = "Reg.exe delete '$regPath' /v '{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5' /f"
                    Run-Trusted -command $command -psversion $psversion
                }
                else {
                    #disable
                    $command = "Reg.exe add '$regPath' /v '{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5' /t REG_DWORD /d '1' /f"
                    Run-Trusted -command $command -psversion $psversion
                }
                
            }
        }
    }

    #disable gaming copilot 
    #found from: https://github.com/meetrevision/playbook/issues/197
    <#
    if ($revert) {
        $command = "reg delete 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions' /f"
        Run-Trusted -command $command -psversion $psversion
    }
    else {
        $command = "reg add 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions' /v 'ActivationType' /t REG_DWORD /d 0 /f;
    reg add 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.Xbox.GamingAI.Companion.Host.GamingCompanionHostOptions' /v 'Server' /t REG_SZ /d `" `" /f
    "
        Run-Trusted -command $command -psversion $psversion
    }
    #>
    
    if (!$revert) {
        #better method than above by setting the gaming copilot widget to false in the xbox overlay settings json file
        #to make this actually work gamebar service needs to be restarted 
        $overlaySettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\LocalState\profileDataSettings.txt"
        if (Test-Path $overlaySettingsPath) {
            Write-Status -msg 'Disabling Gaming Copilot...'
            Get-Process '*gamebar*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue 
            try {
                $content = Get-Content $overlaySettingsPath -Raw -ErrorAction Stop
                $jsonObj = ConvertFrom-Json $content -ErrorAction Stop

                $hasGamingCopilot = $jsonObj.profile.settingsStorage | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -like '*GamingCompanionWidget*' }
                if ($hasGamingCopilot) {
                    #get all the properties for gaming copilot (there can be different ones for some users so we cant just hardcode this)
                    #set all found properties to false besides suppressFirstFavorite
                    $props = $jsonObj.profile.settingsStorage.$($hasGamingCopilot.Name) | Get-Member -MemberType NoteProperty
                    foreach ($prop in $props) {
                        if ($prop.Name -eq 'suppressFirstFavorite') {
                            #this prop needs to be true to hide from favorites
                            $jsonObj.profile.settingsStorage.$($hasGamingCopilot.Name).$($prop.Name) = $true
                        }
                        elseif ($prop.Name -eq 'suppressFirstLaunch') {
                            $jsonObj.profile.settingsStorage.$($hasGamingCopilot.Name).$($prop.Name) = $true
                        }
                        else {
                            $jsonObj.profile.settingsStorage.$($hasGamingCopilot.Name).$($prop.Name) = $false
                        }
                    }
                    #this prop isnt added to the json till the user views settings in gamebar so add the prop and set to false
                    #hide gaming copilot from widgets menu
                    $jsonObj.profile.settingsStorage.$($hasGamingCopilot.Name) | Add-Member -NotePropertyName 'homeMenuVisibleUser' -NotePropertyValue $false -Force
                    
                    $newContent = ConvertTo-Json $jsonObj -Depth 10 -Compress #compress here to match og formatting for this file
                    Set-Content $overlaySettingsPath -Value $newContent -Force
                }
                else {
                    Write-Status -msg 'GamingCompanionWidget NOT Found in profileDataSettings.txt! Skipping...' -warningOutput
                }
            }
            catch {
                Write-Error $_
                Write-Status -msg 'Unable to Disable Gaming Copilot!' -errorOutput
            }
        }
    }
    

    #disable ai setting in uwp photos app
    $uwpPhotosSettings = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\Settings\settings.dat"
    if (Test-Path $uwpPhotosSettings) {
        Write-Status -msg "$(@('Disabling','Enabling')[$revert]) AI in Photos App..."
        
        $photosSettingsBooleans = @(
            'OneDriveOnlineSearchFallbackFilter-IsEnabled'
            'ClipChampPromo-TeachingMoment-AlternateButtonBackground-IsEnabled'
            'FileExplorer-ContextMenu-CreateWithDesigner-IsEnabled'
            'ViewerOcr-IsEnabled'
            'MoodboardIsEnabledIntel'
            'ClipchampNewIconIsEnabled'
            'WindowsIndexerSemanticSearchIsEnabledQCOM'
            'RingTesterPublic'
            'DuplicateVideoProject'
            'EditHVC-BackgroundBlur-IsEnabled'
            'Designer-NewIcon-IsEnabled'
            'StoryBuilder-FX-3DEffectsInAppBar'
            'EditHVC-Stylizer-IsEnabled-LNL'
            'SDXL-IsEnabled'
            'ViewerCopilotOnContextMenu-IsEnabled'
            'EditHVC-AIBadges-IsEnabled'
            'EditHVCSuperResolutionIsEnabledQCOM'
            'EditHVCStylizerIsEnabledQCOM'
            'MoodboardIsEnabledAMD'
            'EditHVC-Win10-BackgroundBlur-IsEnabled'
            'ViewerOcr-SearchInWeb-IsEnabled'
            'StoryBuilder-CreateDropdownUpdate-Enabled'
            'LocationSearch-IsEnabled'
            'StoryBuilder-AddNewSimpleTextStyles'
            'ImageCategorizationIsEnabledAMD'
            'StoryBuilder-ExportFlow-Variant'
            'OneDriveOnlineSearch-IsEnabled'
            'EditHVCSuperResolutionIsEnabledAMD'
            'StoryBuilder-Report-ExportIssues-IsEnabled'
            'Collections-ShowFolderAndSubfoldersFeature-IsEnabled'
            'StoryBuilder-CreateDropdown-NewStrings'
            'MoodboardIsEnabledQCOM'
            'ClipChampPromo-MTCButtonAlternateToolTip-IsEnabled'
            'DesignerEditor-SupportAllLanguages'
            'EditHVC-UseSpotFixWhenGenerativeEraseAreaIsSmall-IsEnabled'
            'Moodboard-IsEnabled'
            'StoryBuilder-CreateDropdown-ReorderVideoButtons'
            'StoryBuilder-AudioRoaming'
            'StoryBuilder-CardEdit-TimeableText'
            'Gallery-SplashScreen-IsEnabled'
            'Designer-IsEnabled'
            'VO-UnifiedAudioButton'
            'EditHVCRelightIsEnabledQCOM'
            'UnifiedEditorOnV0-IsEnabled'
            'RingTester'
            'ClipChampPromo-ButtonAlternateText-IsEnabled'
            'EditHVC-GenerativeErase-IsEnabled'
            'EditHVC-Stylizer-IsEnabled'
            'StoryBuilder-Rotate'
            'Collections-ShowFolderAndSubfoldersDefault-IsEnabled'
            'SpecialEffects-NewRemoveIcon'
            'UserActivity-IsEnabled'
            'OneDriveOnlineSearch-IndexWarming-IsEnabled'
            'WindowsIndexerSemanticSearchIsEnabledIntel'
            'EditHVC-Win10-GenerativeErase-IsEnabled'
            'VideoProjects-ShowAllByDefault'
            'WindowsIndexerSemanticSearchIsEnabledAMD'
            'Moodboard-IsEnabled-STX'
            'StoryBuilder-OnlineContentControl'
            'ClipChampPromo_TeachingMomentAlternateText_IsEnabled'
            'WindowsIndexerSearchIsEnabled'
            'ClipChampPromo-OneUpViewer-TitleBarOverflow-ButtonHasDesc'
            'OneDriveOnlineSearch_IsEnabled'
            'OneDriveOnlineSearch_IndexWarming_IsEnabled'
            'EditHVC-NewAutoEnhance-IsEnabled'
            'ExternalFileDragAndDrop-IsEnabled'
            'EditHVCStylizerIsEnabledAMD'
            'EditHVC_BackgroundBlur_IsEnabled'
            'StoryBuilder-RememberLastUsedTextStyleAndDefaultLayout'
            'ImageCategorizationIsEnabledIntel'
            'EditHVCSuperResolutionIsEnabledIntel'
            'ClipChampPromo-PurpleIcon-IsEnabled'
            'VideoEditorAppBarReorganization'
            'ICloud-EmptyStatesExperimentV2-IsEnabled'
            'VO-NewPage'
            'EditHVC-SuperResolution-IsEnabled'
            'ViewerBingVisualSearch-IsEnabled'
            'WindowsIndexerSemanticSearchIsEnabledLNL'
            'EditHVC-Stylizer-IsEnabled-STX'
            'StoryBuilder-ReorderTextStyles'
            'WindowsIndexerSemanticSearchIsEnabledSTX'
            'SingleClick-IsEnabled'
            'LocationSearch_IsEnabled'
            'StoryBuilder-EmptyNewProject-Enabled'
            'Moodboard-IsEnabled-LNL'
            'EditHVCStylizerIsEnabledIntel'
            'ImageCategorizationIsEnabledQCOM'
            'ICloud-InWin10-IsEnabled'
        )
        foreach ($name in $photosSettingsBooleans) {
            $setting = [PSCustomObject]@{
                Name  = $name
                Value = @('0', '1')[$revert] # 0 = disable    1 = enable
                Type  = '5f5e10b'
            }
            $result = $setting | Set-UwpAppRegistryEntry -FilePath $uwpPhotosSettings
            if ($result -eq 1) {
                #photos app may have never been opened before on this machine so open it once to create the settings.dat structure
                Write-Status -msg 'Opening Photos App once to apply changes!' -warningOutput

                #wait for photos app to fully open
                try {
                    $photos = Start-Process 'ms-photos:' -PassThru -ErrorAction Stop
               
                    while (!$photos.MainWindowHandle -or $photos.MainWindowHandle -eq 0) {
                        Start-Sleep 1
                        $photos.Refresh()
                    }
                }
                catch {
                    #this version of photos is a weird placeholder app that requires the user to install the latest version from the store
                    Write-Status -msg 'This version of Photos App needs to be fully updated from the store to unlock AI features...' -errorOutput
                    taskkill.exe /im Microsoft.Lightbox.exe /f *>$null
                    break
                }
                
                #on slow machines this will kill photos app too soon not allowing it to write to settings.dat creating the structure 
                #so wait here until settings.dat is larger than 8kb (default size for all settings.dat files)
                while ((Get-Item $uwpPhotosSettings).Length -eq 8192) {
                    Start-Sleep 1
                }
                taskkill.exe /im Photos.exe /f *>$null
                
                #now retry and if it fails again then this version doesnt have ai features
                $result = $setting | Set-UwpAppRegistryEntry -FilePath $uwpPhotosSettings
                if ($result -eq 1) {
                    Write-Status -msg 'No AI Features in this version of Photos...' -errorOutput
                    break
                }
            }
             
        }
    }

    
     
    #disable app actions
    #method credit : https://github.com/agadiffe/WindowsMize
    $settingsDat = "$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Settings\settings.dat"

    if (Test-Path $settingsDat) {
        Write-Status -msg "$(@('Disabling','Enabling')[$revert]) App Actions..."

        $apps = @(
            'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' 
            'Microsoft.Office.ActionsServer_8wekyb3d8bbwe' 
            'MSTeams_8wekyb3d8bbwe' 
            'Microsoft.Paint_8wekyb3d8bbwe' 
            'Microsoft.Windows.Photos_8wekyb3d8bbwe'
            'MicrosoftWindows.Client.CBS_cw5n1h2txyewy' #describe image (system)
        )
     
        foreach ($app in $apps) {
            $setting = [PSCustomObject]@{
                Name  = $app
                Path  = 'LocalState\DisabledApps'
                Value = @('1', '0')[$revert] # 1 = disable    0 = enable
                Type  = '5f5e10b'
            }
            
            $setting | Set-UwpAppRegistryEntry -FilePath $settingsDat
        }
     
    }
    
    #disable ai features when npu is detected in snipping tool
    $settingsDat = "$env:LOCALAPPDATA\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\Settings\settings.dat"
    if (Test-Path $settingsDat) {
        Write-Status -msg "$(@('Disabling','Enabling')[$revert]) Click to Do in Snipping Tool..."
        Stop-Process -Name SnippingTool -Force -ErrorAction SilentlyContinue
        $setting = [PSCustomObject]@{
            Name  = 'DeviceHasNpu'
            Path  = 'LocalState'
            Value = @('0', '1')[$revert] # 0 = disable    1 = enable
            Type  = '5f5e104'
        }
            
        $setting | Set-UwpAppRegistryEntry -FilePath $settingsDat
    }

    #remove the ask copilot button from desktop spotlight
    #NOTE: theres also a defaultcreatives key that doesnt seem to have ask copilot in it but will also reset the spotlight images
    #so instead of just using the default one we can remove ask copilot from the json for each image
    if (!$revert) {
        $spotlightConfigPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Creatives'
        if (Test-Path $spotlightConfigPath) {
            try {
                $json = Get-ItemPropertyValue $spotlightConfigPath -Name 'Creatives' -ErrorAction Stop | ConvertFrom-Json
                Write-Status -msg 'Removing Ask Copilot from Desktop Spotlight...'
                foreach ($item in $json.ad) {
                    if ($item.relatedContent) {
                        $item.relatedContent = $item.relatedContent | Where-Object { $_.label -ne 'Ask Copilot' }
                    }
                }

                $newjson = $json | ConvertTo-Json -Depth 20 -Compress
                Set-ItemProperty $spotlightConfigPath -Name 'Creatives' -Value $newjson -Force
            }
            catch {
                #creatives does not exist
            }
            
        }
    }
    
    #force policy changes
    Write-Status -msg 'Applying Registry Changes...'
    gpupdate /force /wait:0 >$null

}



function Install-NOAIPackage {
    
    if (!$revert) {
        $package = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*zoicware*' }
        if (!$package) {
            #check cpu arch
            $arm = ((Get-CimInstance -Class Win32_ComputerSystem).SystemType -match 'ARM64') -or ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64')
            $arch = if ($arm) { 'arm64' } else { 'amd64' }
            #add cert to registry
            $certRegPath = 'HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344'
            if (!(Test-Path "$certRegPath")) {
                New-Item -Path $certRegPath -Force | Out-Null
            }

            #check if script is being ran locally 
            if ((Test-Path "$PSScriptRoot\RemoveWindowsAIPackage\amd64") -and (Test-Path "$PSScriptRoot\RemoveWindowsAIPackage\arm64")) {
                Write-Status -msg 'RemoveWindowsAI Packages Found Locally...'

                Write-Status -msg 'Installing RemoveWindowsAI Package...'
                try {
                    Add-WindowsPackage -Online -PackagePath "$PSScriptRoot\RemoveWindowsAIPackage\$arch\ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -NoRestart -IgnoreCheck -ErrorAction Stop >$null
                }
                catch {
                    #user is using powershell 7 use dism command as fallback
                    dism.exe /Online /Add-Package /PackagePath:"$PSScriptRoot\RemoveWindowsAIPackage\$arch\ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" /NoRestart /IgnoreCheck >$null
                }
           
            }
            else {
                Write-Status -msg 'Downloading RemoveWindowsAI Package From Github...'
                $ProgressPreference = 'SilentlyContinue'
                try {
                    Invoke-WebRequest -Uri "https://github.com/zoicware/RemoveWindowsAI/raw/refs/heads/main/RemoveWindowsAIPackage/$arch/ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -OutFile "$($tempDir)ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -UseBasicParsing -ErrorAction Stop
                }
                catch {
                    Write-Status -msg "Unable to Download Package at: https://github.com/zoicware/RemoveWindowsAI/raw/refs/heads/main/RemoveWindowsAIPackage/$arch/ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -errorOutput
                    return
                }

                Write-Status -msg 'Installing RemoveWindowsAI Package...'
                try {
                    Add-WindowsPackage -Online -PackagePath "$($tempDir)ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -NoRestart -IgnoreCheck -ErrorAction Stop >$null
                }
                catch {
                    dism.exe /Online /Add-Package /PackagePath:"$($tempDir)ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" /NoRestart /IgnoreCheck >$null
                }
            }
        }
        else {
            Write-Status -msg 'Update package already installed...'
        }
        
        Write-Status -msg 'Checking update package install status...'
        $package = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*zoicware*' }
        if ($package.PackageState -eq 'InstallPending') {
            Write-Status -msg 'Package installed incorrectly... Uninstalling!' -errorOutput
            try {
                Remove-WindowsPackage -Online -PackageName $package.PackageName -NoRestart -ErrorAction Stop
            }
            catch {
                dism.exe /Online /remove-package /PackageName:$($package.PackageName) /NoRestart
            }
            #remove reg install location 
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
            Get-ChildItem $regPath | ForEach-Object {
                $value = try { Get-ItemProperty "registry::$($_.Name)" -ErrorAction Stop } catch { $null }
                if ($value -and $value.PSPath -like '*zoicware*') {
                    Remove-Item -Path $value.PSPath -Recurse -Force
                }
            }
        }
    }
    else {
        
        $package = Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*zoicware*' }
        if ($package) {
            Write-Status 'Removing Custom Windows Update Package...' 
            try {
                Remove-WindowsPackage -Online -PackageName $package.PackageName -NoRestart -ErrorAction Stop
            }
            catch {
                dism.exe /Online /remove-package /PackageName:$($package.PackageName) /NoRestart
            }
            #remove reg install location 
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
            Get-ChildItem $regPath | ForEach-Object {
                $value = try { Get-ItemProperty "registry::$($_.Name)" -ErrorAction Stop } catch { $null }
                if ($value -and $value.PSPath -like '*zoicware*') {
                    Remove-Item -Path $value.PSPath -Recurse -Force
                }
            }
            
        }
        else {
            Write-Status 'Unable to Find Update Package...' -errorOutput 
        }
        
    }

}

    
    
function Disable-Copilot-Policies {
    #disable copilot policies in region policy json
    $JSONPath = "$env:windir\System32\IntegratedServicesRegionPolicySet.json"
    if (Test-Path $JSONPath) {
        Write-Host "$(@('Disabling','Enabling')[$revert]) CoPilot Policies in " -NoNewline -ForegroundColor Cyan
        Write-Host "[$JSONPath]" -ForegroundColor Yellow

        #takeownership
        takeown /f $JSONPath *>$null
        icacls $JSONPath /grant *S-1-5-32-544:F /t *>$null

        #edit the content
        $jsonContent = Get-Content $JSONPath | ConvertFrom-Json
        try {
            $copilotPolicies = $jsonContent.policies | Where-Object { $_.'$comment' -like '*CoPilot*' }
            foreach ($policies in $copilotPolicies) {
                $policies.defaultState = @('disabled', 'enabled')[$revert]
            }
            $recallPolicies = $jsonContent.policies | Where-Object { $_.'$comment' -like '*A9*' -or $_.'$comment' -like '*Manage Recall*' -or $_.'$comment' -like '*Settings Agent*' }
            foreach ($recallPolicy in $recallPolicies) {
                if ($recallPolicy.'$comment' -like '*A9*') {
                    $recallPolicy.defaultState = @('enabled', 'disabled')[$revert]
                }
                elseif ($recallPolicy.'$comment' -like '*Manage Recall*') {
                    $recallPolicy.defaultState = @('disabled', 'enabled')[$revert]
                }
                elseif ($recallPolicy.'$comment' -like '*Settings Agent*') {
                    $recallPolicy.defaultState = @('enabled', 'disabled')[$revert]
                }
            }
            $newJSONContent = $jsonContent | ConvertTo-Json -Depth 100
            Set-Content $JSONPath -Value $newJSONContent -Force
            $total = ($copilotPolicies.count) + ($recallPolicies.count)
            Write-Status -msg "$total CoPilot Policies $(@('Disabled','Enabled')[$revert])"
        }
        catch {
            Write-Status -msg 'CoPilot Not Found in IntegratedServicesRegionPolicySet' -errorOutput 
        }

    
    }

    #additional json path for visual assist 
    $visualAssistPath = "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssist\VisualAssistActions.json"
    if (Test-Path $visualAssistPath) {
        Write-Status -msg "$(@('Disabling','Enabling')[$revert]) Generative AI in Visual Assist..."

        takeown /f $visualAssistPath *>$null
        icacls $visualAssistPath /grant *S-1-5-32-544:F /t *>$null

        $jsoncontent = Get-Content $visualAssistPath | ConvertFrom-Json
        $jsonContent.actions | Add-Member -MemberType NoteProperty -Name usesGenerativeAI -Value @($false, $true)[$revert] -force
        $newJSONContent = $jsonContent | ConvertTo-Json -Depth 100
        Set-Content $visualAssistPath -Value $newJSONContent -Force
    }
    
}

#function from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Wrapper-Functions/Download-AppxPackage-Function.ps1
function Download-AppxPackage {
    param(
        # there has to be an alternative, as sometimes the API fails on PackageFamilyName
        [string]$PackageFamilyName,
        [string]$ProductId,
        [string]$outputDir
    )
    if (-Not ($PackageFamilyName -Or $ProductId)) {
        # can't do anything without at least one
        Write-Error 'Missing either PackageFamilyName or ProductId.'
        return $null
    }
      
    try {
        $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome # needed as sometimes the API will block things when it knows requests are coming from PowerShell
    }
    catch {
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
      
    $DownloadedFiles = @()
    $errored = $false
    $allFilesDownloaded = $true
      
    $apiUrl = 'https://store.rg-adguard.net/api/GetFiles'
    $versionRing = 'Retail'
      
    $architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
        'x86' { 'x86' }
        { @('x64', 'amd64') -contains $_ } { 'x64' }
        'arm' { 'arm' }
        'arm64' { 'arm64' }
        default { 'neutral' } # should never get here
    }
      
    if (Test-Path $outputDir -PathType Container) {
        New-Item -Path "$outputDir\$PackageFamilyName" -ItemType Directory -Force | Out-Null
        $downloadFolder = "$outputDir\$PackageFamilyName"
    }
    else {
        
        $downloadFolder = Join-Path $tempDir $PackageFamilyName
        if (!(Test-Path $downloadFolder -PathType Container)) {
            New-Item $downloadFolder -ItemType Directory -Force | Out-Null
        }
    }
        
    $body = @{
        type = if ($ProductId) { 'ProductId' } else { 'PackageFamilyName' }
        url  = if ($ProductId) { $ProductId } else { $PackageFamilyName }
        ring = $versionRing
        lang = 'en-US'
    }

    $headers = @{
        'User-Agent'       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        'Accept'           = 'application/json, text/javascript, */*; q=0.01'
        'Content-Type'     = 'application/x-www-form-urlencoded; charset=UTF-8'
        'X-Requested-With' = 'XMLHttpRequest'
        'Origin'           = 'https://store.rg-adguard.net'
        'Referer'          = 'https://store.rg-adguard.net/'
    }
      
    # required due to the api being protected behind Cloudflare now
    if (-Not $apiWebSession) {
        $global:apiWebSession = $null
        $apiHostname = (($apiUrl.split('/'))[0..2]) -Join '/'
        Invoke-WebRequest -Uri $apiHostname -UserAgent $UserAgent -SessionVariable $apiWebSession -UseBasicParsing 
    }
      
    $raw = $null
    try {
        $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $body -WebSession $apiWebSession
    }
    catch {
        $errorMsg = 'An error occurred: ' + $_
        Write-Host $errorMsg
        $errored = $true
        return $false
    }
      
    # hashtable of packages by $name
    #  > values = hashtables of packages by $version
    #    > values = arrays of packages as objects (containing: url, filename, name, version, arch, publisherId, type)
    [Collections.Generic.Dictionary[string, Collections.Generic.Dictionary[string, array]]] $packageList = @{}
    # populate $packageList
    $patternUrlAndText = '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*\.(app|msi)x.*)<\/a>'
    $raw | Select-String $patternUrlAndText -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object {
        $url = ($_.Groups['url']).Value
        $text = ($_.Groups['text']).Value
        $textSplitUnderscore = $text.split('_')
        $name = $textSplitUnderscore.split('_')[0]
        $version = $textSplitUnderscore.split('_')[1]
        $arch = ($textSplitUnderscore.split('_')[2]).ToLower()
        $publisherId = ($textSplitUnderscore.split('_')[4]).split('.')[0]
        $textSplitPeriod = $text.split('.')
        $type = ($textSplitPeriod[$textSplitPeriod.length - 1]).ToLower()
      
        # create $name hash key hashtable, if it doesn't already exist
        if (!($packageList.keys -match ('^' + [Regex]::escape($name) + '$'))) {
            $packageList["$name"] = @{}
        }
        # create $version hash key array, if it doesn't already exist
        if (!(($packageList["$name"]).keys -match ('^' + [Regex]::escape($version) + '$'))) {
            ($packageList["$name"])["$version"] = @()
        }
       
        # add package to the array in the hashtable
        ($packageList["$name"])["$version"] += @{
            url         = $url
            filename    = $text
            name        = $name
            version     = $version
            arch        = $arch
            publisherId = $publisherId
            type        = $type
        }
    }
      
    # an array of packages as objects, meant to only contain one of each $name
    $latestPackages = @()
    # grabs the most updated package for $name and puts it into $latestPackages
    $packageList.GetEnumerator() | ForEach-Object { ($_.value).GetEnumerator() | Select-Object -Last 1 } | ForEach-Object {
        $packagesByType = $_.value
        $msixbundle = ($packagesByType | Where-Object { $_.type -match '^msixbundle$' })
        $appxbundle = ($packagesByType | Where-Object { $_.type -match '^appxbundle$' })
        $msix = ($packagesByType | Where-Object { ($_.type -match '^msix$') -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
        $appx = ($packagesByType | Where-Object { ($_.type -match '^appx$') -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
        if ($msixbundle) { $latestPackages += $msixbundle }
        elseif ($appxbundle) { $latestPackages += $appxbundle }
        elseif ($msix) { $latestPackages += $msix }
        elseif ($appx) { $latestPackages += $appx }
    }
      
    # download packages
    $latestPackages | ForEach-Object {
        $url = $_.url
        $filename = $_.filename
        # TODO: may need to include detection in the future of expired package download URLs..... in the case that downloads take over 10 minutes to complete
      
        $downloadFile = Join-Path $downloadFolder $filename
      
        # If file already exists, ask to replace it
        if (Test-Path $downloadFile) {
            Write-Host "`"${filename}`" already exists at `"${downloadFile}`"."
            $confirmation = ''
            while (!(($confirmation -eq 'Y') -Or ($confirmation -eq 'N'))) {
                $confirmation = Read-Host "`nWould you like to re-download and overwrite the file at `"${downloadFile}`" (Y/N)?"
                $confirmation = $confirmation.ToUpper()
            }
            if ($confirmation -eq 'Y') {
                Remove-Item -Path $downloadFile -Force
            }
            else {
                $DownloadedFiles += $downloadFile
            }
        }
      
        if (!(Test-Path $downloadFile)) {
            # Write-Host "Attempting download of `"${filename}`" to `"${downloadFile}`" . . ."
            $fileDownloaded = $null
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue' # avoids slow download when using Invoke-WebRequest
            try {
                Invoke-WebRequest -Uri $url -OutFile $downloadFile
                $fileDownloaded = $?
            }
            catch {
                $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
                $errorMsg = 'An error occurred: ' + $_
                Write-Host $errorMsg
                $errored = $true
                break $false
            }
            $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
            if ($fileDownloaded) { $DownloadedFiles += $downloadFile }
            else { $allFilesDownloaded = $false }
        }
    }
      
    if ($errored) { Write-Host 'Completed with some errors.' }
    if (-Not $allFilesDownloaded) { Write-Host 'Warning: Not all packages could be downloaded.' }
    return $DownloadedFiles
}


function Remove-AI-Appx-Packages {

    if ($revert) {
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Copilot_8wekyb3d8bbwe' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Clipchamp.Clipchamp_yxz26nhyzhsrt' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' /v 'DynamicRemovalList' /f *>$null
         

        #download appx packages from store
        $appxBackup = "$env:USERPROFILE\RemoveWindowsAI\Backup\AppxBackup"
        if (Test-Path $appxBackup) {
            $familyNames = Get-Content "$appxBackup\PackageFamilyNames.txt"
            foreach ($package in $familyNames) {
                Write-Status -msg "Attempting to Download $package..."
                $downloadedFiles = Download-AppxPackage -PackageFamilyName $package -outputDir $appxBackup
                $bundle = $downloadedFiles | Where-Object { $_ -match '\.appxbundle$' -or $_ -match '\.msixbundle$' } | Select-Object -First 1
                if ($bundle) {
                    Write-Status -msg "Installing $package..."
                    Add-AppPackage $bundle
                }
            }

            #cleanup
            Remove-Item "$appxBackup\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Status -msg 'Unable to Find AppxBackup in User Directory!' -errorOutput 
        }

    }
    else {

        #to make this part faster make a txt file in temp with chunck of removal 
        #code and then just run that from run 
        #trusted function due to the design of having it hidden from the user
        
        $packageRemovalPath = "$($tempDir)aiPackageRemoval.ps1"
        if (!(test-path $packageRemovalPath)) {
            New-Item $packageRemovalPath -Force | Out-Null
        }

        $aipackages = @(
            # 'MicrosoftWindows.Client.Photon'
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
            #ai component packages installed on copilot+ pcs
            'WindowsWorkload.Data.Analysis*'
            'WindowsWorkload.Manager.*'
            'WindowsWorkload.PSOnnxRuntime*'
            'WindowsWorkload.PSTokenizer*'
            'WindowsWorkload.QueryBlockList.*'
            'WindowsWorkload.QueryProcessor*'
            'WindowsWorkload.SemanticText*'
            'WindowsWorkload.Data.ContentExtraction*'
            'WindowsWorkload.ScrRegDetection*'
            'WindowsWorkload.TextRecognition*'
            'WindowsWorkload.Data.ImageSearch*'
            'WindowsWorkload.ImageContentModeration*'
            'WindowsWorkload.ImageSearch*'
            'WindowsWorkload.PSTokenizerShared*'
            'WindowsWorkload.ImageTextSearch*'
            'WindowsWorkload.SettingsModel*'
            'WindowsWorkload.Data.PhiSilica*'
            'WindowsWorkload.EP.Qualcomm*'
            'WindowsWorkload.ImageDescription*'
            'WindowsWorkload.ImageLLMAdapter*'
            'WindowsWorkload.LanguageModel*'
            'WindowsWorkload.SessionManager*'
            'WindowsWorkload.TextContentModeration*'
            'WindowsWorkload.WinMLShared*'
            'WindowsWorkload.Data.SettingsModel*'
            'MicrosoftCorporationII.WinML.Qualcomm*'
        )

        if ($backup) {

            #create file with package family names for reverting
            $appxBackup = "$env:USERPROFILE\RemoveWindowsAI\Backup\AppxBackup"
            if (!(Test-Path $appxBackup)) {
                New-Item $appxBackup -ItemType Directory -Force | Out-Null
            }

            $backuppath = New-Item $appxBackup -Name 'PackageFamilyNames.txt' -ItemType File -Force

            $familyNames = get-appxpackage -allusers | Where-Object { $aipackages -contains $_.Name } 
            foreach ($familyName in $familyNames) {
                Add-Content -Path $backuppath.FullName -Value $familyName.PackageFamilyName 
            }

        }

        $code = @'
        param(
            [string]$aipackages
        )
$aipackagesarray = $aipackages -split ','

$provisioned = get-appxprovisionedpackage -online 
$appxpackage = get-appxpackage -allusers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

#use eol trick to uninstall some locked packages
foreach ($choice in $aipackagesarray) {
    foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {

        $PackageName = $appx.PackageName 
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force
     
        Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers
    }
    foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {

        $PackageFullName = $appx.PackageFullName
        $PackageFamilyName = $appx.PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force
        Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0
       
        #remove inbox apps
        $inboxApp = "$store\InboxApplications\$PackageFullName"
        Remove-Item -Path $inboxApp -Force

        #get all installed user sids for package due to not all showing up in reg
        foreach ($user in $appx.PackageUserInformation) { 
            $sid = $user.UserSecurityID.SID
            New-Item "$store\EndOfLife\$sid\$PackageFullName" -force -verbose
            remove-appxpackage -package $PackageFullName -User $sid 
        } 
        remove-appxpackage -package $PackageFullName -allusers

        foreach ($sid in $users) { 
            New-Item "$store\EndOfLife\$sid\$PackageFullName" -force
        }  
    }
}
'@
        Set-Content -Path $packageRemovalPath -Value $code -Force 
        #allow removal script to run
        try {
            Set-ExecutionPolicy Unrestricted -Force -ErrorAction Stop
        }
        catch {
            #user has set powershell execution policy via group policy or via settings, to change it we need to update the registry 
            $policyPaths = @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
                'HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell',
                'HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell',
                'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            )
            
            foreach ($path in $policyPaths) {
                $val = try { Get-ItemPropertyValue $path -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue }catch {}

                if ($val) { 
                    $Global:ogExecutionPolicyPath = $path
                    $Global:ogExecutionPolicy = $val
                    #need to apply enabledscripts 1 for policies
                    if ($path -like '*Policies\Microsoft\Windows\PowerShell') {
                        #change path for reg format
                        Reg.exe add $($path -replace ':', '') /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
                    }
                    Reg.exe add $($path -replace ':', '') /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                    break
                }
            }
            
           
        }


        Write-Status -msg 'Removing AI Appx Packages...'
        #prevent packages array from getting expanded too early
        #pass comma seperated string and then convert back to array in new session
        $joined = $aipackages -join ','
        $command = "&`"$($tempDir)aiPackageRemoval.ps1`" -aipackages '$joined'"
        Run-Trusted -command $command -psversion $psversion

        #check packages removal
        #exit loop after 10 tries
        $attempts = 0
        do {
            Start-Sleep 1
            $packages = get-appxpackage -AllUsers | Where-Object { $packageName = $_.Name; $aipackages | Where-Object { $packageName -like $_ } }
            if ($packages) {
                $attempts++
                if ($EnableLogging) {
                    $Global:logInfo.Line = "Attempting to Remove Appx Packages, Attempt: $attempts"
                    $Global:logInfo.Result = "Found Packages: $packages"
                    Add-LogInfo -logPath $logPath -info $Global:logInfo
                }
                #$command = "&`"$($tempDir)aiPackageRemoval.ps1`""
                Run-Trusted -command $command -psversion $psversion
            }
    
        }while ($packages -and $attempts -lt 10)

        if ($EnableLogging) {
            if ($attempts -ge 10) {
                Write-Status -msg 'Packages Removal Failed...' -errorOutput 
                $Global:logInfo.Line = 'Removing Appx Packages'
                $Global:logInfo.Result = "Removal Failed, Reached Max Attempts (10)... Leftover Packages: $packages"
                Add-LogInfo -logPath $logPath -info $Global:logInfo
            }
            else {
                Write-Status -msg 'Packages Removed Sucessfully...'
                $Global:logInfo.Line = 'Removing Appx Packages'
                $Global:logInfo.Result = 'Removal Success'
                Add-LogInfo -logPath $logPath -info $Global:logInfo
            }
        }
        else {
            if ($attempts -ge 10) {
                Write-Status -msg 'Packages Removal Failed...' -errorOutput 
                Write-Status -msg 'Use the Enable Logging Switch to Get More Info...'
            }
            else {
                Write-Status -msg 'Packages Removed Sucessfully...'
            }
        
        }

        #tell windows copilot pwa is already installed
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' /v 'CopilotPWAPreinstallCompleted' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' /v 'Microsoft.Copilot_8wekyb3d8bbwe' /t REG_DWORD /d '1' /f *>$null
        #incase the user is on 25h2 and is using education or enterprise (required for this policy to work)
        #uninstalls copilot with group policy (will ensure it doesnt get reinstalled)
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' /v 'Enabled' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.Copilot_8wekyb3d8bbwe' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages\Clipchamp.Clipchamp_yxz26nhyzhsrt' /v 'RemovePackage' /t REG_DWORD /d '1' /f *>$null
        Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' -Name 'DynamicRemovalList' -Value @(
            'aimgr_8wekyb3d8bbwe'
            'Microsoft.Edge.GameAssist_8wekyb3d8bbwe'
        ) -type 7 #multi-line string

        $uninstallRegPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Copilot'
        if (Test-Path $uninstallRegPath) {
            Write-Status -msg 'Removing Copilot Edge Integration App...'
            $uninstallString = Get-ItemPropertyValue $uninstallRegPath -Name 'UninstallString'
            if ($uninstallString) {
                Start-Process cmd.exe -args "/c $uninstallString" -WindowStyle Hidden -Wait
            }
            else {
                Write-Status -msg 'Unable to Find Copilot Uninstall String!' -errorOutput
            }
        }
        
    }

}

function Remove-Recall-Optional-Feature {
    if (!$revert) {
        #doesnt seem to work just gets stuck (does anyone really want this shit lol)
        #Enable-WindowsOptionalFeature -Online -FeatureName 'Recall' -All -NoRestart
        #remove recall optional feature 
        Write-Status -msg 'Removing Recall Optional Feature...'
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName 'Recall' -ErrorAction Stop).State
            if ($state -and $state -ne 'DisabledWithPayloadRemoved') {
                $ProgressPreference = 'SilentlyContinue'
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -Remove -NoRestart -ErrorAction Stop *>$null
                }
                catch {
                    #incase get-windowsoptionalfeature works but disable doesnt 
                    dism.exe /Online /Disable-Feature /FeatureName:Recall /Remove /NoRestart /Quiet
                }
            }
        }
        catch {
            #if get-windowsoptionalfeature errors fallback to dism
            $dismOutput = dism.exe /Online /Get-FeatureInfo /FeatureName:Recall
    
            if ($LASTEXITCODE -eq 0) {
                $isDisabledWithPayloadRemoved = $dismOutput | Select-String -Pattern 'State\s*:\s*Disabled with Payload Removed'
        
                if (!$isDisabledWithPayloadRemoved) {
                    dism.exe /Online /Disable-Feature /FeatureName:Recall /Remove /NoRestart /Quiet
                }
            }
        }
    }
}

# not restoring for now shouldnt cause any issues (also may not even be possible to restore)
function Remove-AI-CBS-Packages {
    if (!$revert) {
        #additional hidden packages
        Write-Status -msg 'Removing Additional Hidden AI Packages...'
        #unhide the packages from dism, remove owners subkey for removal 
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
        $ProgressPreference = 'SilentlyContinue'
        Get-ChildItem $regPath | ForEach-Object {
            $value = try { Get-ItemPropertyValue "registry::$($_.Name)" -Name Visibility -ErrorAction Stop } catch { $null }
    
            if ($value -ne $null) {
                if ($value -eq 2 -and $_.PSChildName -like '*AIX*' -or $_.PSChildName -like '*Recall*' -or $_.PSChildName -like '*Copilot*' -or $_.PSChildName -like '*CoreAI*') {
                    Set-ItemProperty "registry::$($_.Name)" -Name Visibility -Value 1 -Force
                    New-ItemProperty "registry::$($_.Name)" -Name DefVis -PropertyType DWord -Value 2 -Force | Out-Null
                    Remove-Item "registry::$($_.Name)\Owners" -Force -ErrorAction SilentlyContinue
                    Remove-Item "registry::$($_.Name)\Updates" -Force -ErrorAction SilentlyContinue
                    try {
                        Remove-WindowsPackage -Online -PackageName $_.PSChildName -NoRestart -ErrorAction Stop *>$null
                        $paths = Get-ChildItem "$env:windir\servicing\Packages" -Filter "*$($_.PSChildName)*" -ErrorAction SilentlyContinue 
                        foreach ($path in $paths) {
                            if ($path) {
                                Remove-Item $path.FullName -Force -ErrorAction SilentlyContinue
                            }
                        }
                        
                    }
                    catch {
                        #fallback to dism when user is using powershell 7
                        dism.exe /Online /Remove-Package /PackageName:$($_.PSChildName) /NoRestart /Quiet
                        $paths = Get-ChildItem "$env:windir\servicing\Packages" -Filter "*$($_.PSChildName)*" -ErrorAction SilentlyContinue 
                        foreach ($path in $paths) {
                            if ($path) {
                                Remove-Item $path.FullName -Force -ErrorAction SilentlyContinue
                            }
                        }                    
                    }
        
                }
            }
            
        }
    }
}


function Remove-AI-Files {
    #prob add params here for each file removal 


    if ($revert) {
        if (Test-Path "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles") {
            Write-Status -msg 'Restoring Appx Package Files...'
            $paths = Get-Content "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\backupPaths.txt"
            foreach ($path in $paths) {
                $fileName = Split-Path $path -Leaf
                $dest = Split-Path $path -Parent
                try {
                    Move-Item -Path "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\$fileName" -Destination $dest -Force -ErrorAction Stop
                }
                catch {
                    $command = "Move-Item -Path `"$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\$fileName`" -Destination `"$dest`" -Force"
                    Run-Trusted -command $command -psversion $psversion
                    Start-Sleep 1
                }
            }

            if (Test-Path "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI") {
                Write-Status -msg 'Restoring Office AI Files...'
                Move-Item "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI\x64\AI" -Destination "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16" -Force 
                Move-Item "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI\x86\AI" -Destination "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16" -Force 
                Move-Item "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI\RootAI\AI" -Destination "$env:ProgramFiles\Microsoft Office\root\Office16" -Force 
                Move-Item "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI\ActionsServer\ActionsServer" -Destination "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16" -Force 
                Get-ChildItem "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI" -Filter '*.msix' | ForEach-Object {
                    Move-Item $_.FullName -Destination "$env:ProgramFiles\Microsoft Office\root\Integration\Addons" -Force
                }
            }

            Write-Status -msg 'Restoring AI URIs...'
            $regs = Get-ChildItem "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\URIHandlers"
            foreach ($reg in $regs) {
                Reg.exe import $reg.FullName *>$null
            }
           
            Write-Status -msg 'Files Restored... You May Need to Repair the Apps Using the Microsoft Store'
        }
        else {
            Write-Status -msg 'Unable to Find Backup Files!' -errorOutput 
        }
       
    }
    else {

        $aipackages = @(
            # 'MicrosoftWindows.Client.Photon'
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
            'Microsoft.AIFabric.CBS'
            #ai component packages installed on copilot+ pcs
            'WindowsWorkload'
            'Voiess'
            'Speion'
            'Livtop'
            'InpApp'
            'Filons'
        )

        Write-Status -msg 'Removing Appx Package Files...'
        Write-Status -msg 'This could take a while on some systems, please be patient!' -warningOutput
        #-----------------------------------------------------------------------remove files
        $appsPath = "$env:SystemRoot\SystemApps"
        if (!(Test-Path $appsPath)) {
            $appsPath = "$env:windir\SystemApps"
        }
        $appsPath2 = "$env:ProgramFiles\WindowsApps"
    
        $appsPath3 = "$env:ProgramData\Microsoft\Windows\AppRepository"
    
        $appsPath4 = "$env:SystemRoot\servicing\Packages"
        if (!(Test-Path $appsPath4)) {
            $appsPath4 = "$env:windir\servicing\Packages"
        }
    
        $appsPath5 = "$env:SystemRoot\System32\CatRoot"
        if (!(Test-Path $appsPath5)) {
            $appsPath5 = "$env:windir\System32\CatRoot"
        }

        $appsPath6 = "$env:SystemRoot\SystemApps\SxS"
        if (!(Test-Path $appsPath6)) {
            $appsPath6 = "$env:windir\SystemApps\SxS"
        }

        $paths = @(
            $appsPath,
            $appsPath2,
            $appsPath3,
            $appsPath6
        )

        $jobs = foreach ($path in $paths) {
            $rs = [powershell]::Create().AddScript({
                    param($path)
                    (Get-ChildItem -Path $path -Directory -Force -ErrorAction SilentlyContinue).FullName  
                }).AddParameter('path', $path)
    
            [pscustomobject]@{
                Runspace = $rs
                Handle   = $rs.BeginInvoke()
            }
        }

        $fullPaths = foreach ($job in $jobs) {
            $job.Runspace.EndInvoke($job.Handle)
            $job.Runspace.Dispose()
        }


        $packagesPath = @()
        foreach ($package in $aipackages) {
            foreach ($path in $fullPaths) {
                if ($path -like "*$package*") {
                    $packagesPath += $path
                }
            }
        }

        $paths = @($appsPath4, $appsPath5)
        $jobs = foreach ($path in $paths) {
            $rs = [powershell]::Create().AddScript({
                    param($path)
                    (Get-ChildItem -Path $path -Directory -Force -ErrorAction SilentlyContinue | 
                    Where-Object { $_.FullName -like '*UserExperience-AIX*' -or 
                        $_.FullName -like '*Copilot*' -or 
                        $_.FullName -like '*UserExperience-Recall*' -or 
                        $_.FullName -like '*CoreAI*' 
                    }).FullName
                }).AddParameter('path', $path)
    
            [pscustomobject]@{
                Runspace = $rs
                Handle   = $rs.BeginInvoke()
            }
        }

        $packagesPath += foreach ($job in $jobs) {
            $job.Runspace.EndInvoke($job.Handle)
            $job.Runspace.Dispose()
        }


        #add app actions mcp host
        $paths = @(
            "$env:LOCALAPPDATA\Microsoft\WindowsApps\ActionsMcpHost.exe"
            "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\ActionsMcpHost.exe"
            "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\WindowsApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionsMcpHost.exe"
            "$env:LOCALAPPDATA\Microsoft\WindowsApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionsMcpHost.exe"
        )

        foreach ($path in $paths) {
            if (Test-Path $path) {
                $packagesPath += $path
            }
        }

        foreach ($packageName in $aipackages) {
            $path = Get-ChildItem "$env:LOCALAPPDATA\Packages" -Filter "*$packageName*" 
            if ($path) {
                $packagesPath += $path.FullName
            }
            
        }

    
        if ($backup) {
            Write-Status -msg 'Backing Up AI Files...'
            $backupDir = "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles"
            if (!(Test-Path $backupDir)) {
                New-Item $backupDir -Force -ItemType Directory | Out-Null
            }
        }

        foreach ($Path in $packagesPath) {
            #only remove dlls from photon to prevent startmenu from breaking
            # if ($path -like '*Photon*') {
            #     $command = "`$dlls = (Get-ChildItem -Path $Path -Filter *.dll).FullName; foreach(`$dll in `$dlls){Remove-item ""`$dll"" -force}"
            #     Run-Trusted -command $command -psversion $psversion
            #     Start-Sleep 1
            # }
            # else {

            if ($backup) {
                $backupFiles = "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\backupPaths.txt"
                if (!(Test-Path $backupFiles -PathType Leaf)) {
                    New-Item $backupFiles -Force -ItemType File | Out-Null
                }
                try {
                    Copy-Item -Path $Path -Destination $backupDir -Force -Recurse -ErrorAction Stop
                    Add-Content -Path $backupFiles -Value $Path
                }
                catch {
                    #ignore any errors
                }
            }
            $command = "Remove-item ""$Path"" -force -recurse"
            Run-Trusted -command $command -psversion $psversion
           
        }

        #remove machine learning dlls
        $paths = @(
            "$env:SystemRoot\System32\Windows.AI.MachineLearning.dll"
            "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.dll"
            "$env:SystemRoot\System32\Windows.AI.MachineLearning.Preview.dll"
            "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.Preview.dll"
            "$env:SystemRoot\System32\SettingsHandlers_Copilot.dll"
            "$env:SystemRoot\System32\SettingsHandlers_A9.dll"
        )
        foreach ($path in $paths) {
            if (Test-Path $path) {
                takeown /f $path *>$null
                icacls $path /grant *S-1-5-32-544:F /t *>$null
                try {
                    Remove-Item -Path $path -Force -ErrorAction Stop
                }
                catch {
                    #takeown didnt work remove file with system priv
                    $command = "Remove-Item -Path $path -Force"
                    Run-Trusted -command $command -psversion $psversion
                }
            }
        }
    
        Write-Status -msg 'Removing Hidden Copilot Installers...'
        #remove package installers in edge dir
        #installs Microsoft.Windows.Ai.Copilot.Provider
        $dir = "${env:ProgramFiles(x86)}\Microsoft"
        $folders = @(
            'Edge',
            'EdgeCore',
            'EdgeWebView'
        )
        foreach ($folder in $folders) {
            if ($folder -eq 'EdgeCore') {
                #edge core doesnt have application folder
                $fullPath = (Get-ChildItem -Path "$dir\$folder\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
            
            }
            else {
                $fullPath = (Get-ChildItem -Path "$dir\$folder\Application\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
            }
            if ($fullPath -ne $null) { Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue }
        }
    

        #remove copilot update in edge update dir
        $dir = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate"
        if (Test-Path $dir) {
            $paths = Get-ChildItem $dir -Recurse -Filter '*CopilotUpdate.exe*' 
            foreach ($path in $paths) {
                if (Test-Path $path.FullName) {
                    Remove-Item $path.FullName -Force
                }
            }
        }

        $dir = "${env:ProgramFiles(x86)}\Microsoft"
        if (Test-Path $dir) {
            $paths = Get-ChildItem $dir -Recurse -Filter '*Copilot_setup*' 
            foreach ($path in $paths) {
                if (Test-Path $path.FullName) {
                    Remove-Item $path.FullName -Force
                }
            }
        }

        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\EdgeUpdate' /v 'CopilotUpdatePath' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate' /v 'CopilotUpdatePath' /f *>$null
    
        #remove additional installers
        $inboxapps = 'C:\Windows\InboxApps'
        $installers = Get-ChildItem -Path $inboxapps -Filter '*Copilot*'
        foreach ($installer in $installers) {
            takeown /f $installer.FullName *>$null
            icacls $installer.FullName /grant *S-1-5-32-544:F /t *>$null
            try {
                Remove-Item -Path $installer.FullName -Force -ErrorAction Stop
            }
            catch {
                #takeown didnt work remove file with system priv
                $command = "Remove-Item -Path $($installer.FullName) -Force"
                Run-Trusted -command $command -psversion $psversion
            }
        
        }
    
    
        #remove ai from outlook/office
        $aiPaths = @(
            "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\AI",
            "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\AI",
            "$env:ProgramFiles\Microsoft Office\root\Office16\AI",
            "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\ActionsServer",
            "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\aimgr.msix",
            "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\WritingAssistant.msix",
            "$env:ProgramFiles\Microsoft Office\root\Integration\Addons\ActionsServer.msix"
        )
    
        foreach ($path in $aiPaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                if ($backup) {
                    Write-Status -msg 'Backing Up Office AI Files...'
                    $backupDir = "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI"
                    if (!(Test-Path $backupDir)) {
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }

                    if ($path -eq "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\AI") {
                        $backupDir = "$backupDir\x64"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    elseif ($path -eq "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\AI") {
                        $backupDir = "$backupDir\x86"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    elseif ($path -eq "$env:ProgramFiles\Microsoft Office\root\Office16\AI") {
                        $backupDir = "$backupDir\RootAI"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    elseif ($path -eq "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\ActionsServer") {
                        $backupDir = "$backupDir\ActionsServer"
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    else {
                        $backupDir = "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\OfficeAI"
                    }
                    Copy-Item -Path $path -Destination $backupDir -Force -Recurse -ErrorAction SilentlyContinue
                }
                try {
                    Remove-Item $path -Recurse -Force -ErrorAction Stop
                }
                catch {
                    $command = "Remove-Item $path -Recurse -Force"
                    Run-Trusted -command $command -psversion $psversion
                    Start-Sleep 1
                }
                
            }
        }

        #remove any screenshots from recall
        Write-Status -msg 'Removing Any Screenshots By Recall...'
        Remove-Item -Path "$env:LOCALAPPDATA\CoreAIPlatform*" -Force -Recurse -ErrorAction SilentlyContinue
        if ($env:OneDrive) {
            Remove-Item -Path "$env:OneDrive\Microsoft Copilot Chat Files" -Force -Recurse -ErrorAction SilentlyContinue
        }
       
        #remove ai uri handlers
        Write-Status -msg 'Removing AI URI Handlers...'
        $uris = @(
            'registry::HKEY_CLASSES_ROOT\ms-office-ai'
            'registry::HKEY_CLASSES_ROOT\ms-copilot'
            'registry::HKEY_CLASSES_ROOT\ms-clicktodo'
        )

        foreach ($uri in $uris) {
            if ($backup) {
                if (Test-Path $uri) {
                    $backupDir = "$env:USERPROFILE\RemoveWindowsAI\Backup\AIFiles\URIHandlers"
                    if (!(Test-Path $backupDir)) {
                        New-Item $backupDir -Force -ItemType Directory | Out-Null
                    }
                    $regExportPath = "$backupDir\$($uri -replace 'registry::HKEY_CLASSES_ROOT\\', '').reg"
                    Reg.exe export ($uri -replace 'registry::', '') $regExportPath /y *>$null
                }
            }
            Remove-Item $uri -Recurse -Force -ErrorAction SilentlyContinue
        }

        #prefire copilot nudges package by deleting the registry keys 
        Write-Status -msg 'Removing Copilot Nudges Registry Keys...'
        $keys = @(
            'registry::HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.AppX*.wwa',
            'registry::HKCR\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.wwa',
            'registry::HKCR\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\Applications\MicrosoftWindows.Client.Core_cw5n1h2txyewy!Global.CopilotNudges',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\Applications\MicrosoftWindows.Client.Core_cw5n1h2txyewy!Global.CopilotNudges',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.Core_cw5n1h2txyewy!Global.CopilotNudges',
            'HKLM:\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.AppX*.wwa',
            'HKLM:\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.AppX*.mca',
            'HKLM:\SOFTWARE\Classes\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.Client.Core_*.*.*.*_x64__cw5n1h2txyewy\ActivatableClassId\Global.CopilotNudges.wwa'
        )
        #get full paths and remove
        $fullkey = @()
        foreach ($key in $keys) {
            try {
                $fullKey = Get-Item -Path $key -ErrorAction Stop
                if ($null -eq $fullkey) { continue }
                if ($fullkey.Length -gt 1) {
                    foreach ($multikey in $fullkey) {
                        $command = "Remove-Item -Path `"registry::$multikey`" -Force -Recurse"
                        Run-Trusted -command $command -psversion $psversion
                        Start-Sleep 1
                        #remove any regular admin that have trusted installer bug
                        Remove-Item -Path "registry::$multikey" -Force -Recurse -ErrorAction SilentlyContinue
                    }
                }
                else {
                    $command = "Remove-Item -Path `"registry::$fullKey`" -Force -Recurse"
                    Run-Trusted -command $command -psversion $psversion
                    Start-Sleep 1
                    #remove any regular admin that have trusted installer bug
                    Remove-Item -Path "registry::$fullKey" -Force -Recurse -ErrorAction SilentlyContinue
                }
         
            }
            catch {
                continue
            }
        }

        #remove ai app checks in updates (not sure if this does anything)
        $command = "Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy' /f"
        Run-Trusted -command $command -psversion $psversion
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIX' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'CopilotNudges' /f *>$null
        Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIContext' /f *>$null

        reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\ActionsMcpHost.exe' /f *>$null
        reg.exe delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\ActionsMcpHost.exe' /f *>$null

        #remove app actions files 
        #these will get remade when updating
        taskkill.exe /im AppActions.exe /f *>$null
        taskkill.exe /im VisualAssist.exe /f *>$null
        $paths = @(
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\ActionUI"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssist"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AppActions.exe"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AppActions.dll"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssistExe.exe"
            "$env:windir\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\VisualAssistExe.dll"
        )

        Write-Status -msg 'Removing App Actions Files...'
        foreach ($path in $paths) {
            if (Test-Path $path) {
                if ((Get-Item $path).PSIsContainer) {
                    takeown /f "$path" /r /d Y *>$null
                    icacls "$path" /grant *S-1-5-32-544:F /t *>$null
                    Remove-Item "$path" -Force -Recurse -ErrorAction SilentlyContinue
                }
                else {
                    takeown /f "$path" *>$null
                    icacls "$path" /grant *S-1-5-32-544:F /t *>$null
                    Remove-Item "$path" -Force -ErrorAction SilentlyContinue
                }
            }
        }
        

        Write-Status -msg 'Removing AI From Component Store (WinSxS)...'
        Write-Status -msg 'This could take a while on some systems, please be patient!' -warningOutput
        #additional dirs and reg keys
        $aiKeyWords = @(
            'AIX',
            'Copilot',
            'Recall',
            'CoreAI',
            'aimgr'
        )
        $regLocations = @(
            'registry::HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage',
            'registry::HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages',
            'registry::HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData',
            'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData',
            'registry::HKCR\PackagedCom\Package',
            'HKCU:\Software\Classes\PackagedCom\Package',
            'HKCU:\Software\RegisteredApplications',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners'
        )
        $dirs = @(
            'C:\Windows\WinSxS',
            'C:\Windows\System32\CatRoot'
        )
        
        New-Item "$($tempDir)PathsToDelete.txt" -ItemType File -Force | Out-Null
        foreach ($keyword in $aiKeyWords) {
            foreach ($location in $regLocations) {
                Get-ChildItem $location -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "*$keyword*" } | ForEach-Object {
                    try {
                        Remove-Item $_.PSPath -Recurse -Force -ErrorAction Stop
                    }
                    catch {
                        #ignore when path is null
                    }
                    
                }
            }

        }

        $jobs = foreach ($dir in $dirs) {
            $rs = [powershell]::Create().AddScript({
                    param($dir, $aiKeyWords)
                    (Get-ChildItem $dir -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { 
                        $_.FullName -like "*$($aiKeyWords[0])*" -or 
                        $_.FullName -like "*$($aiKeyWords[1])*" -or 
                        $_.FullName -like "*$($aiKeyWords[2])*" -or
                        $_.FullName -like "*$($aiKeyWords[3])*" -or
                        $_.FullName -like "*$($aiKeyWords[4])*"
                    }).FullName
                }).AddParameter('dir', $dir).AddParameter('aiKeyWords', $aiKeyWords)
    
            [pscustomobject]@{
                Runspace = $rs
                Handle   = $rs.BeginInvoke()
            }
        }

        $pathsToDelete = foreach ($job in $jobs) {
            $job.Runspace.EndInvoke($job.Handle)
            $job.Runspace.Dispose()
        }

        Set-Content "$($tempDir)PathsToDelete.txt" -Value $pathsToDelete -Force | Out-Null

        $command = "Get-Content `"$($tempDir)PathsToDelete.txt`"  | ForEach-Object { Remove-Item `$_ -Force -Recurse -EA 0 }"
        Run-Trusted -command $command -psversion $psversion
        Start-Sleep 1
    }

}


function Hide-AI-Components {
    #hide ai components in immersive settings
    Write-Status -msg "$(@('Hiding','Unhiding')[$revert]) Ai Components in Settings..."

    $existingSettings = try { Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'SettingsPageVisibility' -ErrorAction SilentlyContinue }catch {}
    #early return if the user has already customized this with showonly rather than hide, in this event ill assume the user has knowledge of this key and aicomponents is likely not shown anyway
    if ($existingSettings -like '*showonly*') {
        Write-Status 'SettingsPageVisibility contains "showonly"...Skipping!' -errorOutput
        return 
    }
    
    if ($revert) {
        #if the key is not just hide ai components then just remove it and retain the rest
        if ($existingSettings -ne 'hide:aicomponents;appactions;') {
            #in the event that this is just aicomponents but multiple times newkey will just be hide: which is valid
            $newKey = $existingSettings -replace 'aicomponents;appactions;', ''
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d $newKey /f >$null
        }
        else {
            Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /f >$null
        }
    }
    else {
        if ($existingSettings -and $existingSettings -notlike '*aicomponents;*') {
           
            if (!($existingSettings.endswith(';'))) {
                #doesnt have trailing ; so need to add it 
                $newval = $existingSettings + ';aicomponents;appactions;'
            }
            else {
                $newval = $existingSettings + 'aicomponents;appactions;'
            }
            
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d $newval /f >$null
        }
        elseif ($existingSettings -eq $null) {
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d 'hide:aicomponents;appactions;' /f >$null
        }
       
    }
}

function Disable-Notepad-Rewrite {
    #disable rewrite for notepad
    Write-Status -msg "$(@('Disabling','Enabling')[$revert]) Rewrite Ai Feature for Notepad..."
    <#
    #load notepad settings
    reg load HKU\TEMP "$env:LOCALAPPDATA\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\Settings\settings.dat" >$null
    #>
    #above is old method before this policy to disable ai in notepad, [DEPRECIATED]
    Reg.exe add 'HKLM\SOFTWARE\Policies\WindowsNotepad' /v 'DisableAIFeatures' /t REG_DWORD /d @('1', '0')[$revert] /f *>$null
}



function Remove-WindowsAI-Tasks {
    if (!$revert) {
        #remove recall tasks
        Write-Status -msg 'Removing Windows AI Scheduled Tasks...'
        #believe it or not to disable and remove these you need system priv
        #create another sub script for removal
        $code = @"
Get-ScheduledTask -TaskPath '*WindowsAI*' -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
Remove-Item "`$env:Systemroot\System32\Tasks\Microsoft\Windows\WindowsAI" -Recurse -Force -ErrorAction SilentlyContinue
`$initConfigID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration" -Name 'Id'
`$policyConfigID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration" -Name 'Id'
if(`$initConfigID -and `$policyConfigID){
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$initConfigID" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$policyConfigID" -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI" -Force -Recurse -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName "*Office Actions Server*" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Remove-Item "`$env:Systemroot\System32\Tasks\Microsoft\Office\Office Actions Server" -ErrorAction SilentlyContinue -Force
    `$officeConfigID = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Office\Office Actions Server' -Name 'Id'
    if (`$officeConfigID) {
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$officeConfigID" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Office\Office Actions Server' -Recurse -Force -ErrorAction SilentlyContinue
"@
        
        $subScript = "$($tempDir)RemoveRecallTasks.ps1"
        New-Item "$subScript" -Force | Out-Null
        Set-Content "$subScript" -Value $code -Force

        $command = "&`"$subScript`""
        Run-Trusted -command $command -psversion $psversion
        Start-Sleep 1
        
        #when just running this option alone the tasks will be remade so we need to at least ensure they are disabled
        $command = "
        Get-ScheduledTask -TaskName '*Office Actions Server*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:`$false -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskPath '*WindowsAI*' | Unregister-ScheduledTask -Confirm:`$false -ErrorAction SilentlyContinue
        "
        
        Run-Trusted -command $command -psversion $psversion
        #disable windows ai event viewer logs
        wevtutil sl Microsoft-Windows-AI-ModelContextProtocol/Admin /e:false *>$null
        wevtutil sl Microsoft-Windows-AI-Platform/Admin /e:false *>$null
        wevtutil sl Microsoft-Windows-AI-ModelContextProtocol/Operational /e:false *>$null
        wevtutil sl Microsoft-Windows-AI-Platform/Operational /e:false *>$null
    }
    
}



function Update-Cleanup-Check {
    
    if (!$revert) {
        #fastest method to get majorbuild.updateBuildRevision ex. 26200.7922
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        $OSBuild = "$($key.GetValue('CurrentBuild')).$($key.GetValue('UBR'))"
        $key.Close()
        #attempt to get cached build incase user has already cached one before but is no longer accurate somehow
        try {
            $key2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\RemoveWindowsAI')
            $CurrentCachedBuild = "$($key2.GetValue('CachedBuild'))"
            $key2.Close()
        }
        catch {
            $CurrentCachedBuild = $null
        }

        #cache current build before making update script in regitry if the script detects and update as happened the cachedbuild value will be updated
        $regValName = 'CachedBuild'
        if ($CurrentCachedBuild -ne $OSBuild) {
            Write-Status -msg 'Caching Current OS Build in Registry...' 
            Reg.exe add 'HKLM\SOFTWARE\RemoveWindowsAI' /v $regValName /d "$OSBuild" /t REG_SZ /f >$null
        }

        #grab update cleanup script from github instead of embedding it in here
        try {
            Write-Status -msg 'Attempting to get Update Cleanup script from Github...'
            $scriptContent = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/refs/heads/main/RemoveAI-UpdateCleanup.ps1' -UseBasicParsing -ErrorAction Stop | Select-Object Content
        }
        catch {
            Write-Status -msg 'Unable to get Update Cleanup script from Github!' -errorOutput
            return
        }

        #create script
        $scriptPath = "$env:ProgramData\RemoveAI-UpdateCleanup.ps1"
        Set-Content -Path $scriptPath -Value $scriptContent.Content -Force

        #use conhost --headless to prevent powershell window flash
        Write-Status -msg 'Creating Update Cleanup Scheduled Task...'
        $action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless powershell.exe -ep bypass -f `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18'
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries 
        #create update cleanup checker task
        Register-ScheduledTask -TaskPath '\' -TaskName 'RemoveAI-UpdateCleanupChecker' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        
    }
    else {
        Write-Status -msg 'Removing Update Cleanup Script and Task...'
        Unregister-ScheduledTask -TaskName 'RemoveAI-UpdateCleanupChecker' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item "$env:ProgramData\RemoveAI-UpdateCleanup-Silent.vbs" -ErrorAction SilentlyContinue -Force
        Remove-Item "$env:ProgramData\RemoveAI-UpdateCleanup.ps1" -ErrorAction SilentlyContinue -Force
    }

    
}

function Create-ScriptShortcut {
    param(
        [switch]$Desktop,
        [switch]$Start
    )

    #get powershell 5.1 binary path
    $psPath = "$env:SystemRoot\system32\WindowsPowerShell\v1.0\powershell.exe"
    #removeai icon in base64
    $removeAiIconBase64 = 'AAABAAEAgIAAAAEAIAAoCAEAFgAAACgAAACAAAAAAAEAAAEAIAAAAAAAAAABACUWAAAlFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//zgnyv/Chkf/6qIi/+ihJf/ooyb/6aQl/+mlJv/ppif/6qco/+upKf/rqir/7Ksr/+2rK//trCz/7q4u/+6vL//vsDD/8LEx/++xMf/vsjL/8LMz//G0NP/xtTX/8bc2//K4N//yujf/87s4//S8Of/1vTr/9r47//e/PP/3vzz/9cE9//jBQP/7wkH/+sNA+vTFRvHuxVbm8sZbrv7LUXDNr4dWDg35mAAA//kAAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP/oAAD/WgAA/wEAAP8AAAD/AAAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/AAAA/wAAAP8AAAD/AAAA/xwAAP+vAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//0ozuP/RkDr/6aIj/+iiJf/ooyT/6KQl/+ilJv/qpyj/66gp/+uqKv/rqir/7Ksr/+2sLP/urS3/7a4u/+6vL//vsDD/77Ex/++xMf/vsjL/8LMz//G0NP/xtjX/8bc2//K5N//yujf/87s4//S8Of/1vTr/9r47//e/O//6wTj/+cE9//jBQv/3wkH/+MU+//vFP//7xUL/7sJM/HplqPUGBvv8AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD/8QAA/28AAP8FAAD/AAAA/wAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/AAAA/wAAAP8AAAD/AAAA/yoAAP/BAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AwL8/2FDpP/ZljL/6aIj/+ijJP/opCX/6KUm/+mmJ//qpyj/66kp/+uqKv/sqyv/7Ksr/+2sLP/urS3/7q4u/++vL//vsDD/77Ex/++yMv/wszP/8bQ0//G1Nf/xtzb/8rg2//K5N//zuzj/9Lw5//W9Ov/2vjv/9r47//e+PP/3vz//98FB//XDP//1xD7/9MVB//LERf+afoj/ExDw/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//oAAP+IAAD/CgAA/wAAAP8AAAD/AAAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVFzjAIFssgBjX+AAcEiMADEo4koUDu7pAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//CAb3/3VQkf/hnCv/6KMi/+ijJP/ppSb/6KUm/+mmJ//rqCn/66kq/+yrK//sqyv/7aws/+6tLf/uri7/768v/++wMP/wsTH/77Iy/++yMv/wszP/8LQ0//C2Nf/xtzX/8rg2//O6N//zuzj/9Lw5//W9Ov/1vjv/8sA7//PAPf/4wD//+sE///rDPv/4xT7/r412/yAa5v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA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//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//OCbL/8OIR//qpCL/6aQl/+qlJv/qpif/6qco/+uoKf/rqir/7Ksr/+2sLP/trCz/7q0t/++uLv/vry//77Aw//CxMf/wsjL/8LMz//G0NP/xtTX/8bc2//K4N//zuTj/87o4//S8Of/1vTr/9785/+u2Rf9uVaj/BQT7/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xYT7/+kiIv/9tFR/fbSVtL102dt9NeFEOvESAD26asA9OKYAP3nowD//94AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6c+WAAAAAADUghQA15k+JtKGHsXXgAv/24II/9mDC//ahAz/24UN/9yGDv/eiAz/xHko/0cssv8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//SzW4/8+RO//qpSL/6aQl/+mlJv/ppif/6qco/+upKf/sqiv/7Ksr/+2sLP/urS3/764u/+6vL//vsDD/8LEx//CxMf/vsjL/8LMz//G0NP/wtjX/8bc2//K4N//zujf/87s4//W9OP/wuT7/h2iU/wsI9/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8LCff/jXSc//rPTf/91En/+9NM//vRUPD50lyQ89l3HfOfAAD15K0A9d+iAPnvzgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/zugDrxoAA3qhbAOC1eAvQiCaV1X8M/teACP/ZgQj/2IIK/9mDC//ahAz/3IYO/9yGDv/eiAz/uXI1/zQgx/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8DAvz/X0Ol/9mYMf/qpSP/6aUm/+ilJv/qpyj/66gp/+uqKv/sqyv/7Ksr/+2sLP/urS3/764u/+6vL//vsDD/8LEx//CyMv/wsjL/8LMz//G1NP/wtjX/8bc2//K4N//zujf/8rs6/5x4gf8VEO7/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//BgX7/3Rgrf/zyFT//9JM//7STP/+0Uz//9FO//3STfn11Fmy8Nd8K/LGAADy5MYA8+i+AP/fjwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtGIkAPzhlwCRDgAA0ZI6UdSAD+zUfgj/1X8J/9aACf/Yggn/2YML/9qEDP/bhQ3/3IYO/9yGDv/diQ3/p2hI/yMW2f8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8HBfj/dlOO/+OfKv/ppST/6KUm/+mmJ//qpyj/6qkp/+uqKv/sqyv/7Ksr/+2sLP/urS3/7q8v/++wMP/vsDD/8LEx/++yMv/wszP/8bQ0//C2Nf/xtzb/8rg2//W7Nv+yiW3/IBnl/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//9aS8D/6sFb///US//90k7//NJN//7TTP/90k7//tNK//zSTv7201+1+d93I/fTUgD///8A///LAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPLhzADjr28A3KNSAOCxaxLThh+y1XwH/9d+Bv/Xfwj/14EI/9iCCP/Ygwr/2YML/9qEDP/bhQ3/3IYO/9yIDv/biA//k1tf/xYO5/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8SDO7/kGV3/+aiJv/opSX/6aYn/+qnKP/qqCn/66oq/+yrK//sqyv/7Ksr/+6tLf/uri7/7q8v/++wMP/vsTH/77Ex/++yMv/wszP/8bU0//C2Nf/0uTT/x5db/zUp0/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//PzTS/9mzZv//1Ur//9NM//3TS//91En/+tVK//vUTP//00v//tJM//3TTfz31FyT79qND+7SbgDgsh0A//CxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA68mgAP//xwCyVAAA1pY9TNF9D+3UewX/1XwG/9l+Bf/XgAf/2III/9iCCf/Yggr/2oQM/9uFDf/bhQ3/24cO/9yIDf/ZhxL/fk52/wsH8/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8dFOT/pHRk/+ikJP/opSb/6aYn/+qnKP/qqSn/66oq/+yrK//sqyv/7aws/+6tLf/tri7/7q8v/++wMP/usTH/77Iy//CzM//wtDT/8rcz/9OgTv9IN8P/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//y4m3v/Go3L//9NK///SS///00z//9FN//7SS//81Ur//dNO///STf/+00r//dNM//nRVPHw1mpj9v/xAvTqlwD/9KEA9eyzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+6MgA6KZRAP/21ALZhx+O1XoH/9V7Bf/WfAb/2H0G/9h/Bv/XgAj/2IEJ/9iCCv/agwv/2oQM/9uFDf/bhg3/24cO/9yJDf/Tgxn/aUKO/wYE+P8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8rHtb/t4FS/+mmJP/opSb/6aYn/+qoKf/rqSv/7Kos/+yrKv/trCr/7a0s/++tLv/vri//8LEt/++xL//wsTH/8LIy//K1Mv/gqEL/XEax/wEB/v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8eGOr/tJJ////RSf//0kr//9JL///TTP//0k3//9JN///TTP//003//9JM///SS//+0kz/+9NM//nTVcf31ngm9ctfAP//2gDw6rEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALyCRADJj0YAyJtgFc5+GL/WeQP/13oD/9V7Bf/WfQX/134G/9Z/CP/XgAj/2IEJ/9mCCv/Zgwv/24UN/9uFDf/bhg7/24cO/92KDv/MgCH/Vzah/wIB/f8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//88K8b/xYtG/+qmJP/ppif/6qco/+uoKf/qqiv/66sr/+2qLv/sqy7/66wu/+utMP/srjH/768x//CxMf/xszH/56w7/3RXnf8HBfr/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//Eg7y/5t9kf/9zUv//9BK//7RSv//0kv//9JL///TTP//00z//9NM///TTP//0kv//9JL///SS//+00r//NFR9/bSY3fv8bcD9OCHAPbyvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////ALp2HADMlUg5ynoR59R4A//XewH/1nsD/9Z8Bf/VfQb/1n4H/9eACP/YgQn/2IIK/9mDC//ahAz/24UN/9uFDf/chg7/24gP/96KDf/Deiv/QCi6/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//9QOLT/1JU6/+ymJv/rpif/7Kgn/+mqJ//pqyn/76ku/++qLf/srC3/7a4s//CuLv/wrzD/8LEw/+yvNP+LZ4j/Dgvz/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//woI+P+DaqD/9cdO///OSf/+z0r//tBK//7RSv//0kv//9NM///TTP//00z//9NM///SS///0kv//9JL///SS//80U//+dRRxvHaeiLvzVUA////APrvtwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9v2oAyHMFAOCWNWDSewr40ngD/9Z6Af/WewL/1nwE/9R8B//XfQb/138H/9eACP/YgQn/2YIK/9mDC//ahAz/24UN/9yGDv/chw7/3IgO/96KDf+0cD3/MB7M/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wQD/P9oSZ//3pwy/+ynJv/rpyb/7Kkn/+qnLP/tqSj/7qoo/+qrK//urSv/76wv/++vMP/vsC//ondz/xgS6/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8DAv3/alWx/+7AUf/+zUf//c1J//7OSv/+z0r//tBK///RS///0kv//9NM///TTP//0kv//9JL///SS///00v//9JL//7STP/800/1+ddgZO+zFAD943kA1oEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOmWKQDSdgEA4IkYeNZ7Bf/SeAP/1XkC/9V6Av/WewP/1HsG/9Z8Bf/Xfgf/138H/9eACP/YgQn/2YML/9qDC//ahAz/3IYO/9yHDv/ciA7/3IkO/96LD/+lZ03/IhXa/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//woH9f98V4z/46Et/+mnJ//qqCv/6LVW/+7MgP/vzIP/4rhX/+qsMP/urC//7q8u/7SFYf8nHN3/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//1BAw//htVn//cxF//zMSP/9zUn//c1J//7OSv//z0v//9BL///RS///0kv//9JL///SS///0kv//9JL///SS//+0kz//tJN//3SS//81VSc9+CVCPnadQD24Z0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA030JANd4AQDUewZ+1nkB/9R4Av/SeAP/1HkC/9d6A//VegX/1nwF/9d9Bv/Wfwf/14AI/9iBCf/Zggr/2YML/9qEDP/bhQ3/3IYN/9yHDf/diA7/3YkP/92KEP+TXGH/FA3p/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xIN7/+PZnr/5KMr/+i8Yv/y68r/9Pfy//b19P/z687/6sBm/+uvK//CkFH/NijQ/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8+MdH/0adi//zKQ//6ykb/+8tH//zMSP/9zUn//s5K//7OSv//z0v//9FL///SS///00z//9NM///SS///0kv//9JL//3TTP/90k7//9NK//rRWMv014Ui881qAP///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADKdwcA1ngCAM93BX7VeAL/1XgC/9F3BP/UeAL/13kC/9Z6A//VewT/1nwF/9Z+Bv/Wfwf/14AI/9iBCf/Zggr/2YML/9uFDf/bhg3/3IcN/9yIDv/diQ//3YoP/9qJFP9+UHj/DQjx/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xwU5P+kenD/996t//f4+P/49/X/9ff2//H2+//24a3/z51P/0g1vf8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//KyLe/8KabP/7yEL/+chE//rJRf/6ykb/+8tH//zMSP/+zkr//s5K///PS///0Ev//9JL///SS///00z//9JL///SS///0kv//NNL//7STf/+0U3/+9FU7vjZc0X1zFcA//+8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN6EFgDSeAMA2n8PftF6BP/TeQH/0XkB/9Z3A//XeAL/1HoD/9Z7BP/WfAX/130G/9h+B//Yfwj/2IEJ/9iCCv/Zgwv/2oQM/9uFDf/bhg3/24cO/9uID//ciRD/3osP/9WGGv9rQ4z/BgT4/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//ysl5f/Bven/+fj3//n29f/19/T/8/f7/+Xe3/9cTcT/AgH7/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xwW6v+rh3z/+cVB//rGQv/6x0P/+shF//rKRv/8y0f//MxI//3NSf/9zUn//s5K///QSv//0Ur//9JL///TTP//00z//9JL///SS//+00z//tJN//7RTv/+0lD3/ttbX/zQTgD/6WsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7qUzAM11AADfkB5203wG/9N4Af/SeQH/1XcD/9Z4Av/VeQP/1noD/9Z7BP/WfAX/130G/9d+B//XgAj/2IEJ/9mCCv/Zgwv/2oQM/9uFDf/bhg7/2ocO/9uID//ciRD/34sP/8+CIf9WN6P/AQH+/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//z4//f/R0fj/+vj3//b49f/s7vX/eHf6/wgI/v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8SDvH/lnWM//XBQ//5xUH/+cVC//rGQ//6x0T/+slF//vKRv/8y0f//MxI//3NSf/+zkr//89J///QSf//0Ur//9JL///TTP//00z//9JL///TTP//0kz//tJN//7ST/r91lFn/tFOAPzaVQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD82WEAyncCAOKoMmbWfgn51ncA/9R4Af/TeAP/03gC/9V5Av/WegP/1nsE/9V7BP/WfAX/134G/9d/CP/XgAj/2IEJ/9mCCv/Zgwv/2oQM/9uGDf/ahw7/24gP/9yJEP/dihD/34wP/8N8Lv9DKrj/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//1RT/f/g3/j/9PX3/5GR9v8ODv//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//CAb5/4Bkm//xvUT/+cM///jDQf/5xUL/+cVC//nHQ//5yET/+slF//vKRv/8y0f//MxI//7OSv/+zkn//9BJ//7RSv/+0Ur//9JL///SS///00z//9NL///TS//+00z//tJN+vvSTGn+004A99JLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/2fADWkRoA6MFJXdmIEvbVdwH/1ngB/9J4A//ReQH/1XgB/9V5Av/WegP/1XsE/9Z8Bf/XfQb/134H/9eACP/YgQn/2YIK/9mDC//ahAz/24UN/9uGDv/bhw7/24gP/9yJD//dihD/340P/7Z0PP8yIMr/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//BAT//2tr/P+Zm/v/Gxv9/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wMC/f9lT6//6LVJ//nDPf/4wj//+MNA//jEQf/5xUL/+cZD//nHRP/6yUX/+8pG//zLR//8zEj//c1J//7OSv/+z0r//tBK//7RSv//0kv//9NM///TTP//00v//9NL//7TS//+00z6+9NLaf/TTAD300sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7u1yAPHDSQDz22Fa3Z8m9tJ3AP/WeAH/03gD/9F5Af/VeAH/1XkC/9Z6A//WewT/1XsE/9Z8Bf/XfQb/138H/9eACP/YgQn/2YIK/9mDC//ahAz/24UN/9yGDv/chw7/3IkP/92KEP/dixD/340Q/6RpT/8dE+D/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//CAj//xER//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//TDvD/9uqUf/4wTv/98E+//jCP//4w0D/+MNA//jEQf/5xUL/+sZD//nIRP/6yUX/+8pG//zLR//8zEj//s5K//7OSv/90Ev//tFL///SS///0kv//9JL///TS///0kv//tNK///SS/v900xq/9JLAPrVTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADn6m4A/uBlAPfpblrpv0T20n4G/9V4Af/WdwP/03gB/9V4Af/UeAH/1XkC/9V6A//VegP/1XsE/9d9Bv/Wfgb/1n8H/9iBCf/Yggr/2YML/9qEDP/bhQ3/3IYO/9yGDv/biA7/3IkP/92KEP/djBD/24wT/4xZaf8TDOv/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//zMo1v/Jm17/+MA5//W/PP/2wD3/+MI///jCP//3w0D/+MRB//nFQv/5xkL/+cdD//rJRf/7ykb/+8pG//zMSP/9zUn//c5K//3PSv/90Ev//tFK///SS///0kv//9JM//7TTf/+00z//9NM+/3TTGr/0ksA/NRMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOTocAD96GwA9OpwWfbbXvXdkhn/03cA/9d3A//TeAH/1XgB/9V4Af/VeAH/1XkC/9N6A//UewT/13wF/9Z9Bv/Wfgf/14AI/9iBCf/Yggr/2YML/9qEDP/bhQ3/24YO/9uHDv/biA//3IkP/92KEP/ejBD/2YoX/3lNff8KBvX/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8kG+L/tItt//a+Of/2vjv/9b47//bAPf/3wT7/98I///fDQP/4xEH/+cRB//nFQv/5xkP/+chE//rJRf/7ykb/+8tH//zMSP/9zUn//c9K//3QS//+0Ev//tFL///SS///0kz//tNN//7UTP//00z7/dNMav/SSwD71EwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5+puAPbnbQDw6W5Z+OZs9eq3P//QfAb/03cD/9N5Av/VeQH/1XgA/9Z3Af/UeAL/0nkD/9N7A//XewT/13wF/9d9Bv/Yfgf/14AI/9iCCv/Zgwv/2oQM/9uFDf/bhQ3/24YO/9uHD//ciRD/3YoQ/96LEf/fjBD/04cd/2M/lv8EA/v/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//FxHs/6B6fP/zuzn/9b05//a+O//1vjv/9b88//bAPf/3wT7/+MI///nDQP/5xEH/+MRB//nFQv/6xkP/+chE//rJRf/7ykb//MxI//3NSf/+zkr//s9L//7PS//+0Uv//9JN///STP/+003//tNM///TS/v900tq/9NMAPrTSwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD26G8A++ZuAPnnb1v65272+Nxh/9yZIf/RdwP/1HkC/9N5Af/QegD/03gB/9Z4Af/WeAP/1XoD/9R7BP/VfAT/13wF/9d+B//XgAj/2IEJ/9mCCv/agwv/2oQM/9uFDf/chg7/24cO/9uID//ciQ//3YoQ/96LEf/gjRD/y4In/1E0qf8BAf7/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wwJ9f+JaI7/8Lc6//S8OP/0vDn/9b06//a+O//2vjv/9sA9//fBPv/3wT7/+cI///jDQP/4xEH/+cVC//rGQ//5x0T/+slF//vKRv/7y0f//MxI//3NSf/+zkr//s9K//3QS//+0Uz//9JM//3STP/+00z//9JL+/3TS2r/00wA+tNLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP7ocgD75m4A/OdwW/jnbvb66G3/8MtQ/9SGEP/TdwD/1HgB/9F5AP/SeQH/1XgB/9h3Av/YeAP/03oE/9R7BP/WfAX/130G/9d/B//XgAj/2IEJ/9mCCv/Zgwv/2oQM/9uFDf/chg7/24cO/9yID//ciQ//3YoQ/96MEf/gjhD/wXsy/z4ovf8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8GBfr/cVWg/+ewP//zuTX/87o3//O7OP/1vTr/9b06//a+O//2vzz/9sA9//fBPv/4wj//+MNA//fDQP/4xEH/+cVC//nGQ//5yET/+slF//vKRv/8y0f//MxI//3NSf/+zkr//c9L//7RTP/+0kv//dJM//7TS///00v7/dNLav/TTAD600sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9OtyAProcAD36XFZ+uhv9fjobv/35mn/6rpB/9F/CP/WdwH/13gB/9N4Af/TdwH/1XcB/9d3Av/VeQT/1XoE/9Z8Bf/XfQb/134H/9eACP/YgQn/2YIK/9mDC//ahAz/24UN/9yGDv/chg7/3IgO/9yJD//dihD/3osR/96MEv/gjxD/snJC/ysc0f8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AgH+/1xEsv/ep0T/87g0//K4N//zuTf/87s4//S8Of/1vTr/9b06//a+O//2vzz/9sA9//fBPv/4wj//+MNA//jEQf/4xEH/+cVC//nHQ//6yUX/+8pG//vLR//8zEj//c1J//7OSv/9z0r//dBL//7RS//90kz//tNL///TTPv900tq/9NMAPrTSwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD66nIA++hwAPrpcVr66HD2+Ohv//fobf/54Wf/5bE4/9N+CP/TdwL/1HgC/9R4Av/SeAH/03gB/9d4A//WegT/1XsE/9Z8Bf/XfQb/134H/9eACP/YgQn/2IIK/9mDC//ahAz/24UN/9yGDv/dhw7/3YgO/9yJD//dihD/3osR/96NEv/fjxL/omhU/yAU3v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//9EM8X/055M//O2Mv/xtjX/8bc2//K4N//zuTf/9Ls4//S8Of/1vTr/9r47//e/PP/3vzz/98E+//jCP//4w0D/+MNA//jEQf/5xUL/+cZD//nIRP/6yUX/+8pG//zLR//8zEj//c1J//7OSv/+z0r//tBK//3RTP/900v//9NL+/3T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//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//DA3//4eI+//y7/X/9/Lp//Ls1P/24K3/5btm/+eoLf/uryv/8bQy//G1Of/2tzj/8rk4//O6Of/0uzr/9bw6//W+O//1vjv/9L88//TAPf/0wj7/9MM///XEQP/3xEH/+cVC//jGQv/4x0P/+chE//rJRf/7ykb/+8tH//3NSf/9zUn//s1K//7PSv/+0Ev7/NJLav7RSgD71EsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA++11APrsdAD77XVY+u1z9frscv/66nD/+uhv//fobf/45mz/9uVr//bjaf/24mf/+eFm//neZP/z1Fr/7sJJ/+evN//dmyT/3IsV/9iBC//UfQf/0X0G/9N/Bv/Yfwf/24AI/9uCCf/ahAr/1oYL/9aHDP/dhg3/2YkH/9ibPv/05Mv/9vf5//b3+f/y9/b/9Pb1//n49v/X1ff/Q0P9/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wYG//90c/v/7ezz//j68f/1+PX/8vX7//P2+v/y4sz/2qFB/92REv/jlxv/558l/++oK//wsDL/9LY3//e6Ov/3vDv/9r07//a+O//2vzz/9r88//fBPf/3wj//98I///jDQP/6xEH/+cVC//nGQ//5yET/+slF//vKRv/7y0f//MxI//3NSf/9zUr//c9J//7QSvv80kpq/tBKAPrTSwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD87nYA+u10APvtdVj57XT1+uxy//vrcf/66XD/9+hu//nnbf/35mv/9uRq//XiaP/34Gj/999n//beZv/43mT/99ti//HXXP/wzVL/7b9F/+WtNP/gmiT/24wV/9WFDf/Tggn/1YEJ/9mBCf/dgwv/34MM/92FDP/Uhwn/5bd0//n09v/59fn/9vb4//T39f/29vX/9ff1//b59f/Dxvf/LS79/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8CAv//W1r8/+Pj9//39/f/9fb3//b29f/29/T/9vb1//j18//ju3L/14kO/9qHD//XiBD/14oQ/9qOE//glhr/56Ej/+6rLP/0tDT/+Lo5//m+PP/4vz7/+cA+//nBPv/4wj//98NA//jEQP/4xEH/+cVC//nHQ//5yET/+slF//vKRv/7y0f//MxJ//3NSf/9zkn//s9K+/vRSWr+0EkA+dJKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP3vdwD77nUA/O52WPrudPX77XP//Oxx//rpcP/46W7/+udt//zmbP/95Gr/+uNp//bhaP/14Gf/9d5m//bdZP/03GL/8tth//LbYP/02l7/9dZb//XRV//zyE7/6rtB/+OqMf/gmiL/3I4X/9iHEP/XhA3/3IIN/9qECv/ot3D/+PXx//n29v/29fj/9/b1//f29v/39vb/+vn1/8rJ9v8vL/3/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wUF//+Af/r/9PP2//f29//39fj/+fX3//r29f/39vX/9/bz/+m5df/biBH/3IkQ/9qID//ahg7/2YUM/9eEC//VhQr/1IYL/9eMEP/flRn/5qEj/+ysLf/0tjb/+L08//jBP//3w0D/9cRA//bEQf/5xUL/+cZD//nHRP/6yUX/+8pG//vLR//8zEj//MxJ//3OSf/+z0n7+tBJav3PSQD40UkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/e93APzvdgD973dY++919fvtc//87HL/++px//nqb//76G7/+uds//rla//55Gr/+uJp//fhZ//y4Gb/899l//bdY//122L/9dph//XYX//01l7/9NVd//XUXP/z1Fr/8tJX//HNUv/vxEn/6rc+/+SoMP/dnCL/248X/9qfP//y5cX/+Pf2//T2+f/29vf/9Pb3//b4+P/Y2Pr/SEf9/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xgZ/v+jpfn/9fb3//X29//39vf/+Pf3//f49//y6Mj/3p1E/92IFv/ciRP/2YgS/9mID//Zhw7/14UM/9eEC//Wggn/1n8I/9V+Bv/Ufgb/04EH/9iIDf/ekxb/5qEj/++wMP/3vDv/+MNA//jFQf/5xUL/+MdD//nIRP/6yUX/+8pG//vLR//8zEn//c5I//3PSfv60Elq/c9IAPjRSQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+8HgA/e93AP3wd1j873b1++50//ztc//763L/+epw//jpb//26G3/9+Zs//jla//342n/+OJo//ngZv/432X/991k//XcYv/02mH/9Nlg//PXX//x1l7/8tRc//LTWv/y0ln/8tFY//LQV//xz1X/8M1T/+/ITv/xvkX/6LQ+/+TFb//05bf/9PDW//bz6P/7+PP/5eX0/19g+/8CAv//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//ycn/f+5uvf/+Pjy//Xz6f/w69L/8dao/9uqWv/YjRr/2Y4R/9WN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bf/55Wv/+ONp//jhZ//34Gb/9t9l//XeZP/03GL/9Nth//TZYP/02F//89Zd//LVXP/y01r/8tJZ//LQWP/xz1f/8M1W/+7MVP/szFH/7MtO/+/LS/+ylnj/JR/j/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//BwX4/2tIkP/VjyH/3pQX/92RGP/djhj/3I0W/9qMFP/ZixL/2okQ/9mID//Yhw7/2YYN/9iFDP/Xgwr/14EJ/9Z/B//Vfgb/1XwF/9R6A//UeQL/1HgB/9Z3Av/UeAL/0XgC/9V3Af/XdwD/1oIJ/+yrLv/7xkX/+MlG//rKRv/7y0f7/MtHbP3MSAD8y0cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//R7AP70ewD/9HtX/PR59fzyd//88Xb//O91//nuc//77HL/+utx//npcP/5527/+eZt//nlbP/45Gr/+OJo//jhZ//232X/9t5k//XdY//022L/89pg//XYX//0117/89Vc//PUW//y0lr/8tFY//LPV//yzlX/8c1U//DMU//yzE//x6Zu/zUs2P8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//DAjz/4BWev/bkRz/3ZIY/9yQF//cjhb/24wV/9qLE//ZihH/2YkQ/9mHDv/Zhg3/2IUM/9eEC//Xggn/14AI/9Z/B//VfQX/1XsE/9R5Av/UeAH/03gB/9J4Av/TeAH/1ngB/9d3Av/SdwH/1oQL//GxM//7x0X/+8pG//rLRvv8y0ds+8tHAPzLRwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+9HsA/vV7AP70e1f89Hr1/PN4//3xd//78Hb/+u90//ztc//77HL/+epw//nob//4527/+eZs//jlav/442n/9+Jo//fgZv/232X/9t5k//TcYv/z22H/9dlg//TXXv/z1l3/8tVc//LTWv/y0Vn/8tBY//LPVv/yzlX/885S/9S0Zf9KPsn/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//Fg/o/5RjZv/ckhn/3JEX/9yPFv/cjRb/24wV/9qLEv/ZiRD/2YgP/9iHDv/Zhg3/14QL/9iDCv/YgQn/14AI/9Z+Bv/WfAX/1XoD/9V5Av/TeQH/0nkB/9J5Af/TeAH/1HgC/9N4Av/SdwH/14wQ//W7Ov/9yUb/+ctG+/rLR2z5y0YA+stHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP71fAD+9XwA/vV8Vv31e/T883n//PJ4//zwd//773X//e10//vscv/663H/+elw//nnbv/55m3/+OVs//jkav/34mn/9+Fn//ffZv/23mX/9dxk//TbYv/12mH/9Nhf//PXXv/z1Vz/8tRb//LSWf/x0Vj/8NBW//HQVP/evmH/XVC8/wIC/f8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//Ihfc/6RtVP/dkhf/3JAX/9yOFv/bjBX/24sT/9mKEf/ZiRD/2YgP/9mGDf/YhQz/2IML/9iCCv/WgAj/1n8H/9V9Bf/VewT/1XkC/9V5Af/UeAH/0nkB/9J4Af/TeAH/1HgB/9R4Af/TeQH/45oe//vDQ//6ykb7+MtFbPnLRQD2zEUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//Z9AP72fAD/9n1W/fV79Pz0ev/883j//PF4//vwdv/97XT//O1z//vscv/56nD/+ehv//jnbv/45m3/+OVs//jjav/34Wn/999n//beZv/23WX/9dtj//XaYf/02WD/89de//PWXf/y1Vz/8dNa//HSWf/z0Vf/6chc/3Rkrf8GBfv/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//Lx/O/7V3Qv/fkhb/3I8X/9yNFf/bixT/2ooS/9mJEP/ZiA//2IcO/9mGDf/YhAz/2IIK/9aACP/Wfwf/1X4G/9V8Bf/UegP/1HkC/9R4Af/UeAH/1HgB/9R4Af/UeAH/1HgB/9d3Af/TgAf/7bAy//zIRfv2y0Ns+8lDAPPMRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/9n0A/vZ9AP/2fVb99nv0/fR7//3zef/98Xn//PF2//3udf/87nT/++1z//rrcf/66XD/+ehv//jnbv/45Wz/9+Rr//fiaf/34Wj/999n//bdZf/13GT/9dti//XaYf/z2F//89de//PWXf/y1Fv/8tNZ/+/OW/+MeZ7/Dgz1/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//Qiy6/8J/NP/fkRb/3I4W/9yMFf/bixP/2YoR/9mJEP/Zhw7/2YYN/9mFDP/Zgwv/14EJ/9eACP/Wfwf/1nwF/9V7BP/VeQL/1HgB/9R4Af/UeAH/1HgB/9R4Af/UeAH/1ngB/9B5Af/clBj/+sJA+/bLRGz+yEMA7s1DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/3fgD/930A//d+Vv72fPT99Xv//fR6//3yev/88Xf//e92//zvdf/77XP/++xy//rqcP/56G//+Odu//jmbf/45Wz/9+Nq//fhaf/34Gf/995m//bdZf/23GP/9dph//TZYP/02F//89Zd//LVW//y01r/ooyQ/xkV7v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8CAf3/VTin/8yFKv/ekBX/3I0W/9uMFP/aixL/2YkQ/9mID//Yhw7/2IYN/9iEDP/Ygwr/14EJ/9aACP/WfQb/1nwF/9V6A//VeQL/1HgB/9R4Af/UeAH/1HgB/9R4Af/UeAH/03cB/9SAB//zsjP7+MtFbP/EQgDvzUQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//mAAP/3fgD/+H9V//d99P72fP/99Xr//fN6//zyeP/98Hf//O91//vudP/67HL/+utx//npcP/46G7/+OZt//jlbP/35Gv/9+Jp//fhaP/332f/9t5l//XdY//122L/9Nph//TYX//0117/9Ndb/7iigv8lIOb/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AQH//wgI//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8FA/r/akWQ/9WLH//djxX/240U/9qMEv/ZihH/2YkQ/9iHDv/Yhg3/2IUM/9iDC//XgQn/14AI/9Z+B//VfQX/1XsE/9V5Av/UeAH/1HgB/9R4Af/UeAH/1HgB/9N4Af/VdwH/1HkC/+edIPv4xkJs+rc4APLLRQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/+oEA//h/AP/5gFX++H70/vZ8//32e//99Hv//fN4//7xeP/88Hb/++50//rtc//67HL/+epw//jpb//4527/+OZt//fka//342r/9+Jp//bfZ//23mb/9t5k//XcYv/12mH/9dlg//baXf/Otnb/PTbW/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//84OP3/h4r6/x0e/v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8PCvD/hVdz/9uOGv/cjhT/240T/9qLEv/ZiRD/2YgP/9mHDv/Zhg3/2IQL/9iCCv/XgQn/1n8H/9V+Bv/WfAX/1noD/9V5Av/UeAH/1HgB/9R4Af/UeAH/1HkB/9Z4Av/TdwD/3IwR/PK3Nm3mmhwA+ctIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/6ggD/+YAA//mBVP75f/T+933//vZ7//70fP/99Hn//vJ4//zwdv/873X/++50//vscv/663H/+epw//jobv/45m3/+OVs//jka//442r/9+Bo//beZv/23mX/9t1j//XbYf/321//3sRu/1JJyf8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//JSX+/7u3+P/y9fb/kJL4/w4O//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8ZEOX/mWNf/92PFf/bjhT/2owT/9mKEf/ZiRD/2YgP/9mHDv/YhQz/2IML/9iCCv/XgAj/1n8H/9d9Bv/XewT/1XkC/9R4Af/UeAH/1HgB/9R4Af/VeAH/1HcC/9J4Af/Uggf96aYncM5+AgD/xkYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9faTAP/5hAD8+IpL//mB8f75fv/+93z//fZ7//z2eP/+83j//PF3//zwdv/77nT/++1z//vscv/56nD/+ehv//nnbv/55m3/+OVs//jjav/34Wj/9uBm//bfZf/23mT/9t1h/+fPaf9rX7r/BAP9/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xcW//+jo/f/9/f1//f49v/w7Pj/e3r4/wgI/v8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8mGdf/q29L/92PE//bjBT/2ooT/9iIEf/Yhw//2YcO/9iFDP/YhAv/2IML/9eBCf/WgAj/1n4G/9V8BP/UegP/1HkC/9R4Af/UeAH/1HgB/9d4AP/ReAL/z3cE/9V9Bf/klBl5zncAAPSpLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD0/a4A/faKAPv3k0T+94fv/vh///73ff/993r//PV6//7ze//98nj//PB2//zvdf/77nT/++xy//rrcf/56XD/+ehv//nnbv/55Wz/+eRr//fiaf/24Wf/9uBm//ffZP/u12f/gHOs/woJ+P8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8NDPn/i4rz/+7x+P/y9/f/9vb2//f3+P/l4dz/XFDG/wMC+/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//82I8b/uHc8/92OE//aixT/2YkS/9iIEP/Yhw7/2YYN/9iFDP/Zgwv/2IIK/9aACP/Vfwf/1X0F/9R7BP/UeQL/1HgB/9R4Af/UeAH/1ngA/9F4Av/QeAP/1XoC/9+ECn7TeAAA5o0RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//6QD485EA+fadOvv2i+r/+YD///h+//34ev/99Hz//vJ9//7zef/88Xf//PB2//vudP/77XP/++xy//rqcP/56G//+edu//nmbf/45Wz/+ONq//fiaP/34Wb/9d5m/5eJn/8SEPT/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//BgX5/29cr//m3L7/9fn2//f29f/69Pj/9Pb5//Tjtf/PoVv/Sje//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//9GLrX/xX8u/9yNEv/aihP/2YkR/9mID//Zhw7/2YYN/9iEDP/Ygwr/14EJ/9aACP/Wfgb/1XwE/9R6A//UeQL/1HgB/9R4Af/TeQH/03gB/9N5Af/UeQH/23sBftd5AADdfQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////APLzlQDz86YX+PqFuf76gP//+X7//vd9//31ff/+9Hz//fR5//3yeP/88Xf//O91//vudP/77HL/++px//rpcP/56G//+eZt//jlbP/45Gr/+ONo//jiZv+wn5L/Hhvs/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wEB/v9ZR7n/2q5R/+vMdf/17tD/9/by//f19v/07NH/6cRv/+q0Nv/ClFj/NyrQ/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wIB/f9bO5//zoUj/9uMEv/aihL/2okQ/9mHDv/Yhg3/2IUM/9iEC//Xggr/14EJ/9Z/B//UfQX/1HsE/9R5Av/UeAH/1HgB/9F5Af/UeAH/1HoA/9J5Av/aewd+03cBAN5/DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD59cIA8fqZAN735gL2+4R5/fmB/f/6f//+94H//vd8//32ef/99Xr//fJ4//zxd//88Hb//O91//rtc//77HL/+upw//nob//5527/+eZt//jla//55Wj/wrGJ/y4q4/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//RTjJ/86mXf/vv0D/6rpG/+bDaP/v1I3/6tSN/+bCY//mtD//5rI7/+iyNv+xh2b/KB7c/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wgF9/9vR4n/04gc/9uLEf/ZiRD/2IgP/9iHDv/Zhg3/2IUM/9eDCv/XgQn/14AI/9V+Bv/VewT/1HoD/9R5Av/UeAH/0nkB/9V4Af/UeQD/0XoH/9iFHnbMdgQA4ZAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOLajADz/6oA+PGAAPT2kkv8+YLt//qA//74gv/+933//vd6//31ev/983n//PJ4//zxd//873X/++50//vtc//663H/+elw//nob//55m3/++hq/9LDgP8+Odn/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//zMq1//BnWn/8MFD/+u9RP/su0L/7bk//+i4Pv/kuD3/6Lg6/+W2O//ltDv/57M4/+exN/+fenT/GRPp/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//w4J8P+BU3X/2IoW/9qKEP/ZiA//2IcO/9mHDv/YhQz/14QL/9eCCv/XgAj/1n8H/9V9Bf/VewT/1HkC/9R4Af/TeAH/1HkB/9N4Af/Qegv22JQ7W8VzBwD0v3sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+/fCAP///wD69owA+vWhFf77gLT++oH//fmC///3gP//93z//vZ7//31ef/983j//PF3//zwdv/873T/++1z//vscv/56nD/+ehv//vpbf/j0nn/VlDM/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8iHOX/rZF4/+/CSP/wwET/6L1H/+e8Rv/qu0H/5blC/+u3QP/ttj//6LRA/+i1Ov/oszr/57I4/+OuOf+JaIf/Dwvy/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//xcP5v+XYVz/2osR/9mJEP/ZiA//2IcO/9mGDf/YhQz/2IMK/9iBCf/Wfwf/1n4G/9Z8Bf/VegP/1XkC/9Z4Af/TeQL/0ncE/9B7DenSmUY7wXgVAP///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//XOAP/4qAD/+P8B/PeOX/35g/D8+oL//viC//73fv/99nz//fZ4//z0eP/88nj//PF3//zwdP/87nP/++xy//rrcf/662//7Nx2/25mvv8FBfz/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//FhLv/5mAiv/rw0r/7cNJ/+zBR//pv0b/6L1F/+m8Q//oukL/6rhA/+q3P//ptj//6LU9/+i0O//nsjn/57E3/92pPf9zWJr/CAb4/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//yYY1v+oa0r/24oR/9qI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//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//9AN9L/z7Fq//DMUP/uyU//7sdN/+3GTP/uxUv/7cRK/+zBSP/swEf/7L9G/+u9RP/qvEP/6rpB/+m4QP/ptz//6bc9/+m2PP/otDr/57I5/+awN//mrzb/568z/6+EY/8jGuD/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//BwX3/29Ghf/Uhhb/2YgO/9mHDv/YhQz/2IQL/9eCCf/XgAj/1n8H/9V9Bf/VewT/z3wQ7MyOOlKGFwAA/deaAJ5rNwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//+cAPv52AD0+tEA/98AAPj0pCP69pCn+/iF+/v5ff/+93v//vR///3yfv/+9nb/3NSH/0pG1/8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//LSbg/72hev/xzlP/78tS/+7JT//uyE7/7sdN/+7FS//uxEr/7cJJ/+3BSP/sv0b/675F/+q8Q//qu0L/6rlB/+q3P//qtz7/6rc8/+i1O//nszr/57E4/+ewN//mrzX/5a00/5hyeP8XEev/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//EArt/4hWaf/YhxD/2ogO/9mGDf/YhQz/2IIK/9eBCf/XgAj/1X4G/9F8C/7HgymU1bOAC9SkYADnvoAA//XMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+v3YAPX6uAD3+sUA+fBeAP32qib79JeN+veE5f36ef/+93j///d5/+nigv9fXMv/AgL+/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//x4a6v+rk4j/8c9W//DNVf/vy1P/78pQ/+/JT//ux03/7sZM/+7FS//tw0r/7cFI/+3AR//sv0b/671E/+u8Q//qukL/6rhA/+q4P//qtz3/6bU8/+izOv/nsjn/57A3/+avNv/mrjT/4qo3/4Njif8NCvT/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//HBLh/5lgVf/Zhw//2YcO/9eFDf/Ygwv/2YII/9iACP/Vfwj/1oUWxtmXOSfXgxUArAAAAOjKlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8/9gA/P/AAPr3tAD8+sMA5dZIAPbztAv19JZZ+vaGv/35e/n07nz9d3S//wYF/P8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8SD/P/l4OX//DPWf/yz1b/8M1W//DMVP/wy1H/78lP/+/ITv/ux03/7sVL/+3ESv/swkn/7MFI/+vAR//rvkX/6r1E/+q7Qv/pukH/6Lg//+i3Pv/otj3/6LU7/+ezOf/msTj/5bA3/+WvNv/nrjP/3aY6/21Snf8GBPr/AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//JxjU/6pp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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAD/AAAA/wAAAP8AAAD/EQAA/5wAAP/+AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//Fxby+6mZlvf33GL999pg//PZYP/z2F//9NZd//PVW//z1Fn/8dJY//HRV//xz1b/8M5V/+7NU//tzFL/7cpQ/+/ITf/vx0z/7cVL/+3ESv/tw0n/7MFI/+u/Rv/qvkX/671E/+q7Qv/pukD/6bg//+m4Pv/ptj3/6LQ8/+eyOv/msTj/5rA3/+avNv/mrTT/5awz/+WrMf/hpzL/gWCI/wwJ9P8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP/gAAD/SwAA/wAAAP8AAAD/AAAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/wAAAP8AAAD/AAAA/woAAP+EAAD/+AAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA/+w0MuWA69p1XvLcdqXv2HLk8dln7fLZYPT0113/9NVd//TTXf/x0ln/8NNW//DQV//xzVb/785T/+7NU//wyVL/8chO/+/ITP/uxkz/7sVL/+3ESv/swkj/68BH/+m+Rf/rvUT/67xD/+m6Qf/puUD/6bc//+m2Pv/otDz/6LM6/+eyOf/msTj/5q82/+auNf/lrDP/5Ksy/+WpMf/aoTn/bVCb/wcF+f8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP/QAAD/NgAA/wAAAP8AAAD/AAAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAD/AAAA/wAAAP8EAAD/bQAA//AAAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP/1AAD/ewAA/wePgpcA4t+2EungmC/z3XVE8NlpWuzVcq3v1Gva8tNh6PDRXv7w0Vn/89FV//XPVf/x0FH/8c5P//TJVP/wyFL/7chN/+7HTf/uxUv/7cRK/+3DSf/swUj/6r9G/+u+Rf/svUT/6rtC/+q5Qf/quED/6bc//+i1Pf/otDv/6LM6/+axOP/msDf/5q82/+atNP/lrDP/5aoy/+eqLv/UnDz/WkKs/wIB/f8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP+9AAD/JwAA/wAAAP8AAAD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/wAAAP8AAAD/AAAA/1QAAP/nAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//AAA/5MAAP8OBwb8AP//WQDl3KAA59uOAPHadAD/1gAA5t+uEfHffyjx12Y+6NJ6jejTbMDt01vR8c5a7fLNVv/tz1D/6s1Q/+/JUv/wyE//7sdN/+3GTP/txUv/7cRK/+zCSP/rwEf/679G/+u+Rf/rvEP/6rpB/+m5QP/ptz//6LY+/+m1PP/oszr/57I5/+awN//mrzb/5a41/+StM//kqzL/5qgy/+ioL//JlUX/QzK//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP+qAAD/GQAA/wAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/AAAA/wAAAP85AAD/1wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP+rAAD/GgAA/wAAAP8AAAD/AP//7gD//qwAydDqAOLcugDo25wA8N19APLTTQDc6+kF7OqJFOfYaCHoz3Fi8M1g1vLMV//szVP/78tS//LIUf/vyE7/7cZM/+3FS//txEr/7MNJ/+zBSP/swEf/675F/+q9RP/qu0L/6bpB/+m4QP/otj7/6bY9/+i1O//nszn/5rE4/+awN//lrjX/5K01/+KqN//kqTP/5akw/+WqLP+5iVT/MiXR/wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//wAAP+PAAD/CAAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAD/AAAA/zQAAP/TAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD/xQAA/yoAAP8AAAD/AAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8B////AB////wP///////+Af///gAP///4B////////AB///AAB///8AP///////gAf//AAAP//+AB///////4AD//AAAD///AAP//////8AAf/gAAA///gAB//////+AAD/gAAAP//wAAf//////AAA/wAAAD//8AAD//////gAADAAAAA//+AAAf/////wAAAAAAAAP//AAAD/////8AAAAAAAAD//gAAAf////+AAAAAAAAA//wAAAD/////AAAAAAAAAH/4AAAAf////gAAAAAAAAB/+AAAAH////4AAAAAAAAAA/AAAAB////+AAAAAAAAAABgAAAAf////gAAAAAAAAAAAAAAAH////4AAAAAAAAAAAAAAAB////+AAAAAAAAAAAAAAAAf////gAAAAAAAAAAAAAAAH////8AAAAAAAAAAAAAAAD/////gAAAAAAAAAAAAAAA/////8AAAAAAAAAAAAAAA/////+AAAAAAAAAAAAAAAP/////AAAAAAAAAAAAAAAH/////gAAAAAAAAAAAAAAAf////wAAAAAAAAAAAAAAAD////8AAAAAAAAAAAAAAAA////+AAAAAAAAAAAAAAAAH////gAAAAAAAAAAAAAAAB////wAAAAAAAAAAAAAAAAP///8AAAAAAAAAAAAAAAAB////AAAAAAAAAAAAAAAAAf///wAAAAAAAAAAAAAAAAH///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAD///8AAAAAAAAAAAAAAAAA////gAAAAAAAAAAAAAAAAP///4AAAAAAAAAAAAAAAAD///+AAAAAAAAAAAAAAAAA////wAAAAAAAAAAAAAAAAP///+AAAAAAAAAAAAAAAAH////gAAAAAAAAAAAAAAAB////8AAAAAAAAAAAAAAAA/////AAAAAAAAAAAAAAAAP////4AAAAAAAAAAAAAAAH/////gAAAAAAAAAAAAAAD/////4AAAAAAAAAAAAAAB/////8AAAAAAAAAAAAAAA/////+AAAAAAAAAAAAAAAH/////AAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAH////4AAAAAAAAAAAAAAAB////+AAAAAAAAAAAAAAAAf////gAAAAAAAAAAAAAAAH////4AAAACAAAAAAAAAAB////+AAAAB8AAAAAAAAAAf////gAAAA/+AAAAAAAAAH////4AAAAf/gAAAAAAAAB/////AAAAH/8AAAAAAAAA/////8AAAH//AAAAAAAAAf/////AAAB//wAAAAEAAAP/////4AAA//8AAAADgAAD//////AAAf//AAAAP8AAB//////4AAP//wAAAH/AAA//////+AAD//8AAAH/4AAf//////4AD///AAAD//gAP//////+AA///wAAH//4AH///////wAf//+AAD///AB///////+AP///wAH///4A////////wH///+AD////Af///////8D//////////wP///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8='
    $icoPath = "$env:ProgramData\RemoveWindowsAI.ico"
    $bytes = [Convert]::FromBase64String($removeAiIconBase64)
    [System.IO.File]::WriteAllBytes($icoPath, $bytes)

    if ($Desktop) {
        Write-Status -msg 'Creating shortcut to run RemoveWindowsAI script -> [DESKTOP]...' 
        #get users correct desktop path
        $desktopPath = [Environment]::GetFolderPath('Desktop')
        #$desktopPathPublic = [Environment]::GetFolderPath('CommonDesktopDirectory')
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$desktopPath\RemoveWindowsAI.lnk")
        $Shortcut.TargetPath = $psPath
        $Shortcut.Arguments = "-ep bypass -c `"& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1')))`""
        $Shortcut.IconLocation = $icoPath
        $Shortcut.Save()
        #runasadmin
        $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)
    }

    if ($Start) {
        Write-Status -msg 'Creating shortcut to run RemoveWindowsAI script -> [START MENU]...'
        $startPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs" #"$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$startPath\RemoveWindowsAI.lnk")
        $Shortcut.TargetPath = $psPath
        $Shortcut.Arguments = "-ep bypass -c `"& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1')))`""
        $Shortcut.IconLocation = $icoPath
        $Shortcut.Save()
        #runasadmin
        $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)
    }
}

#===============================================================================================================================
#
#                                             CLASSIC APP INSTALL FUNCTIONS
#
#===============================================================================================================================
function install-photoviewer {
    
    #restore classic photoviewer
    $extensions = @('.Bmp', '.Cr2', '.Dib', '.Gif', '.JFIF', '.Jpe', '.Jpeg', '.Jpg', '.Jxr', '.Png', '.Tif', '.Tiff', '.Wdp')

    foreach ($ext in $extensions) {
        if ($ext -in @('.JFIF', '.Jpeg', '.Gif', '.Png', '.Wdp')) {
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext" /v 'EditFlags' /t REG_DWORD /d 65536 /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext" /v 'ImageOptionFlags' /t REG_DWORD /d 1 /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext" /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055' /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\DefaultIcon" /ve /t REG_SZ /d '%SystemRoot%\System32\imageres.dll,-72' /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\shell\open" /v 'MuiVerb' /t REG_EXPAND_SZ /d '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043' /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\shell\open\command" /ve /t REG_EXPAND_SZ /d "%SystemRoot%\System32\rundll32.exe \`"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll\`", ImageView_Fullscreen %1" /f >$null
            reg.exe add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc$ext\shell\open\DropTarget" /v 'Clsid' /t REG_SZ /d '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' /f >$null
        }
    
        if ($ext -in @('.Cr2', '.Tif')) {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f >$null
        }
        elseif ($ext -in @('.Dib', '.Bmp')) {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d 'PhotoViewer.FileAssoc.Bitmap' /f >$null
        }
        elseif ($ext -in @('.Jpg', '.Jpe', '.Jpeg')) {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d 'PhotoViewer.FileAssoc.Jpeg' /f >$null
        }
        else {
            reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' /v $ext.ToLower() /t REG_SZ /d "PhotoViewer.FileAssoc$ext" /f >$null
        }
    }
}

function install-paint {
    param(
        [string]$path
    )

    get-appxpackage '*Microsoft.Paint*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    
    $command = "
    copy-item `"$path\paint\mspaint.exe`" -Destination `"$env:systemroot\system32\mspaint.exe`" -Force
    copy-item `"$path\paint\mspaint.exe.mui`" -Destination `"$env:systemroot\System32\en-US\mspaint.exe.mui`" -Force
    copy-item `"$path\paint\mspaint.exe.mun`" -Destination `"$env:systemroot\SystemResources`" -Force
"
    Run-Trusted -command $command
    Start-Sleep 1

    $command = "regedit.exe /s `"$path\paint\paint.reg`""
    Run-Trusted -command $command
    
    $langID = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage').InstallLanguage
    $languageMap = @{
        '0804' = @{PAD = 'zh-CN'; Name = 'Chinese (Simplified)' }
        '0412' = @{PAD = 'ko-KR'; Name = 'Korean' }
        '0404' = @{PAD = 'zh-TW'; Name = 'Chinese (Traditional)' }
        '0422' = @{PAD = 'uk-UA'; Name = 'Ukrainian' }
        '041f' = @{PAD = 'tr-TR'; Name = 'Turkish' }
        '041e' = @{PAD = 'th-TH'; Name = 'Thai' }
        '241a' = @{PAD = 'sr-Latn-RS'; Name = 'Serbian (Latin)' }
        '0424' = @{PAD = 'sl-SI'; Name = 'Slovenian' }
        '041b' = @{PAD = 'sk-SK'; Name = 'Slovak' }
        '0419' = @{PAD = 'ru-RU'; Name = 'Russian' }
        '0418' = @{PAD = 'ro-RO'; Name = 'Romanian' }
        '0816' = @{PAD = 'pt-PT'; Name = 'Portuguese (Portugal)' }
        '0416' = @{PAD = 'pt-BR'; Name = 'Portuguese (Brazil)' }
        '0415' = @{PAD = 'pl-PL'; Name = 'Polish' }
        '0413' = @{PAD = 'nl-NL'; Name = 'Dutch' }
        '0414' = @{PAD = 'nb-NO'; Name = 'Norwegian' }
        '0426' = @{PAD = 'lv-LV'; Name = 'Latvian' }
        '0427' = @{PAD = 'lt-LT'; Name = 'Lithuanian' }
        '0411' = @{PAD = 'ja-JP'; Name = 'Japanese' }
        '0410' = @{PAD = 'it-IT'; Name = 'Italian' }
        '040e' = @{PAD = 'hu-HU'; Name = 'Hungarian' }
        '041a' = @{PAD = 'hr-HR'; Name = 'Croatian' }
        '040d' = @{PAD = 'he-IL'; Name = 'Hebrew' }
        '040c' = @{PAD = 'fr-FR'; Name = 'French (France)' }
        '0c0c' = @{PAD = 'fr-CA'; Name = 'French (Canada)' }
        '040b' = @{PAD = 'fi-FI'; Name = 'Finnish' }
        '0425' = @{PAD = 'et-EE'; Name = 'Estonian' }
        '080a' = @{PAD = 'es-MX'; Name = 'Spanish (Mexico)' }
        '040a' = @{PAD = 'es-ES'; Name = 'Spanish (Spain)' }
        '0809' = @{PAD = 'en-GB'; Name = 'English (UK)' }
        '0408' = @{PAD = 'el-GR'; Name = 'Greek' }
        '0407' = @{PAD = 'de-DE'; Name = 'German' }
        '0406' = @{PAD = 'da-DK'; Name = 'Danish' }
        '0405' = @{PAD = 'cs-CZ'; Name = 'Czech' }
        '0402' = @{PAD = 'bg-BG'; Name = 'Bulgarian' }
        '0401' = @{PAD = 'ar-SA'; Name = 'Arabic' }
        '041d' = @{PAD = 'sv-SE'; Name = 'Swedish' }
    }

    if ($languageMap.ContainsKey($langID)) {
        $lang = $languageMap[$langID]
        $pad = $lang.PAD
    
        # Copy language specific MUI file
        $command = "Copy-Item -Path `"$path\paint\paint_lang_files\$pad\mspaint.exe.mui`" -Destination `"$env:SYSTEMROOT\System32\$pad\mspaint.exe.mui`" -Force"
        Run-Trusted -command $command

        Write-Status -msg "Copied $pad language file"
    }
   
    
    #create start shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Paint.lnk')
    $Shortcut.TargetPath = 'C:\Windows\System32\mspaint.exe'
    $Shortcut.Save()

}

function install-snipping {
    param(
        [string]$path
    )
    # uninstall uwp
    Get-AppxPackage '*ScreenSketch*' -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

    $command = "
    copy-item `"$path\snipping\SnippingTool.exe`" -Destination `"$env:systemroot\system32\SnippingTool.exe`" -Force
    copy-item `"$path\snipping\SnippingTool.exe.mui`" -Destination `"$env:systemroot\System32\en-US\SnippingTool.exe.mui`" -Force
"
    Run-Trusted -command $command
    Start-Sleep 1

    $langID = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage').InstallLanguage
    $languageMap = @{
        '0804' = @{PAD = 'zh-CN'; Name = 'Chinese (Simplified)' }
        '0412' = @{PAD = 'ko-KR'; Name = 'Korean' }
        '0404' = @{PAD = 'zh-TW'; Name = 'Chinese (Traditional)' }
        '0422' = @{PAD = 'uk-UA'; Name = 'Ukrainian' }
        '041f' = @{PAD = 'tr-TR'; Name = 'Turkish' }
        '041e' = @{PAD = 'th-TH'; Name = 'Thai' }
        '241a' = @{PAD = 'sr-Latn-RS'; Name = 'Serbian (Latin)' }
        '0424' = @{PAD = 'sl-SI'; Name = 'Slovenian' }
        '041b' = @{PAD = 'sk-SK'; Name = 'Slovak' }
        '0419' = @{PAD = 'ru-RU'; Name = 'Russian' }
        '0418' = @{PAD = 'ro-RO'; Name = 'Romanian' }
        '0816' = @{PAD = 'pt-PT'; Name = 'Portuguese (Portugal)' }
        '0416' = @{PAD = 'pt-BR'; Name = 'Portuguese (Brazil)' }
        '0415' = @{PAD = 'pl-PL'; Name = 'Polish' }
        '0413' = @{PAD = 'nl-NL'; Name = 'Dutch' }
        '0414' = @{PAD = 'nb-NO'; Name = 'Norwegian' }
        '0426' = @{PAD = 'lv-LV'; Name = 'Latvian' }
        '0427' = @{PAD = 'lt-LT'; Name = 'Lithuanian' }
        '0411' = @{PAD = 'ja-JP'; Name = 'Japanese' }
        '0410' = @{PAD = 'it-IT'; Name = 'Italian' }
        '040e' = @{PAD = 'hu-HU'; Name = 'Hungarian' }
        '041a' = @{PAD = 'hr-HR'; Name = 'Croatian' }
        '040d' = @{PAD = 'he-IL'; Name = 'Hebrew' }
        '040c' = @{PAD = 'fr-FR'; Name = 'French (France)' }
        '0c0c' = @{PAD = 'fr-CA'; Name = 'French (Canada)' }
        '040b' = @{PAD = 'fi-FI'; Name = 'Finnish' }
        '0425' = @{PAD = 'et-EE'; Name = 'Estonian' }
        '080a' = @{PAD = 'es-MX'; Name = 'Spanish (Mexico)' }
        '040a' = @{PAD = 'es-ES'; Name = 'Spanish (Spain)' }
        '0809' = @{PAD = 'en-GB'; Name = 'English (UK)' }
        '0408' = @{PAD = 'el-GR'; Name = 'Greek' }
        '0407' = @{PAD = 'de-DE'; Name = 'German' }
        '0406' = @{PAD = 'da-DK'; Name = 'Danish' }
        '0405' = @{PAD = 'cs-CZ'; Name = 'Czech' }
        '0402' = @{PAD = 'bg-BG'; Name = 'Bulgarian' }
        '0401' = @{PAD = 'ar-SA'; Name = 'Arabic' }
        '041d' = @{PAD = 'sv-SE'; Name = 'Swedish' }
    }

    if ($languageMap.ContainsKey($langID)) {
        $lang = $languageMap[$langID]
        $pad = $lang.PAD
    
        # Copy language specific MUI file
        $command = "Copy-Item -Path `"$path\snipping\snipping_lang_files\$pad\SnippingTool.exe.mui`" -Destination `"$env:SYSTEMROOT\System32\$pad\SnippingTool.exe.mui`" -Force"
        Run-Trusted -command $command

        Write-Status -msg "Copied $pad language file"
    
    }
   

    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\SnippingTool.lnk')
    $Shortcut.TargetPath = ('C:\Windows\System32\SnippingTool.exe')
    $Shortcut.Save()

}


function install-notepad {

    #uninstall new notepad 
    taskkill.exe /im notepad.exe /f *>$null
    taskkill.exe /im dllhost.exe /f *>$null
    get-appxpackage '*notepad*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    #enable win10 notepad
    Add-WindowsCapability -Online -Name Microsoft.Windows.Notepad.System~~~~0.0.1.0 -LimitAccess | Out-Null
    # fix registry 
    Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe' -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Applications\notepad.exe' -Name NoOpenWith -Force -ErrorAction SilentlyContinue
    reg.exe add 'HKLM\SOFTWARE\Classes\*\OpenWithList\notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.htm\OpenWithList' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.htm\OpenWithList\notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.inf' /ve /t REG_SZ /d 'inffile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.ini' /ve /t REG_SZ /d 'inifile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.log' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.ps1' /ve /t REG_SZ /d 'Microsoft.PowerShellScript.1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.psd1' /ve /t REG_SZ /d 'Microsoft.PowerShellData.1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.psm1' /ve /t REG_SZ /d 'Microsoft.PowerShellModule.1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.scp' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.txt' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.txt\ShellNew' /v 'ItemName' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\notepad.exe,-470' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.txt\ShellNew' /v 'NullFile' /t REG_SZ /d ' ' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\.wtx' /ve /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\edit' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\edit\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Applications\notepad.exe\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile' /ve /t REG_SZ /d 'Setup Information' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d '@%SystemRoot%\System32\setupapi.dll,-2000' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\DefaultIcon' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\System32\imageres.dll,-69' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\print' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inffile\shell\print\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE /p %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile' /ve /t REG_SZ /d 'Configuration Settings' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile' /v 'EditFlags' /t REG_DWORD /d 0x00200000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile' /v 'FriendlyTypeName' /t REG_SZ /d '@shell32.dll,-10151' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\DefaultIcon' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\imageres.dll,-69' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\print' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\inifile\shell\print\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE /p %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1' /v 'EditFlags' /t REG_DWORD /d 0x00020000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d "@\`"%systemroot%\system32\windowspowershell\v1.0\powershell.exe\`",-104" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1\Shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1\Shell\Open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellData.1\Shell\Open\Command' /ve /t REG_SZ /d "\`"C:\Windows\System32\notepad.exe\`" \`"%1\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1' /v 'EditFlags' /t REG_DWORD /d 0x00020000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d "@\`"%systemroot%\system32\windowspowershell\v1.0\powershell.exe\`",-106" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1\Shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1\Shell\Open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellModule.1\Shell\Open\Command' /ve /t REG_SZ /d "\`"C:\Windows\System32\notepad.exe\`" \`"%1\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1' /v 'EditFlags' /t REG_DWORD /d 0x00020000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d "@\`"%systemroot%\system32\windowspowershell\v1.0\powershell.exe\`",-103" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\DefaultIcon' /ve /t REG_SZ /d "\`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe\`",1" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell\Open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell\Open\Command' /ve /t REG_SZ /d "\`"C:\Windows\System32\notepad.exe\`" \`"%1\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\OpenWithList' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\OpenWithList\Notepad.exe' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\edit' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\edit\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\SystemFileAssociations\text\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile' /ve /t REG_SZ /d 'Text Document' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile' /v 'EditFlags' /t REG_DWORD /d 0x00210000 /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile' /v 'FriendlyTypeName' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\notepad.exe,-469' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\DefaultIcon' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\imageres.dll,-102' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\open' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\open\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\print' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\print\command' /ve /t REG_EXPAND_SZ /d '%SystemRoot%\system32\NOTEPAD.EXE /p %1' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\printto' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Classes\txtfile\shell\printto\command' /ve /t REG_EXPAND_SZ /d "%SystemRoot%\system32\notepad.exe /pt \`"%1\`" \`"%2\`" \`"%3\`" \`"%4\`"" /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities' /v 'ApplicationDescription' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\NOTEPAD.EXE,-9' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities' /v 'ApplicationName' /t REG_EXPAND_SZ /d '@%SystemRoot%\system32\NOTEPAD.EXE,-9' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.ini' /t REG_SZ /d 'inifile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.log' /t REG_SZ /d 'logfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.scp' /t REG_SZ /d 'scpfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.txt' /t REG_SZ /d 'txtfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Notepad\Capabilities\FileAssociations' /v '.wtx' /t REG_SZ /d 'wtxfile' /f >$null
    reg.exe add 'HKLM\SOFTWARE\RegisteredApplications' /v 'Notepad' /t REG_SZ /d 'Software\Microsoft\Windows\Notepad\Capabilities' /f >$null
    reg.exe add 'HKCU\Software\Microsoft\Notepad' /v 'ShowStoreBanner' /t REG_DWORD /d 0x00000000 /f >$null

    #create start shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk')
    $Shortcut.TargetPath = 'C:\Windows\System32\Notepad.exe'
    $Shortcut.Save()

}

function install-photoslegacy {

    $appx = Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -like '*PhotosLegacy*' }

    if (!$appx) {

        try {
            Get-Command store -ErrorAction Stop
            #install photos legacy using new store cmdlet
            store install 9NV2L4XVMCXM
        }
        catch {
            Remove-Item "$($tempDir)Microsoft.PhotosLegacy_8wekyb3d8bbwe*" -Force -Recurse -ErrorAction SilentlyContinue
            $downloadedfiles = Download-AppxPackage -PackageFamilyName 'Microsoft.PhotosLegacy_8wekyb3d8bbwe' -outputDir "$tempDir"
            $package = $downloadedfiles | Where-Object { $_ -match '\.appxbundle$' } | Select-Object -First 1
            $dependencies = $downloadedfiles | Where-Object { $_ -match '\.appx$' } 
            if ($package) {
                try {
                    Add-AppPackage $package -DependencyPath $dependencies -ForceApplicationShutdown
                }
                catch {
                    Write-status -msg "Can't install PhotosLegacy via appxbundle... make sure you have the appx service enabled" -errorOutput
                }
                
            }
            else {
                Write-status -msg "Can't find PhotosLegacy Installer" -errorOutput
            }
        }
        
    }
}

function install-classicapps {
    param(
        [ValidateSet('photoviewer', 'mspaint', 'snippingtool', 'notepad', 'photoslegacy')]
        [array]$app
    )

    #check if files are downloaded locally
    if (Test-Path "$PSScriptroot\ClassicApps") {
        Write-Status -msg 'Classic Apps Files Found Locally'
        $classicApps = "$PSScriptroot\ClassicApps"
    }
    else {
        #check if they are already downloaded if not download them
        
        if (!(Test-Path "$($tempDir)ClassicApps")) {
            $ProgressPreference = 'SilentlyContinue'
            Write-Status -msg 'Downloading Classic Apps Files from Github...'
            $url = 'https://github.com/zoicware/RemoveWindowsAI/archive/refs/heads/main.zip'
            try {
                Invoke-WebRequest -Uri $url -OutFile "$($tempDir)main.zip" -ErrorAction Stop
            }
            catch {
                Write-Status -msg 'Unable to Download Github Repo' -errorOutput 
                return
            }
            Expand-Archive -Path "$($tempDir)main.zip" -DestinationPath "$tempDir" -Force
            $sourceDir = "$($tempDir)RemoveWindowsAI-main\ClassicApps"
            $destDir = "$($tempDir)ClassicApps"
            Copy-Item -Path $sourceDir -Destination $destDir -Recurse -Force
            Remove-Item "$($tempDir)RemoveWindowsAI-main" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "$($tempDir)main.zip" -Recurse -Force -ErrorAction SilentlyContinue
        }

        $classicApps = "$($tempDir)ClassicApps"
    }

    #verify binaries
    $exes = (Get-ChildItem $classicApps -Filter '*.exe' -Recurse).FullName
    $paintDetails = [PSCustomObject]@{
        InternalName     = 'MSPAINT'
        OriginalFilename = 'MSPAINT.EXE'
        FileVersion      = '10.0.26100.7309 (WinBuild.160101.0800)'
        FileDescription  = 'Paint'
        LegalCopyright   = '© Microsoft Corporation. All rights reserved.'
        CompanyName      = 'Microsoft Corporation'
    }
    $snippingDetails = [PSCustomObject]@{
        InternalName     = 'SnippingTool'
        OriginalFilename = 'SnippingTool.exe'
        FileVersion      = '10.0.26100.7309 (WinBuild.160101.0800)'
        FileDescription  = 'Snipping Tool'
        LegalCopyright   = '© Microsoft Corporation. All rights reserved.'
        CompanyName      = 'Microsoft Corporation'
    }
    foreach ($exe in $exes) {
        $exeDetails = (Get-Item "$exe").VersionInfo | Select-Object InternalName, OriginalFilename, FileVersion, FileDescription, LegalCopyright, CompanyName
        #compare object returns null when objects match so we need -not for this to make more sense 
        $matchesPaint = -not (Compare-Object $exeDetails $paintDetails -Property $exeDetails.PSObject.Properties.Name)
        $matchesSnipping = -not (Compare-Object $exeDetails $snippingDetails -Property $exeDetails.PSObject.Properties.Name)
        if (!$matchesPaint -and !$matchesSnipping) {
            Write-Status -msg 'Downloaded binary details do not match whats expected... removing files and aborting!' -errorOutput
            Remove-Item $classicApps -Force -Recurse
            return
        }

    }

   
    switch ($app) {
        'photoviewer' {  
            Write-Status -msg 'Installing Classic Photo Viewer...'
            install-photoviewer
        }
        'mspaint' {
            Write-Status -msg 'Installing Classic Paint...'
            install-paint -path $classicApps
        }
        'snippingtool' {
            Write-Status -msg 'Installing Classic Snipping Tool...'
            install-snipping -path $classicApps
        }
        'notepad' {
            Write-Status -msg 'Installing Classic Notepad...'
            install-notepad
        }
        'photoslegacy' {
            Write-Status -msg 'Installing Photos Legacy...'
            install-photoslegacy
        }
        Default {
            Write-Status -msg 'Unknown Classic App Option' -errorOutput
        }
    }
}

function Update-Repair {
    Write-Host 'Stopping Windows Update Services...' -ForegroundColor Green
    Stop-Service BITS -Force -ErrorAction SilentlyContinue
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service DoSvc -Force -ErrorAction SilentlyContinue
    Stop-Service UsoSvc -Force -ErrorAction SilentlyContinue
    Stop-Service WaaSMedicSvc -Force -ErrorAction SilentlyContinue
    taskkill.exe /im 'wuaucltcore.exe' /f *>$null
    taskkill.exe /im 'TiWorker.exe' /f *>$null
    Get-BitsTransfer -AllUsers | Remove-BitsTransfer 

    Write-Host 'Removing Windows Update Cache...' -ForegroundColor Green
    Remove-Item -Path "$env:windir\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:windir\Logs\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' /f *>$null
    reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting' /f *>$null
    Remove-Item "$env:ProgramData\Application Data\Microsoft\Network\Downloader\*.*" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:windir\System32\catroot2" -Force -Recurse -ErrorAction SilentlyContinue
    Rename-Item "$env:windir\WinSxS\pending.xml" -NewName 'pending.xml.old' -Force -ErrorAction SilentlyContinue
    $temp1 = "$env:windir\Temp"
    $temp2 = $tempDir
    $tempFiles = (Get-ChildItem -Path "$temp1" , "$temp2" -Recurse -Force).FullName
    foreach ($file in $tempFiles) {
        Remove-Item -Path "$file" -Recurse -Force -ErrorAction SilentlyContinue
    }
    #run disk cleanup 
    $options = @(
        'Active Setup Temp Folders'
        'Delivery Optimization Files'
        'Downloaded Program Files'
        'Internet Cache Files'
        'Setup Log Files'
        'Temporary Files'
        'Windows Error Reporting Files'
        'Offline Pages Files'
        'Recycle Bin'
        'Temporary Setup Files'
        'Update Cleanup'
        'Upgrade Discarded Files'
        'Windows Defender'
        'Windows ESD installation files'
        'Windows Reset Log Files'
        'Windows Upgrade Log Files'
        'Previous Installations'
    )
    $key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    foreach ($option in $options) {
        reg.exe add "$key\$option" /v StateFlags0069 /t REG_DWORD /d 00000002 /f >$null
    }

    #credits to @instead1337 for monitoring logic
    $timeout = 600
    $cleanupProcess = Start-Process cleanmgr.exe -ArgumentList '/sagerun:69' -Wait:$false -PassThru
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastCpuUsage = 0
    $lastMemoryUsage = 0

    while ($cleanupProcess -and !$cleanupProcess.HasExited -and $stopwatch.Elapsed.TotalSeconds -lt $timeout) {
        Start-Sleep -Seconds 10
        $process = Get-Process -Id $cleanupProcess.Id -EA SilentlyContinue
        if ($process) {
            $cpuUsage = $process.CPU
            $memoryUsage = $process.WS
            if ($cpuUsage -eq $lastCpuUsage -and $memoryUsage -eq $lastMemoryUsage) {
                if ($cleanupProcess.MainWindowHandle) {
                    $cleanupProcess.CloseMainWindow() | Out-Null
                    Start-Sleep -Seconds 5
                    if (!$cleanupProcess.HasExited) { $cleanupProcess | Stop-Process -EA SilentlyContinue }
                }
                else {
                    $cleanupProcess | Stop-Process -EA SilentlyContinue
                }
            }
            $lastCpuUsage = $cpuUsage
            $lastMemoryUsage = $memoryUsage
        }
        
    }

    Write-Host 'Setting Windows Update Services StartType...' -ForegroundColor Green
    Set-Service BITS -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service UsoSvc -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service DoSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service AppReadiness -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service CryptSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service WaaSMedicSvc -StartupType Manual -ErrorAction SilentlyContinue

    Write-Host 'Running DISM Repair...' -ForegroundColor Green
    Write-Host 'DISM can take a very long time please let this process finish...' -ForegroundColor DarkYellow
    Write-Host '[TIP!] You can view the process in task manager by finding "Windows Module Installer Worker"' -ForegroundColor DarkYellow
    Add-AppxPackage -RegisterByFamilyName -MainPackage 'MicrosoftWindows.Client.CBS_cw5n1h2txyewy' 
    Dism.exe /Online /Cleanup-Image /RestoreHealth
    Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Resetbase
    sfc.exe /scannow

    Write-Host 'Starting Windows Update Services...' -ForegroundColor Green
    Start-Service BITS *>$null
    Start-Service DoSvc *>$null
    Start-Service CryptSvc *>$null

    Add-Type -AssemblyName System.Windows.Forms
    $result = [System.Windows.Forms.MessageBox]::Show(
        "A restart is required to finish.`n`nWould you like to restart now?",
        'Restart Required',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        Restart-Computer -Force
    }
    else {
        exit
    }
 
}

if ($RunWinUpdateRepair) {
    Update-Repair
}


if ($nonInteractive) {
    if ($backup) {
        Create-RestorePoint -nonInteractive
    }
    if ($AllOptions) {
        Disable-Registry-Keys 
        Install-NOAIPackage
        Disable-Copilot-Policies 
        Remove-AI-Appx-Packages 
        Remove-Recall-Optional-Feature 
        Remove-AI-CBS-Packages 
        Remove-AI-Files 
        Hide-AI-Components 
        Disable-Notepad-Rewrite 
        Remove-WindowsAI-Tasks 
        Update-Cleanup-Check
    }
    else {
        $allFunctions = @(
            'DisableRegKeys' 
            'Prevent-AI-Package-Reinstall' 
            'DisableCopilotPolicies' 
            'RemoveAppxPackages' 
            'RemoveRecallFeature' 
            'RemoveCBSPackages' 
            'RemoveAIFiles' 
            'HideAIComponents'
            'DisableRewrite'
            'RemoveWindowsAITasks' 
            'UpdateCleanupCheck' 
        )
        #remove excluded options from the array
        $activeOptions = if ($ExcludeOptions) {
            $allFunctions | Where-Object { $Options -notcontains $_ }
        }
        else {
            $Options
        }

        #loop through options array and run desired tweaks
        switch ($activeOptions) {
            'DisableRegKeys' { Disable-Registry-Keys }
            'Prevent-AI-Package-Reinstall' { Install-NOAIPackage }
            'DisableCopilotPolicies' { Disable-Copilot-Policies }
            'RemoveAppxPackages' { Remove-AI-Appx-Packages }
            'RemoveRecallFeature' { Remove-Recall-Optional-Feature }
            'RemoveCBSPackages' { Remove-AI-CBS-Packages }
            'RemoveAIFiles' { Remove-AI-Files }
            'HideAIComponents' { Hide-AI-Components }
            'DisableRewrite' { Disable-Notepad-Rewrite }
            'RemoveWindowsAITasks' { Remove-WindowsAI-Tasks }
            'UpdateCleanupCheck' { Update-Cleanup-Check }
        }
    }

    if ($InstallClassicApps) {
        foreach ($app in $InstallClassicApps) {
            install-classicapps -app $app
        }
    }
}
else {

    #===============================================================================
    #BEGIN UI
    #===============================================================================

    $functionDescriptions = @{
        'Disable-Registry-Keys'          = 'Disables Copilot and Recall through registry modifications, including Windows Search integration and Edge Copilot features. Also disables AI image creator in Paint and various AI-related privacy settings.'
        'Prevent-AI-Package-Reinstall'   = 'Installs a custom Windows Update Package to prevent Windows Update and DISM from reinstalling AI packages.'
        'Disable-Copilot-Policies'       = 'Disables Copilot policies in the Windows integrated services region policy JSON file by setting their default state to disabled.'
        'Remove-AI-Appx-Packages'        = 'Removes AI-related AppX packages including Copilot, AIX, CoreAI, and various WindowsWorkload AI components using advanced removal techniques.'
        'Remove-Recall-Optional-Feature' = 'Removes the Recall optional Windows feature completely from the system, including payload removal.'
        'Remove-AI-CBS-Packages'         = 'Removes additional hidden AI packages from Component Based Servicing (CBS) by unhiding them and forcing removal.'
        'Remove-AI-Files'                = 'Removes AI-related files from SystemApps, WindowsApps, and other system directories. Also removes machine learning DLLs and Copilot installers.'
        'Hide-AI-Components'             = 'Hides AI components in Windows Settings by modifying the SettingsPageVisibility policy to prevent user access to AI settings.'
        'Disable-Notepad-Rewrite'        = 'Disables the AI Rewrite feature in Windows Notepad through registry modifications and group policy settings.'
        'Remove-WindowsAI-Tasks'         = 'Removes Windows AI scheduled tasks from Task Scheduler to prevent AI data collection processes from running.'
        'Update-Cleanup-Check'           = 'Creates a silent scheduled task to run at log-on to check if Windows has been updated... if it has then the script will cleanup newly installed AI features'
    }

    $window = New-Object System.Windows.Window
    $window.Title = 'Remove Windows AI - by @zoicware'
    $window.Width = 600
    $window.Height = 700
    $window.WindowStartupLocation = 'CenterScreen'
    $window.ResizeMode = 'NoResize'

    $window.Background = [System.Windows.Media.Brushes]::Black
    $window.Foreground = [System.Windows.Media.Brushes]::White

    $mainGrid = New-Object System.Windows.Controls.Grid
    $window.Content = $mainGrid

    $titleRow = New-Object System.Windows.Controls.RowDefinition
    $titleRow.Height = [System.Windows.GridLength]::new(80)
    $mainGrid.RowDefinitions.Add($titleRow) | Out-Null

    $contentRow = New-Object System.Windows.Controls.RowDefinition
    $contentRow.Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $mainGrid.RowDefinitions.Add($contentRow) | Out-Null

    $toggleRow = New-Object System.Windows.Controls.RowDefinition
    $toggleRow.Height = [System.Windows.GridLength]::new(165) 
    $mainGrid.RowDefinitions.Add($toggleRow) | Out-Null

    $bottomRow = New-Object System.Windows.Controls.RowDefinition
    $bottomRow.Height = [System.Windows.GridLength]::new(80)
    $mainGrid.RowDefinitions.Add($bottomRow) | Out-Null

   
    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = 'Remove Windows AI'
    $title.FontSize = 18
    $title.FontWeight = 'Bold'
    $title.Foreground = [System.Windows.Media.Brushes]::Cyan
    $title.HorizontalAlignment = 'Center'
    $title.VerticalAlignment = 'Center'
    $title.Margin = '0,20,0,0'
    [System.Windows.Controls.Grid]::SetRow($title, 0)
    $mainGrid.Children.Add($title) | Out-Null

    $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
    $scrollViewer.VerticalScrollBarVisibility = 'Auto'
    $scrollViewer.Margin = '20,10,20,10'
    [System.Windows.Controls.Grid]::SetRow($scrollViewer, 1)
    $mainGrid.Children.Add($scrollViewer) | Out-Null

    $scrollViewerStyle = @'
<Style xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
       xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
       TargetType="{x:Type ScrollViewer}">
    <Setter Property="Template">
        <Setter.Value>
            <ControlTemplate TargetType="{x:Type ScrollViewer}">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <ScrollContentPresenter Grid.Column="0" Margin="0,0,15,0"/>
                    <ScrollBar Grid.Column="1" 
                               Name="PART_VerticalScrollBar"
                               Value="{TemplateBinding VerticalOffset}"
                               Maximum="{TemplateBinding ScrollableHeight}"
                               ViewportSize="{TemplateBinding ViewportHeight}"
                               Visibility="{TemplateBinding ComputedVerticalScrollBarVisibility}"
                               Width="12"
                               Margin="3,0,8,0">
                        <ScrollBar.Style>
                            <Style TargetType="ScrollBar">
                                <Setter Property="Background" Value="#2B2B2B"/>
                                <Setter Property="Template">
                                    <Setter.Value>
                                        <ControlTemplate TargetType="ScrollBar">
                                            <Grid>
                                                <Border Background="{TemplateBinding Background}" CornerRadius="6"/>
                                                <Track Name="PART_Track" IsDirectionReversed="True">
                                                    <Track.Thumb>
                                                        <Thumb>
                                                            <Thumb.Style>
                                                                <Style TargetType="Thumb">
                                                                    <Setter Property="Background" Value="#5A5A5A"/>
                                                                    <Setter Property="Template">
                                                                        <Setter.Value>
                                                                            <ControlTemplate TargetType="Thumb">
                                                                                <Border Background="{TemplateBinding Background}" 
                                                                                        CornerRadius="6"
                                                                                        Margin="2"/>
                                                                            </ControlTemplate>
                                                                        </Setter.Value>
                                                                    </Setter>
                                                                    <Style.Triggers>
                                                                        <Trigger Property="IsMouseOver" Value="True">
                                                                            <Setter Property="Background" Value="#7A7A7A"/>
                                                                        </Trigger>
                                                                    </Style.Triggers>
                                                                </Style>
                                                            </Thumb.Style>
                                                        </Thumb>
                                                    </Track.Thumb>
                                                </Track>
                                            </Grid>
                                        </ControlTemplate>
                                    </Setter.Value>
                                </Setter>
                            </Style>
                        </ScrollBar.Style>
                    </ScrollBar>
                </Grid>
            </ControlTemplate>
        </Setter.Value>
    </Setter>
</Style>
'@

    $reader = New-Object System.Xml.XmlNodeReader([xml]$scrollViewerStyle)
    $scrollViewer.Style = [Windows.Markup.XamlReader]::Load($reader)


    $stackPanel = New-Object System.Windows.Controls.StackPanel
    $stackPanel.Orientation = 'Vertical'
    $scrollViewer.Content = $stackPanel

    $checkboxes = @{}
    $functions = @(
        'Disable-Registry-Keys'          
        'Prevent-AI-Package-Reinstall'
        'Disable-Copilot-Policies'       
        'Remove-AI-Appx-Packages'        
        'Remove-Recall-Optional-Feature' 
        'Remove-AI-CBS-Packages'         
        'Remove-AI-Files'               
        'Hide-AI-Components'            
        'Disable-Notepad-Rewrite'       
        'Remove-WindowsAI-Tasks'
        'Update-Cleanup-Check'          
    )

    $unchecked = @(
        'Remove-AI-Files'
        'Remove-AI-CBS-Packages'
        'Prevent-AI-Package-Reinstall'
    )

    foreach ($func in $functions) {
        $optionContainer = New-Object System.Windows.Controls.DockPanel
        $optionContainer.Margin = '0,5,0,5'
        $optionContainer.LastChildFill = $false

        $infoButton = New-Object System.Windows.Controls.Button
        $infoButton.Content = '?'
        $infoButton.Width = 25
        $infoButton.Height = 25
        $infoButton.FontSize = 12
        $infoButton.FontWeight = 'Bold'
        $infoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
        $infoButton.Foreground = [System.Windows.Media.Brushes]::White
        $infoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
        $infoButton.BorderThickness = 0
        $infoButton.VerticalAlignment = 'Center'
        $infoButton.Cursor = 'Hand'
        [System.Windows.Controls.DockPanel]::SetDock($infoButton, 'Right')

        $infoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
        $infoButton.Template = [System.Windows.Markup.XamlReader]::Parse($infoTemplate)

        $infoButton.Add_Click({
                param($sender, $e)
                $funcName = $functions | Where-Object { $checkboxes[$_] -eq $optionContainer.Children[0] }
                if (!$funcName) {
                    # Find the function name by looking at the parent container
                    $parentContainer = $sender.Parent
                    $checkboxInContainer = $parentContainer.Children | Where-Object { $_ -is [System.Windows.Controls.CheckBox] }
                    $funcName = $functions | Where-Object { ($checkboxes[$_].Content -replace ' ', '-') -eq ($checkboxInContainer.Content -replace ' ', '-') }
                }
        
                # Find the correct function name
                foreach ($f in $functions) {
                    if ($checkboxes[$f].Parent -eq $sender.Parent) {
                        $funcName = $f
                        break
                    }
                }
        
                $description = $functionDescriptions[$funcName]
                [System.Windows.MessageBox]::Show($description, $funcName, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            })
    
        $checkboxPanel = New-Object System.Windows.Controls.StackPanel
        $checkboxPanel.Orientation = 'Horizontal'
        $checkboxPanel.VerticalAlignment = 'Center'

        $checkboxLabel = New-Object System.Windows.Controls.TextBlock
        $checkboxLabel.Text = $func.Replace('-', ' ')
        $checkboxLabel.FontSize = 14
        $checkboxLabel.Foreground = [System.Windows.Media.Brushes]::White
        $checkboxLabel.VerticalAlignment = 'Center'
        $checkboxPanel.Children.Add($checkboxLabel) | Out-Null

        if ($unchecked -contains $func) {
            $warningIcon = New-Object System.Windows.Controls.TextBlock
            $warningIcon.Text = ' ⚠'
            $warningIcon.FontSize = 14
            $warningIcon.Foreground = [System.Windows.Media.SolidColorBrush]::new(
                [System.Windows.Media.Color]::FromRgb(255, 180, 0))
            $warningIcon.VerticalAlignment = 'Center'
            $warningIcon.Cursor = 'Arrow'

            $tooltip = New-Object System.Windows.Controls.ToolTip
            $tooltip.Content = 'Warning: This option may break Windows Update'
            $tooltip.Background = [System.Windows.Media.SolidColorBrush]::new(
                [System.Windows.Media.Color]::FromRgb(60, 30, 0))
            $tooltip.Foreground = [System.Windows.Media.Brushes]::Yellow
            $tooltip.FontSize = 11
            $tooltip.BorderBrush = [System.Windows.Media.SolidColorBrush]::new(
                [System.Windows.Media.Color]::FromRgb(180, 100, 0))
            $tooltip.BorderThickness = 1
            $tooltip.Padding = '6,4,6,4'
            $warningIcon.ToolTip = $tooltip

            $checkboxPanel.Children.Add($warningIcon) | Out-Null
        }

        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $checkboxPanel
        $checkbox.FontSize = 14
        $checkbox.Foreground = [System.Windows.Media.Brushes]::White
        $checkbox.Margin = '0,0,10,0'
        $checkbox.VerticalAlignment = 'Center'
        $checkbox.IsChecked = if ($unchecked -notcontains $func) { $true } else { $false }
        [System.Windows.Controls.DockPanel]::SetDock($checkbox, 'Left')
        $checkboxes[$func] = $checkbox

        $optionContainer.Children.Add($infoButton) | Out-Null
        $optionContainer.Children.Add($checkbox) | Out-Null
        $stackPanel.Children.Add($optionContainer) | Out-Null
    }

    #add switches for backup and revert modes
    function Add-iOSToggleToUI {
        param(
            [System.Windows.Controls.Panel]$ParentControl,
            [bool]$IsChecked = $false,
            [string]$Name = 'iOSToggle'
        )
                
        $styleXaml = @'
            <ResourceDictionary 
                xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
                
                <Style x:Key="CleanToggleStyle" TargetType="{x:Type ToggleButton}">
                    <Setter Property="Background" Value="Transparent"/>
                    <Setter Property="BorderBrush" Value="Transparent"/>
                    <Setter Property="BorderThickness" Value="0"/>
                    <Setter Property="Width" Value="40"/>
                    <Setter Property="Height" Value="24"/>
                    <Setter Property="Cursor" Value="Hand"/>
                    <Setter Property="Focusable" Value="False"/>
                    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
                    <Setter Property="Template">
                        <Setter.Value>
                            <ControlTemplate TargetType="{x:Type ToggleButton}">
                                <Grid>
                                    <!-- Switch Track -->
                                    <Border x:Name="SwitchTrack" 
                                            Width="40" Height="24" 
                                            Background="#E5E5E7" 
                                            CornerRadius="12"
                                            BorderThickness="0">
                                        
                                        <!-- Switch Thumb -->
                                        <Border x:Name="SwitchThumb" 
                                                Width="20" Height="20" 
                                                Background="White" 
                                                CornerRadius="10"
                                                HorizontalAlignment="Left"
                                                VerticalAlignment="Center"
                                                Margin="2,0,0,0">
                                            <Border.Effect>
                                                <DropShadowEffect Color="#00000040" 
                                                                  Direction="270" 
                                                                  ShadowDepth="1" 
                                                                  BlurRadius="3"
                                                                  Opacity="0.4"/>
                                            </Border.Effect>
                                            <Border.RenderTransform>
                                                <TranslateTransform x:Name="ThumbTransform" X="0"/>
                                            </Border.RenderTransform>
                                        </Border>
                                    </Border>
                                </Grid>
                                
                                <ControlTemplate.Triggers>
                                    <!-- Checked State (ON) -->
                                    <Trigger Property="IsChecked" Value="True">
                                        <Trigger.EnterActions>
                                            <BeginStoryboard>
                                                <Storyboard>
                                                    <!-- Slide thumb to right -->
                                                    <DoubleAnimation 
                                                        Storyboard.TargetName="ThumbTransform"
                                                        Storyboard.TargetProperty="X"
                                                        To="16" 
                                                        Duration="0:0:0.2"/>
                                                    <!-- Change track color to green -->
                                                    <ColorAnimation 
                                                        Storyboard.TargetName="SwitchTrack"
                                                        Storyboard.TargetProperty="Background.Color"
                                                        To="#34C759" 
                                                        Duration="0:0:0.2"/>
                                                </Storyboard>
                                            </BeginStoryboard>
                                        </Trigger.EnterActions>
                                        <Trigger.ExitActions>
                                            <BeginStoryboard>
                                                <Storyboard>
                                                    <!-- Slide thumb to left -->
                                                    <DoubleAnimation 
                                                        Storyboard.TargetName="ThumbTransform"
                                                        Storyboard.TargetProperty="X"
                                                        To="0" 
                                                        Duration="0:0:0.2"/>
                                                    <!-- Change track color to gray -->
                                                    <ColorAnimation 
                                                        Storyboard.TargetName="SwitchTrack"
                                                        Storyboard.TargetProperty="Background.Color"
                                                        To="#E5E5E7" 
                                                        Duration="0:0:0.2"/>
                                                </Storyboard>
                                            </BeginStoryboard>
                                        </Trigger.ExitActions>
                                    </Trigger>
                                </ControlTemplate.Triggers>
                            </ControlTemplate>
                        </Setter.Value>
                    </Setter>
                </Style>
            </ResourceDictionary>
'@
                
        $reader = New-Object System.Xml.XmlNodeReader([xml]$styleXaml)
        $resourceDict = [Windows.Markup.XamlReader]::Load($reader)
                
        $toggleButton = New-Object System.Windows.Controls.Primitives.ToggleButton
        $toggleButton.Name = $Name
        $toggleButton.IsChecked = $IsChecked
        $toggleButton.Style = $resourceDict['CleanToggleStyle']
        $ParentControl.Children.Add($toggleButton) | Out-Null
                
        return $toggleButton
    }
    
    $divider = New-Object System.Windows.Controls.Separator
    $divider.Margin = '0,10,0,10'
    $divider.Background = [System.Windows.Media.Brushes]::DarkGray
    $stackPanel.Children.Add($divider) | Out-Null

    $classicAppsHeader = New-Object System.Windows.Controls.TextBlock
    $classicAppsHeader.Text = 'Install Classic Windows Apps'
    $classicAppsHeader.FontSize = 16
    $classicAppsHeader.FontWeight = 'Bold'
    $classicAppsHeader.Foreground = [System.Windows.Media.Brushes]::Cyan
    $classicAppsHeader.Margin = '0,10,0,10'
    $stackPanel.Children.Add($classicAppsHeader) | Out-Null

    $classicAppsFunctions = @(
        'Install-Classic-Photoviewer'
        'Install-Classic-Mspaint'
        'Install-Classic-SnippingTool'
        'Install-Classic-Notepad'
        'Install-Photos-Legacy'
    )

    $classicAppsDescriptions = @{
        'Install-Classic-Photoviewer'  = 'Installs the classic Windows Photo Viewer from Windows 7/8, allowing you to view images with the traditional viewer instead of the modern Photos app.'
        'Install-Classic-Mspaint'      = 'Installs the classic Microsoft Paint application from older Windows versions.'
        'Install-Classic-SnippingTool' = 'Installs the classic Snipping Tool, replacing the modern Snip & Sketch app.'
        'Install-Classic-Notepad'      = 'Installs the classic Notepad from Windows 10, replacing the modern uwp version.'
        'Install-Photos-Legacy'        = 'Installs the legacy Windows Photos app from the Microsoft Store.'
    }

    $functionDescriptions += $classicAppsDescriptions
    foreach ($func in $classicAppsFunctions) {
        $optionContainer = New-Object System.Windows.Controls.DockPanel
        $optionContainer.Margin = '0,5,0,5'
        $optionContainer.LastChildFill = $false
    
        $checkbox = New-Object System.Windows.Controls.CheckBox
        $checkbox.Content = $func.Replace('-', ' ')
        $checkbox.FontSize = 14
        $checkbox.Foreground = [System.Windows.Media.Brushes]::White
        $checkbox.Margin = '0,0,10,0'
        $checkbox.VerticalAlignment = 'Center'
        $checkbox.IsChecked = $false  
        [System.Windows.Controls.DockPanel]::SetDock($checkbox, 'Left')
        $checkboxes[$func] = $checkbox
    
        $infoButton = New-Object System.Windows.Controls.Button
        $infoButton.Content = '?'
        $infoButton.Width = 25
        $infoButton.Height = 25
        $infoButton.FontSize = 12
        $infoButton.FontWeight = 'Bold'
        $infoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
        $infoButton.Foreground = [System.Windows.Media.Brushes]::White
        $infoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
        $infoButton.BorderThickness = 0
        $infoButton.VerticalAlignment = 'Center'
        $infoButton.Cursor = 'Hand'
        [System.Windows.Controls.DockPanel]::SetDock($infoButton, 'Right')
    
        $infoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
        $infoButton.Template = [System.Windows.Markup.XamlReader]::Parse($infoTemplate)
    
        $infoButton.Add_Click({
                param($sender, $e)
        
                # Find the correct function name
                foreach ($f in $classicAppsFunctions) {
                    if ($checkboxes[$f].Parent -eq $sender.Parent) {
                        $funcName = $f
                        break
                    }
                }
        
                $description = $functionDescriptions[$funcName]
                [System.Windows.MessageBox]::Show($description, $funcName, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            })
    
        $optionContainer.Children.Add($checkbox) | Out-Null
        $optionContainer.Children.Add($infoButton) | Out-Null
        $stackPanel.Children.Add($optionContainer) | Out-Null
    }

    $allFunctions = $functions + $classicAppsFunctions
    
    $toggleGrid = New-Object System.Windows.Controls.Grid
    [System.Windows.Controls.Grid]::SetRow($toggleGrid, 2)  
    $toggleGrid.Margin = '20,10,55,15'
        
    $row1 = New-Object System.Windows.Controls.RowDefinition
    $row1.Height = [System.Windows.GridLength]::Auto
    $row2 = New-Object System.Windows.Controls.RowDefinition
    $row2.Height = [System.Windows.GridLength]::Auto
    $toggleGrid.RowDefinitions.Add($row1) | Out-Null
    $toggleGrid.RowDefinitions.Add($row2) | Out-Null
        
    $mainGrid.Children.Add($toggleGrid) | Out-Null

    $togglePanel1 = New-Object System.Windows.Controls.DockPanel
    $togglePanel1.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $togglePanel1.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $togglePanel1.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10) 
    $togglePanel1.LastChildFill = $false
    [System.Windows.Controls.Grid]::SetRow($togglePanel1, 0)
        
    $toggleLabel1 = New-Object System.Windows.Controls.TextBlock
    $toggleLabel1.Text = 'Revert Mode:'
    $toggleLabel1.Foreground = [System.Windows.Media.Brushes]::White
    $toggleLabel1.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $toggleLabel1.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
    [System.Windows.Controls.DockPanel]::SetDock($toggleLabel1, 'Left')
    $togglePanel1.Children.Add($toggleLabel1) | Out-Null
        
    $revertModeToggle = Add-iOSToggleToUI -ParentControl $togglePanel1 -IsChecked $revert
    [System.Windows.Controls.DockPanel]::SetDock($revertModeToggle, 'Left')

    $revertInfoButton = New-Object System.Windows.Controls.Button
    $revertInfoButton.Content = '?'
    $revertInfoButton.Width = 25
    $revertInfoButton.Height = 25
    $revertInfoButton.FontSize = 12
    $revertInfoButton.FontWeight = 'Bold'
    $revertInfoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
    $revertInfoButton.Foreground = [System.Windows.Media.Brushes]::White
    $revertInfoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $revertInfoButton.BorderThickness = 0
    $revertInfoButton.VerticalAlignment = 'Center'
    $revertInfoButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
    $revertInfoButton.Cursor = 'Hand'
    [System.Windows.Controls.DockPanel]::SetDock($revertInfoButton, 'Right')

    $revertInfoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $revertInfoButton.Template = [System.Windows.Markup.XamlReader]::Parse($revertInfoTemplate)
    $revertInfoButton.Add_Click({
            $description = 'Revert Mode will undo changes made by this tool, restoring AI features and settings to their original state. Selected options above will be reverted/enabled when this mode is selected.'
            [System.Windows.MessageBox]::Show($description, 'Revert Mode', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        })

    $togglePanel1.Children.Add($revertInfoButton) | Out-Null
    $toggleGrid.Children.Add($togglePanel1) | Out-Null

    $togglePanel2 = New-Object System.Windows.Controls.DockPanel
    $togglePanel2.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $togglePanel2.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $togglePanel2.LastChildFill = $false
    [System.Windows.Controls.Grid]::SetRow($togglePanel2, 1)
        
    $toggleLabel2 = New-Object System.Windows.Controls.TextBlock
    $toggleLabel2.Text = 'Backup Mode:'
    $toggleLabel2.Foreground = [System.Windows.Media.Brushes]::White
    $toggleLabel2.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $toggleLabel2.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
    [System.Windows.Controls.DockPanel]::SetDock($toggleLabel2, 'Left')
    $togglePanel2.Children.Add($toggleLabel2) | Out-Null
        
    $backupModeToggle = Add-iOSToggleToUI -ParentControl $togglePanel2 -IsChecked $backup
    [System.Windows.Controls.DockPanel]::SetDock($backupModeToggle, 'Left')

    $backupInfoButton = New-Object System.Windows.Controls.Button
    $backupInfoButton.Content = '?'
    $backupInfoButton.Width = 25
    $backupInfoButton.Height = 25
    $backupInfoButton.FontSize = 12
    $backupInfoButton.FontWeight = 'Bold'
    $backupInfoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
    $backupInfoButton.Foreground = [System.Windows.Media.Brushes]::White
    $backupInfoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $backupInfoButton.BorderThickness = 0
    $backupInfoButton.VerticalAlignment = 'Center'
    $backupInfoButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
    $backupInfoButton.Cursor = 'Hand'
    [System.Windows.Controls.DockPanel]::SetDock($backupInfoButton, 'Right')

    $backupInfoTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="12">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $backupInfoButton.Template = [System.Windows.Markup.XamlReader]::Parse($backupInfoTemplate)
    $backupInfoButton.Add_Click({
            $description = 'Backup Mode keeps necessary files in your User directory allowing revert mode to work properly, use this option while removing AI if you would like to fully revert the removal process.'
            [System.Windows.MessageBox]::Show($description, 'Backup Mode', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        })

  
    $row3 = New-Object System.Windows.Controls.RowDefinition
    $row3.Height = [System.Windows.GridLength]::Auto
    $toggleGrid.RowDefinitions.Add($row3) | Out-Null

    $togglePanel3 = New-Object System.Windows.Controls.DockPanel
    $togglePanel3.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $togglePanel3.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $togglePanel3.Margin = New-Object System.Windows.Thickness(0, 10, 0, 0)
    $togglePanel3.LastChildFill = $false
    [System.Windows.Controls.Grid]::SetRow($togglePanel3, 2)

    $desktopShortcutCheckbox = New-Object System.Windows.Controls.CheckBox
    $desktopShortcutCheckbox.Content = 'Desktop Shortcut'
    $desktopShortcutCheckbox.FontSize = 14
    $desktopShortcutCheckbox.Foreground = [System.Windows.Media.Brushes]::White
    $desktopShortcutCheckbox.Margin = New-Object System.Windows.Thickness(0, 0, 20, 0)
    $desktopShortcutCheckbox.VerticalAlignment = 'Center'
    $desktopShortcutCheckbox.IsChecked = $false
    [System.Windows.Controls.DockPanel]::SetDock($desktopShortcutCheckbox, 'Left')
    $togglePanel3.Children.Add($desktopShortcutCheckbox) | Out-Null

    $startMenuShortcutCheckbox = New-Object System.Windows.Controls.CheckBox
    $startMenuShortcutCheckbox.Content = 'Start Menu Shortcut'
    $startMenuShortcutCheckbox.FontSize = 14
    $startMenuShortcutCheckbox.Foreground = [System.Windows.Media.Brushes]::White
    $startMenuShortcutCheckbox.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
    $startMenuShortcutCheckbox.VerticalAlignment = 'Center'
    $startMenuShortcutCheckbox.IsChecked = $false
    [System.Windows.Controls.DockPanel]::SetDock($startMenuShortcutCheckbox, 'Left')
    $togglePanel3.Children.Add($startMenuShortcutCheckbox) | Out-Null

    $shortcutInfoButton = New-Object System.Windows.Controls.Button
    $shortcutInfoButton.Content = '?'
    $shortcutInfoButton.Width = 25
    $shortcutInfoButton.Height = 25
    $shortcutInfoButton.FontSize = 12
    $shortcutInfoButton.FontWeight = 'Bold'
    $shortcutInfoButton.Background = [System.Windows.Media.Brushes]::DarkBlue
    $shortcutInfoButton.Foreground = [System.Windows.Media.Brushes]::White
    $shortcutInfoButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $shortcutInfoButton.BorderThickness = 0
    $shortcutInfoButton.VerticalAlignment = 'Center'
    $shortcutInfoButton.Cursor = 'Hand'
    [System.Windows.Controls.DockPanel]::SetDock($shortcutInfoButton, 'Right')
    $shortcutInfoButton.Template = [System.Windows.Markup.XamlReader]::Parse($revertInfoTemplate)
    $shortcutInfoButton.Add_Click({
            $description = 'Creates a shortcut that runs the latest version of this script from GitHub.'
            [System.Windows.MessageBox]::Show($description, 'Shortcut Options', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        })
    $togglePanel3.Children.Add($shortcutInfoButton) | Out-Null

    $toggleGrid.Children.Add($togglePanel3) | Out-Null

    $togglePanel2.Children.Add($backupInfoButton) | Out-Null
    $toggleGrid.Children.Add($togglePanel2) | Out-Null
    # ensure that backup mode and revert mode arent both selected at the same time (cant believe i have to do this....)
    $backupModeToggle.Add_Checked({ 
            $Global:backup = 1
            $revertModeToggle.IsChecked = $false
        }) | Out-Null

    $backupModeToggle.Add_Unchecked({ 
            $Global:backup = 0 
        }) | Out-Null

    $revertModeToggle.Add_Checked({ 
            $Global:revert = 1 
            $backupModeToggle.IsChecked = $false
        }) | Out-Null

    $revertModeToggle.Add_Unchecked({ 
            $Global:revert = 0 
        }) | Out-Null
   
    $bottomGrid = New-Object System.Windows.Controls.Grid
    [System.Windows.Controls.Grid]::SetRow($bottomGrid, 3)
    $bottomGrid.Margin = '25,15,25,15'

    $leftColumn = New-Object System.Windows.Controls.ColumnDefinition
    $leftColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $bottomGrid.ColumnDefinitions.Add($leftColumn) | Out-Null

    $rightColumn = New-Object System.Windows.Controls.ColumnDefinition
    $rightColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $bottomGrid.ColumnDefinitions.Add($rightColumn) | Out-Null

    $socialPanel = New-Object System.Windows.Controls.StackPanel
    $socialPanel.Orientation = 'Horizontal'
    $socialPanel.HorizontalAlignment = 'Left'
    $socialPanel.VerticalAlignment = 'Center'
    [System.Windows.Controls.Grid]::SetColumn($socialPanel, 0)

    # Base64 encoded png icons
    $Global:discordIconBase64 = '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'

    $Global:githubIconBase64 = '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'

    function New-ImageFromBase64 {
        param([string]$base64String)
    
        try {
            $imageBytes = [Convert]::FromBase64String($base64String)
            $stream = New-Object System.IO.MemoryStream($imageBytes, 0, $imageBytes.Length)
        
            $image = New-Object System.Windows.Controls.Image
            $bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
            $bitmap.BeginInit()
            $bitmap.StreamSource = $stream
            $bitmap.CacheOption = 'OnLoad'
            $bitmap.CreateOptions = 'PreservePixelFormat'
            $bitmap.EndInit()
        
            [System.Windows.Media.RenderOptions]::SetBitmapScalingMode($image, 'HighQuality')
            [System.Windows.Media.RenderOptions]::SetEdgeMode($image, 'Unspecified')
            $image.Source = $bitmap
        
            $image.Width = 30  
            $image.Height = 30
            $image.Stretch = 'Uniform'  
            $image.HorizontalAlignment = 'Center'
            $image.VerticalAlignment = 'Center'
        
            return $image
        }
        catch {
            Write-Host "Error loading image: $($_.Exception.Message)"
            # Fallback text if image fails to load
            $textBlock = New-Object System.Windows.Controls.TextBlock
            $textBlock.Text = '?'
            $textBlock.Foreground = [System.Windows.Media.Brushes]::White
            $textBlock.FontSize = 16
            $textBlock.HorizontalAlignment = 'Center'
            $textBlock.VerticalAlignment = 'Center'
            return $textBlock
        }
    }


    $discordButton = New-Object System.Windows.Controls.Button
    $discordButton.Width = 40
    $discordButton.Height = 40
    $discordButton.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(114, 137, 218))  # Discord blue
    $discordButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $discordButton.BorderThickness = 0
    $discordButton.Margin = '0,0,10,0'
    $discordButton.Cursor = 'Hand'

    $discordIcon = New-ImageFromBase64 -base64String $Global:discordIconBase64
    $discordButton.Content = $discordIcon

    $discordTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="20">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $discordButton.Template = [System.Windows.Markup.XamlReader]::Parse($discordTemplate)
    $discordButton.Add_Click({
            Start-Process 'https://discord.gg/VsC7XS5vgA'
        })

    $githubButton = New-Object System.Windows.Controls.Button
    $githubButton.Width = 40
    $githubButton.Height = 40
    $githubButton.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(83, 83, 83))  # GitHub dark #rgb(83, 83, 83)
    $githubButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $githubButton.BorderThickness = 0
    $githubButton.Cursor = 'Hand'

    $githubIcon = New-ImageFromBase64 -base64String $Global:githubIconBase64
    $githubButton.Content = $githubIcon

    $githubTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="20">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $githubButton.Template = [System.Windows.Markup.XamlReader]::Parse($githubTemplate)
    $githubButton.Add_Click({
            Start-Process 'https://github.com/zoicware/RemoveWindowsAI'
        })

    $socialPanel.Children.Add($discordButton) | Out-Null
    $socialPanel.Children.Add($githubButton) | Out-Null

    $actionPanel = New-Object System.Windows.Controls.StackPanel
    $actionPanel.Orientation = 'Horizontal'
    $actionPanel.HorizontalAlignment = 'Right'
    $actionPanel.VerticalAlignment = 'Center'
    [System.Windows.Controls.Grid]::SetColumn($actionPanel, 1)

    $cancelButton = New-Object System.Windows.Controls.Button
    $cancelButton.Content = 'Cancel'
    $cancelButton.Width = 80
    $cancelButton.Height = 35
    $cancelButton.Background = [System.Windows.Media.Brushes]::DarkRed
    $cancelButton.Foreground = [System.Windows.Media.Brushes]::White
    $cancelButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $cancelButton.BorderThickness = 0
    $cancelButton.Margin = '0,0,10,0'
    $cancelButton.Cursor = 'Hand'

    $cancelTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="17">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $cancelButton.Template = [System.Windows.Markup.XamlReader]::Parse($cancelTemplate)
    $cancelButton.Add_Click({
            $window.Close()
        })

    $applyButton = New-Object System.Windows.Controls.Button
    $applyButton.Content = 'Apply'
    $applyButton.Width = 80
    $applyButton.Height = 35
    $applyButton.Background = [System.Windows.Media.Brushes]::DarkGreen
    $applyButton.Foreground = [System.Windows.Media.Brushes]::White
    $applyButton.BorderBrush = [System.Windows.Media.Brushes]::Transparent
    $applyButton.BorderThickness = 0
    $applyButton.Cursor = 'Hand'

    $applyTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
    <Border Background="{TemplateBinding Background}" 
            BorderBrush="{TemplateBinding BorderBrush}" 
            BorderThickness="{TemplateBinding BorderThickness}" 
            CornerRadius="17">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border>
</ControlTemplate>
'@
    $applyButton.Template = [System.Windows.Markup.XamlReader]::Parse($applyTemplate)
    $applyButton.Add_Click({
            Write-Status -msg 'Killing AI Processes...'
            #kill ai processes to ensure script runs smoothly
            $aiProcesses = @(
                'ai.exe'
                'Copilot.exe'
                'aihost.exe'
                'aicontext.exe'
                'ClickToDo.exe'
                'aixhost.exe'
                'WorkloadsSessionHost.exe'
                'WebViewHost.exe'
                'aimgr.exe'
                'AppActions.exe'
                'M365Copilot.exe'
            )
            foreach ($procName in $aiProcesses) {
                taskkill /im $procName /f *>$null
            }
    
            $progressWindow = New-Object System.Windows.Window
            $progressWindow.Title = 'Processing...'
            $progressWindow.Width = 400
            $progressWindow.Height = 200
            $progressWindow.WindowStartupLocation = 'CenterOwner'
            $progressWindow.Owner = $window
            $progressWindow.Background = [System.Windows.Media.Brushes]::Black
            $progressWindow.Foreground = [System.Windows.Media.Brushes]::White
            $progressWindow.ResizeMode = 'NoResize'
    
            $progressGrid = New-Object System.Windows.Controls.Grid
            $progressWindow.Content = $progressGrid
    
            $progressText = New-Object System.Windows.Controls.TextBlock
            $progressText.Text = 'Initializing...'
            $progressText.FontSize = 14
            $progressText.Foreground = [System.Windows.Media.Brushes]::Cyan
            $progressText.HorizontalAlignment = 'Center'
            $progressText.VerticalAlignment = 'Center'
            $progressText.TextWrapping = 'Wrap'
            $progressGrid.Children.Add($progressText) | Out-Null
    
            $progressWindow.Show()
    
            $selectedFunctions = @()
            foreach ($func in $allFunctions) {
                if ($checkboxes[$func].IsChecked) {
                    $selectedFunctions += $func
                }
            }
    
            if ($selectedFunctions.Count -eq 0 -and !$desktopShortcutCheckbox.IsChecked -and !$startMenuShortcutCheckbox.IsChecked) {
                $progressWindow.Close()
                [System.Windows.MessageBox]::Show('No options selected.', 'Nothing to Process', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                return
            }
    
            try {
                if ($backup) {
                    Create-RestorePoint
                }
                foreach ($func in $selectedFunctions) {
                    $progressText.Text = "Executing: $($func.Replace('-', ' '))"
                    $progressWindow.UpdateLayout()
                    [System.Windows.Forms.Application]::DoEvents()

                    switch ($func) {
                        'Disable-Registry-Keys' { Disable-Registry-Keys }
                        'Prevent-AI-Package-Reinstall' { Install-NOAIPackage }
                        'Disable-Copilot-Policies' { Disable-Copilot-Policies }
                        'Remove-AI-Appx-Packages' { Remove-AI-Appx-Packages }
                        'Remove-Recall-Optional-Feature' { Remove-Recall-Optional-Feature }
                        'Remove-AI-CBS-Packages' { Remove-AI-CBS-Packages }
                        'Remove-AI-Files' { Remove-AI-Files }
                        'Hide-AI-Components' { Hide-AI-Components }
                        'Disable-Notepad-Rewrite' { Disable-Notepad-Rewrite }
                        'Remove-WindowsAI-Tasks' { Remove-WindowsAI-Tasks }
                        'Update-Cleanup-Check' { Update-Cleanup-Check }
                        'Install-Classic-Photoviewer' { install-classicapps -app 'photoviewer' }
                        'Install-Classic-Mspaint' { install-classicapps -app 'mspaint' }
                        'Install-Classic-SnippingTool' { install-classicapps -app 'snippingtool' }
                        'Install-Classic-Notepad' { install-classicapps -app 'notepad' }
                        'Install-Photos-Legacy' { install-classicapps -app 'photoslegacy' }
                    }
            
                    Start-Sleep -Milliseconds 500
                }

                if ($desktopShortcutCheckbox.IsChecked -or $startMenuShortcutCheckbox.IsChecked) {
                    $progressText.Text = 'Creating shortcuts...'
                    $progressWindow.UpdateLayout()
                    [System.Windows.Forms.Application]::DoEvents()
                    Create-ScriptShortcut -Desktop:$desktopShortcutCheckbox.IsChecked -Start:$startMenuShortcutCheckbox.IsChecked
                }
        
                $progressText.Text = 'Completed successfully!'
                Start-Sleep -Seconds 2
                $progressWindow.Close()
        
                $result = [System.Windows.MessageBox]::Show("AI removal process completed successfully!`n`nWould you like to restart your computer now to ensure all changes take effect?", 'Process Complete', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        
                if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                    #cleanup code
                    try {
                        Remove-Item "$($tempDir)aiPackageRemoval.ps1" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}
                    try {
                        Remove-Item "$($tempDir)RemoveRecallTasks.ps1" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}
                    try {
                        Remove-Item "$($tempDir)PathsToDelete.txt" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}  
                    try {
                        Remove-Item "$($tempDir)ZoicwareRemoveWindowsAI-*1.0.0.0.cab" -Force -ErrorAction SilentlyContinue
                    }
                    catch {}

                    #set executionpolicy back to what it was
                    if ($Global:ogExecutionPolicy) {
                        Reg.exe add $($Global:ogExecutionPolicyPath -replace ':', '') /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
                    }
                    Restart-Computer -Force
                }
        
                $window.Close()
            }
            catch {
                $progressWindow.Close()
                [System.Windows.MessageBox]::Show("An error occurred: $($_.Exception.Message)", 'Error', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        })


    $actionPanel.Children.Add($cancelButton) | Out-Null
    $actionPanel.Children.Add($applyButton) | Out-Null

    $bottomGrid.Children.Add($socialPanel) | Out-Null
    $bottomGrid.Children.Add($actionPanel) | Out-Null
    $mainGrid.Children.Add($bottomGrid) | Out-Null

    $window.ShowDialog() | Out-Null
}

#cleanup code
try {
    Remove-Item "$($tempDir)aiPackageRemoval.ps1" -Force -ErrorAction SilentlyContinue
}
catch {}
try {
    Remove-Item "$($tempDir)RemoveRecallTasks.ps1" -Force -ErrorAction SilentlyContinue
}
catch {}
try {
    Remove-Item "$($tempDir)PathsToDelete.txt" -Force -ErrorAction SilentlyContinue
}
catch {}
try {
    Remove-Item "$($tempDir)ZoicwareRemoveWindowsAI-*1.0.0.0.cab" -Force -ErrorAction SilentlyContinue
}
catch {}

#set executionpolicy back to what it was
if ($Global:ogExecutionPolicy) {
    Reg.exe add $($Global:ogExecutionPolicyPath -replace ':', '') /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
}

if (!$nonInteractive) {
    Write-Host 'Done! Press Any Key to Exit...' -ForegroundColor Green
    [System.Console]::ReadKey() >$null
}