If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

function Run-Trusted([String]$command) {

    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    #get bin path to revert later
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    #make sure path is valid and the correct location
    $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
    if ($DefaultBinPath -ne $trustedInstallerPath) {
        $DefaultBinPath = $trustedInstallerPath
    }
    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
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
        [bool]$errorOutput = $false
    )
    if ($errorOutput) {
        Write-Host "[ ! ] $msg" -ForegroundColor Red
    }
    else {
        Write-Host "[ + ] $msg" -ForegroundColor Cyan
    }
   
    
}

Write-Host '~ ~ ~ Remove Windows AI by @zoicware ~ ~ ~' -ForegroundColor DarkCyan

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
)
foreach ($procName in $aiProcesses) {
    taskkill /im $procName /f *>$null
}

#disable ai registry keys
Write-Status -msg 'Disabling Copilot and Recall...'
#set for local machine and current user to be sure
$hives = @('HKLM', 'HKCU')
foreach ($hive in $hives) {
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v 'TurnOffWindowsCopilot' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableAIDataAnalysis' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'AllowRecallEnablement' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableClickToDo' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat" /v 'IsUserEligible' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v 'IsCopilotAvailable' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Microsoft\Windows\Shell\Copilot" /v 'CopilotDisabledReason' /t REG_SZ /d 'FeatureIsDisabled' /f *>$null
}
Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCopilotButton' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKCU\Software\Microsoft\input\Settings' /v 'InsightsEnabled' /t REG_DWORD /d '0' /f *>$null
#remove copilot from search
Write-Status -msg 'Disabling Copilot In Windows Search...'
Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableSearchBoxSuggestions' /t REG_DWORD /d '1' /f *>$null
#disable copilot in edge
Write-Status -msg 'Disabling Copilot In Edge...'
Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotCDPPageContext' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Edge' /v 'HubsSidebarEnabled' /t REG_DWORD /d '0' /f *>$null
#disable additional keys
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'AutoOpenCopilotLargeScreens' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI' /v 'Value' /t REG_SZ /d 'Deny' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessGenerativeAI' /t REG_DWORD /d '2' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessSystemAIModels' /t REG_DWORD /d '2' /f *>$null
Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsCopilot' /v 'AllowCopilotRuntime' /t REG_DWORD /d '0' /f *>$null
#disable ai image creator in paint
Write-Status -msg 'Disabling Image Creator In Paint...'
#policy manager keys prob not neccessary 
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'Behavior' /t REG_DWORD /d '1056800' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'highrange' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'lowrange' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'mergealgorithm' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'policytype' /t REG_DWORD /d '4' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'RegKeyPathRedirect' /t REG_SZ /d 'Software\Microsoft\Windows\CurrentVersion\Policies\Paint' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'RegValueNameRedirect' /t REG_SZ /d 'DisableImageCreator' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'value' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableImageCreator' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableCocreator' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableGenerativeFill' /t REG_DWORD /d '1' /f *>$null
#force policy changes
Write-Status -msg 'Applying Registry Changes...'
gpupdate /force >$null


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
                Run-Trusted -command $command
                Start-Sleep 1
                #remove any regular admin that have trusted installer bug
                Remove-Item -Path "registry::$multikey" -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
        else {
            $command = "Remove-Item -Path `"registry::$fullKey`" -Force -Recurse"
            Run-Trusted -command $command
            Start-Sleep 1
            #remove any regular admin that have trusted installer bug
            Remove-Item -Path "registry::$fullKey" -Force -Recurse -ErrorAction SilentlyContinue
        }
        
    }
    catch {
        continue
    }
}
    
    





#disable copilot policies in region policy json
$JSONPath = "$env:windir\System32\IntegratedServicesRegionPolicySet.json"
if (Test-Path $JSONPath) {
    Write-Host 'Disabling CoPilot Policies in ' -NoNewline
    Write-Host "[$JSONPath]" -ForegroundColor Yellow

    #takeownership
    takeown /f $JSONPath *>$null
    icacls $JSONPath /grant administrators:F /t *>$null

    #edit the content
    $jsonContent = Get-Content $JSONPath | ConvertFrom-Json
    try {
        $copilotPolicies = $jsonContent.policies | Where-Object { $_.'$comment' -like '*CoPilot*' }
        foreach ($policies in $copilotPolicies) {
            $policies.defaultState = 'disabled'
        }
        $newJSONContent = $jsonContent | ConvertTo-Json -Depth 100
        Set-Content $JSONPath -Value $newJSONContent -Force
        Write-Status -msg "$($copilotPolicies.count) CoPilot Policies Disabled"
    }
    catch {
        Write-Status -msg 'CoPilot Not Found in IntegratedServicesRegionPolicySet' -errorOutput $true
    }

    
}

#to make this part faster make a txt file in temp with chunck of removal 
#code and then just run that from run 
#trusted function due to the design of having it hidden from the user

$packageRemovalPath = "$env:TEMP\aiPackageRemoval.ps1"
if (!(test-path $packageRemovalPath)) {
    New-Item $packageRemovalPath -Force | Out-Null
}

#needed for separate powershell sessions
$aipackages = @(
    'MicrosoftWindows.Client.Photon'
    'MicrosoftWindows.Client.AIX'
    'MicrosoftWindows.Client.CoPilot'
    'Microsoft.Windows.Ai.Copilot.Provider'
    'Microsoft.Copilot'
    'Microsoft.MicrosoftOfficeHub'
    'MicrosoftWindows.Client.CoreAI'
    #ai component packages installed on copilot+ pcs
    'WindowsWorkload.Data.Analysis.Stx.1'
    'WindowsWorkload.Manager.1'
    'WindowsWorkload.PSOnnxRuntime.Stx.2.7'
    'WindowsWorkload.PSTokenizer.Stx.2.7'
    'WindowsWorkload.QueryBlockList.1'
    'WindowsWorkload.QueryProcessor.Data.1'
    'WindowsWorkload.QueryProcessor.Stx.1'
    'WindowsWorkload.SemanticText.Data.1'
    'WindowsWorkload.SemanticText.Stx.1'
    'WindowsWorkload.Data.ContentExtraction.Stx.1'
    'WindowsWorkload.ScrRegDetection.Data.1'
    'WindowsWorkload.ScrRegDetection.Stx.1'
    'WindowsWorkload.TextRecognition.Stx.1'
    'WindowsWorkload.Data.ImageSearch.Stx.1'
    'WindowsWorkload.ImageContentModeration.1'
    'WindowsWorkload.ImageContentModeration.Data.1'
    'WindowsWorkload.ImageSearch.Data.3'
    'WindowsWorkload.ImageSearch.Stx.2'
    'WindowsWorkload.ImageSearch.Stx.3'
    'WindowsWorkload.ImageTextSearch.Data.3'
    'WindowsWorkload.PSOnnxRuntime.Stx.3.2'
    'WindowsWorkload.PSTokenizerShared.Data.3.2'
    'WindowsWorkload.PSTokenizerShared.Stx.3.2'
    'WindowsWorkload.ImageTextSearch.Stx.2'
    'WindowsWorkload.ImageTextSearch.Stx.3'
)

$code = @'
$aipackages = @(
    'MicrosoftWindows.Client.Photon'
    'MicrosoftWindows.Client.AIX'
    'MicrosoftWindows.Client.CoPilot'
    'Microsoft.Windows.Ai.Copilot.Provider'
    'Microsoft.Copilot'
    'Microsoft.MicrosoftOfficeHub'
    'MicrosoftWindows.Client.CoreAI'
    'WindowsWorkload.Data.Analysis.Stx.1'
    'WindowsWorkload.Manager.1'
    'WindowsWorkload.PSOnnxRuntime.Stx.2.7'
    'WindowsWorkload.PSTokenizer.Stx.2.7'
    'WindowsWorkload.QueryBlockList.1'
    'WindowsWorkload.QueryProcessor.Data.1'
    'WindowsWorkload.QueryProcessor.Stx.1'
    'WindowsWorkload.SemanticText.Data.1'
    'WindowsWorkload.SemanticText.Stx.1'
    'WindowsWorkload.Data.ContentExtraction.Stx.1'
    'WindowsWorkload.ScrRegDetection.Data.1'
    'WindowsWorkload.ScrRegDetection.Stx.1'
    'WindowsWorkload.TextRecognition.Stx.1'
    'WindowsWorkload.Data.ImageSearch.Stx.1'
    'WindowsWorkload.ImageContentModeration.1'
    'WindowsWorkload.ImageContentModeration.Data.1'
    'WindowsWorkload.ImageSearch.Data.3'
    'WindowsWorkload.ImageSearch.Stx.2'
    'WindowsWorkload.ImageSearch.Stx.3'
    'WindowsWorkload.ImageTextSearch.Data.3'
    'WindowsWorkload.PSOnnxRuntime.Stx.3.2'
    'WindowsWorkload.PSTokenizerShared.Data.3.2'
    'WindowsWorkload.PSTokenizerShared.Stx.3.2'
    'WindowsWorkload.ImageTextSearch.Stx.2'
    'WindowsWorkload.ImageTextSearch.Stx.3'
)

$provisioned = get-appxprovisionedpackage -online 
$appxpackage = get-appxpackage -allusers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

#use eol trick to uninstall some locked packages
foreach ($choice in $aipackages) {
    foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {

        $PackageName = $appx.PackageName 
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName

        New-Item "$store\Deprovisioned\$PackageFamilyName" -force
     
        Set-NonRemovableAppsPolicy -Online -PackageFamilyName $PackageFamilyName -NonRemovable 0
       
        foreach ($sid in $users) { 
            New-Item "$store\EndOfLife\$sid\$PackageName" -force
        }  
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
            if ($users -notcontains $sid) {
                $users += $sid
            }
            New-Item "$store\EndOfLife\$sid\$PackageFullName" -force
            remove-appxpackage -package $PackageFullName -User $sid 
        } 
        remove-appxpackage -package $PackageFullName -allusers
    }
}
'@
Set-Content -Path $packageRemovalPath -Value $code -Force 
#allow removal script to run
try {
    Set-ExecutionPolicy Unrestricted -Force -ErrorAction Stop
}
catch {
    #user has set powershell execution policy via group policy, to change it we need to update the registry 
    $ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
}


Write-Status -msg 'Removing AI Appx Packages...'
$command = "&$env:TEMP\aiPackageRemoval.ps1"
Run-Trusted -command $command

#check packages removal
do {
    Start-Sleep 1
    $packages = get-appxpackage -AllUsers | Where-Object { $aipackages -contains $_.Name }
    if ($packages) {
        $command = "&$env:TEMP\aiPackageRemoval.ps1"
        Run-Trusted -command $command
    }
    
}while ($packages)

Write-Status -msg 'Packages Removed Sucessfully...'

## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
$eolPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife'
$eolKeys = (Get-ChildItem $eolPath).Name
foreach ($path in $eolKeys) {
    Remove-Item "registry::$path" -Recurse -Force -ErrorAction SilentlyContinue
}

#remove recall optional feature 
Write-Status -msg 'Removing Recall Optional Feature...'
$state = (Get-WindowsOptionalFeature -Online -FeatureName 'Recall').State
if ($state -and $state -ne 'DisabledWithPayloadRemoved') {
    $ProgressPreference = 'SilentlyContinue'
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -Remove -NoRestart -ErrorAction Stop *>$null
    }
    catch {
        #hide error
    }
    
}

Write-Status -msg 'Removing Appx Package Files...'
#-----------------------------------------------------------------------remove files
$appsPath = 'C:\Windows\SystemApps'
$appsPath2 = 'C:\Program Files\WindowsApps'
$pathsSystemApps = (Get-ChildItem -Path $appsPath -Directory -Force).FullName 
$pathsWindowsApps = (Get-ChildItem -Path $appsPath2 -Directory -Force).FullName 

$packagesPath = @()
#get full path
foreach ($package in $aipackages) {

    foreach ($path in $pathsSystemApps) {
        if ($path -like "*$package*") {
            $packagesPath += $path
        }
    }

    foreach ($path in $pathsWindowsApps) {
        if ($path -like "*$package*") {
            $packagesPath += $path
        }
    }

}


foreach ($Path in $packagesPath) {
    #only remove dlls from photon to prevent startmenu from breaking
    if ($path -like '*Photon*') {
        $command = "`$dlls = (Get-ChildItem -Path $Path -Filter *.dll).FullName; foreach(`$dll in `$dlls){Remove-item ""`$dll"" -force}"
        Run-Trusted -command $command
        Start-Sleep 1
    }
    else {
        $command = "Remove-item ""$Path"" -force -recurse"
        Run-Trusted -command $command
        Start-Sleep 1
    }
}

#remove machine learning dlls
$paths = @(
    "$env:SystemRoot\System32\Windows.AI.MachineLearning.dll"
    "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.dll"
    "$env:SystemRoot\System32\Windows.AI.MachineLearning.Preview.dll"
    "$env:SystemRoot\SysWOW64\Windows.AI.MachineLearning.Preview.dll"
)
foreach ($path in $paths) {
    takeown /f $path *>$null
    icacls $path /grant administrators:F /t *>$null
    try {
        Remove-Item -Path $path -Force -ErrorAction Stop
    }
    catch {
        #takeown didnt work remove file with system priv
        $command = "Remove-Item -Path $path -Force"
        Run-Trusted -command $command 
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


#remove additional installers
$inboxapps = 'C:\Windows\InboxApps'
$installers = Get-ChildItem -Path $inboxapps -Filter '*Copilot*'
foreach ($installer in $installers) {
    takeown /f $installer.FullName *>$null
    icacls $installer.FullName /grant administrators:F /t *>$null
    try {
        Remove-Item -Path $installer.FullName -Force -ErrorAction Stop
    }
    catch {
        #takeown didnt work remove file with system priv
        $command = "Remove-Item -Path $($installer.FullName) -Force"
        Run-Trusted -command $command 
    }
    
}


#hide ai components in immersive settings
Write-Status -msg 'Hiding Ai Components in Settings...'
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d 'hide:aicomponents;' /f >$null

#disable rewrite for notepad
Write-Status -msg 'Disabling Rewrite Ai Feature for Notepad...'
#load notepad settings
reg load HKU\TEMP "$env:LOCALAPPDATA\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\Settings\settings.dat" >$null
#add disable rewrite
$regContent = @'
Windows Registry Editor Version 5.00

[HKEY_USERS\TEMP\LocalState]
"RewriteEnabled"=hex(5f5e10b):00,e0,d1,c5,7f,ee,83,db,01
'@
New-Item "$env:TEMP\DisableRewrite.reg" -Value $regContent -Force | Out-Null
regedit.exe /s "$env:TEMP\DisableRewrite.reg"
Start-Sleep 1
reg unload HKU\TEMP >$null
Remove-Item "$env:TEMP\DisableRewrite.reg" -Force -ErrorAction SilentlyContinue
#above is old method before this policy to disable ai in notepad, leaving older method just incase 
Reg.exe add 'HKLM\SOFTWARE\Policies\WindowsNotepad' /v 'DisableAIFeatures' /t REG_DWORD /d '1' /f *>$null

#remove any screenshots from recall
Write-Status -msg 'Removing Any Screenshots By Recall...'
Remove-Item -Path "$env:LOCALAPPDATA\CoreAIPlatform*" -Force -Recurse -ErrorAction SilentlyContinue

#remove recall tasks
Write-Status -msg 'Removing Recall Scheduled Tasks...'
#believe it or not to disable and remove these you need system priv
#create another sub script for removal
$code = @"
Get-ScheduledTask -TaskPath "*Recall*" | Disable-ScheduledTask -ErrorAction SilentlyContinue
Remove-Item "`$env:Systemroot\System32\Tasks\Microsoft\Windows\WindowsAI" -Recurse -Force -ErrorAction SilentlyContinue
`$initConfigID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration" -Name 'Id'
`$policyConfigID = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration" -Name 'Id'

Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$initConfigID" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`$policyConfigID" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WindowsAI" -Force -Recurse -ErrorAction SilentlyContinue
"@
$subScript = "$env:TEMP\RemoveRecallTasks.ps1"
New-Item $subScript -Force | Out-Null
Set-Content $subScript -Value $code -Force

$command = "&$subScript"
Run-Trusted -command $command
Start-Sleep 1

#cleanup code
Remove-Item $packageRemovalPath -Force
Remove-Item $subScript -Force
#set executionpolicy back to what it was
if ($ogExecutionPolicy) {
    Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
}

$input = Read-Host 'Done! Press Any Key to Exit'
if ($input) { exit }
