If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

function Run-Trusted([String]$command) {

    Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
    #get bin path to revert later
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
    #run the command
    sc.exe start TrustedInstaller | Out-Null
    #set bin back to default
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    # Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue

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

#disable ai registry keys
Write-Status -msg 'Disabling Copilot and Recall...'
#set for local machine and current user to be sure
$hives = @('HKLM', 'HKCU')
foreach ($hive in $hives) {
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v 'TurnOffWindowsCopilot' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'DisableAIDataAnalysis' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add "$hive\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v 'AllowRecallEnablement' /t REG_DWORD /d '0' /f *>$null
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
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat' /v 'IsUserEligible' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat' /v 'IsUserEligible' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'AutoOpenCopilotLargeScreens' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI' /v 'Value' /t REG_SZ /d 'Deny' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessGenerativeAI' /t REG_DWORD /d '2' /f *>$null
#disable ai image creator in paint
Write-Status -msg 'Disabling Image Creator In Paint...'
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'Behavior' /t REG_DWORD /d '1056800' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'highrange' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'lowrange' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'mergealgorithm' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'policytype' /t REG_DWORD /d '4' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'RegKeyPathRedirect' /t REG_SZ /d 'Software\Microsoft\Windows\CurrentVersion\Policies\Paint' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'RegValueNameRedirect' /t REG_SZ /d 'DisableImageCreator' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableImageCreator' /v 'value' /t REG_DWORD /d '0' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableImageCreator' /t REG_DWORD /d '1' /f *>$null
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
)

$provisioned = get-appxprovisionedpackage -online 
$appxpackage = get-appxpackage -allusers
$eol = @()
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
        $eol += $PackageName
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
        $eol += $PackageFullName
        remove-appxpackage -package $PackageFullName -allusers
    }
}
'@
Set-Content -Path $packageRemovalPath -Value $code -Force 

Write-Status -msg 'Removing AI Appx Packages...'
$command = "&$env:TEMP\aiPackageRemoval.ps1"
Run-Trusted -command $command

#check packages removal
do {
    Start-Sleep 1
    $packages = get-appxpackage -AllUsers | Where-Object { $aipackages -contains $_.Name }
    foreach ($package in $packages) {
        if ($package.PackageUserInformation -like '*pending removal*') {
            $ProgressPreference = 'SilentlyContinue'
            &$env:TEMP\aiPackageRemoval.ps1 *>$null
        }
    }
    
}while ($packages)

Write-Status -msg 'Packages Removed Sucessfully...'
#cleanup code
Remove-Item $packageRemovalPath -Force

## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
$eolPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife'
$eolKeys = (Get-ChildItem $eolPath).Name
foreach ($path in $eolKeys) {
    Remove-Item "registry::$path" -Recurse -Force -ErrorAction SilentlyContinue
}

#remove recall optional feature 
$ProgressPreference = 'SilentlyContinue'
try {
    Write-Status -msg 'Removing Recall Optional Feature...'
    Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -Remove -NoRestart -ErrorAction Stop *>$null
}
catch {
    #hide error
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

#remove any screenshots from recall
Write-Status -msg 'Removing Any Screenshots By Recall...'
Remove-Item -Path "$env:LOCALAPPDATA\CoreAIPlatform*" -Force -Recurse -ErrorAction SilentlyContinue


$input = Read-Host 'Done! Press Any Key to Exit'
if ($input) { exit }
