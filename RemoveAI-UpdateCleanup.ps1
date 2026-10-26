function Run-Trusted([String]$command, $psversion) {

    #modified from https://github.com/agadiffe/WindowsMize/blob/e64923ac8055f652c701e99da89a9b680070178e/src/modules/helper_functions/general/public/Invoke-CommandAsSystem.ps1
    function New-SystemScheduledTask {
        param(
            [string]$Name,
            [string]$command
        )

        $TaskTriggerParam = @{
            ClassName = 'MSFT_TaskRegistrationTrigger' # at task creation/modification
            Namespace = 'Root/Microsoft/Windows/TaskScheduler'
        }
        $Trigger = Get-CimClass @TaskTriggerParam -Verbose:$false

        $TaskPath = '\'
        $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -C `"$command`""
        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18'
        $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries

        $ScheduledTaskParam = @{
            TaskName  = $Name
            TaskPath  = $TaskPath
            Action    = $TaskAction
            Trigger   = $Trigger
            Principal = $TaskPrincipal
            Settings  = $TaskSettings
        }

        Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $Name -Confirm:$false -ErrorAction 'SilentlyContinue'
        Register-ScheduledTask @ScheduledTaskParam -Verbose:$false
    }

    function RunAsSystem {
        param(
            [string] $Command
        )

        $TaskData = New-SystemScheduledTask -Name 'RunAsSystem' -command $Command

        while ((Get-ScheduledTask -TaskPath $TaskData.TaskPath -TaskName $TaskData.TaskName).State -eq 'Running') {
            Start-Sleep -Seconds 0.1
        }

        Unregister-ScheduledTask -TaskPath $TaskData.TaskPath -TaskName $TaskData.TaskName -Confirm:$false 
    }

    $psexe = 'PowerShell.exe'

    $checkSvc = Get-Service 'TrustedInstaller' -ErrorAction SilentlyContinue
    if ($checkSvc -and $checkSvc.Status -eq 'Running') {
        taskkill /im trustedinstaller.exe /f *>$null
    }

    # trusted installer proc not found (128) or access denied (1)
    if ($LASTEXITCODE -eq 128 -or $LASTEXITCODE -eq 1 -or !$checkSvc) {
        Write-Status -msg 'Failed to stop TrustedInstaller.exe... Using fallback method!' -warningOutput
        RunAsSystem -Command $command
        Start-Sleep 1
        return 
    }

    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)

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
        taskkill /im trustedinstaller.exe /f *>$null
    }
    
}

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

function Set-FeatureID {
    param(
        [switch]$enable,
        [switch]$disable,
        [uint32]$FeatureId
    )

    $regID = ObfuscateFeatureId $FeatureId
    # 1 = disabled 2 = enabled
    $value = @('1', '2')[[int]([bool]$enable)]
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\$regID" /v 'EnabledState' /t REG_DWORD /d "$value" /f 
}

$Global:tempDir = ([System.IO.Path]::GetTempPath())
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
$OSBuild = "$($key.GetValue('CurrentBuild')).$($key.GetValue('UBR'))"
$key.Close()
try {
    $key2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\RemoveWindowsAI')
    $CurrentCachedBuild = "$($key2.GetValue('CachedBuild'))"
    $key2.Close()
}
catch {
    $CurrentCachedBuild = $null
}
$regValName = 'CachedBuild'
if ($CurrentCachedBuild -ne $OSBuild) {
    #update has occured because current cached build is not equal to current reported build
    #updated cached build
    Reg.exe add 'HKLM\SOFTWARE\RemoveWindowsAI' /v $regValName /d "$OSBuild" /t REG_SZ /f >$null

    #run through checks for reinstalled ai
    #===================================================================================================
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
    $packageRemovalPath = "$($tempDir)aiPackageRemoval.ps1"
    if (!(test-path $packageRemovalPath)) {
        New-Item $packageRemovalPath -Force | Out-Null
    }

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
        'Microsoft.Ink.Handwriting*'
        'Microsoft.AIFabric.CBS*'
        'MicrosoftWindows.*.Voiess'
        'MicrosoftWindows.*.Speion'
        'MicrosoftWindows.*.Livtop'
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
            #$command = "&`"$($tempDir)aiPackageRemoval.ps1`""
            Run-Trusted -command $command
        }
    
    }while ($packages -and $attempts -lt 10)

    Set-FeatureID -disable -FeatureId 58375086
    Set-FeatureID -disable -FeatureId 63366798
    Set-FeatureID -disable -FeatureId 58375066


    #add registry keys even tho im pretty sure they dont get changed 
    #add maybe some file cleanup


    #set executionpolicy back to what it was
    if ($Global:ogExecutionPolicy) {
        Reg.exe add $($Global:ogExecutionPolicyPath -replace ':', '') /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
}
