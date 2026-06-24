function Run-Trusted([String]$command, $psversion) {

    #run as ti by aveyo refactored for powershell use only
    #no powershell window flash
    #removed reg sym link as its not needed
    #fixed some issues with reflection methods
    function Invoke-AsTrustedInstaller {
        param(
            [Parameter(Mandatory)]
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


    #add registry keys even tho im pretty sure they dont get changed 
    #add maybe some file cleanup


    #set executionpolicy back to what it was
    if ($Global:ogExecutionPolicy) {
        Reg.exe add $($Global:ogExecutionPolicyPath -replace ':', '') /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
    }
}