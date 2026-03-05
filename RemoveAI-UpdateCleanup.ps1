function Run-Trusted([String]$command, $psversion) {

    function RunAsTI {
        param(
            [Parameter(Position = 0)]$cmd, 
            [Parameter(ValueFromRemainingArguments)]$xargs
        )

        $Ex = $xargs -contains '-Exit'
        $xargs = $xargs | Where-Object { $_ -ne '-Exit' }
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $id = 'RunAsTI'
        $key = "Registry::HKU\$($wi.User.Value)\Volatile Environment"
        $arg = ''
        $rs = $false
        $csf = Get-PSCallStack | Where-Object { $_.ScriptName -and $_.ScriptName -like '*.ps1' } | Select-Object -l 1
        $cs = if ($csf) { $csf.ScriptName } else { $null }

        if (!$cmd) {
            if ((whoami /groups) -like '*S-1-16-16384*') { return }

            $rs = $true
            $arr = [Environment]::GetCommandLineArgs()
            $i = [array]::IndexOf($arr, '-File')
            if ($i -lt 0) { 
                $i = [array]::IndexOf($arr, '-f') 
            }

            if ($i -ge 0 -and ($i + 1) -lt $arr.Count) { 
                if (!$cs) { 
                    $cs = $arr[$i + 1] 
                } 

                if (($i + 2) -lt $arr.Count) { 
                    $arg = ($arr[($i + 2)..($arr.Count - 1)] | ForEach-Object { "`"$($_-replace'"','""')`"" }) -join ' ' 
                } 
            }
            else {
                $cp = if ($csf) { $csf.InvocationInfo.BoundParameters } else { Get-Variable PSBoundParameters -sc 1 -va -ea 0 } 

                $ca = if ($csf) { $csf.InvocationInfo.UnboundArguments } else { Get-Variable args -sc 1 -va -ea 0 }

                if ($null -eq $cp) { 
                    $cp = @{} 
                }
                if ($null -eq $ca) { 
                    $ca = @() 
                }

                $arg = (@($cp.GetEnumerator() | ForEach-Object { if (($_.Value -is [switch] -and $_.Value.IsPresent) -or ($_.Value -eq $true)) { "-$($_.Key)" }elseif ($_.Value -isnot [switch] -and $_.Value -ne $true -and $_.Value -ne $false) { "-$($_.Key) `"$($_.Value-replace'"','""')`"" } }) + @($ca | ForEach-Object { "`"$($_-replace'"','""')`"" })) -join ' '
            }

            if ($cs) { 
                $cmd = 'powershell'
                $arg = "-nop -ep bypass -f `"$cs`" $arg" 
            }
            else { 
                $cmd = 'powershell'
                $arg = '-nop -ep bypass' 
            }
        }
        elseif ($xargs) { 
            $arg = $xargs -join ' ' 
        } 

        $V = ''
        'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }

        Set-ItemProperty $key $id $($V, @'
 $I=[int32];$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$P=$I.module.gettype("System.Int`Ptr");$S=[string]
 $D=@();$T=@();$DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1);$Z=[uintptr]::size
 0..5|%{$D+=$DM."Defin`eType"("AveYo_$_",1179913,[ValueType])};$D+=[uintptr];4..6|%{$D+=$D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|%{$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|%{$k=$_;$n=1;$DF[$_-1]|%{$9=$D[$k]."Defin`eField"('f'+$n++,$_,6)}};0..5|%{$T+=$D[$_]."Creat`eType"()}
 0..5|%{nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo};function F($1,$2){$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*S-1-16-16384*';$As=0
 if(!$TI){'TrustedInstaller','lsass','winlogon'|%{if(!$As){$9=sc.exe start $_;$As=@(gps -name $_ -ea 0|%{$_})[0]}}
 function M($1,$2,$3){$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)};$H=@();$Z,(4*$Z+16)|%{$H+=M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle);$A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1
 $A2.f6=$A1;$A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1];M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2-as$D[2]),$A4.f2,$false)
 $Run=@($null,"powershell -win hidden -nop -c iex `$env:R; # $id",0,0,0,0x0E080600,0,$null,($A4-as$T[4]),($A5-as$T[5]))
 F 'CreateProcess' $Run;return};$env:R='';rp $key $id -force;$priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege'|%{$priv.Invoke($null,@("$_",2))}
 $HKU=[uintptr][uint32]2147483651;$NT='S-1-5-18';$reg=($HKU,$NT,8,2,($HKU-as$D[9]));F 'RegOpenKeyEx' $reg;$LNK=$reg[4]
 function L($1,$2,$3){sp 'HKLM\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 L ($key-split'\\')[1] $LNK '';$R=[diagnostics.process]::start($cmd,$arg);if($R){$R.WaitForExit()};L '.Default' $LNK 'Interactive User'
'@) -type 7

        $a = "-win hidden -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R"
        if ($Ex) { 
            $wshell = New-Object -ComObject WScript.Shell
            $exe = 'powershell.exe'
            $wshell.Run("$exe $a", 0, $false) >$null
        }
        else { 
            $wshell = New-Object -ComObject WScript.Shell
            $exe = 'powershell.exe'
            $wshell.Run("$exe $a", 0, $true) >$null # true to -wait
        } 

        # if ($rs -or $Ex) { exit }
    } 
    # lean & mean snippet by AveYo; refined by RapidOS [haslate]
    # zoicware change log:
    # changed start-process to wshell run to avoid the first powershell instance window from flashing


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
        RunAsTI $psexe "-win hidden -encodedcommand $base64Command"
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
$aipackages = @(
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
    'MicrosoftWindows.*.Voiess'
    'MicrosoftWindows.*.Speion'
    'MicrosoftWindows.*.Livtop'
    'MicrosoftWindows.*.InpApp'
    'MicrosoftWindows.*.Filons'
    'WindowsWorkload.Data.Analysis.Stx.*'
    'WindowsWorkload.Manager.*'
    'WindowsWorkload.PSOnnxRuntime.Stx.*'
    'WindowsWorkload.PSTokenizer.Stx.*'
    'WindowsWorkload.QueryBlockList.*'
    'WindowsWorkload.QueryProcessor.Data.*'
    'WindowsWorkload.QueryProcessor.Stx.*'
    'WindowsWorkload.SemanticText.Data.*'
    'WindowsWorkload.SemanticText.Stx.*'
    'WindowsWorkload.Data.ContentExtraction.Stx.*'
    'WindowsWorkload.ScrRegDetection.Data.*'
    'WindowsWorkload.ScrRegDetection.Stx.*'
    'WindowsWorkload.TextRecognition.Stx.*'
    'WindowsWorkload.Data.ImageSearch.Stx.*'
    'WindowsWorkload.ImageContentModeration.*'
    'WindowsWorkload.ImageContentModeration.Data.*'
    'WindowsWorkload.ImageSearch.Data.*'
    'WindowsWorkload.ImageSearch.Stx.*'
    'WindowsWorkload.ImageTextSearch.Data.*'
    'WindowsWorkload.PSOnnxRuntime.Stx.*'
    'WindowsWorkload.PSTokenizerShared.Data.*'
    'WindowsWorkload.PSTokenizerShared.Stx.*'
    'WindowsWorkload.ImageTextSearch.Stx.*'
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
        try {
            $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction Stop
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
            $Global:executionPolicyUser = $false
            $Global:executionPolicyMachine = $false
            $Global:executionPolicyWow64 = $false
            $Global:executionPolicyUserPol = $false
        }
        catch {
            try {
                $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction Stop
                Reg.exe add 'HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                $Global:executionPolicyUser = $true
                $Global:executionPolicyMachine = $false
                $Global:executionPolicyWow64 = $false
                $Global:executionPolicyUserPol = $false
            }
            catch {
                try {
                    $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction Stop
                    Reg.exe add 'HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                    $Global:executionPolicyUser = $false
                    $Global:executionPolicyMachine = $true
                    $Global:executionPolicyWow64 = $false
                    $Global:executionPolicyUserPol = $false
                }
                catch {
                    try {
                        $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction Stop
                        Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                        $Global:executionPolicyUser = $false
                        $Global:executionPolicyMachine = $false
                        $Global:executionPolicyWow64 = $true
                        $Global:executionPolicyUserPol = $false

                    }
                    catch {
                        $Global:ogExecutionPolicy = Get-ItemPropertyValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' 
                        Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
                        Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
                        $Global:executionPolicyUser = $false
                        $Global:executionPolicyMachine = $false
                        $Global:executionPolicyWow64 = $false
                        $Global:executionPolicyUserPol = $true
                    }
                        

                }
                    
            }
               
        }
            
           
    }

    $command = "&`"$($tempDir)aiPackageRemoval.ps1`""
    Run-Trusted -command $command

    #needed for separate powershell sessions
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
        #ai component packages installed on copilot+ pcs
        'MicrosoftWindows.*.Voiess'
        'MicrosoftWindows.*.Speion'
        'MicrosoftWindows.*.Livtop'
        'MicrosoftWindows.*.InpApp'
        'MicrosoftWindows.*.Filons'
        'WindowsWorkload.Data.Analysis.Stx.*'
        'WindowsWorkload.Manager.*'
        'WindowsWorkload.PSOnnxRuntime.Stx.*'
        'WindowsWorkload.PSTokenizer.Stx.*'
        'WindowsWorkload.QueryBlockList.*'
        'WindowsWorkload.QueryProcessor.Data.*'
        'WindowsWorkload.QueryProcessor.Stx.*'
        'WindowsWorkload.SemanticText.Data.*'
        'WindowsWorkload.SemanticText.Stx.*'
        'WindowsWorkload.Data.ContentExtraction.Stx.*'
        'WindowsWorkload.ScrRegDetection.Data.*'
        'WindowsWorkload.ScrRegDetection.Stx.*'
        'WindowsWorkload.TextRecognition.Stx.*'
        'WindowsWorkload.Data.ImageSearch.Stx.*'
        'WindowsWorkload.ImageContentModeration.*'
        'WindowsWorkload.ImageContentModeration.Data.*'
        'WindowsWorkload.ImageSearch.Data.*'
        'WindowsWorkload.ImageSearch.Stx.*'
        'WindowsWorkload.ImageTextSearch.Data.*'
        'WindowsWorkload.PSOnnxRuntime.Stx.*'
        'WindowsWorkload.PSTokenizerShared.Data.*'
        'WindowsWorkload.PSTokenizerShared.Stx.*'
        'WindowsWorkload.ImageTextSearch.Stx.*'
    )

    #check packages removal
    #exit loop after 10 tries
    $attempts = 0
    do {
        Start-Sleep 1
        $packages = get-appxpackage -AllUsers | Where-Object { $aipackages -contains $_.Name }
        if ($packages) {
            $attempts++
            $command = "&`"$($tempDir)aiPackageRemoval.ps1`""
            Run-Trusted -command $command
        }
    
    }while ($packages -and $attempts -lt 10)


    #add registry keys even tho im pretty sure they dont get changed 
    #add maybe some file cleanup




    #set executionpolicy back to what it was
    if ($ogExecutionPolicy) {
        if ($Global:executionPolicyUser) {
            Reg.exe add 'HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
        }
        elseif ($Global:executionPolicyMachine) {
            Reg.exe add 'HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
        }
        elseif ($Global:executionPolicyWow64) {
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
        }
        elseif ($Global:executionPolicyUserPol) {
            Reg.exe add 'HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
        }
        else {
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d $ogExecutionPolicy /f >$null
        }
    }
}