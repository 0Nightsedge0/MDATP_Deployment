####################################################################################################################
#
# MDATP deployment Checking script POC
# Version: V1.0
# Last Edited: 9 Dec 2020
# Tested on: Windows 10, Windows Server 2016, 08r2, 12r2, 2012
# 64bit only!
# Warning: it is just a POC script, please edit for your environment before your apply it!
# Warning: some app / KB installation may cause network and IO congestion, please have a deployment stratehy before launch
#
####################################################################################################################

####################################################################################################################
#
# hardcoded variables:

Param(
    # **** important to edit ****
    # Share drive path
    [Parameter(Mandatory = $false)]
    [String]
    $Share_drive_path = "\\Mdatp-dc08r2\mdatp\MDATP_deploy_all_in_one\",

    # **** important to edit ****
    # MDATP onboarding checking log folder
    [Parameter(Mandatory = $false)]
    [String]
    $Log_folder = "onboarding_check_logs"
)

# Share Drive Path
$global:Scriptdir = $Share_drive_path

# Log folder Path
$global:Log_folder = $Log_folder


####################################################################################################################
#
# Functions
#
####################################################################################################################

Function Write-Log{
    [CmdletBinding()]
    
    Param(
        [Parameter(Mandatory = $True)]
        [string]
        $Message,

        [Parameter(Mandatory = $False)]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG", "SUCCESS")]
        [String]
        $Level = "INFO"
    )

    $Stamp = (Get-Date).ToUniversalTime().toString("yyyy/MM/dd HH:mm:ss") + "_UTC"

    $hostname = (hostname)
    $Line = "$Level, $hostname, $Stamp, $Message,"
    If ($global:logfile) {
        Add-Content $global:logfile -Value $Line
        $color = ""
        switch ($Level) {
            INFO { $color = "White"; break }
            WARN { $color = "Yellow"; break }
            ERROR { $color = "Red"; break }
            FATAL { $color = "Red"; break }
            DEBUG { $color = "Gray"; break }
            SUCCESS { $color = "Green"; break }
        }
        if ($Level -eq "FATAL") {
            Write-Host $Line -ForegroundColor $color -BackgroundColor White
        }
        else {
            Write-Host $Line -ForegroundColor $color
        }
    }
    Else {
        Write-Output $Line
    }
}

Function Get-WindowsVersion($check_os){
    if ($check_os -like "*Windows 10*"){
		Write-Log "[*] Windows 10 Detected"
        return "Windows 10"

    } elseif ($check_os -like "*Windows Server 2019*") {
		Write-Log "[*] Windows 2019 Detected"
        return "Windows 2019"

    } elseif ($check_os -like "*Windows Server 2016*") {
    	Write-Log "[*] Windows 2016 Detected"
        return "Windows 2016"

    } elseif ($check_os -like "*Windows Server 2012 R2*") {
        Write-Log "[*] Windows 2012 R2 Detected"
        return "Windows 2012 R2"

    } elseif ($check_os -like "*Windows Server 2012*") {
        Write-Log "[*] Windows 2012 Detected"
        return "Windows 2012"

    } elseif ($check_os -like "*Windows Server 2008 R2*") {
        Write-Log "[*] Windows 2008 R2 Detected"
        return "Windows 2008 R2"

	} else {
        # No case triggered, Exit Script
		Write-Log ("[!] Unsupported OS" + $OSinfo.Version + " " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "FATAL"
		
		Exit
	}
}

Function Get-ActiveSessions{
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Name
        ,
        [switch]$Quiet
    )
    Begin{
        $return = @()
    }
    Process{
        If(!(Test-Connection $Name -Quiet -Count 1)){
            Write-Error -Message "Unable to contact $Name. Please verify its network connectivity and try again." -Category ObjectNotFound -TargetObject $Name
            Return
        }
        If([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")){ #check if user is admin, otherwise no registry work can be done
            #the following registry key is necessary to avoid the error 5 access is denied error
            $LMtype = [Microsoft.Win32.RegistryHive]::LocalMachine
            $LMkey = "SYSTEM\CurrentControlSet\Control\Terminal Server"
            $LMRegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($LMtype,$Name)
            $regKey = $LMRegKey.OpenSubKey($LMkey,$true)
            If($regKey.GetValue("AllowRemoteRPC") -ne 1){
                $regKey.SetValue("AllowRemoteRPC",1)
                Start-Sleep -Seconds 1
            }
            $regKey.Dispose()
            $LMRegKey.Dispose()
        }
        $result = qwinsta /server:$Name
        If($result){
            ForEach($line in $result[1..$result.count]){ #avoiding the line 0, don't want the headers
                $tmp = $line.split(" ") | ?{$_.length -gt 0}
                If(($line[19] -ne " ")){ #username starts at char 19
                    If($line[48] -eq "A"){ #means the session is active ("A" for active)
                        $return += New-Object PSObject -Property @{
                            "ComputerName" = $Name
                            "SessionName" = $tmp[0]
                            "UserName" = $tmp[1]
                            "ID" = $tmp[2]
                            "State" = $tmp[3]
                            "Type" = $tmp[4]
                        }
                    }Else{
                        $return += New-Object PSObject -Property @{
                            "ComputerName" = $Name
                            "SessionName" = $null
                            "UserName" = $tmp[0]
                            "ID" = $tmp[1]
                            "State" = $tmp[2]
                            "Type" = $null
                        }
                    }
                }
            }
        }Else{
            Write-Error "Unknown error, cannot retrieve logged on users"
        }
    }
    End{
        If($return){
            If($Quiet){
                Return $true
            }
            Else{
                Return $return
            }
        }Else{
            If(!($Quiet)){
                Write-Host "No active sessions."
            }
            Return $false
        }
    }
}

Function Check-Windows2008R2{
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-server-endpoints#windows-server-2008-r2-sp1-windows-server-2012-r2-and-windows-server-2016

    Write-Log "[+] Handling Windows 2008 R2 Onboard Now"
    # Step : Check SP1 and NET FRAMEWORK installed
    #Check if Windows 2008 R2 server is patched with service pack 1
    if ([System.Environment]::OSVersion.ServicePack -ne 'Service Pack 1'){
        Write-Log "[!] Windows 2008 R2 Service Pack 1 not installed" "ERROR"
        <#
        Write-Log "[+] Installing Windows 2008 R2 Service Pack 1..." "INFO"
        
        Start-Process -FilePath $global:08R2_SP1_Patch_Path -ArgumentList ("/norestart") -Wait -Verb runas

        Start-Sleep -s 600 -ErrorAction SilentlyContinue 
        Write-Log "[+] After waiting 12 mins, assumed Win08R2 SP1 installed" "INFO"
        #>
        Exit
    } else {
        Write-Log "[+] Detected 08R2 SP1 already installed" "SUCCESS"
    }

    # Check if .Net Framework >=4.5 and install .Net Framework 4.8 if needed
    $dotnet_version = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ( $dotnet_version.Version -ge '4.5')
    {
        Write-Log "[+] Detected .Net Framework Version $($dotnet_version.Version)" "SUCCESS"
    }
    else
    {
        Write-Log "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5" "ERROR"
        <#
        Write-Log "[+] Installing .Net Framework 4.5..." "INFO"
        # Write-Log $DotNet48_Path
        Start-Process -FilePath $global:DotNet45_Path -ArgumentList ("/q", "/norestart") -Wait -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue 
        Write-Log "[+] After waiting 1 min, assumed .NET 4.5 installed" "INFO"
        #>
        Exit
    }

    # Step : Install required patch
    # Try install KB4074598 and Custpomer_Experience and Diagnostic_Telemetry_Update KB3080149 if needed. 

    # Try install 2018 Monthly Feb Update Rollup KB4074598 
    # https://support.microsoft.com/en-hk/help/4074598/windows-7-update-kb4074598
    
    $HotfixCore = get-hotfix -Id KB4074598 -ErrorAction SilentlyContinue #Check if the update KB4074598 is installed 

    # Write-Log $global:08R2_SP1_KB4074598_Path
    if (($HotfixCore))
    {
        Write-Log "[+] KB4074598 installed." "SUCCESS"
    } 
    else #Return error Code 1 if the missing KB4074598 could not be installed 
    {
        Write-Log "[!] KB4074598 Not Installed." "ERROR"
        <#
        Write-Log "[+] Installing KB4074598..." "INFO"
        wusa $08R2_SP1_KB4074598_Path /quiet /norestart | Out-Null
        Start-Sleep -s 60 -ErrorAction SilentlyContinue 
        Write-Log "[+] After waiting 1 min, assumed KB4074598 installed" "INFO"
        #>
        Exit
    }

    # Try install Custpomer_Experience and Diagnostic_Telemetry_Update if needed. 

    $HotfixCore = get-hotfix -Id KB3080149 -ErrorAction SilentlyContinue  #Check if the update for customer experience and diagnostic telemetry KB3080149 is installed 

    if (($HotfixCore))
    {
        Write-Log "[+] KB3080149 installed." "SUCCESS"
    }
    else  #Return error Code 1 if the missing KB3080149 could not be installed 
    {
        Write-Log "[!] KB3080149 could not be installed." "ERROR"
        <#
        Write-Log "[+] Installing KB3080149..." "INFO"
        wusa $global:08R2_SP1_KB3080149_Path /quiet /norestart | Out-Null
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed KB3080149 installed" "INFO"
        #>
        Exit
    }

    # Try install Update for SHA2
    ## https://support.microsoft.com/en-gb/help/4472027/2019-sha-2-code-signing-support-requirement-for-windows-and-wsus

    $HotfixCore = get-hotfix -Id KB4474419 -ErrorAction SilentlyContinue
    $HotfixCore1 = get-hotfix -Id KB4490628 -ErrorAction SilentlyContinue
    if (($HotfixCore) -and ($HotfixCore1))
    {
        Write-Log "[+] SHA2 Update Installed. skip SHA2 update hotfix installation" "SUCCESS"
    }
    else
    {
        $fileNames = @($global:08R2_SP1_SHA2_KB4474419_Path, $global:08R2_SP1_SHA2_KB4490628_Path)
        foreach ($file in $fileNames) {
            Write-Log "[!] SHA2 Not Installed.  Please Install KB4474419 & KB4490628" "ERROR"
            <#
            Write-Log "[+] File: $($file) found try to install SHA2 update" "INFO"
            Write-Log "[+] Installing $($file)..." "INFO"
            wusa $file /quiet /norestart | Out-Null
            Start-Sleep -s 30 -ErrorAction SilentlyContinue
            Write-Log "[+] After waiting 30s, assumed $($file) installed" "INFO"
            #>

        }
        Exit
    }

    # Step : Install Configure SCEP
    $SCEP_status = Get-WmiObject -Namespace root\Microsoft\SecurityClient -class AntimalwareHealthStatus
    If (!($SCEP_status)){
        Write-Log "[+] Failed: need to install SCEP..." "Error"
        <#
        Start-Process -FilePath $global:SCEP_installer_Path -ArgumentList ("/s", "/q", "/policy $global:SCEP_Policy_Path", "/sqmoptin") -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed SCEP installed" "INFO"
        #>
        EXit
    } else {
        Write-Log "[!] SCEP Installation SUCCESS" "SUCCESS"
    }
    
    ## Get MMA Onboarding Status
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if ( $MDATP.OnboardingState -eq '1')
    {
        Write-Log "[*] MMA OnboardingState OK" "SUCCESS"
    } else {
        Write-Log "[!] MMA OnboardingState Maybe Failed. Need to reboot and double check" "Error"
    }
}

Function Check-Windows2012R2{
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-server-endpoints

    # Check if .Net Framework >=4.5 and install .Net Framework 4.8 if needed
    $dotnet_version = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ( $dotnet_version.Version -ge '4.5')
    {
        Write-Log "[+] Detected .Net Framework Version $($dotnet_version.Version)" "SUCCESS"
    }
    else
    {
        Write-Log "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5" "ERROR"
        <#
        Write-Log "[+] Installing .Net Framework 4.5..." "INFO"
        # Write-Log $DotNet48_Path
        Start-Process -FilePath $global:DotNet45_Path -ArgumentList ("/q", "/norestart") -Wait -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue 
        Write-Log "[+] After waiting 1 min, assumed .NET 4.5 installed" "INFO"
        #>
        Exit
    }
    
    # Step : Install required patch
    ## Try install Custpomer Experience and Diagnostic Telemetry Update if needed. 
    Write-Log "[+] Check KB3080149 for Windows 2012 R2" "INFO"
    $HotfixCore = get-hotfix -Id KB3080149 -ErrorAction SilentlyContinue
    
    ## Try another method to collect patching status 
    if(-Not $hotfixcore)
    {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $TotalResults = $Searcher.Search("IsInstalled=1").Updates 
        $KB3080149 = $TotalResults | where {$_Title -like '*3080149*'} | ft -a Title 
    }

    if (($HotfixCore) -or ($KB3080149))
    {
        Write-Log "[*] KB3080149 installed." "SUCCESS"
    } elseif ((get-hotfix -Id KB2919355) -or ($TotalResults | where {$_Title -like '*2919355*'} | ft -a Title )) {
        Write-Log "[!] Need to Install KB3080149..." "ERROR"
        # Write-Log $global:2012R2_KB3080149_Path
        # wusa $global:2012R2_KB3080149_Path /quiet /norestart | Out-Null
        #Start-Sleep -s 10
        # Write-Log "[+] Installed KB3080149" "SUCCESS"
        Exit
    } else {
        Write-Log "[!] KB3080149 could not be installed or Prerequisites status is unknown" "ERROR"
        Exit
    }

    # Step : Install Configure SCEP
    $SCEP_status = Get-WmiObject -Namespace root\Microsoft\SecurityClient -class AntimalwareHealthStatus
    If (!($SCEP_status)){
        Write-Log "[!] Need to install SCEP..." "Error"
        <#
        Start-Process -FilePath $global:SCEP_installer_Path -ArgumentList ("/s", "/q", "/policy $global:SCEP_Policy_Path", "/sqmoptin") -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed SCEP installed" "INFO"
        #>
        EXit
    } else {
        Write-Log "[!] SCEP Installation SUCCESS" "SUCCESS"
    }
    
    # Get MMA Onboarding Status
    ## Check Services 
    $serviceDiagTrack = Get-Service -Name DiagTrack #| Where-Object {$_.Status -eq "Running"}
    $serviceSCEPDefend = Get-Service -Name MsMpSvc #| Where-Object {$_.Status -eq "Running"}
    $serviceMPSSVC = Get-Service -Name mpssvc #| Where-Object {$_.Status -eq "Running"}

    If (($serviceDiagTrack.Status -ne 'Running' ) -OR  ($serviceSCEPDefend.Status -ne 'Running') -OR ($serviceMPSSVC.Status -ne 'Running')){
        Write-Log "[!] Failed :  At least one MMA related service is not running" "Error"
        Write-Log "[!] Checked : DiagTrack: $($serviceDiagTrack.Status)" "DEBUG"
        Write-Log "[!] Checked : MsMpSvc: $($serviceSCEPDefend.Status)" "DEBUG"
        Write-Log "[!] Checked : MPSSVC: $($serviceMPSSVC.Status)" "DEBUG"
    }

    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if ( $MDATP.OnboardingState -eq '1')
    {
        Write-Log "[*] MMA OnboardingState OK" "SUCCESS"
    } else {
        Write-Log "[!] MMA OnboardingState Maybe Failed. Need to reboot and double check" "Error"
    }
}

Function Check-Windows2016{
    # Check if .Net Framework >=4.5 and install .Net Framework 4.8 if needed
    $dotnet_version = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ( $dotnet_version.Version -ge '4.5')
    {
        Write-Log "[+] Detected .Net Framework Version $($dotnet_version.Version)" "SUCCESS"
    }
    else
    {
        Write-Log "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5" "ERROR"
        <#
        Write-Log "[+] Installing .Net Framework 4.5..." "INFO"
        # Write-Log $DotNet48_Path
        Start-Process -FilePath $global:DotNet45_Path -ArgumentList ("/q", "/norestart") -Wait -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue 
        Write-Log "[+] After waiting 1 min, assumed .NET 4.5 installed" "INFO"
        #>
        Exit
    }

    # Step : Windows Defender
    ## Install MDAV Server Feature
    try {
        # Test if WDAV is already installed and running
        $WDAVProcess = Get-Process -ProcessName MsMpEng 2> $null
        if ($null -eq $WDAVProcess) {
            Write-Log "[!] Windows Defender is not running. Checking WDAV feature status" "ERROR"
            $WDAVFeature = Get-WindowsFeature -Name "Windows-Defender-Features"
            if ($WDAVFeature.InstallState -ne "Installed") {
                Write-Log "[+] WDAV Feature is not installed." "ERROR"
                # $WDAVInstall = Install-WindowsFeature -Name "Windows-Defender-Features"
                if ($WDAVInstall.RestartNeeded -eq "Yes") { 
                    Write-Log "[!] WDAV Restart Needed" "ERROR"
                }
            }
            else {
                Write-Log "[+] WDAV Feature is installed. but service is not running. please reinstall or restart feature" "ERROR"
                # $WDAVInstall = Uninstall-WindowsFeature -Name "Windows-Defender-Features"
                if ($WDAVInstall.RestartNeeded -eq "Yes") { 
                    Write-Log "[!] WDAV Restart Needed" "ERROR"
                }
            }
        } else {
            # Start-Service -Name windefend
            Get-Service -Name windefend
            Write-Log "[*] Windows Defender is already installed and running" "SUCCESS"
        }
    }
    catch {
        Write-Log "[!] Error installing or updating MDAV" "ERROR"
        Write-Log $_ "ERROR"
    }

    ## Get MMA Onboarding Status
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if ( $MDATP.OnboardingState -eq '1')
    {
        Write-Log "[*] MMA OnboardingState OK" "SUCCESS"
    } else {
        Write-Log "[!] MMA OnboardingState Maybe Failed. need to reboot and double check" "Error"
    }

}



####################################################################################################################
#
# Main
#
####################################################################################################################


#0. Check runas Admin & Set ExecutionPolicy
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    # Write-Host ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    if(! ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
        Write-Log "[!] Please runas NT auth/system or admin" "ERROR"
        Exit
    }
    set-executionpolicy bypass -scope Process -Force



#1. since runas NT auth/system, will create C:\Deploy_MDATP_TEMP\deploy_log.txt for debug use
    # $hardcode_log_path = "C:\Deploy_MDATP_TEMP\deploy_log.txt"
    $hostname = (hostname)
    if (!(Test-Path ("$Scriptdir\$($Log_folder)\"))){
        New-Item -Path $Scriptdir -Name $Log_folder -ItemType "directory"
    }
    $Log_folder = "$Scriptdir\$($Log_folder)\"
    $Date_str = (Get-Date).ToUniversalTime().toString("yyyy-MM-dd_HHmmss") + "_UTC"
    $log_file_name = "$($hostname)_mdatp_checking_log_$($Date_str).csv"
    New-Item -Path $Log_folder -Name $log_file_name -ItemType "file"
    $global:logfile = "$($Log_folder)\$($log_file_name)"


#2. Set Script Directory to share drive
    if (!(Test-Path ("filesystem::\$($share_drive_path)"))){
        $Scriptdir = (Get-Item -Path $share_drive_path -Verbose).FullName
        Write-Log "[+] Share drive $($share_drive_path) existed"
    } elseif (dir $share_drive_path) {
        $Scriptdir = (Get-Item -Path $share_drive_path -Verbose).FullName
        Write-Log "[+] Share drive $($share_drive_path) existed"
    } else{
        Write-Log "[+] Share drive $($share_drive_path) not existed" "Error"
        Exit
    }


#3. Check already onboarded
    $MATPstatus = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status")."OnboardingState"
    if ($MATPstatus) {
        if($MATPstatus -eq 1){
            Write-Log "[!] Onboarded status detected. Please check the onboarding on MDATP Security Center" "SUCCESS"
        } else {
            Write-Log "[!] MDATP reg key found but no offboarded status detected!" "ERROR"
            Write-Log "[+] Now checking patches and applications" "DEBUG"
        }
    }else{
        Write-Log "[*] No Onboard key detected. now using following Powershell command to have a look." "ERROR"
        Write-Log "[*] If there is not output of reg key of Windows Advanced Threat Protection. Assumed as not Offboarded!" "DEBUG"
        Write-Log "[+] Powershell: Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'" "DEBUG"
        $status_all = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
        if ($status_all) {
            Write-Log $status_all "DEBUG"
        }
        Write-Log "[+] Powershell: Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' - OUTPUT END" "DEBUG"
        Write-Log "[+] Now checking patches and applications" "DEBUG"
    }

#4. Detect Anti-Virus Software
	# TrendMicro engine: ntrtscan.exe
	$AVProcesses = "ntrtscan"
	$thirdPartyAV = $null
	$thirdPartyAV = get-process -name $AVProcesses 2> $null

	# Read-Host -prompt "[!] Warning, Please check and remove and Third Party Anti-Virus software before launch this script"

	if ($thirdPartyAV) {
		#if a third party AV is present then do not install MDAV
		if ($thirdPartyAV.ProcessName -eq "ntrtscan"){
			$AV_name = "TrendMicro"
		}
		Write-Log "[!] Third party Anti-Virus Software Detected: Please remove $($AV_name)" "ERROR"
		Exit
	}else{
        Write-Log "[+] Seems No Third party Anti-Virus Software Detected, process checking Anti-Virus"
    }


#5. Check Windows Version and install mdatp onboard
    $OSinfo = Get-WmiObject -Class Win32_OperatingSystem
	$OSCaption = $OSinfo.Caption
    $OSVersion = Get-WindowsVersion $OSCaption
    if ($OSVersion -eq "Windows 10"){
        Write-Log "[+] Windows 10: Please check pervious result"
    } elseif ($OSVersion -eq "Windows 2019") {
        Write-Log "[+] Windows 2019: Please check pervious result"
    } elseif ($OSVersion -eq "Windows 2016") {
        Check-Windows2016
    } elseif ($OSVersion -eq "Windows 2012 R2") {
        Check-Windows2012R2
    } elseif ($OSVersion -eq "Windows 2008 R2") {
        Check-Windows2008R2
    }


Write-Log "[!] Script Finished" "SUCCESS"

<#
$hostname = $env:computername
$sessions = Get-ActiveSessions $hostname
foreach($sess in $sessions){
    if ($sess.State -eq "Active"){
        Write-Log "[+] Get Active Desktop Session: $($sess.ID, $sess.SessionName, $sess.Type, $sess.UserName, $sess.ComputerName)" "DEBUG"
        Write-Log "[+] Get Active Desktop Session ID: $($sess.ID)" "DEBUG"
        cmd /c "$($Scriptdir)psexec.exe -accepteula -i $($sess.ID) cmd.exe /c `"$($Scriptdir)\msg.bat`" "
        cmd /c "$($Scriptdir)psexec.exe -accepteula -i $($sess.ID) cmd.exe /c `"$($Scriptdir)\msg.bat`" "
        Write-Log "[!] Trying pop up!" "DEBUG"
    }
}
#>