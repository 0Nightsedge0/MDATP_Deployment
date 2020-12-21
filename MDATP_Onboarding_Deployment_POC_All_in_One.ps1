####################################################################################################################
#
# MDATP deployment script POC
# Version: V1.3
# Last Edited: 21 Dec 2020
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
    # MDATP workspace ID
    [Parameter(Mandatory = $false)]
    [String]
    $workspaceId = "workspaceID",

    # **** important to edit ****
    # MDATP workspace Key
    [Parameter(Mandatory = $false)]
    [String]
    $workspaceKey = "workspaceKey",

    # Supported OS, selection will be auto detected
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Windows10x64", "Windows2008R2", "Windows2012R2", "Windows2016", "Windows2019")]
    [String]
    $OS,

    # **** important to edit ****
    # MDATP install log folder
    [Parameter(Mandatory = $false)]
    [String]
    $Log_folder = "\\MDATP-DC08R2\MDATP_logs\deployment_logs",

    # **** important to edit ****
    # Share drive path - for scripts
    [Parameter(Mandatory = $false)]
    [String]
    $Share_drive_path = "\\Mdatp-dc08r2\mdatp\MDATP_deploy_all_in_one\",

    # Windows 10 Onboarding Package Zip Path & Onboarding Package Script Path
    [Parameter(Mandatory = $false)]
    [String]
    $Win10_OnboardingPackageZipName = "Win10\WindowsDefenderATPOnboardingPackage.zip",

    [Parameter(Mandatory = $false)]
    [String]
    $Win10_OnboardingPackageScriptName = "Win10\WindowsDefenderATPOnboardingScript.cmd",

    # Windows 2019 Onboarding Script / Package Path
    [Parameter(Mandatory = $false)]
    [String]
    $Win2019_OnboardingPackageZipName = "Win2019\WindowsDefenderATPOnboardingPackage.zip",

    [Parameter(Mandatory = $false)]
    [String]
    $Win2019_OnboardingPackageScriptName = "Win2019\WindowsDefenderATPOnboardingScript.cmd",

    # uninstall trendmicro tools
    [Parameter(Mandatory = $false)]
    [String]
    $Uninstall_Trendmicro_tool_path = "\Cut_Mv\CUT_forNonA1\CUT.exe",

    # MDATP ADMX files (Optional GPO template)
    # Here default is local GPO, if want to domain GPO, please copy directly to "C:\Windows\PolicyDefinitions\" in Domain Controller
    [Parameter(Mandatory = $false)]
    [String]
    $ADMXDestinationFolder = "C:\Windows\PolicyDefinitions\",

    # LGPO.exe path
    [Parameter(Mandatory = $false)]
    [String]
    $LGPO_Path = "LGPO\LGPO_30\",
    
    # local group policy path
    [Parameter(Mandatory = $false)]
    [String]
    $PolicyDirectory = "{42D49818-FBE7-4BEC-94A4-E36006EDC284}",

    # Windows Server 2008 R2 SP1 Patch Path
    [Parameter(Mandatory = $false)]
    [String]
    $08R2_SP1_Patch_Path = "Win08R2_SP1\windows6.1-kb976932-x64_74865ef2562006e51d7f9333b4a8d45b7a749dab.exe",

    # .Net Framework 4.8 Path
    [Parameter(Mandatory = $false)]
    [String]
    $DotNet48_Path = "DotNet\ndp48-x86-x64-allos-enu.exe",

    # .Net Framework 4.5 Path
    [Parameter(Mandatory = $false)]
    [String]
    $DotNet45_Path = "DotNet\NDP452-KB2901907-x86-x64-AllOS-ENU.exe",

    # KB4074598 for Windows Server 2008 R2 SP1
    [Parameter(Mandatory = $false)]
    [String]
    $08R2_SP1_KB4074598_Path = "Win08R2_SP1\KB4074598\windows6.1-kb4074598-x64_87a0c86bfb4c01d9c32d2cd3717b73c1b83cb798.msu",

    # KB3080149 for Windows Server 2008 R2 SP1
    [Parameter(Mandatory = $false)]
    [String]
    $08R2_SP1_KB3080149_Path = "KB3080149\Windows6.1-KB3080149-x64.msu",

    # KB3080149 for Windows Server 2012 R2
    [Parameter(Mandatory = $false)]
    [String]
    $12R2_KB3080149_Path = "KB3080149\Windows8.1-KB3080149-x64.msu",

    # SHA2: KB4490628 for Windows Server 2008 R2 SP1
    [Parameter(Mandatory = $false)]
    [String]
    $08R2_SP1_SHA2_KB4490628_Path = "Win08R2_SP1\SHA2\windows6.1-kb4490628-x64_d3de52d6987f7c8bdc2c015dca69eac96047c76e.msu",

    # SHA2: KB4474419 for Windows Server 2008 R2 SP1
    [Parameter(Mandatory = $false)]
    [String]
    $08R2_SP1_SHA2_KB4474419_Path = "Win08R2_SP1\SHA2\windows6.1-kb4474419-v3-x64_b5614c6cea5cb4e198717789633dca16308ef79c.msu",

    # SCEP installer 
    [Parameter(Mandatory = $false)]
    [String]
    $SCEP_installer_Path = "SCEP\scepinstall_2c54f8168cc9d05422cde174e771147d527c92ba.exe",

    # SCEP Policy 
    [Parameter(Mandatory = $false)]
    [String]
    $SCEP_Policy_Path = "SCEP\SCEP_Config_v1.0.xml",

    # SCEP: AV definition update - Microsoft Security Client exe 
    [Parameter(Mandatory = $false)]
    [String]
    $MpCmdRunEXE = "C:\Program Files\Microsoft Security Client\MpCmdRun.exe",

    # SCEP hotfix for Windows 2008 R2 SP1
    [Parameter(Mandatory = $false)]
    [String]
    $SCEP_hotfix_Path = "SCEP\mpam-fe.exe",

    # MMA Setup
    [Parameter(Mandatory = $false)]
    [String]
    $MMA_installer_Path = "MMA\setup\Setup.exe",

    # KB3080149 for Windows Server 2012 R2
    [Parameter(Mandatory = $false)]
    [String]
    $2012R2_KB3080149_Path = "Win2012R2\Windows8.1-KB3080149-x64.msu",

    # Test Detection script
    [Parameter(Mandatory = $false)]
    [String]
    $Test_Detection_Script_Path = "Test-Detection.ps1"

)
# MDATP workspace ID
$global:workspaceId = $workspaceId

# MDATP workspace Key
$global:workspaceKey = $workspaceKey

# Log folder Path
$global:Log_folder = $Log_folder

# Share Drive Path
$global:Scriptdir = $Share_drive_path

# Windows 10 Onboarding Script / Package Path
$global:Win10_OnboardingPackageZipName = $Scriptdir + $Win10_OnboardingPackageZipName
$global:Win10_OnboardingPackageScriptName = $Scriptdir + $Win10_OnboardingPackageScriptName

# Windows 2019 Onboarding Script / Package Path
$global:Win2019_OnboardingPackageZipName = $Scriptdir + $Win2019_OnboardingPackageZipName
$global:Win2019_OnboardingPackageScriptName = $Scriptdir + $Win2019_OnboardingPackageScriptName

# Uninstall trendmicro tools
$global:Uninstall_Trendmicro_tool_path = $Scriptdir + $Uninstall_Trendmicro_tool_path

# MDATP optional Policy Path
$policyADMXFolder = "OptionalParamsPolicy"
$global:ADMXSourceFolder = $Scriptdir + $policyADMXFolder

# LGPO.exe Path
$global:LGPO_EXE_Path = $Scriptdir + $LGPO_Path
# Local GPO sample Path
$global:DefenderPolicyPath = $LGPO_EXE_Path + $PolicyDirectory

# 08R2 SP1 Path
$global:08R2_SP1_Patch_Path = $Scriptdir + $08R2_SP1_Patch_Path

# .Net Framework 4.8 Path
$global:DotNet48_Path = $Scriptdir + $DotNet48_Path

# .Net Framework 4.5 Path
$global:DotNet45_Path = $Scriptdir + $DotNet45_Path

# Windows 2008 R2 SP1 KB4074598 February 13, 2018—KB4074598
$global:08R2_SP1_KB4074598_Path = $Scriptdir + $08R2_SP1_KB4074598_Path

# KB3080149 for Windows Server 2008 R2 SP1
$global:08R2_SP1_KB3080149_Path = $Scriptdir + $08R2_SP1_KB3080149_Path

# KB3080149 for Windows Server 2012 R2
$global:12R2_KB3080149_Path = $Scriptdir + $12R2_KB3080149_Path

# SHA2: KB4490628 for Windows Server 2008 R2 SP1
$global:08R2_SP1_SHA2_KB4490628_Path =  $Scriptdir + $08R2_SP1_SHA2_KB4490628_Path

# SHA2: KB4474419 for Windows Server 2008 R2 SP1
$global:08R2_SP1_SHA2_KB4474419_Path =  $Scriptdir + $08R2_SP1_SHA2_KB4474419_Path

# SCEP installer
$global:SCEP_installer_Path = $Scriptdir + $SCEP_installer_Path

# SCEP Profile
$global:SCEP_Policy_Path = $Scriptdir + $SCEP_Policy_Path

# SCEP: AV definition update - Microsoft Security Client exe 
$global:MpCmdRunEXE = $MpCmdRunEXE

# SCEP hotfix for Windows 2008 R2 SP1
$global:SCEP_hotfix_Path = $Scriptdir + $SCEP_hotfix_Path

# KB3080149 for Windows Server 2012 R2
$global:2012R2_KB3080149_Path = $Scriptdir + $2012R2_KB3080149_Path

# MMA Setup
$global:MMA_installer_Path = $Scriptdir + $MMA_installer_Path

# Test Detection script
$global:Test_Detection_Script_Path = $Scriptdir + $Test_Detection_Script_Path



####################################################################################################################
#
# Functions
#
####################################################################################################################


## Write Log Function
Function Write-Log {
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


## Check-Windows-Version
Function Check-Windows-Version($check_os){
    $status = "" | Select-Object -Property code, msg
    $status.code = "SUCCESS"

    if ($check_os -like "*Windows 10*"){
		Write-Log "[*] Windows 10 Detected"
        $status.msg = "Windows 10"

    } elseif ($check_os -like "*Windows Server 2019*") {
		Write-Log "[*] Windows 2019 Detected"
        $status.msg = "Windows 2019"

    } elseif ($check_os -like "*Windows Server 2016*") {
    	Write-Log "[*] Windows 2016 Detected"
        $status.msg = "Windows 2016"

    } elseif ($check_os -like "*Windows Server 2012 R2*") {
        Write-Log "[*] Windows 2012 R2 Detected"
        $status.msg = "Windows 2012 R2"

    } elseif ($check_os -like "*Windows Server 2012*") {
        Write-Log "[*] Windows 2012 Detected"
        $status.msg = "Windows 2012"

    } elseif ($check_os -like "*Windows Server 2008 R2*") {
        Write-Log "[*] Windows 2008 R2 Detected"
        $status.msg = "Windows 2008 R2"

	} else {
        # No case triggered, Exit Script
        Write-Log ("[!] Unsupported OS" + $OSinfo.Version + " " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")") "ERROR"
        $status.code = "ERROR"
        $status.msg = "[!] Unsupported OS" + $OSinfo.Version + " " + $OSinfo.OperatingSystemSKU + " (" + $OSinfo.Caption + ")"
    }
    Return $status
}


#Check runas Admin & Set ExecutionPolicy
Function Get-RunningPriv(){
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    # Write-Host ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

    # status
    $status = "" | Select-Object -Property code, msg

    if(! ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
        Write-Log "[!] Please runas NT auth/system or admin" "ERROR"
        $status.code = "ERROR"
        $status.msg = "[!] Please runas NT auth/system or admin"
    } else {
        $status.code = "SUCCESS"
        $status.msg = ""
        set-executionpolicy bypass -scope Process -Force
    }
    Return $status
}

## Get Active User Session ID for pop up reboot msg
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




####################################################################################################################
#
# Deployment Functions
#
####################################################################################################################




## Install-Windows08R2 (Tested)
Function Install-Windows2008R2{
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-server-endpoints#windows-server-2008-r2-sp1-windows-server-2012-r2-and-windows-server-2016

    Write-Log "[+] Handling Windows 2008 R2 Onboard Now"

    $status = "" | Select-Object -Property code, msg
    $status.code = "SUCCESS"

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
        $status.code = "ERROR"
        $status.msg = "[!] Windows 2008 R2 Service Pack 1 not installed"
        return $status
    } else {
        Write-Log "[+] Detected 08R2 SP1 already installed" "INFO"
    }

    # Check if .Net Framework >=4.5 and install .Net Framework 4.8 if needed
    $dotnet_version = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ( $dotnet_version.Version -ge '4.5')
    {
        Write-Log "[+] Detected .Net Framework Version $($dotnet_version.Version)" "INFO"
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
        $status.code = "ERROR"
        $status.msg = "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5"
        return $status
    }

    # Step : Install required patch
    # Try install KB4074598 and Custpomer_Experience and Diagnostic_Telemetry_Update KB3080149 if needed. 

    # Try install 2018 Monthly Feb Update Rollup KB4074598 
    # https://support.microsoft.com/en-hk/help/4074598/windows-7-update-kb4074598
    

    $HotfixCore = get-hotfix -Id KB4074598 -ErrorAction SilentlyContinue #Check if the update KB4074598 is installed 

    # Write-Log $global:08R2_SP1_KB4074598_Path
    if (($HotfixCore))
    {
        Write-Log "[+] KB4074598 installed , skip KB4074598 hotfix installation" "INFO"
    }
    else #Return error Code 1 if the missing KB4074598 could not be installed 
    {
        Write-Log "[!] KB4074598 not installed" "Error"
        <#
        Write-Log "[+] Installing KB4074598..." "INFO"
 
        wusa $08R2_SP1_KB4074598_Path /quiet /norestart | Out-Null
        Start-Sleep -s 60 -ErrorAction SilentlyContinue 
        Write-Log "[+] After waiting 1 min, assumed KB4074598 installed" "INFO"
        #>
        $status.code = "ERROR"
        $status.msg = "[!] KB4074598 not installed"
        return $status
    }

    # Try install Custpomer_Experience and Diagnostic_Telemetry_Update if needed. 

    $HotfixCore = get-hotfix -Id KB3080149 -ErrorAction SilentlyContinue  #Check if the update for customer experience and diagnostic telemetry KB3080149 is installed 

    if (($HotfixCore))
    {
        Write-Log "[+] KB3080149 installed , skip KB3080149 hotfix installation" "INFO"
    }
    else  #Return error Code 1 if the missing KB3080149 could not be installed 
    {
        Write-Log "[!] KB3080149 not installed" "ERROR"
        <#
        Write-Log "[+] Installing KB3080149..." "INFO"
        wusa $global:08R2_SP1_KB3080149_Path /quiet /norestart | Out-Null
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed KB3080149 installed" "INFO"
        #>
        $status.code = "ERROR"
        $status.msg = "[!] KB3080149 not installed"
        return $status
    }

    # Try install Update for SHA2
    ## https://support.microsoft.com/en-gb/help/4472027/2019-sha-2-code-signing-support-requirement-for-windows-and-wsus

    $HotfixCore = get-hotfix -Id KB4474419 -ErrorAction SilentlyContinue
    $HotfixCore1 = get-hotfix -Id KB4490628 -ErrorAction SilentlyContinue
    if (($HotfixCore) -and ($HotfixCore1))
    {
        Write-Log "[+] SHA2 Update Installed, skip SHA2 update hotfix installation" "INFO"
    }
    else
    {
        $fileNames = @($global:08R2_SP1_SHA2_KB4474419_Path, $global:08R2_SP1_SHA2_KB4490628_Path)
        foreach ($file in $fileNames) {
            Write-Log "[!] SHA2 Not Installed. Please Install KB4474419,KB4490628" "ERROR"
            <#
            Write-Log "[+] File: $($file) found try to install SHA2 update" "INFO"
            Write-Log "[+] Installing $($file)..." "INFO"
            wusa $file /quiet /norestart | Out-Null
            Start-Sleep -s 30 -ErrorAction SilentlyContinue
            Write-Log "[+] After waiting 30s, assumed $($file) installed" "INFO"
            #>

        }
        $status.code = "ERROR"
        $status.msg = "[!] SHA2 Not Installed. Please Install KB4474419,KB4490628"
        return $status
    }

    # Step : Install Configure SCEP
    $SCEP_status = Get-WmiObject -Namespace root\Microsoft\SecurityClient -class AntimalwareHealthStatus
    If (!($SCEP_status)){
        Write-Log "[+] Missing SCEP, Installing SCEP..." "INFO"
        Write-Log $global:SCEP_installer_Path
        Start-Process -FilePath $global:SCEP_installer_Path -ArgumentList ("/s", "/q", "/policy $($global:SCEP_Policy_Path)", "/sqmoptin") -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed SCEP installed" "INFO"
        
        ## Apply SCEP hotfix
        Write-Log "[+] SCEP hotfix installing..." "INFO"
        Start-Process -FilePath $global:SCEP_hotfix_Path -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed SCEP hotfix completed" "INFO"
    } else {
        Write-Log "[!] Already Installed SCEP" "SUCCESS"
    }

    # Step : MMA Setup
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if (!($MDATP)){
        Write-Log "[+] MMA installing..." "INFO"
        & $global:MMA_installer_Path /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$workspaceId OPINSIGHTS_WORKSPACE_KEY=$workspaceKey AcceptEndUserLicenseAgreement=1 | Out-Null
        Start-Sleep -s 120 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 3 mins, assumed MMA installed" "INFO"
        
        $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction SilentlyContinue
        $mma.AddCloudWorkspace($workspaceId, $workspaceKey)
        $mma.ReloadConfiguration()
        Write-Log "[+] MMA Setup End" "INFO"
        Start-Sleep -s 10 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 10s, assumed MMA configured" "INFO"
    } else {
        Write-Log "[!] MMA already installed" "SUCCESS"
    }

    # Step : Validation MMA
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

    ## Get MMA Onboarding Status
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if ( $MDATP.OnboardingState -eq '1')
    {
        Write-Log "[*] MMA OnboardingState OK" "SUCCESS"
    } else {
        Write-Log "[!] MMA OnboardingState Maybe Failed, need to reboot and double check" "Error"
        $status.code = "ERROR"
        $status.msg = "[!] MMA OnboardingState Maybe Failed, need to reboot and double check"
        return $status
    }

}


## Install-Windows2012R2
Function Install-Windows2012R2{
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-server-endpoints
    Write-Log "[+] Handling Windows 2012 R2 Onboarding Now"

    $status = "" | Select-Object -Property code, msg
    $status.code = "SUCCESS"

    # Step: DotNet 
    ## Check if .Net Framework >=4.5 and install .Net Framework 4.8 if needed
    $dotnet_version = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ( $dotnet_version.Version -ge '4.5')
    {
        Write-Log "[+] Detected .Net Framework Version: $($dotnet_version.Version)" "SUCCESS"
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
        $status.code = "ERROR"
        $status.msg = "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5"
        return $status
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
        Write-Log "[*] KB3080149 installed , skip KB3080149 hotfix installation" "SUCCESS"
    } elseif ((get-hotfix -Id KB2919355) -or ($TotalResults | where {$_Title -like '*2919355*'} | ft -a Title )) {
        Write-Log "[+] need to Install KB3080149..." "ERROR"
        # Write-Log $global:2012R2_KB3080149_Path
        # wusa $global:2012R2_KB3080149_Path /quiet /norestart | Out-Null
        # Start-Sleep -s 10
        # Write-Log "[+] Installed KB3080149" "INFO"
        $status.code = "ERROR"
        $status.msg = "[+] need to Install KB3080149..."
        return $status
    } else {
        Write-Log "KB3080149 could not be installed or Prerequisites (KB2919355) status is unknown" "ERROR"
        $status.code = "ERROR"
        $status.msg = "KB3080149 could not be installed or Prerequisites (KB2919355) status is unknown"
        return $status
    }

    # Step : Install Configure SCEP
    $SCEP_status = Get-WmiObject -Namespace root\Microsoft\SecurityClient -class AntimalwareHealthStatus
    If (!($SCEP_status)){
        Write-Log "[+] Missing SCEP, Installing SCEP..." "INFO"
        Write-Log $global:SCEP_installer_Path
        Start-Process -FilePath $global:SCEP_installer_Path -ArgumentList ("/s", "/q", "/policy $($global:SCEP_Policy_Path)", "/sqmoptin") -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed SCEP installed" "INFO"
        
        ## Apply SCEP hotfix
        Write-Log "[+] SCEP hotfix installing..." "INFO"
        Start-Process -FilePath $global:SCEP_hotfix_Path -Verb runas
        Start-Sleep -s 60 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 1 min, assumed SCEP hotfix completed" "INFO"
    } else {
        Write-Log "[!] Already Installed SCEP" "SUCCESS"
    }

    # Step : MMA Setup
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if (!($MDATP)){
        Write-Log "[+] MMA installing..." "INFO"
        & $global:MMA_installer_Path /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$workspaceId OPINSIGHTS_WORKSPACE_KEY=$workspaceKey AcceptEndUserLicenseAgreement=1 | Out-Null
        Start-Sleep -s 120 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 3 mins, assumed MMA installed" "INFO"
        
        $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction SilentlyContinue
        $mma.AddCloudWorkspace($workspaceId, $workspaceKey)
        $mma.ReloadConfiguration()
        Write-Log "[+] MMA Setup End" "INFO"
        Start-Sleep -s 10 -ErrorAction SilentlyContinue
        Write-Log "[+] After waiting 10s, assumed MMA configured" "INFO"
    } else {
        Write-Log "[!] MMA already installed" "SUCCESS"
    }

    # Step : Validation MMA
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

    ## Get MMA Onboarding Status
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if ( $MDATP.OnboardingState -eq '1')
    {
        Write-Log "[*] MMA OnboardingState OK" "SUCCESS"
    } else {
        Write-Log "[!] MMA OnboardingState Maybe Failed, need to reboot and double check" "Error"
        $status.code = "ERROR"
        $status.msg = "[!] MMA OnboardingState Maybe Failed, need to reboot and double check"
        return $status
    }

}


## Install-Windows2016 (Tested)
Function Install-Windows2016{
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-server-endpoints
    Write-Log "[+] Handling Windows 2016 Onboarding Now"

    $status = "" | Select-Object -Property code, msg
    $status.code = "SUCCESS"

    # Step: DotNet 
    ## Check if .Net Framework >=4.5 and install .Net Framework 4.8 if needed
    $dotnet_version = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
    if ( $dotnet_version.Version -ge '4.5')
    {
        Write-Log "[+] Detected .Net Framework Version: $($dotnet_version.Version)" "INFO"
    }
    else
    {
        Write-Log "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5" "WARN"
        <#
        # Write-Log "[+] Installing .Net Framework 4.5..." "INFO"
        # Write-Log $DotNet48_Path
        # Start-Process -FilePath $global:DotNet45_Path -ArgumentList ("/q", "/norestart") -Wait -Verb runas
        # Start-Sleep -s 60 -ErrorAction SilentlyContinue 
        # Write-Log "[+] After waiting 1 min, assumed .NET 4.5 installed" "INFO"
        #>
        $status.code = "ERROR"
        $status.msg = "[!] .Net Framework 4 Not Installed.  Install .Net Framework 4.5"
        return $status
    }

    # Step : Windows Defender
    ## Install MDAV Server Feature
    try {
        # Test if WDAV is already installed and running
        $WDAVProcess = Get-Process -ProcessName MsMpEng 2> $null
        if ($null -eq $WDAVProcess) {
            Write-Log "[!] Windows Defender is not running, Checking WDAV feature status" "WARN"
            $WDAVFeature = Get-WindowsFeature -Name "Windows-Defender-Features"
            if ($WDAVFeature.InstallState -ne "Installed") {
                Write-Log "[+] WDAV Feature is not installed, Installing now..."
                $WDAVInstall = Install-WindowsFeature -Name "Windows-Defender-Features"
                if ($WDAVInstall.RestartNeeded -eq "Yes") { 
                    Write-Log "[!] WDAV Restart Needed" "WARN"
                }
            }
            else {
                Write-Log "[+] WDAV Feature is installed, but service is not running. Uninstalling feature" ""
                $WDAVInstall = Uninstall-WindowsFeature -Name "Windows-Defender-Features"
                if ($WDAVInstall.RestartNeeded -eq "Yes") { 
                    Write-Log "[!] WDAV Restart Needed" "WARN"
                }
                Restart-Service -Name windefend
            }
        } else {
            Start-Service -Name windefend
            Get-Service -Name windefend
            Write-Log "[*] Windows Defender is already installed and running" "SUCCESS"
            Write-Log "[+] Checking security intelligence updates settings"
            $WUSetting = (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions).AUOptions
            if (($WUSetting -eq "3") -or ($WUSetting -eq "4")) {
                Write-Log "[+] Launching security intelligence updates"
                Update-MPSignature -UpdateSource MicrosoftUpdateServer
            }
        }
    }
    catch {
        Write-Log "[!] Error installing or updating MDAV" "ERROR"
        Write-Log $_ "ERROR"
        $status.code = "ERROR"
        $status.msg = "[!] Error installing or updating MDAV"
        return $status
    }


    ## Run Signaure Update 
    $serviceWinDefend = Get-Service -Name windefend
    $DefenderGUIFeature = Get-WindowsFeature -Name Windows-Defender-GUI
    Start-Sleep -s 10
    
    If (($serviceWinDefend) -AND ($DefenderGUIFeature.InstallState -eq 'Installed')){
        & 'C:\Program Files\Windows Defender\MSASCui.exe' -Update -hide
        Start-Sleep -s 60
        & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -signatureupdate
        Start-Sleep -s 30
        Write-Log "[!] SUCCESS : Windows Defender Signature Updated" "SUCCESS"
    } else {
        Write-Log "[!] Failed : Windows Defender Signature Update Component Check Failed, need to check Windows Defender status" "ERROR"
        $status.code = "ERROR"
        $status.msg = "[!] Failed : Windows Defender Signature Update Component Check Failed, need to check Windows Defender status"
        return $status
    }

    # Step : MMA Setup
    Write-Log "[+] MMA installing..." "INFO"
    & $global:MMA_installer_Path /qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=0 OPINSIGHTS_WORKSPACE_ID=$workspaceId OPINSIGHTS_WORKSPACE_KEY=$workspaceKey AcceptEndUserLicenseAgreement=1 | Out-Null
    Start-Sleep -s 120 -ErrorAction SilentlyContinue
    Write-Log "[+] After waiting 3 mins, assumed MMA installed" "INFO"
    
    $mma = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg' -ErrorAction SilentlyContinue
    $mma.AddCloudWorkspace($workspaceId, $workspaceKey)
    $mma.ReloadConfiguration()
    Write-Log "[+] MMA Setup End" "INFO"
    Start-Sleep -s 10 -ErrorAction SilentlyContinue
    Write-Log "[+] After waiting 10s, assumed MMA configured" "INFO"

    ## Get MMA Onboarding Status
    $MDATP = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if ( $MDATP.OnboardingState -eq '1')
    {
        Write-Log "[*] MMA OnboardingState OK" "SUCCESS"
    } else {
        Write-Log "[!] MMA OnboardingState Maybe Failed, need to reboot and double check" "Error"
        $status.code = "ERROR"
        $status.msg = "[!] MMA OnboardingState Maybe Failed, need to reboot and double check"
    }
    return $status

}


## Install-Windows2019 (Tested)
Function Install-Windows2019{
    Write-Log "[+] Handling Windows 2019 Onboard Script Now"

    $status = "" | Select-Object -Property code, msg
    $status.code = "SUCCESS"

    $OnboardingPackageScriptPath = $global:Win2019_OnboardingPackageScriptName
    $OnboardingPackageZipPath = $global:Win2019_OnboardingPackageZipName
	# Execute Onboard script
	if (Test-Path "filesystem::$($OnboardingPackageScriptPath)"){
		try{
			Write-Log "[+] Onboarding script detected, proceed with onboarding"
			Start-Process -FilePath ($OnboardingPackageScriptPath) -Wait -Verb RunAs
			Write-Log "[*] Onboarding completed" "SUCCESS"
		} catch {
			Write-Log "[!] Error while trying to onboard the machine to MDATP" "ERROR"
			Write-Log $_ "ERROR"
            $status.code = "ERROR"
            $status.msg = "[!] Error while trying to onboard the machine to MDATP"
		}
	} elseif (Test-Path "filesystem::$($OnboardingPackageZipPath)"){
		try{
			Write-Log "[+] Onboarding package detected, proceed with onboarding"
			Expand-Archive -Path $OnboardingPackageZipPath -DestinationPath "$($Scriptdir)\Win2019" -Force
			Start-Process -FilePath ($OnboardingPackageScriptPath) -Wait -Verb RunAs
			Write-Log "[*] Onboarding completed" "SUCCESS"
		} catch {
			Write-Log "[!] Error while trying to onboard the machine to MDATP" "ERROR"
			Write-Log $_ "ERROR"
            $status.code = "ERROR"
            $status.msg = "[!] Error while trying to onboard the machine to MDATP"
		}
	} else{
        Write-Log "[!] No Onboarding package or script in share drive" "ERROR"
        $status.code = "ERROR"
        $status.msg = "[!] No Onboarding package or script in share drive"
    }
    return $status
}

## Install-Windows10 (Tested)
Function Install-Windows10{
    Write-Log "[+] Handling Windows 10 Onboard Script Now"

    $status = "" | Select-Object -Property code, msg
    $status.code = "SUCCESS"

    $OnboardingPackageScriptPath = $global:Win10_OnboardingPackageScriptName
    $OnboardingPackageZipPath = $global:Win10_OnboardingPackageZipName
	# Execute Onboard script
	if (Test-Path "filesystem::$($OnboardingPackageScriptPath)"){
		try{
			Write-Log "[+] Onboarding script detected, proceed with onboarding"
			Start-Process -FilePath ($OnboardingPackageScriptPath) -Wait -Verb RunAs
			Write-Log "[*] Onboarding completed" "SUCCESS"
		} catch {
			Write-Log "[!] Error while trying to onboard the machine to MDATP" "ERROR"
			Write-Log $_ "ERROR"
            $status.code = "ERROR"
            $status.msg = "[!] Error while trying to onboard the machine to MDATP"
		}
	} elseif (Test-Path "filesystem::$($OnboardingPackageZipPath)"){
		try{
			Write-Log "[+] Onboarding package detected, proceed with onboarding"
			Expand-Archive -Path $OnboardingPackageZipPath -DestinationPath "$($Scriptdir)\Win10" -Force
			Start-Process -FilePath ($OnboardingPackageScriptPath) -Wait -Verb RunAs
			Write-Log "[*] Onboarding completed" "SUCCESS"
		} catch {
			Write-Log "[!] Error while trying to onboard the machine to MDATP" "ERROR"
            Write-Log $_ "ERROR"
            $status.code = "ERROR"
            $status.msg = "[!] Error while trying to onboard the machine to MDATP"
		}
	} else{
        Write-Log "[!] No Onboarding package or script in share drive" "ERROR"
        $status.code = "ERROR"
        $status.msg = "[!] No Onboarding package or script in share drive"
    }
    return $status
}


## Run a detection test
Function Test-Detection{
    Start-Process powershell.exe -ArgumentList ("-file $($global:Test_Detection_Script_Path)", "-ExecutionPolicy Bypass")
}


####################################################################################################################
#
# Main
#
####################################################################################################################

Function Main(){
#0. Check log path exist & create log files
    $hostname = (hostname)
    
    if (!(Test-Path ($global:Log_folder))){
        Exit
        # New-Item -Path $global:Log_folder -Name $Log_folder -ItemType "directory"
    }

    $Date_str = (Get-Date).ToUniversalTime().toString("yyyy-MM-dd_HHmmss") + "_UTC"
    $log_file_name = "$($hostname)_mdatp_deploy_log_$($Date_str).csv"
    New-Item -Path $Log_folder -Name $log_file_name -ItemType "file"
    $global:logfile = "$($Log_folder)\$($log_file_name)"


#1. Check runas Admin & Set ExecutionPolicy
    $status = Get-RunningPriv
    if($status.code -eq "ERROR"){
        rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
        Exit
    }


#2. Set Script Directory to share drive
    if (!(Test-Path ("filesystem::\$($share_drive_path)"))){
        $Scriptdir = (Get-Item -Path $share_drive_path -Verbose).FullName
        Write-Log "[+] Share drive $($share_drive_path) existed"
    } elseif (dir $share_drive_path) {
        $Scriptdir = (Get-Item -Path $share_drive_path -Verbose).FullName
        Write-Log "[+] Share drive $($share_drive_path) existed"
    } else{
        Write-Log "[+] Share drive $($share_drive_path) not existed" "Error"
        rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
        Exit
    }


#3. Check already onboarded
    $MATPstatus = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status")."OnboardingState"
    if ($MATPstatus) {
        if($MATPstatus -eq 1){
            Write-Log "[!] Onboarded status detected. Please check the onboarding on MDATP Security Center" "SUCCESS"
            Write-Log "[!] Script Finished" "SUCCESS"
            rename-item $global:logfile -newname "$($Log_folder)\SUCCESS_$($log_file_name)"
            Exit
        } else {
            Write-Log "[!] MDATP reg key found but no offboarded status detected!" "ERROR"
            Write-Log "[+] Now checking patches and applications" "DEBUG"
        }
    }else{
        Write-Log "[*] No Onboard key detected. Now using following Powershell command to have a look." "ERROR"
        Write-Log "[*] If there is not output of reg key of Windows Advanced Threat Protection. Assumed as not Offboarded!" "DEBUG"
        Write-Log "[+] Powershell: Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -- OUTPUT START" "DEBUG"
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
            Write-Log "[!] Third party Anti-Virus Software Detected: Please remove $($AV_name)" "ERROR"
            Write-Log "[!] Uninstalling TrendMicro officescan now..." "ERROR"
            Start-Process -FilePath $global:Uninstall_Trendmicro_tool_path -ArgumentList ("-noinstall") -Wait -Verb runas
            Start-Sleep -Seconds 30
            Write-Log "[+] After waiting 30s, assumed TrendMicro officescan uninstalled" "INFO"
            # double confirm
            $thirdPartyAV = get-process -name $AVProcesses 2> $null
            if($thirdPartyAV){
                Write-Log "[!] TrendMicro officescan Uninstall Process Failed" "Error"
                rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
                Exit
            } else {
                Write-Log "[!] TrendMicro officescan Uninstall Process Success" "Success"
            }
		}
	}else{
        Write-Log "[+] Seems No Third party Anti-Virus Software Detected"
    }

    # Make sure MDAV can be ran
    Write-Log "[+] Ensure there are no registry keys to prevent MDAV to run" "INFO"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Policies\Windows Defender" -Name "DisableAntiSpyware" -Value 0 2> $null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Policies\Windows Defender" -Name "DisableAntiVirus" -Value 0 2> $null

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 2> $null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 2> $null

    Write-Log "[*] MDAV Regrisy keys Edited" "SUCCESS"


#5. Check Windows Version and install mdatp onboard
    $OSinfo = Get-WmiObject -Class Win32_OperatingSystem
	$OSCaption = $OSinfo.Caption
    $status = Check-Windows-Version $OSCaption
    if ($status.code -eq "SUCCESS"){
        $OSVersion = $status.msg
    } else {
        rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
        Exit
    }
    
    if ($OSVersion -eq "Windows 10"){
        $deploy_status = Install-Windows10
    } elseif ($OSVersion -eq "Windows 2019") {
        $deploy_status = Install-Windows2019
    } elseif ($OSVersion -eq "Windows 2016") {
        $deploy_status = Install-Windows2016
    } elseif ($OSVersion -eq "Windows 2012 R2") {
        $deploy_status = Install-Windows2012R2
    } elseif ($OSVersion -eq "Windows 2008 R2") {
        $deploy_status = Install-Windows2008R2
    }

    Start-Sleep 10
    if ($deploy_status.code -eq "ERROR"){
        rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
        Exit
    }


#5. Optional: sample sharing used in the deep analysis feature
    # Recommanded to copy them to domain controller to support & manage the deep analysis function!
    #5.1 POC in copy to local drive
	If (ls $global:ADMXSourceFolder -Name)
	{
		Write-Log "[+] Copying ADMX Files"
		Copy-Item $global:ADMXSourceFolder\* $global:ADMXDestinationFolder -Recurse -Force
		Write-Log "[!] Finished Copying ADMX Files" "SUCCESS"
	}
	else
	{
        Write-Log "[!] Failed : COPY Policy ADMX Failed, no additonal GPO template exist" "ERROR"
        rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
        Exit
	}


#5.1 Recommanded: GPO
	# Suggested to deploy as Domain GPO
	# Please check: 
	#	- HTML recommanded GPO
	#	- https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-endpoints-gp
    # Recommanded to change Group Policy to manage endpoint protection configuration!!! local policy just POC
    # This POC havent config ASR attack surface reduction
    #5.1.1 POC in edit local policy
    if (($OSVersion -eq "Windows 10") -or ($OSVersion -eq "Windows 2019") -or ($OSVersion -eq "Windows 2016")){
        if (dir $global:DefenderPolicyPath){
            $lgpo_path = "$($global:DefenderPolicyPath)"
            if(dir $lgpo_path){
                & "$($global:LGPO_EXE_Path)\LGPO.exe" @('/g', "$($global:DefenderPolicyPath)", '/q')
                Write-Log "[!] LGPO Updated" "SUCCESS"
            } else {
                Write-Log "[!] No Policy folder in share drive" "ERROR"
                rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
                Exit
            }
        }else{
            Write-Log "[!] No LGPO folder in share drive" "ERROR"
            rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
            Exit
        }
    }

#6. double check the MDATP status
    $MATPstatus = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status")."OnboardingState"
    if ($MATPstatus) {
        if($MATPstatus -eq 1){
            Write-Log "[!] Onboarded status detected. Please check the onboarding on MDATP Security Center" "SUCCESS"
        } else {
            Write-Log "[!] MDATP reg key found but no offboarded status detected!" "ERROR"
            rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
            Exit
        }
    }else{
        Write-Log "[!] No Onboard key detected. now using following Powershell command to have a look." "ERROR"
        Write-Log "[*] If there is not output of reg key of Windows Advanced Threat Protection. Assumed as not Offboarded!" "DEBUG"
        Write-Log "[+] Powershell: Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'" "DEBUG"
        $status_all = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
        if ($status_all) {
            Write-Log $status_all "DEBUG"
        }
        Write-Log "[+] Powershell: Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' - OUTPUT END" "DEBUG"
        Write-Log "[!] No Onboard key detected." "ERROR"
        rename-item $global:logfile -newname "$($Log_folder)\ERROR_$($log_file_name)"
        Exit
    }


#7. Launch test detection script
    Write-Log "[+] Launch: Test Detection Script" "DEBUG"
    Test-Detection


#8. pop up reboot msg to active user session
    if ($OSVersion -eq "Windows 10"){
        $hostname = $env:computername
        $sessions = Get-ActiveSessions $hostname
        foreach($sess in $sessions){
            if ($sess.State -eq "Active"){
                Write-Log "[+] Get Active Desktop Session: $($sess.ID, $sess.SessionName, $sess.Type, $sess.UserName, $sess.ComputerName)" "DEBUG"
                Write-Log "[+] Get Active Desktop Session ID: $($sess.ID)" "DEBUG"
                cmd /c "$($Scriptdir)psexec.exe -accepteula -i $($sess.ID) cmd.exe /c `"$($Scriptdir)\msg.bat`" "
                cmd /c "$($Scriptdir)psexec.exe -accepteula -i $($sess.ID) cmd.exe /c `"$($Scriptdir)\msg.bat`" "
                Write-Log "[!] Trying pop up reboot msg!" "DEBUG"
            }
        }
    }

Write-Log "[*] Installation completed. Restart is required" "INFO"
rename-item $global:logfile -newname "$($Log_folder)\SUCCESS_$($log_file_name)"
}

####################################################################################################################
#
# Run
#
####################################################################################################################

Main
