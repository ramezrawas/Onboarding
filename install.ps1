###########################################################
#                                                         #
#                                                         #
#               IOM "Autopilot on a stick"                #
#                                                         #
#  Script takes the following actions                     #
#    1. rename the computer                               #
#    2. set timezone and force a resync                   #
#    3. reboot                                            #
#    4. join the Active Directory                         #
#    5. reboot                                            #
#    6. installing software                               #
#    7. setting Default App Associations                  #
#    8. importing Taskbar layout                          #
#    9. setting default URL in Edge and Chrome            #
#   10. setting up IE mode for MNL certificate            #
#   11. disabling Internet Edge FirstRun experience       #
#   12. disabled - uninstalling Internet Explorer         #
#   13. creating Desktop shortcuts                        #
#   14. configuring Adobe Acrobat DC                      #
#   15. logging in with domain account                    #
#   16. checking for proper Administrators memberships    #
#   17. checking Azure device replication                 #
#   18. loading CO script if available                    #
#                                                         #
#  Software that will be installed:                       #
#    1. 7-Zip                                             #
#    2. Zscaler                                           #
#    3. Acrobat Reader                                    #
#    4. Any Connect with SBL + VPN profiles               #
#    5. Chrome                                            #
#    6. SAP                                               #
#    7. TeamViewer Host                                   #
#    8. Dell Command / Lenovo System Update               #
#    9. Office M365                                       #
#                                                         #
#                                                         #
# Author: Valentin VALEANU (RO Brussels) vvaleanu@iom.int #
###########################################################

set-executionpolicy -scope CurrentUser -executionPolicy Bypass -Force

# disabling errors
$ErrorActionPreference= 'silentlycontinue'

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

# checking for log folder path
If (-not (Test-Path "$PSScriptRoot\logs")) {
    New-Item -Path "$PSScriptRoot\logs" -ItemType Directory
}

#load script configuration
Foreach ($i in $(Get-Content $PSScriptRoot\script.conf)){
    Set-Variable -Name $i.split("=")[0] -Value $i.split("=",2)[1]
}

# getting the manufacturer
$manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer

Write-Host "
IOM setup script
    "
Write-Host "-----------------------------------------"

if(-not (Test-PAth -Path "$PSScriptRoot\status.xml" -PathType Leaf))
{
    Set-Content -Path "$PSScriptRoot\status.xml" -Value "0"
}

Write-Host "***  This script is meant to be used on new or newly installed computers.  ***

***  The script will take the following actions:  ***
"
if ((Get-Content -Path "$PSScriptRoot\status.xml") -ge 1)
{
    Write-Host " 1. rename the computer
 2. set timezone
 3. reboot" -BackgroundColor Green
}
else
{
    Write-Host " 1. rename the computer
 2. set timezone
 3. reboot"
}
if ((Get-Content -Path "$PSScriptRoot\status.xml") -ge 2)
{
    Write-Host " 4. join the Active Directory
 5. reboot" -BackgroundColor Green
}
else
{
    Write-Host " 4. join the Active Directory
 5. reboot"
}
if ((Get-Content -Path "$PSScriptRoot\status.xml") -ge 3)
{
    Write-Host " 6. installing software
 7. setting Default App Associations
 8. importing Taskbar layout
 9. setting default URL in Edge and Chrome
10. setting up IE mode for MNL certificate 
11. uninstalling Internet Explorer
12. creating Desktop shortcuts
13. configuring Adobe Acrobat DC" -BackgroundColor Green
}
else
{
    Write-Host " 6. installing software
 7. setting Default App Associations
 8. importing Taskbar layout
 9. setting default URL in Edge and Chrome
10. setting up IE mode for MNL certificate 
11. uninstalling Internet Explorer
12. creating Desktop shortcuts
13. configuring Adobe Acrobat DC"
}
Write-Host "14. logging in with domain account
15. checking for proper Administrators memberships
16. checking Azure device replication
17. loading COScript.ps1 if available
    
The below software will be installed:
1. 7-Zip
2. Zscaler
3. Acrobat Reader
4. Any Connect with SBL + VPN profiles
5. Chrome
6. SAP
7. TeamViewer Host"
if($manufacturer -match "Dell") { Write-Host "8. Dell Command Update" }
if($manufacturer -match "Lenovo") { Write-Host "8. Lenovo System Update" }
Write-Host "9. Office M365
    
-----------------------------------------
    
"

if((Get-Content -Path "$PSScriptRoot\status.xml") -eq 0) {

    # setting timezone
    Set-TimeZone -Id "$Timezone"
    #force a time resync
    net start W32Time
    W32tm /resync /force

    # enable logging
    $timestamp = Get-Date
    Set-Content -Path "$PSScriptRoot\logs\$ComputerName.txt" -Value "$timestamp - computer renaming, join to AD and software installation started"
    Add-Content $PSScriptRoot\logs\$ComputerName.txt "`n$timestamp - Computer name configured: $ComputerName"
    Add-Content $PSScriptRoot\logs\$ComputerName.txt "`n$timestamp - OU path: $OUpath"

    #register task for script persistence during reboots
    $scriptPath = "$PSScriptRoot\install.ps1"
    Unregister-ScheduledTask -TaskName "IOM_Setup" -Confirm:$false
    Register-ScheduledTask -TaskName "IOM_Setup" -Trigger (New-ScheduledTaskTrigger -AtLogon) -Action (New-ScheduledTaskAction -Execute "${Env:WinDir}\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ("-Command `"& '" + $scriptPath + "'`"")) -Principal (New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest)
    
    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$ComputerName.txt "`n$timestamp - Scheduled task registered, renaming computer, setting timezone and rebooting"

    Set-Content -Path "$PSScriptRoot\status.xml" -Value "1"

    # configuring Autologin
    #$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    #Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
    #Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "iom" -type String 
    #Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "iom" -type String

    Rename-Computer -NewName $ComputerName -Restart
    
}

if((Get-Content -Path "$PSScriptRoot\status.xml") -eq 1) {

    Write-Host "Computer name set to: $env:computername"

    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Computer renamed, attempting domain join"

    DO
    {
        Write-Host "Checking the connection ... " -NoNewline
        $dnsOk = (Resolve-DnsName iom.int 2>$1 -EA SilentlyContinue -EV Err -WarningAction SilentlyContinue).Count
        if($dnsOk -ge 10)
        {
            Write-Host " connection is ok " -BackgroundColor Green
        }
        else
        {
            Write-Host " not ready " -BackgroundColor Red
            Sleep 5
            Clear-Host
        }
    }
    While (-not(Resolve-DnsName iom.int 2>$1 -EA SilentlyContinue -EV Err -WarningAction SilentlyContinue))

    Write-Host "Joining IOM.INT ... " -NoNewline

    #using credentials from script config
    $PasswordConverted = $ADUserPassword | ConvertTo-SecureString -AsPlainText -Force
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ADUserName,$PasswordConverted

    $join = Add-Computer -DOMAINNAME IOM.INT -OUPath "$OUpath" -cred $cred -passthru

    if ($join.HasSucceeded) { 
       Write-Host "Successfully added computer '$($join.ComputerName)'" -ForegroundColor Green
       Set-Content -Path "$PSScriptRoot\status.xml" -Value "2"

       # logging
       $timestamp = Get-Date
       Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Computer joined to domain, rebooting"

       # configuring Autologin
       #$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
       #Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
       #Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "iom" -type String 
       #Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "iom" -type String

       Restart-Computer
    }
    else
    {
       Write-Host "Adding computer '$($join.ComputerName)' failed!" -ForegroundColor red
       # logging
       $timestamp = Get-Date
       Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Computer join FAILED: $join"

       # sleep to prevent script window close
       Sleep 999999
    }

}

if((Get-Content -Path "$PSScriptRoot\status.xml") -eq 2) {

    Write-Host "Installing 7zip ... " -NoNewline
    Start-Process -FilePath "$PSScriptRoot\7z2201-x64.exe" -ArgumentList "/S" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "7-Zip 22.01 (x64)" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - 7-Zip installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - 7-Zip installation failed"
    }

    Write-Host "Installing Zscaler ... " -NoNewline
    Start-Process "msiexec.exe" -ArgumentList "/i $PSScriptRoot\Zscaler-windows-3.9.0.183-installer-x64.msi /qn" -Wait -NoNewWindow
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Zscaler" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Zscaler installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Zscaler failed"
    }

    Write-Host "Installing Acrobat Reader ... " -NoNewline
    Start-Process -FilePath "$PSScriptRoot\AcroRdrDCx642300120064_MUI.exe" -ArgumentList "/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Adobe Acrobat (64-bit)" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Acrobat Reader installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Acrobat Reader failed"
    }

    Write-Host "Installing AnyConnect core ... " -NoNewline
    Start-Process "msiexec.exe" -ArgumentList "/i $PSScriptRoot\anyconnect\anyconnect-win-4.10.01075-core-vpn-predeploy-k9.msi /qn reboot=ReallySuppress" -Wait -NoNewWindow
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Cisco AnyConnect Secure Mobility Client" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Cisco AnyConnect Secure Mobility Client installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Cisco AnyConnect Secure Mobility Client failed"
    }
    Write-Host "Installing AnyConnect SBL ... " -NoNewline
    Start-Process "msiexec.exe" -ArgumentList "/i $PSScriptRoot\anyconnect\anyconnect-win-4.10.01075-SBL-predeploy-k9.msi /qn reboot=ReallySuppress" -Wait -NoNewWindow
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Cisco AnyConnect Start Before Login Module" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Cisco AnyConnect Start Before Login Module installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Cisco AnyConnect Start Before Login Module failed"
    }

    # generating Cisco AnyConnect VPN profiles based on computer name
    if($env:computername -like "BRU*")
    {
        Write-Host "Generating Cisco AnyConnect config file for Brussels ... " -NoNewline
        Set-Content -Path "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\vpn_profiles.xml" -Value '<?xml version="1.0" encoding="UTF-8"?>
        <AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
            <ServerList>
                <HostEntry>
                    <HostName>Berlin</HostName>
                    <HostAddress>bercoportal.iom.int</HostAddress>
                </HostEntry>
                <HostEntry>
                    <HostName>Nuremberg</HostName>
                    <HostAddress>nueportal.iom.int</HostAddress>
                </HostEntry>
            </ServerList>
        </AnyConnectProfile>'
    }
    else
    {
        Write-Host "Generating Cisco AnyConnect config file ... " -NoNewline
        Set-Content -Path "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\vpn_profiles.xml" -Value '<?xml version="1.0" encoding="UTF-8"?>
        <AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
            <ServerList>
                <HostEntry>
                    <HostName>IOM</HostName>
                    <HostAddress>connect.iom.int</HostAddress>
                </HostEntry>
            </ServerList>
        </AnyConnectProfile>'
    }

    if(Test-PAth -Path "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\vpn_profiles.xml" -PathType Leaf)
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - VPN profiles created"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - VPN profiles failed"
    }

    Write-Host "Installing Chrome ... " -NoNewline
    Start-Process -FilePath "$PSScriptRoot\ChromeStandaloneSetup64.exe" -ArgumentList "/silent /install" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Google Chrome" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Chrome installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Chrome failed"
    }

    Write-Host "Installing Firefox ... " -NoNewline
    Start-Process -FilePath "$PSScriptRoot\FirefoxInstaller.exe" -ArgumentList "/silent /install" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Firefox" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Firefox installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Firefox failed"
    }

    Write-Host "Installing SAP GUI ... " -NoNewline
    Start-Process -FilePath "$PSScriptRoot\SAP-GUI-7.6\SAP_installer\Setup\NwSapSetup.exe" -ArgumentList "/silent /product=SAPGUI+SAPWUS+PdfPrintGui" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "SAP GUI for Windows 7.60  (Patch 9)" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - SAP GUI installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - SAP GUI failed"
    }
    Write-Host "Preparing configuration files ..." -NoNewline
    Copy-Item -Path "$PSScriptRoot\SAP-GUI-7.6\SAP" -Destination "C:\SAP" -Recurse
    if(Test-PAth -Path "C:\SAP\SAPUILandscape.xml" -PathType Leaf)
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - SAP configuration done"
    }
    else
    {
        Write-Host "** ERROR **" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - SAP configuration failed"
    }
    Write-Host "Setting environment variable ..." -NoNewline
    if(setx SAPLOGON_LSXML_FILE "C:\SAP\SAPUILandscape.xml" /M)
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - SAP variable set"
    }
    else
    {
        Write-Host "** ERROR **" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - SAP variable failed"
    }

    #Copy TV
    Copy-Item -Path “C:\Users\admin\Downloads\kit-new-auto\TeamViewerQS-idcxbvp3ht.exe” -Destination “C:\Users\Public\Desktop”

    #Write-Host "Installing TeamViewer Host ... " -NoNewline
    #Start-Process -FilePath "$PSScriptRoot\TeamViewer_15_Host_setup.exe" -ArgumentList "/S" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    #Write-Host " done " -BackgroundColor Green -NoNewline
    #Write-Host " | Verifying ... " -NoNewline
    #if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "TeamViewer Host" }))
    #{
    #    Write-Host " installed ok "-BackgroundColor Green
        # logging
    #    $timestamp = Get-Date
    #    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - TeamViewer installed"
    #}
    #else
    #{
    #    Write-Host "** ERROR **"-BackgroundColor Red
        # logging
    #    $timestamp = Get-Date
    #    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - TeamViewer failed"
    #}

    #if($manufacturer -match "Dell") {
    #    Write-Host "Installing Dell Command Update ... " -NoNewline
    #    if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Dell Command | Update for Windows Universal" }) -or (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Dell Update for Windows 10" }))
    #    {
    #        Write-Host " skipped, already installed. " -BackgroundColor Green
            # logging
    #        $timestamp = Get-Date
    #        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Dell Command Update skipped, already installed"
    #    }
    #    else
    #    {
    #        Start-Process -FilePath "$PSScriptRoot\DellCommandUpdateApp_Setup.exe" -ArgumentList "/S /v/qn" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    #        Write-Host " done " -BackgroundColor Green -NoNewline
    #        Write-Host " | Verifying ... " -NoNewline
    #        if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Dell Command | Update for Windows Universal" }))
    #        {
    #            Write-Host " installed ok "-BackgroundColor Green
                # logging
    #            $timestamp = Get-Date
    #            Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Dell Command Update installed"
    #        }
    #        else
    #        {
    #            Write-Host "** ERROR **"-BackgroundColor Red
                # logging
    #            $timestamp = Get-Date
    #            Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Dell Command Update failed"
    #        }
    #    }
    #}

    if($manufacturer -match "Lenovo") {
        Write-Host "Installing Lenovo System Update ... " -NoNewline
        if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Lenovo System Update" }))
        {
            Write-Host " skipped, already installed. " -BackgroundColor Green
            # logging
            $timestamp = Get-Date
            Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Lenovo System Update skipped, already installed"
        }
        else
        {
            Start-Process -FilePath "$PSScriptRoot\system_update_5.08.01.exe" -ArgumentList "/VERYSILENT /NORESTART" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
            Write-Host " done " -BackgroundColor Green -NoNewline
            Write-Host " | Verifying ... " -NoNewline
            if((Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Lenovo System Update" }))
            {
                Write-Host " installed ok "-BackgroundColor Green
                # logging
                $timestamp = Get-Date
                Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Lenovo System Update installed"
            }
            else
            {
                Write-Host "** ERROR **"-BackgroundColor Red
                # logging
                $timestamp = Get-Date
                Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Lenovo System Update failed"
            }
        }
    }

    Write-Host "Installing M365 (removing pre-installed) ... " -NoNewline
    Start-Process -FilePath "$PSScriptRoot\O365\setup.exe" -ArgumentList "/configure $PSScriptRoot\O365\$M365XMLFilename" -WorkingDirectory $env:TEMP -Wait -LoadUserProfile
    Write-Host " done " -BackgroundColor Green -NoNewline
    Write-Host " | Verifying ... " -NoNewline
    if((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq "Microsoft 365 Apps for enterprise - en-us" }))
    {
        Write-Host " installed ok "-BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - M365 installed"
    }
    else
    {
        Write-Host "** ERROR **"-BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - M365 failed"
    }

    # configuring Default App Associations
    dism /online /Import-DefaultAppAssociations:"$PSScriptRoot\DefaultAppAssociations.xml"
    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Default apps imported"

    # importing Taskbar layout
    Write-Host "Importing Taskbar layout ..." -NoNewline
    Import-StartLayout -LayoutPath "C:\kit-new-auto\TaskBarLayout.xml" -MountPath "C:\"
    Write-Host " done " -BackgroundColor Green
    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Taskbar layout imported"

    # default URL in Edge
    Write-Host "Setting default page in Edge ..." -NoNewline
    $EdgeHome = 'HKLM:\Software\Policies\Microsoft\Edge'
    If ( -Not (Test-Path $EdgeHome))
    {
      New-Item -Path $EdgeHome | Out-Null
    }
    Set-ItemProperty -Path $EdgeHome -Name 'RestoreOnStartup' -Value 4 -Type 'DWORD'
    $EdgeSUURL = "$EdgeHome\RestoreOnStartupURLs"
    If ( -Not (Test-Path $EdgeSUURL))
    {
      New-Item -Path $EdgeSUURL | Out-Null
    }
    Set-ItemProperty -Path $EdgeSUURL -Name '1' -Value 'https://intranetportal/en-us/Pages/Home.aspx'
    if((Get-ItemProperty -Path $EdgeSUURL -Name '1').1 -eq 'https://intranetportal/en-us/Pages/Home.aspx')
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Intranet set as default in Edge"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Intranet FAILED as default in Edge"
    }
    # default URL in Chrome
    Write-Host "Setting default page in Chrome ..." -NoNewline
    $ChromeHome = 'HKLM:\Software\Policies\Google\Chrome'
    If ( -Not (Test-Path $ChromeHome))
    {
      New-Item -Path $ChromeHome | Out-Null
    }
    Set-ItemProperty -Path $ChromeHome -Name 'RestoreOnStartup' -Value 4 -Type 'DWORD'
    $ChromeSUURL = "$ChromeHome\RestoreOnStartupURLs"
    If ( -Not (Test-Path $ChromeSUURL))
    {
      New-Item -Path $chromeSUURL | Out-Null
    }
    Set-ItemProperty -Path $ChromeSUURL -Name '1' -Value 'https://intranetportal/en-us/Pages/Home.aspx'
    if((Get-ItemProperty -Path $ChromeSUURL -Name '1').1 -eq 'https://intranetportal/en-us/Pages/Home.aspx')
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Intranet set as default in Chrome"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Intranet FAILED as default in Chrome"
    }

    # setting IE mode in Edge for https://mnl2k12cert01/certsrv
    Write-Host "Generating site list for IE mode ... " -NoNewline
    Set-Content -Path "C:\ie_site_list.xml" -Value '<site-list version="1">
  <created-by>
    <tool>EMIESiteListManager</tool>
    <version>10.0.14357.1004</version>
    <date-created>04/26/2023 19:16:42</date-created>
  </created-by>
  <site url="mnl2k12cert01/certsrv">
    <compat-mode>Default</compat-mode>
    <open-in>IE11</open-in>
  </site>
</site-list>'
    if(Test-Path 'C:\ie_site_list.xml'){
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - C:\ie_site_list.xml created"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - C:\ie_site_list.xml FAILED"
    }
    
    Write-Host "Configuring registry settings for IE mode ... " -NoNewline
    if(!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge')){
        New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
    }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'InternetExplorerIntegrationLevel' -Type DWord -Value '1' -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'InternetExplorerIntegrationSiteList' -Type String -Value 'C:\\ie_site_list.xml' -Force
    if(((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'InternetExplorerIntegrationLevel') -eq '1') -and ((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'InternetExplorerIntegrationSiteList') -eq 'C:\\ie_site_list.xml'))
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - IE mode registry done"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - IE mode registry FAILED"
    }

    # uninstalling Internet Explorer
    #Write-Host "Uninstalling Internet Explorer ... " -NoNewline
    #if (Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 –Online -NoRestart -ea silentlyContinue -WarningAction silentlyContinue)
    #{
    #    Write-Host " done " -BackgroundColor Green
    #    # logging
    #    $timestamp = Get-Date
    #    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Internet Explorer uninstalled"
    #}

    # disabling Internet Edge FirstRun experience
    Write-Host "Disabling Internet Edge FirstRun experience ..." -NoNewline
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'HideFirstRunExperience' -Type DWord -Value '1' -Force
    if((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'HideFirstRunExperience') -eq '1')
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Internet Edge FirstRun experience disabled"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Internet Edge FirstRun experience FAILED"
    }

    # creating Desktop shortcuts
    #
    Write-Host "Creating Desktop shortcuts ... " -NoNewline
    # creating shortcut on Desktop for Intranet Portal
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Default\Desktop\Intranet Portal.url")
    $Shortcut.TargetPath = "https://intranetportal/en-us/Pages/Home.aspx"
    #$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe" #"shell32.dll,21"
    $Shortcut.Save()

    # creating shortcut on Desktop for InfoSec
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Default\Desktop\InfoSec portal.url")
    $Shortcut.TargetPath = "https://infosecservices.iom.int/infosecservices/page.axd"
    #$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe" #"shell32.dll,21"
    $Shortcut.Save()

    # creating shortcut on Desktop for PRISM Apps
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Default\Desktop\PRISM Apps.url")
    $Shortcut.TargetPath = "https://prismapps.iom.int/prismapps"
    #$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe" #"shell32.dll,21"
    $Shortcut.Save()

    # creating shortcut on Desktop for FinCoorP
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Default\Desktop\FinCoorP.url")
    $Shortcut.TargetPath = "https://fincoorp.iom.int/support/home"
    #$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe" #"shell32.dll,21"
    $Shortcut.Save()

    # creating shortcut on Desktop for IOM ICT Procurement portal
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Default\Desktop\IOM ICT Procurement portal.url")
    $Shortcut.TargetPath = "https://hrm.iom.int/support/home"
    #$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe" #"shell32.dll,21"
    $Shortcut.Save()

    # creating shortcut on Desktop for IOM HRM
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\Users\Default\Desktop\IOM Human Resources.url")
    $Shortcut.TargetPath = "https://iomprocurement.freshservice.com/support/home"
    #$Shortcut.IconLocation = "C:\Program Files\Google\Chrome\Application\chrome.exe" #"shell32.dll,21"
    $Shortcut.Save()

    Write-Host " done " -BackgroundColor Green
    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Desktop shortcuts created"

    # configuring Adobe Acrobat DC
    Write-Host "Configuring Adobe Acrobat DC ... " -NoNewline
    if(!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSecurity\cPubSec')){
        New-Item 'HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSecurity\cPubSec' -Force | Out-Null
    }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSecurity\cPubSec' -Name 'bEnableCEFBasedUI' -Type DWord -Value '0' -Force
    if((Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSecurity\cPubSec' -Name 'bEnableCEFBasedUI') -eq '0')
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Adobe Acrobat DC configured"
    }
    else
    {
        Write-Host " ERROR " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Adobe Acrobat DC configuration FAILED"
    }

    # configuring Autologin with domain account
    #Write-Host "Configuring autologin with domain account ... " -NoNewline
    #$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    #Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
    #Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$ADUserName" -type String 
    #Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$ADUserPassword" -type String
    #Write-Host "  done  " -BackgroundColor Green

    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - autologin with domain account configured"

    # setting mode for Domain Login and continuing tasks
    Set-Content -Path "$PSScriptRoot\status.xml" -Value "3"

    # sleep 5
    Sleep 5

    Restart-Computer

}


if((Get-Content -Path "$PSScriptRoot\status.xml") -eq 3) {
    
    ### checking proper Administrators memberships and elevation
    #
    # checking Regional IT group
    Write-Host "$ROAdminGroup Administrators membership ... " -NoNewline
    if ((Get-LocalGroupMember -group "Administrators").Name -contains "IOMINT\$ROAdminGroup")
    {
        Write-Host "  true  " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - $ROAdminGroup is Administrator"
    }

    else
    {
        Write-Host "  FALSE  " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - $ROAdminGroup is NOT an Administrator"
    }

    # checking Country Office IT group
    Write-Host "$COAdminGroup Administrators membership ... " -NoNewline
    if ((Get-LocalGroupMember -group "Administrators").Name -contains "IOMINT\$COAdminGroup")
    {
        Write-Host "  true  " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - $COAdminGroup is Administrator"
    }

    else
    {
        Write-Host "  FALSE  " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - $COAdminGroup is NOT an Administrator"
    }

    # removing temporary local admin account iom\iom

    if(((Get-LocalGroupMember -group "Administrators").Name -contains "IOMINT\$ROAdminGroup") -and ((Get-LocalGroupMember -group "Administrators").Name -contains "IOMINT\$COAdminGroup"))
    {
        Write-Host "Removing iom account from Administrators ..." -NoNewline
        Remove-LocalGroupMember -Group "Administrators" -Member "iom"
        if(-not(Get-LocalGroupMember -group "Administrators").Name -contains "$ComputerName\iom")
        {
            Write-Host "  ERROR  " -BackgroundColor Red
            # logging
            $timestamp = Get-Date
            Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - iom account NOT removed from Administrators"
        }
        else
        {
            Write-Host "  done  " -BackgroundColor Green
            # logging
            $timestamp = Get-Date
            Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - iom account is removed from Administrators"
        }
    }
    else
    {
        Write-Host "Please check the Administrators membership" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Please check the Administrators membership"
    }

    # deleting profile and account
    $iom_account_path = (Get-CimInstance Win32_UserProfile -Filter "SID = '$((Get-LocalUser 'iom').Sid)'").LocalPath
    
    Write-Host "Deleting profile $iom_account_path ... " -NoNewline
    
    Get-ciminstance win32_userprofile -filter "SID = '$((Get-localuser 'iom').Sid)'" | Remove-ciminstance
    
    if(Test-PAth -Path "$iom_account_path"){
        Write-Host "  ERROR  " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - iom profile is NOT deleted"
    }
    else
    {
        Write-Host "  ok  " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - iom profile deleted"
    }

    Write-Host "Deleting iom local account ... " -NoNewline
    Remove-LocalUser -Name "iom"
    if((Get-LocalUser).Name -contains "iom"){
        Write-Host "  ERROR  " -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - iom account is NOT deleted"
    }
    else
    {
        Write-Host "  ok  " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - iom account deleted"
    }

    Write-Host "-----------------------------------------

clearing the screen in 10 seconds to prepare for the next step, logs available: $PSScriptRoot\logs\$env:computername.txt"

    Sleep 10

    # clearing screen
    Clear-Host

    Start-ScheduledTask -TaskPath "\Microsoft\Windows\Workplace Join\" -TaskName "Automatic-Device-Join"

    $timestamp = Get-Date
    $timestamp_start = Get-Date
    Write-Host "Checking for Azure device status every minute...
Started: $timestamp_start
Last check: $timestamp"

    # getting dsregcmd /status
    $Dsregcmd = New-Object PSObject ; Dsregcmd /status | Where {$_ -match ' : '}|ForEach {$Item = $_.Trim() -split '\s:\s'; $Dsregcmd|Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]','') -Value $Item[1] -EA SilentlyContinue}

    Write-Host "Azure replicated:" -NoNewline
    $status = $Dsregcmd.AzureAdJoined
    if ($status -eq "Yes")
    {
        $status = Write-Host " Yes " -BackgroundColor Green
    }
    else
    {
        $status = Write-Host " NO " -BackgroundColor Red
    }

    DO
    {
        Sleep 60

        # clearing screen
        Clear-Host

        Start-ScheduledTask -TaskPath "\Microsoft\Windows\Workplace Join\" -TaskName "Automatic-Device-Join"

        $timestamp = Get-Date
        $elapsed = [Math]::Ceiling(($timestamp - $timestamp_start).TotalMinutes)
        Write-Host "Checking for Azure device status every minute...
Started: $timestamp_start
Elapsed minutes: $elapsed
Last check: $timestamp"

        # getting dsregcmd /status
        $Dsregcmd = New-Object PSObject ; Dsregcmd /status | Where {$_ -match ' : '}|ForEach {$Item = $_.Trim() -split '\s:\s'; $Dsregcmd|Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]','') -Value $Item[1] -EA SilentlyContinue}

        Write-Host "Azure replicated:" -NoNewline
        $status = $Dsregcmd.AzureAdJoined
        if ($status -eq "Yes")
        {
            $status = Write-Host " Yes " -BackgroundColor Green
        }
        else
        {
            $status = Write-Host " NO " -BackgroundColor Red
        }
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('+{CAPSLOCK}')

    } while ($Dsregcmd.AzureAdJoined -eq "No")

    [system.console]::beep(2500,500)

    # logging
    $timestamp = Get-Date
    Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - $ComputerName replicated to Azure after $elapsed minutes"

    Write-Host "-----------------------------------------

Cleaning up ...
Removing Task ... " -NoNewline

    Unregister-ScheduledTask -TaskName "IOM_Setup" -Confirm:$false
    if(Get-ScheduledTask | Where-Object {$_.TaskName -like "IOM_Setup" })
    {
        Write-Host "** ERROR **" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Scheduled task unregister failed"
    }
    else
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Scheduled task unregistered"
    }

    Write-Host "Resetting the status, deleting credentials ... " -NoNewline
    Remove-Item -Path "$PSScriptRoot\status.xml", "$PSScriptRoot\script.conf"

    if(!(Test-PAth -Path "$PSScriptRoot\status.xml" -PathType Leaf) -and !(Test-PAth -Path "$PSScriptRoot\script.conf" -PathType Leaf))
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - cleanup done"
    }
    else
    {
        Write-Host "** ERROR **" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - cleanup failed"
    }

    Write-Host "Removing Autologin ... " -NoNewline
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Remove-ItemProperty -Path $RegistryPath -Name "DefaultUsername"
    Remove-ItemProperty -Path $RegistryPath -Name "DefaultPassword"
    Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "0" -Type String 

    if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon') -and -not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultUsername') -and -not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword') )
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Autologin disabled"
    }
    else
    {
        
        Write-Host "** ERROR **" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - Autologin disabling failed"
    }

    Write-Host "Uninstalling IOM OOBE provisioning package ... " -NoNewline
    Uninstall-ProvisioningPackage -PackageId "71612bb2-70da-4f31-95c1-c0b192458aa4"
    if(Get-ProvisioningPackage -PackageId "71612bb2-70da-4f31-95c1-c0b192458aa4")
    {
        Write-Host "** ERROR **" -BackgroundColor Red
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - IOM OOBE provision package uninstallation failed"
    }
    else
    {
        Write-Host " done " -BackgroundColor Green
        # logging
        $timestamp = Get-Date
        Add-Content $PSScriptRoot\logs\$env:computername.txt "`n$timestamp - IOM OOBE provision package uninstalled"
    }

    # removing login message "setup completed successfully"
    if(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LostMode")
    {
        Write-Host "Removing LostMode message ... " -NoNewline
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LostMode" -Force
        if(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LostMode")
        {
            Write-Host " ERROR " -BackgroundColor Red
        }
        else
        {
            Write-Host " done " -BackgroundColor Green    
        }
    }

    # loading CO script if available
    Write-Host "Looking for COScript.ps1 ... " -NoNewline
    if(Test-Path -Path "$PSScriptRoot\COScript.ps1")
    {
        Write-Host " script found, starting " -BackgroundColor Green
        powershell.exe -executionpolicy bypass "& '$PSScriptRoot\COScript.ps1'"
    }
    else
    {
        Write-Host " script not found "
    }

    Read-Host -Prompt "Done! Logs available: $PSScriptRoot\logs\$env:computername.txt
    
Remember to delete C:\kit-new-auto folder!
    
You can now restart, login with a standard account and run the user-onboarding script available at C:\kit-new-auto\user-onboarding.ps1"
}