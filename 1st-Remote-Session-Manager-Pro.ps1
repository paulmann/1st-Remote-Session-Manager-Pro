<#
.SYNOPSIS
    Remote Session Manager Pro - Advanced RDP session control and management tool
    
.DESCRIPTION
    Professional tool for managing, monitoring, and controlling RDP sessions on Windows systems.
    Supports Windows 7/8/10/11 and Server editions with PowerShell 5.1+ compatibility.
    
.NOTES
    Author: Mikhail Deynekin (mid1977@gmail.com)
    GitHub: https://github.com/paulmann/1st-Remote-Session-Manager-Pro
    Version: 1.0.0
    Last Modified: 2025-01-15
    
.LICENSE
    MIT License - Free for commercial and personal use with attribution.
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Alias('i')]
    [ValidateRange(0, 65536)]
    [int]$SessionId = -1,
    
    [Parameter()]
    [Alias('h', '?')]
    [switch]$Help,
    
    [Parameter()]
    [Alias('v')]
    [switch]$Version,
    
    [Parameter()]
    [Alias('s')]
    [switch]$Status,
    
    [Parameter()]
    [Alias('e')]
    [switch]$Sessions,
    
    [Parameter()]
    [Alias('u')]
    [switch]$Update,
    
    [Parameter()]
    [Alias('d')]
    [switch]$DebugMode,
    
    [Parameter()]
    [Alias('o')]
    [switch]$ViewOnly,
    
    [Parameter()]
    [Alias('x')]
    [switch]$Disconnect,
    
    [Parameter()]
    [Alias('l')]
    [switch]$Logoff,
    
    [Parameter()]
    [Alias('m')]
    [string]$Message,
    
    [Parameter()]
    [Alias('c')]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter()]
    [Alias('q')]
    [switch]$Quiet,
    
    [Parameter()]
    [Alias('f')]
    [switch]$Force
)

#region CONSTANTS AND CONFIGURATION
# ============================================================================
# GLOBAL CONSTANTS AND CONFIGURATION
# ============================================================================

# Script metadata
$SCRIPT_NAME = "RemoteSessionManagerPro"
$SCRIPT_VERSION = "1.0.0"
$SCRIPT_AUTHOR = "Mikhail Deynekin"
$GITHUB_REPO = "https://github.com/mid1977/RemoteSessionManagerPro"
$RAW_GITHUB_URL = "https://raw.githubusercontent.com/mid1977/RemoteSessionManagerPro/refs/heads/main/RemoteSessionManagerPro.ps1"

# RDP/MSTSC Configuration
$DEFAULT_MSTSC_PARAMS = @(
    "/noConsentPrompt",      # Skip consent prompt (requires appropriate permissions)
    "/control",             # Enable toolbar for session control
    "/admin",               # Connect to console/admin session
    "/f",                   # Full screen mode
    "/span"                 # Span across multiple monitors
    # Alternative parameters (commented out):
    # "/w:1920",            # Window width
    # "/h:1080",            # Window height
    # "/multimon",          # Multiple monitor support (alternative to /span)
    # "/public",            # Public mode (no credential persistence)
    # "/restrictedAdmin"    # Restricted admin mode (Windows 8.1+)
)

# Registry paths for RDP configuration
$REGISTRY_PATHS = @{
    TerminalServer = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    TerminalServicesPolicies = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    TerminalServicesClient = "HKLM:\SOFTWARE\Microsoft\Terminal Services Client"
    WinStations = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
}

# Shadow mode values
$SHADOW_MODES = @{
    Disabled = 0            # No shadowing allowed
    WithPermission = 1      # Shadow with user permission
    WithoutPermission = 2   # Shadow without permission (view only)
    FullControl = 3         # Full control without permission (Windows Server 2016+)
    WithPermissionNotification = 4  # Shadow with permission and notification
}

# Session states
$SESSION_STATES = @{
    Active = "Active"
    Connected = "Connected"
    ConnectQuery = "ConnectQuery"
    Shadow = "Shadow"
    Disconnected = "Disconnected"
    Idle = "Idle"
    Listen = "Listen"
    Reset = "Reset"
    Down = "Down"
    Init = "Init"
}

# Colors for console output
$COLORS = @{
    Success = "Green"
    Error = "Red"
    Warning = "Yellow"
    Info = "Cyan"
    Debug = "Gray"
    Verbose = "Magenta"
}

# Error codes
$ERROR_CODES = @{
    Success = 0
    AdminRequired = 1
    ExecutionPolicy = 2
    SessionNotFound = 3
    ConnectionFailed = 4
    RegistryAccessDenied = 5
    ServiceError = 6
    InvalidParameter = 7
    UpdateFailed = 8
}

# Maximum retry attempts for various operations
$MAX_RETRIES = 3
$RETRY_DELAY = 2  # seconds

# Supported Windows versions
$SUPPORTED_WINDOWS_VERSIONS = @(
    "6.1",  # Windows 7 / Server 2008 R2
    "6.2",  # Windows 8 / Server 2012
    "6.3",  # Windows 8.1 / Server 2012 R2
    "10.0"  # Windows 10/11 / Server 2016+
)

#endregion

#region HELPER FUNCTIONS
# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-DebugLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [object]$Data = $null
    )
    
    if ($DebugMode -or $VerbosePreference -ne 'SilentlyContinue') {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $color = $COLORS.Debug
        
        switch ($Level) {
            "ERROR"   { $color = $COLORS.Error; $symbol = "[✗]" }
            "SUCCESS" { $color = $COLORS.Success; $symbol = "[✓]" }
            "WARNING" { $color = $COLORS.Warning; $symbol = "[!]" }
            "DEBUG"   { $color = $COLORS.Debug; $symbol = "[D]" }
            default   { $color = $COLORS.Info; $symbol = "[i]" }
        }
        
        $logMessage = "$timestamp $symbol $Message"
        Write-Host $logMessage -ForegroundColor $color
        
        if ($Data -and $DebugMode) {
            Write-Host "Data: " -NoNewline -ForegroundColor $color
            $Data | Format-List | Out-String | Write-Host -ForegroundColor $color
        }
    }
}

function Test-IsAdministrator {
    # Check if running as administrator
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-DebugLog "Admin check result: $isAdmin" "DEBUG" @{ User = $identity.Name; IsAdmin = $isAdmin }
    
    return $isAdmin
}

function Test-ExecutionPolicy {
    # Check if script execution is allowed
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
    
    Write-DebugLog "Execution policies - CurrentUser: $currentPolicy, LocalMachine: $machinePolicy" "DEBUG"
    
    $requiredPolicies = @("Unrestricted", "RemoteSigned", "Bypass")
    
    if ($currentPolicy -notin $requiredPolicies -and $machinePolicy -notin $requiredPolicies) {
        return $false
    }
    
    return $true
}

function Get-WindowsVersion {
    # Get Windows version with compatibility check
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    
    if (-not $os) {
        # Fallback for older systems
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    }
    
    if ($os) {
        $version = $os.Version
        $caption = $os.Caption
        $productType = $os.ProductType
        
        Write-DebugLog "Windows version detected: $version ($caption)" "DEBUG" @{
            Version = $version
            Caption = $caption
            ProductType = $productType
            IsServer = ($productType -eq 2 -or $productType -eq 3)
        }
        
        return @{
            Version = $version
            Caption = $caption
            IsServer = ($productType -eq 2 -or $productType -eq 3)
            BuildNumber = $os.BuildNumber
        }
    }
    
    return $null
}

function Test-ShadowSupport {
    # Check if shadowing is supported and configured
    $winVersion = Get-WindowsVersion
    
    if (-not $winVersion) {
        Write-DebugLog "Cannot determine Windows version" "WARNING"
        return $false
    }
    
    # Check if version is supported
    $supported = $false
    foreach ($supportedVersion in $SUPPORTED_WINDOWS_VERSIONS) {
        if ($winVersion.Version.StartsWith($supportedVersion)) {
            $supported = $true
            break
        }
    }
    
    if (-not $supported) {
        Write-DebugLog "Unsupported Windows version: $($winVersion.Version)" "WARNING"
        return $false
    }
    
    # Check registry settings
    try {
        $shadowValue = Get-ItemProperty -Path $REGISTRY_PATHS.TerminalServicesPolicies -Name "Shadow" -ErrorAction SilentlyContinue
        
        if ($shadowValue) {
            Write-DebugLog "Current shadow setting: $($shadowValue.Shadow)" "DEBUG"
            
            # Check if full control is enabled
            if ($shadowValue.Shadow -eq $SHADOW_MODES.FullControl -or 
                $shadowValue.Shadow -eq $SHADOW_MODES.WithoutPermission) {
                return $true
            }
        } else {
            # Check legacy path
            $legacyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            $shadowValue = Get-ItemProperty -Path $legacyPath -Name "Shadow" -ErrorAction SilentlyContinue
            
            if ($shadowValue -and $shadowValue.Shadow -eq 1) {
                Write-DebugLog "Legacy shadow setting found" "DEBUG"
                return $true
            }
        }
        
        Write-DebugLog "Shadow mode not properly configured" "WARNING"
        return $false
        
    } catch {
        Write-DebugLog "Error checking shadow support: $_" "ERROR"
        return $false
    }
}

function Enable-RDPShadowing {
    # Enable RDP shadowing with full control
    Write-DebugLog "Enabling RDP shadowing..." "INFO"
    
    try {
        $steps = @()
        
        # 1. Enable RDP connections
        $steps += "Enabling RDP connections"
        Set-ItemProperty -Path $REGISTRY_PATHS.TerminalServer -Name "fDenyTSConnections" -Value 0 -Force
        Write-DebugLog "Set fDenyTSConnections = 0" "SUCCESS"
        
        # 2. Create policies key if it doesn't exist
        $steps += "Creating Terminal Services policies key"
        if (-not (Test-Path $REGISTRY_PATHS.TerminalServicesPolicies)) {
            New-Item -Path $REGISTRY_PATHS.TerminalServicesPolicies -Force | Out-Null
            Write-DebugLog "Created registry path" "SUCCESS"
        }
        
        # 3. Set shadow mode based on Windows version
        $steps += "Configuring shadow mode"
        $winVersion = Get-WindowsVersion
        
        if ($winVersion.IsServer -or $winVersion.Version.StartsWith("10.0")) {
            # Windows Server 2016+ or Windows 10/11
            $shadowValue = $SHADOW_MODES.FullControl
        } else {
            # Older versions
            $shadowValue = $SHADOW_MODES.WithoutPermission
        }
        
        Set-ItemProperty -Path $REGISTRY_PATHS.TerminalServicesPolicies -Name "Shadow" -Value $shadowValue -Type DWord -Force
        Write-DebugLog "Set Shadow = $shadowValue" "SUCCESS"
        
        # 4. Set NoRemoteDesktopWallpaper for better performance
        $steps += "Optimizing RDP settings"
        Set-ItemProperty -Path $REGISTRY_PATHS.TerminalServicesPolicies -Name "NoRemoteDesktopWallpaper" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        
        # 5. Configure WinStations
        $steps += "Configuring WinStations"
        Set-ItemProperty -Path $REGISTRY_PATHS.WinStations -Name "Shadow" -Value $shadowValue -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $REGISTRY_PATHS.WinStations -Name "UserAuthentication" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        
        # 6. Allow RDP in firewall
        $steps += "Configuring Windows Firewall"
        $firewallRuleName = "Remote Desktop"
        
        # Try multiple possible rule group names
        $ruleGroups = @("Remote Desktop", "RemoteDesktop", "Удаленный рабочий стол")
        
        foreach ($group in $ruleGroups) {
            try {
                netsh advfirewall firewall set rule group="$group" new enable=Yes 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-DebugLog "Enabled firewall rule for group: $group" "SUCCESS"
                    break
                }
            } catch {
                # Continue trying other group names
            }
        }
        
        # 7. Restart Terminal Services
        $steps += "Restarting Terminal Services"
        $services = @("TermService", "SessionEnv", "UmRdpService")
        
        foreach ($service in $services) {
            try {
                Restart-Service -Name $service -Force -ErrorAction SilentlyContinue
                Write-DebugLog "Restarted service: $service" "SUCCESS"
            } catch {
                Write-DebugLog "Could not restart $service: $_" "WARNING"
            }
        }
        
        # 8. Optional: Enable Remote Desktop Service
        $steps += "Enabling Remote Desktop services"
        Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name TermService -ErrorAction SilentlyContinue
        
        Write-DebugLog "RDP shadowing enabled successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-DebugLog "Failed to enable RDP shadowing: $_" "ERROR" @{ ErrorDetails = $_.Exception }
        return $false
    }
}

function Get-RDPSessions {
    # Get active RDP sessions with detailed information
    Write-DebugLog "Retrieving RDP sessions..." "INFO"
    
    $sessions = @()
    
    # Method 1: Try qwinsta (most reliable for older systems)
    try {
        $qwinstaOutput = qwinsta /server:$ComputerName 2>$null
        
        if ($qwinstaOutput) {
            Write-DebugLog "Using qwinsta for session enumeration" "DEBUG"
            
            # Parse qwinsta output
            $lines = $qwinstaOutput -split "`r`n" | Where-Object { $_ -match '\S' }
            
            # Skip header lines
            $startIndex = 0
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^ SESSIONNAME\s+USERNAME\s+ID\s+STATE\s+TYPE\s+DEVICE') {
                    $startIndex = $i + 1
                    break
                }
            }
            
            for ($i = $startIndex; $i -lt $lines.Count; $i++) {
                $line = $lines[$i].Trim()
                
                if ($line -match '^(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\w+)\s+(?<Type>\w+)\s+(?<Device>\S+)?') {
                    $session = [PSCustomObject]@{
                        SessionName = $matches.SessionName
                        UserName = $matches.UserName
                        SessionId = [int]$matches.Id
                        State = $matches.State
                        Type = $matches.Type
                        Device = $matches.Device
                        Source = "qwinsta"
                    }
                    
                    $sessions += $session
                }
            }
        }
    } catch {
        Write-DebugLog "qwinsta failed: $_" "DEBUG"
    }
    
    # Method 2: Try PowerShell cmdlets (PowerShell 5.1+)
    if ($sessions.Count -eq 0 -or $PSVersionTable.PSVersion.Major -ge 5) {
        try {
            Write-DebugLog "Using Get-RDUserSession (if available)" "DEBUG"
            
            # Try to load RemoteDesktop module
            $rdpModule = Get-Module -Name RemoteDesktop -ListAvailable -ErrorAction SilentlyContinue
            
            if ($rdpModule) {
                Import-Module RemoteDesktop -ErrorAction SilentlyContinue
                $rdpSessions = Get-RDUserSession -ConnectionBroker $ComputerName -ErrorAction SilentlyContinue
                
                if ($rdpSessions) {
                    foreach ($rdpSession in $rdpSessions) {
                        $session = [PSCustomObject]@{
                            SessionName = $rdpSession.SessionName
                            UserName = $rdpSession.UserName
                            SessionId = $rdpSession.UnifiedSessionId
                            State = $rdpSession.SessionState
                            Type = "RDP"
                            Device = $rdpSession.HostServer
                            ClientName = $rdpSession.ClientName
                            ClientAddress = $rdpSession.ClientAddress
                            Source = "Get-RDUserSession"
                        }
                        
                        $sessions += $session
                    }
                }
            }
        } catch {
            Write-DebugLog "Get-RDUserSession failed: $_" "DEBUG"
        }
    }
    
    # Method 3: Try query session (alternative)
    if ($sessions.Count -eq 0) {
        try {
            Write-DebugLog "Using query session command" "DEBUG"
            $queryOutput = query session /server:$ComputerName 2>$null
            
            if ($queryOutput) {
                $lines = $queryOutput -split "`r`n"
                
                foreach ($line in $lines) {
                    if ($line -match '^(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\w+)\s+(?<Type>\w+)\s+(?<Device>\S+)?') {
                        $session = [PSCustomObject]@{
                            SessionName = $matches.SessionName
                            UserName = $matches.UserName
                            SessionId = [int]$matches.Id
                            State = $matches.State
                            Type = $matches.Type
                            Device = $matches.Device
                            Source = "query session"
                        }
                        
                        $sessions += $session
                    }
                }
            }
        } catch {
            Write-DebugLog "query session failed: $_" "DEBUG"
        }
    }
    
    # Get client IP addresses (additional step for extended info)
    if ($Sessions) {
        Write-DebugLog "Gathering extended session information..." "DEBUG"
        
        try {
            # This requires administrative privileges and might not work on all systems
            $netstatOutput = netstat -an | Select-String "ESTABLISHED.*3389" -ErrorAction SilentlyContinue
            
            foreach ($line in $netstatOutput) {
                if ($line -match '\s+(?<ClientIP>\d+\.\d+\.\d+\.\d+):\d+\s+(?<ServerIP>\d+\.\d+\.\d+\.\d+):3389') {
                    $clientIP = $matches.ClientIP
                    
                    # Try to resolve hostname
                    try {
                        $clientHost = [System.Net.Dns]::GetHostEntry($clientIP).HostName
                    } catch {
                        $clientHost = "Unknown"
                    }
                    
                    # Add to sessions if we can match them
                    # Note: This is approximate and may not always match correctly
                }
            }
        } catch {
            Write-DebugLog "Could not retrieve client IP information: $_" "WARNING"
        }
    }
    
    Write-DebugLog "Found $($sessions.Count) sessions" "DEBUG" @{ Sessions = $sessions.Count }
    return $sessions
}

function Connect-RDPSession {
    param(
        [int]$SessionId,
        [bool]$ViewOnly = $false,
        [string[]]$AdditionalParams = @()
    )
    
    Write-DebugLog "Preparing to connect to session $SessionId" "INFO" @{
        SessionId = $SessionId
        ViewOnly = $ViewOnly
        AdditionalParams = $AdditionalParams
    }
    
    # Validate session exists
    $sessions = Get-RDPSessions
    $targetSession = $sessions | Where-Object { $_.SessionId -eq $SessionId }
    
    if (-not $targetSession) {
        Write-DebugLog "Session $SessionId not found" "ERROR"
        return $false
    }
    
    if ($targetSession.State -ne $SESSION_STATES.Active -and 
        $targetSession.State -ne $SESSION_STATES.Connected) {
        Write-DebugLog "Session $SessionId is not in active state: $($targetSession.State)" "WARNING"
        
        if (-not $Force) {
            $confirm = Read-Host "Session is not active. Connect anyway? (y/N)"
            if ($confirm -ne 'y') {
                return $false
            }
        }
    }
    
    # Build mstsc command
    $mstscParams = New-Object System.Collections.Generic.List[string]
    
    # Add default parameters
    foreach ($param in $DEFAULT_MSTSC_PARAMS) {
        $mstscParams.Add($param)
    }
    
    # Add shadow parameter
    if ($ViewOnly) {
        $mstscParams.Add("/shadow:$SessionId")
        $mstscParams.Add("/noconsentprompt")
    } else {
        $mstscParams.Add("/shadow:$SessionId")
        $mstpcParams.Add("/control")
    }
    
    # Add any additional parameters
    foreach ($param in $AdditionalParams) {
        $mstscParams.Add($param)
    }
    
    # Add v parameter if ComputerName is specified and not localhost
    if ($ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne 'localhost') {
        $mstscParams.Add("/v:$ComputerName")
    }
    
    $command = "mstsc " + ($mstscParams -join ' ')
    Write-DebugLog "Executing command: $command" "DEBUG"
    
    try {
        # Start mstsc process
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "mstsc.exe"
        $processStartInfo.Arguments = $mstscParams -join ' '
        $processStartInfo.UseShellExecute = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        
        if ($process.Start()) {
            Write-DebugLog "Successfully launched mstsc for session $SessionId" "SUCCESS"
            
            # Wait a moment for connection to establish
            Start-Sleep -Seconds 2
            
            # Verify connection
            if (-not $process.HasExited) {
                Write-DebugLog "RDP session established" "DEBUG"
                return $true
            } else {
                Write-DebugLog "mstsc process exited unexpectedly" "WARNING"
                return $false
            }
        } else {
            Write-DebugLog "Failed to start mstsc process" "ERROR"
            return $false
        }
        
    } catch {
        Write-DebugLog "Error connecting to session: $_" "ERROR" @{ ErrorDetails = $_.Exception }
        return $false
    }
}

function Send-SessionMessage {
    param(
        [int]$SessionId,
        [string]$Message,
        [string]$Title = "Administrator Message"
    )
    
    Write-DebugLog "Sending message to session $SessionId" "INFO" @{
        SessionId = $SessionId
        Message = $Message
        Title = $Title
    }
    
    try {
        # Try msg command
        $msgResult = msg $SessionId "$Message" /TIME:30 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-DebugLog "Message sent successfully to session $SessionId" "SUCCESS"
            return $true
        } else {
            Write-DebugLog "msg command failed: $msgResult" "WARNING"
            
            # Alternative: Use PowerShell if available
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                try {
                    $session = Get-RDPSessions | Where-Object { $_.SessionId -eq $SessionId }
                    
                    if ($session.UserName) {
                        # This is a simpler approach but less reliable
                        Write-Host "Message for user $($session.UserName):" -ForegroundColor $COLORS.Info
                        Write-Host "$Message" -ForegroundColor $COLORS.Info
                        return $true
                    }
                } catch {
                    Write-DebugLog "PowerShell message method failed: $_" "ERROR"
                }
            }
            
            return $false
        }
        
    } catch {
        Write-DebugLog "Error sending message: $_" "ERROR"
        return $false
    }
}

function Disconnect-Session {
    param(
        [int]$SessionId,
        [bool]$Logoff = $false
    )
    
    $action = if ($Logoff) { "logoff" } else { "disconnect" }
    Write-DebugLog "Attempting to $action session $SessionId" "INFO" @{
        SessionId = $SessionId
        Action = $action
    }
    
    try {
        if ($Logoff) {
            # Logoff session (hard termination)
            $result = logoff $SessionId /server:$ComputerName 2>&1
        } else {
            # Disconnect session (soft, can be reconnected)
            $result = reset session $SessionId /server:$ComputerName 2>&1
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-DebugLog "Successfully performed $action on session $SessionId" "SUCCESS"
            return $true
        } else {
            Write-DebugLog "Failed to $action session $SessionId: $result" "ERROR"
            return $false
        }
        
    } catch {
        Write-DebugLog "Error during session $action: $_" "ERROR"
        return $false
    }
}

function Show-SystemStatus {
    # Display comprehensive system status
    Write-DebugLog "Generating system status report..." "INFO"
    
    $statusReport = @"
REMOTE SESSION MANAGER PRO - SYSTEM STATUS REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $($env:COMPUTERNAME)
User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
PowerShell: $($PSVersionTable.PSVersion)
"@
    
    Write-Host $statusReport -ForegroundColor $COLORS.Info
    
    # 1. Windows Version
    $winVersion = Get-WindowsVersion
    Write-Host "`n[1] WINDOWS VERSION" -ForegroundColor $COLORS.Info
    Write-Host "   Version: $($winVersion.Version)" -ForegroundColor $COLORS.Debug
    Write-Host "   Edition: $($winVersion.Caption)" -ForegroundColor $COLORS.Debug
    Write-Host "   Is Server: $($winVersion.IsServer)" -ForegroundColor $COLORS.Debug
    
    # 2. RDP Configuration
    Write-Host "`n[2] RDP CONFIGURATION" -ForegroundColor $COLORS.Info
    
    try {
        $rdpEnabled = Get-ItemProperty -Path $REGISTRY_PATHS.TerminalServer -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        Write-Host "   RDP Enabled: $($rdpEnabled.fDenyTSConnections -eq 0)" -ForegroundColor $(if ($rdpEnabled.fDenyTSConnections -eq 0) { $COLORS.Success } else { $COLORS.Error })
    } catch {
        Write-Host "   RDP Enabled: Unknown" -ForegroundColor $COLORS.Warning
    }
    
    # 3. Shadow Configuration
    Write-Host "`n[3] SHADOW CONFIGURATION" -ForegroundColor $COLORS.Info
    
    try {
        $shadowValue = Get-ItemProperty -Path $REGISTRY_PATHS.TerminalServicesPolicies -Name "Shadow" -ErrorAction SilentlyContinue
        
        if ($shadowValue) {
            $shadowMode = $shadowValue.Shadow
            $modeDescription = switch ($shadowMode) {
                0 { "Disabled" }
                1 { "With Permission" }
                2 { "Without Permission" }
                3 { "Full Control" }
                4 { "With Permission and Notification" }
                default { "Unknown ($shadowMode)" }
            }
            
            Write-Host "   Shadow Mode: $modeDescription" -ForegroundColor $(if ($shadowMode -ge 2) { $COLORS.Success } else { $COLORS.Warning })
        } else {
            Write-Host "   Shadow Mode: Not Configured" -ForegroundColor $COLORS.Warning
        }
    } catch {
        Write-Host "   Shadow Mode: Error reading registry" -ForegroundColor $COLORS.Error
    }
    
    # 4. Firewall Rules
    Write-Host "`n[4] FIREWALL STATUS" -ForegroundColor $COLORS.Info
    
    try {
        $firewallRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        if ($firewallRules) {
            $enabledRules = $firewallRules | Where-Object { $_.Enabled -eq $true }
            Write-Host "   RDP Rules: $($enabledRules.Count) enabled, $($firewallRules.Count) total" -ForegroundColor $(if ($enabledRules.Count -gt 0) { $COLORS.Success } else { $COLORS.Error })
        } else {
            Write-Host "   RDP Rules: Not found" -ForegroundColor $COLORS.Warning
        }
    } catch {
        Write-Host "   RDP Rules: Could not check" -ForegroundColor $COLORS.Warning
    }
    
    # 5. Services Status
    Write-Host "`n[5] SERVICE STATUS" -ForegroundColor $COLORS.Info
    
    $rdpServices = @(
        @{ Name = "TermService"; DisplayName = "Remote Desktop Services" }
        @{ Name = "SessionEnv"; DisplayName = "Remote Desktop Configuration" }
        @{ Name = "UmRdpService"; DisplayName = "Remote Desktop Services UserMode Port Redirector" }
    )
    
    foreach ($service in $rdpServices) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            
            if ($svc) {
                $statusColor = switch ($svc.Status) {
                    "Running" { $COLORS.Success }
                    "Stopped" { $COLORS.Error }
                    default { $COLORS.Warning }
                }
                
                Write-Host "   $($service.DisplayName): $($svc.Status)" -ForegroundColor $statusColor
            } else {
                Write-Host "   $($service.DisplayName): Not found" -ForegroundColor $COLORS.Warning
            }
        } catch {
            Write-Host "   $($service.DisplayName): Error" -ForegroundColor $COLORS.Error
        }
    }
    
    # 6. Active Sessions
    Write-Host "`n[6] ACTIVE SESSIONS" -ForegroundColor $COLORS.Info
    
    $sessions = Get-RDPSessions
    $activeSessions = $sessions | Where-Object { $_.State -eq $SESSION_STATES.Active -or $_.State -eq $SESSION_STATES.Connected }
    
    Write-Host "   Total Sessions: $($sessions.Count)" -ForegroundColor $COLORS.Debug
    Write-Host "   Active Sessions: $($activeSessions.Count)" -ForegroundColor $(if ($activeSessions.Count -gt 0) { $COLORS.Success } else { $COLORS.Debug })
    
    if ($activeSessions.Count -gt 0) {
        foreach ($session in $activeSessions) {
            Write-Host "     ID $($session.SessionId): $($session.UserName) [$($session.State)]" -ForegroundColor $COLORS.Debug
        }
    }
    
    # 7. Recommendations
    Write-Host "`n[7] RECOMMENDATIONS" -ForegroundColor $COLORS.Info
    
    if (-not (Test-ShadowSupport)) {
        Write-Host "   [!] Shadow mode is not properly configured" -ForegroundColor $COLORS.Warning
        Write-Host "       Run: .\$SCRIPT_NAME.ps1 --SessionId <ID> to auto-configure" -ForegroundColor $COLORS.Debug
    }
    
    if ($activeSessions.Count -eq 0) {
        Write-Host "   [!] No active RDP sessions found" -ForegroundColor $COLORS.Warning
    }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor $COLORS.Debug
}

function Update-Script {
    # Self-update from GitHub
    Write-DebugLog "Checking for updates..." "INFO"
    
    try {
        # Download latest version
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add('User-Agent', 'RemoteSessionManagerPro/1.0')
        
        $latestScript = $webClient.DownloadString($RAW_GITHUB_URL)
        
        if ([string]::IsNullOrWhiteSpace($latestScript)) {
            Write-DebugLog "Failed to download update: Empty response" "ERROR"
            return $false
        }
        
        # Extract version from downloaded script
        $versionMatch = [regex]::Match($latestScript, '\$SCRIPT_VERSION\s*=\s*["'']([^"'']+)["'']')
        
        if ($versionMatch.Success) {
            $latestVersion = $versionMatch.Groups[1].Value
            
            if ($latestVersion -ne $SCRIPT_VERSION) {
                Write-Host "Update available: $SCRIPT_VERSION -> $latestVersion" -ForegroundColor $COLORS.Warning
                
                $backupPath = "$PSScriptRoot\$SCRIPT_NAME.ps1.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                
                # Backup current script
                Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $backupPath -Force
                Write-DebugLog "Backup created: $backupPath" "SUCCESS"
                
                # Replace with new version
                $latestScript | Out-File -FilePath $MyInvocation.MyCommand.Path -Encoding UTF8 -Force
                
                Write-Host "Script updated successfully!" -ForegroundColor $COLORS.Success
                Write-Host "Backup saved to: $backupPath" -ForegroundColor $COLORS.Info
                
                # Reload script
                if (-not $Quiet) {
                    $reload = Read-Host "Reload updated script? (Y/n)"
                    if ($reload -ne 'n') {
                        & $MyInvocation.MyCommand.Path @PSBoundParameters
                        exit $ERROR_CODES.Success
                    }
                }
                
                return $true
            } else {
                Write-DebugLog "Already running latest version ($SCRIPT_VERSION)" "SUCCESS"
                return $true
            }
        } else {
            Write-DebugLog "Could not determine version from downloaded script" "WARNING"
            return $false
        }
        
    } catch {
        Write-DebugLog "Update failed: $_" "ERROR" @{ ErrorDetails = $_.Exception }
        return $false
    }
}

function Show-Help {
    # Display comprehensive help
    $helpText = @"
REMOTE SESSION MANAGER PRO v$SCRIPT_VERSION
Advanced RDP session management tool for Windows

USAGE:
    .\$SCRIPT_NAME.ps1 [PARAMETERS]

PARAMETERS:
    -SessionId, -i <ID>      Connect to specific session ID
    -Help, -h, -?            Show this help message
    -Version, -v             Show version information
    -Status, -s              Show system status and configuration
    -Sessions, -e            Show extended session information
    -Update, -u              Update to latest version from GitHub
    -DebugMode, -d           Enable debug output
    -ViewOnly, -o            View-only mode (no control)
    -Disconnect, -x          Disconnect specified session
    -Logoff, -l              Logoff specified session (hard termination)
    -Message, -m <text>      Send message to specified session
    -ComputerName, -c <name> Target computer (default: localhost)
    -Quiet, -q               Quiet mode (minimal output)
    -Force, -f               Force operations without confirmation

EXAMPLES:
    # List all active sessions
    .\$SCRIPT_NAME.ps1 -Sessions

    # Connect to session ID 2 with full control
    .\$SCRIPT_NAME.ps1 -SessionId 2

    # Connect to session ID 3 in view-only mode
    .\$SCRIPT_NAME.ps1 -SessionId 3 -ViewOnly

    # Disconnect session ID 4
    .\$SCRIPT_NAME.ps1 -SessionId 4 -Disconnect

    # Send message to session ID 5
    .\$SCRIPT_NAME.ps1 -SessionId 5 -Message "Please save your work"

    # Check system configuration
    .\$SCRIPT_NAME.ps1 -Status

    # Update to latest version
    .\$SCRIPT_NAME.ps1 -Update

    # Debug mode with verbose output
    .\$SCRIPT_NAME.ps1 -Sessions -DebugMode

NOTES:
    - Administrative privileges are required for most operations
    - Session IDs can be obtained using the -Sessions parameter
    - First run may require RDP shadowing to be configured automatically

AUTHOR:
    $SCRIPT_AUTHOR
    GitHub: $GITHUB_REPO
"@
    
    Write-Host $helpText -ForegroundColor $COLORS.Info
}

function Show-Version {
    $versionInfo = @"
Remote Session Manager Pro v$SCRIPT_VERSION
Author: $SCRIPT_AUTHOR
GitHub: $GITHUB_REPO
PowerShell: $($PSVersionTable.PSVersion)
Windows: $(Get-WindowsVersion).Caption
Administrator: $(Test-IsAdministrator)
"@
    
    Write-Host $versionInfo -ForegroundColor $COLORS.Info
}

#endregion

#region MAIN EXECUTION
# ============================================================================
# MAIN EXECUTION LOGIC
# ============================================================================

Write-DebugLog "Starting Remote Session Manager Pro v$SCRIPT_VERSION" "INFO" @{
    ComputerName = $ComputerName
    User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    PowerShellVersion = $PSVersionTable.PSVersion
    Parameters = $PSBoundParameters
}

# Step 1: Handle help and version requests first (no admin required)
if ($Help) {
    Show-Help
    exit $ERROR_CODES.Success
}

if ($Version) {
    Show-Version
    exit $ERROR_CODES.Success
}

# Step 2: Check if running as administrator (required for most operations)
if (-not (Test-IsAdministrator)) {
    Write-Host "Administrative privileges are required for this operation!" -ForegroundColor $COLORS.Error
    Write-Host "Please restart PowerShell as Administrator and run the script again." -ForegroundColor $COLORS.Warning
    
    # Try to self-elevate
    if (-not $Quiet) {
        $elevate = Read-Host "Attempt to restart as administrator? (Y/n)"
        
        if ($elevate -ne 'n') {
            try {
                $scriptPath = $MyInvocation.MyCommand.Path
                
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "powershell.exe"
                $psi.Arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" " + ($PSBoundParameters | ForEach-Object { 
                    if ($_.Key -ne 'Help' -and $_.Key -ne 'Version') { 
                        "-$($_.Key):$($_.Value)" 
                    } 
                }) -join ' '
                $psi.Verb = "runas"
                $psi.UseShellExecute = $true
                
                [System.Diagnostics.Process]::Start($psi) | Out-Null
                exit $ERROR_CODES.Success
            } catch {
                Write-Host "Failed to restart as administrator: $_" -ForegroundColor $COLORS.Error
            }
        }
    }
    
    exit $ERROR_CODES.AdminRequired
}

# Step 3: Check execution policy
if (-not (Test-ExecutionPolicy)) {
    Write-Host "Current execution policy may prevent script execution." -ForegroundColor $COLORS.Warning
    Write-Host "To allow script execution, run one of the following commands:" -ForegroundColor $COLORS.Info
    Write-Host "  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor $COLORS.Debug
    Write-Host "  Set-ExecutionPolicy Bypass -Scope Process" -ForegroundColor $COLORS.Debug
    Write-Host "" -ForegroundColor $COLORS.Debug
    Write-Host "Or run this script with:" -ForegroundColor $COLORS.Info
    Write-Host "  PowerShell -ExecutionPolicy Bypass -File $SCRIPT_NAME.ps1" -ForegroundColor $COLORS.Debug
    
    if (-not $Force) {
        exit $ERROR_CODES.ExecutionPolicy
    }
}

# Step 4: Handle update request
if ($Update) {
    $updateResult = Update-Script
    
    if ($updateResult) {
        exit $ERROR_CODES.Success
    } else {
        exit $ERROR_CODES.UpdateFailed
    }
}

# Step 5: Handle status request
if ($Status) {
    Show-SystemStatus
    exit $ERROR_CODES.Success
}

# Step 6: Check and configure shadow support if needed
if ($SessionId -ge 0 -or $Sessions -or $Disconnect -or $Logoff -or $Message) {
    if (-not (Test-ShadowSupport)) {
        Write-Host "RDP shadowing is not properly configured." -ForegroundColor $COLORS.Warning
        
        if (-not $Quiet) {
            $configure = Read-Host "Configure RDP shadowing automatically? (Y/n)"
            
            if ($configure -ne 'n') {
                $configureResult = Enable-RDPShadowing
                
                if (-not $configureResult) {
                    Write-Host "Failed to configure RDP shadowing. Manual configuration may be required." -ForegroundColor $COLORS.Error
                    
                    if (-not $Force) {
                        exit $ERROR_CODES.RegistryAccessDenied
                    }
                }
            }
        } elseif ($Force) {
            # Force configuration
            Enable-RDPShadowing | Out-Null
        }
    }
}

# Step 7: Handle sessions list request
if ($Sessions) {
    $sessions = Get-RDPSessions
    
    if ($sessions.Count -eq 0) {
        Write-Host "No active sessions found." -ForegroundColor $COLORS.Warning
    } else {
        # Format session list
        $sessionTable = $sessions | Format-Table -Property @{
            Label = "ID"
            Expression = { $_.SessionId }
            Width = 4
            Align = 'Right'
        },
        @{
            Label = "User"
            Expression = { if ($_.UserName) { $_.UserName } else { "SYSTEM" } }
            Width = 20
        },
        @{
            Label = "State"
            Expression = { $_.State }
            Width = 12
        },
        @{
            Label = "Type"
            Expression = { $_.Type }
            Width = 8
        },
        @{
            Label = "Session"
            Expression = { if ($_.SessionName) { $_.SessionName } else { "N/A" } }
            Width = 15
        },
        @{
            Label = "Device"
            Expression = { if ($_.Device) { $_.Device } else { "N/A" } }
            Width = 10
        } -AutoSize | Out-String
        
        Write-Host "ACTIVE SESSIONS:" -ForegroundColor $COLORS.Info
        Write-Host $sessionTable -ForegroundColor $COLORS.Debug
        
        # Show active sessions count
        $activeCount = ($sessions | Where-Object { $_.State -eq $SESSION_STATES.Active }).Count
        Write-Host "Total: $($sessions.Count) sessions ($activeCount active)" -ForegroundColor $COLORS.Info
    }
    
    if ($SessionId -lt 0) {
        # If only listing sessions, exit here
        exit $ERROR_CODES.Success
    }
}

# Step 8: Handle session management operations
if ($Disconnect -or $Logoff) {
    if ($SessionId -lt 0) {
        Write-Host "Session ID is required for disconnect/logoff operations." -ForegroundColor $COLORS.Error
        exit $ERROR_CODES.InvalidParameter
    }
    
    $result = Disconnect-Session -SessionId $SessionId -Logoff $Logoff
    
    if ($result) {
        exit $ERROR_CODES.Success
    } else {
        exit $ERROR_CODES.ConnectionFailed
    }
}

if ($Message) {
    if ($SessionId -lt 0) {
        Write-Host "Session ID is required for sending messages." -ForegroundColor $COLORS.Error
        exit $ERROR_CODES.InvalidParameter
    }
    
    $result = Send-SessionMessage -SessionId $SessionId -Message $Message
    
    if ($result) {
        exit $ERROR_CODES.Success
    } else {
        exit $ERROR_CODES.ConnectionFailed
    }
}

# Step 9: Handle session connection
if ($SessionId -ge 0) {
    Write-DebugLog "Processing connection request to session $SessionId" "INFO"
    
    # If no session specified but sessions were listed, prompt for selection
    if ($SessionId -lt 0 -and -not $Quiet) {
        $sessions = Get-RDPSessions
        $activeSessions = $sessions | Where-Object { $_.State -eq $SESSION_STATES.Active -or $_.State -eq $SESSION_STATES.Connected }
        
        if ($activeSessions.Count -eq 0) {
            Write-Host "No active sessions available for connection." -ForegroundColor $COLORS.Warning
            exit $ERROR_CODES.SessionNotFound
        }
        
        Write-Host "`nSelect a session to connect to:" -ForegroundColor $COLORS.Info
        
        $index = 1
        foreach ($session in $activeSessions) {
            Write-Host "  [$index] ID $($session.SessionId): $($session.UserName) [$($session.State)]" -ForegroundColor $COLORS.Debug
            $index++
        }
        
        Write-Host "  [0] Cancel" -ForegroundColor $COLORS.Debug
        
        try {
            $choice = Read-Host "`nEnter selection"
            $choiceIndex = [int]$choice - 1
            
            if ($choice -eq 0) {
                exit $ERROR_CODES.Success
            }
            
            if ($choiceIndex -ge 0 -and $choiceIndex -lt $activeSessions.Count) {
                $SessionId = $activeSessions[$choiceIndex].SessionId
            } else {
                Write-Host "Invalid selection." -ForegroundColor $COLORS.Error
                exit $ERROR_CODES.InvalidParameter
            }
        } catch {
            Write-Host "Invalid input." -ForegroundColor $COLORS.Error
            exit $ERROR_CODES.InvalidParameter
        }
    }
    
    # Connect to selected session
    $result = Connect-RDPSession -SessionId $SessionId -ViewOnly $ViewOnly
    
    if ($result) {
        Write-DebugLog "Session connection completed successfully" "SUCCESS"
        exit $ERROR_CODES.Success
    } else {
        Write-DebugLog "Failed to connect to session" "ERROR"
        exit $ERROR_CODES.ConnectionFailed
    }
}

# Step 10: Default action (show help if no parameters)
if ($PSBoundParameters.Count -eq 0) {
    Show-Help
    exit $ERROR_CODES.Success
}

Write-DebugLog "Script execution completed" "SUCCESS"
exit $ERROR_CODES.Success

#endregion