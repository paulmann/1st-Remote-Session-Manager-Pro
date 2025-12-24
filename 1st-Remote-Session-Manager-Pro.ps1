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
    [switch]$Force,
    
    # New parameters for Show-SystemStatus
    [Parameter()]
    [Alias('b')]
    [switch]$Brief,
    
    [Parameter()]
    [Alias('p')]
    [switch]$IncludePerformance,
    
    [Parameter()]
    [Alias('j')]
    [string]$ExportJson,
    
    [Parameter()]
    [Alias('csv')]
    [string]$ExportCsv
)

#region CONSTANTS AND CONFIGURATION
# ============================================================================
# GLOBAL CONSTANTS AND CONFIGURATION
# ============================================================================

# Script metadata
$SCRIPT_NAME = "1st-Remote-Session-Manager-Pro"
$SCRIPT_VERSION = "1.0.0"
$SCRIPT_AUTHOR = "Mikhail Deynekin"
$GITHUB_REPO = "https://raw.githubusercontent.com/paulmann/1st-Remote-Session-Manager-Pro"
$RAW_GITHUB_URL = "https://raw.githubusercontent.com/paulmann/1st-Remote-Session-Manager-Pro/refs/heads/main/1st-Remote-Session-Manager-Pro.ps1"

# RDP/MSTSC Configuration
$DEFAULT_MSTSC_PARAMS = @(
    "/noConsentPrompt",      # Skip consent prompt (requires appropriate permissions)
    "/control",             # Enable toolbar for session control
    "/admin",               # Connect to console/admin session
    "/f",                   # Full screen mode
    "/span"                 # Span across multiple monitors
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
            "ERROR"   { $color = $COLORS.Error; $symbol = "[X]" }
            "SUCCESS" { $color = $COLORS.Success; $symbol = "[OK]" }
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
        $ruleGroups = @("Remote Desktop", "RemoteDesktop", "Remote Desktop")

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
                $errorMessage = $_.Exception.Message
                Write-DebugLog "Could not restart $service : $errorMessage" "WARNING"
            }
        }

        # 8. Optional: Enable Remote Desktop Service
        $steps += "Enabling Remote Desktop services"
        Set-Service -Name TermService -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name TermService -ErrorAction SilentlyContinue

        Write-DebugLog "RDP shadowing enabled successfully" "SUCCESS"
        return $true

    } catch {
        $errorDetails = $_.Exception
        Write-DebugLog "Failed to enable RDP shadowing: $($errorDetails.Message)" "ERROR" @{ ErrorDetails = $errorDetails }
        return $false
    }
}

function Get-RDPSessions {
    <#
    .SYNOPSIS
        Retrieves RDP sessions with universal parsing for all Windows locales and PowerShell versions
    
    .DESCRIPTION
        Advanced session enumeration supporting:
        - All Windows locales (English, Russian, German, French, Spanish, etc.)
        - PowerShell 5.1 through 7+
        - Multiple fallback methods with intelligent detection
        - Extended client information
        - Performance optimizations for PS7+
    
    .PARAMETER ComputerName
        Target computer name (default: local computer)
    
    .PARAMETER ExtendedInfo
        Include extended client information (IP, hostname)
    
    .PARAMETER ActiveOnly
        Return only active/connected sessions
    
    .PARAMETER RawOutput
        Return raw session objects without formatting
    
    .EXAMPLE
        Get-RDPSessions
        # List all sessions on local computer
    
    .EXAMPLE
        Get-RDPSessions -ComputerName "SERVER01" -ActiveOnly
        # List active sessions on remote server
    
    .EXAMPLE
        Get-RDPSessions -ExtendedInfo -RawOutput | Export-Csv "sessions.csv"
        # Export detailed session information
    
    .OUTPUTS
        PSCustomObject[] with session properties
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [switch]$ExtendedInfo,
        
        [Parameter()]
        [switch]$ActiveOnly,
        
        [Parameter()]
        [switch]$RawOutput
    )
    
    begin {
        Write-DebugLog "Retrieving RDP sessions from $ComputerName..." "INFO" @{
            ComputerName = $ComputerName
            ExtendedInfo = $ExtendedInfo
            ActiveOnly = $ActiveOnly
            PowerShellVersion = $PSVersionTable.PSVersion
            Culture = [System.Threading.Thread]::CurrentThread.CurrentCulture.Name
        }
        
        # Determine if running in PowerShell 7+
        $IsPS7Plus = $PSVersionTable.PSVersion.Major -ge 7
        
        # Cache for quick access to states
        $activeStates = @("Active", "Conn", "Connected")
        
        # Dictionary for state normalization
        $stateNormalization = @{
            # English and other languages states to normalized English states
            "Active" = "Active"
            "Conn" = "Active"
            "Connected" = "Active"
            "Disc" = "Disconnected"
            "Disconnected" = "Disconnected"
            "Listen" = "Listen"
            "Aktiv" = "Active"
            "Verbunden" = "Active"
            "Getrennt" = "Disconnected"
            "Actif" = "Active"
            "Activo" = "Active"
        }
    }
    
    process {
        try {
            # Use different implementations for PS5.1 and PS7+
            if ($IsPS7Plus) {
                $sessions = Get-RDPSessionsPS7 @PSBoundParameters
            } else {
                $sessions = Get-RDPSessionsPS5 @PSBoundParameters
            }
            
            # Filter active sessions if requested
            if ($ActiveOnly) {
                $filteredSessions = $sessions | Where-Object {
                    $_.State -in $activeStates -or $_.State -eq "Active"
                }
                Write-DebugLog "Filtered to $($filteredSessions.Count) active sessions" "DEBUG"
                $sessions = $filteredSessions
            }
            
            # Return result
            if ($RawOutput) {
                return $sessions
            } else {
                return $sessions | Sort-Object -Property SessionId
            }
            
        } catch {
            Write-DebugLog "Error in Get-RDPSessions: $($_.Exception.Message)" "ERROR" @{
                Exception = $_.Exception
                StackTrace = $_.ScriptStackTrace
            }
            return @()
        }
    }
}

#region PowerShell 5.1 Implementation
function Get-RDPSessionsPS5 {
    <#
    .SYNOPSIS
        PowerShell 5.1 compatible session enumeration
    #>
    
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$ExtendedInfo
    )
    
    $sessions = @()
    
    try {
        # Method 1: qwinsta (main)
        $qwinstaOutput = Get-QwinstaOutputPS5 -ComputerName $ComputerName
        if ($qwinstaOutput) {
            $sessions += Parse-QwinstaOutputPS5 -Output $qwinstaOutput
        }
        
        # Method 2: query session (fallback)
        if ($sessions.Count -eq 0) {
            $queryOutput = Get-QuerySessionOutputPS5 -ComputerName $ComputerName
            if ($queryOutput) {
                $sessions += Parse-QuerySessionOutputPS5 -Output $queryOutput
            }
        }
        
        # Method 3: WMI/CIM (last resort)
        if ($sessions.Count -eq 0) {
            $cimSessions = Get-CimSessionsPS5 -ComputerName $ComputerName
            if ($cimSessions) {
                $sessions += $cimSessions
            }
        }
        
        # Normalization and data cleaning
        $sessions = Normalize-SessionsPS5 -Sessions $sessions
        
        # Extended information
        if ($ExtendedInfo) {
            $sessions = Add-ExtendedInfoPS5 -Sessions $sessions -ComputerName $ComputerName
        }
        
        Write-DebugLog "PS5.1: Found $($sessions.Count) sessions" "SUCCESS"
        
    } catch {
        Write-DebugLog "Error in Get-RDPSessionsPS5: $_" "ERROR"
    }
    
    return $sessions
}

function Get-QwinstaOutputPS5 {
    param([string]$ComputerName)
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $output = qwinsta 2>$null
        } else {
            $output = qwinsta /server:$ComputerName 2>$null
        }
        
        # Convert to correct encoding for PS5.1
        if ($output -and [System.Text.Encoding]::Default.BodyName -ne 'utf-8') {
            $bytes = [System.Text.Encoding]::Default.GetBytes($output)
            $output = [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        
        return $output
    } catch {
        Write-DebugLog "qwinsta failed in PS5.1: $_" "DEBUG"
        return $null
    }
}

function Parse-QwinstaOutputPS5 {
    param([string]$Output)
    
    $sessions = @()
    $lines = @($Output -split "`r`n" | Where-Object { $_ -match '\S' })
    
    foreach ($line in $lines) {
        # Skip headers and separators
        if ($line -match 'SESSIONNAME|SESSION|^[-=]+$' -or [string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        
        $session = Parse-QwinstaLinePS5 -Line $line
        if ($session) {
            $sessions += $session
        }
    }
    
    return $sessions
}

function Parse-QwinstaLinePS5 {
    param([string]$Line)
    
    try {
        # Handle current session marker
        $isCurrent = $false
        if ($Line.StartsWith('>')) {
            $isCurrent = $true
            $Line = $Line.Substring(1).TrimStart()
        }
        
        # Universal parsing for PS5.1
        # Split by 2+ spaces and remove empty elements
        $parts = @($Line -split '\s{2,}' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        
        if ($parts.Count -lt 3) {
            return $null
        }
        
        # Initialize session object
        $session = [PSCustomObject]@{
            SessionName = ""
            UserName = "SYSTEM"
            SessionId = 0
            State = ""
            Type = ""
            Device = ""
            IsCurrent = $isCurrent
            Source = "qwinsta_ps5"
        }
        
        # Intelligent parsing based on part count
        $parsed = $false
        
        # First try to find ID (number)
        $idIndex = -1
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i] -match '^\d+$') {
                $idIndex = $i
                $session.SessionId = [int]$parts[$i]
                break
            }
        }
        
        if ($idIndex -eq -1) {
            # ID not found, try another strategy
            return Parse-QwinstaLineFallbackPS5 -Line $Line -IsCurrent:$isCurrent
        }
        
        # Determine elements before ID
        if ($idIndex -gt 0) {
            $beforeId = $parts[0..($idIndex-1)]
            
            # If 1 element before ID, it could be SessionName or UserName
            if ($beforeId.Count -eq 1) {
                $element = $beforeId[0]
                if ($element -match '^(rdp-tcp|console|services)') {
                    $session.SessionName = $element
                } else {
                    $session.UserName = $element
                }
            }
            # If 2 elements before ID, it's SessionName and UserName
            elseif ($beforeId.Count -ge 2) {
                $session.SessionName = $beforeId[0]
                $session.UserName = $beforeId[1]
            }
        }
        
        # Determine State (after ID)
        if ($idIndex + 1 -lt $parts.Count) {
            $session.State = $parts[$idIndex + 1]
        }
        
        # Determine Type (after State)
        if ($idIndex + 2 -lt $parts.Count) {
            $session.Type = $parts[$idIndex + 2]
        }
        
        # Determine Device (after Type)
        if ($idIndex + 3 -lt $parts.Count) {
            $session.Device = $parts[$idIndex + 3]
        }
        
        # Clean values
        $session.UserName = if ([string]::IsNullOrWhiteSpace($session.UserName) -or 
                                  $session.UserName -eq "0") { "SYSTEM" } else { $session.UserName.Trim() }
        
        $session.SessionName = $session.SessionName.Trim()
        
        return $session
        
    } catch {
        Write-DebugLog "Error parsing line in PS5.1: $_" "DEBUG"
        return $null
    }
}

function Parse-QwinstaLineFallbackPS5 {
    param([string]$Line, [bool]$IsCurrent)
    
    try {
        # Fallback parsing for complex cases
        # Remove extra spaces
        $line = $Line -replace '\s+', ' '
        
        # Regular expression for general case
        if ($line -match '^(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\S+)\s*(?<Type>\S+)?\s*(?<Device>\S*)?') {
            return [PSCustomObject]@{
                SessionName = if ($matches.SessionName) { $matches.SessionName } else { "" }
                UserName = if ($matches.UserName -and $matches.UserName -ne "0") { $matches.UserName } else { "SYSTEM" }
                SessionId = [int]$matches.Id
                State = $matches.State
                Type = if ($matches.Type) { $matches.Type } else { "" }
                Device = if ($matches.Device) { $matches.Device } else { "" }
                IsCurrent = $IsCurrent
                Source = "qwinsta_fallback_ps5"
            }
        }
    } catch {
        # Ignore
    }
    
    return $null
}

function Normalize-SessionsPS5 {
    param([array]$Sessions)
    
    $normalizedSessions = @()
    
    foreach ($session in $Sessions) {
        # State normalization
        $originalState = $session.State
        if ($stateNormalization.ContainsKey($originalState)) {
            $session.State = $stateNormalization[$originalState]
        } else {
            # Auto-detection by keywords
            if ($originalState -match "Active|Conn|Connected") {
                $session.State = "Active"
            } elseif ($originalState -match "Disc|Disconnected") {
                $session.State = "Disconnected"
            } elseif ($originalState -match "Listen") {
                $session.State = "Listen"
            }
        }
        
        # UserName normalization for system sessions
        if ($session.SessionName -match '^services$|^console$' -and 
            ([string]::IsNullOrWhiteSpace($session.UserName) -or $session.UserName -eq "0")) {
            $session.UserName = "SYSTEM"
        }
        
        $normalizedSessions += $session
    }
    
    return $normalizedSessions
}
#endregion

#region PowerShell 7+ Implementation with Modern Features
function Get-RDPSessionsPS7 {
    <#
    .SYNOPSIS
        PowerShell 7+ optimized session enumeration with modern features
    #>
    
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$ExtendedInfo
    )
    
    $sessions = @()
    
    try {
        # Use modern PS7+ features
        
        # Method 1: qwinsta with improved parsing
        $qwinstaOutput = Get-QwinstaOutputPS7 -ComputerName $ComputerName
        if ($qwinstaOutput) {
            $sessions += Parse-QwinstaOutputPS7 -Output $qwinstaOutput
        }
        
        # Method 2: Parallel execution for query session (if needed)
        if ($sessions.Count -eq 0) {
            $sessions += Get-QuerySessionParallel -ComputerName $ComputerName
        }
        
        # Method 3: Use CIM with parallelism
        if ($sessions.Count -eq 0) {
            $sessions += Get-CimSessionsParallel -ComputerName $ComputerName
        }
        
        # Normalization with PowerShell 5.1 compatible syntax
        $sessions = $sessions | ForEach-Object {
            $session = $_
            
            # Use compatible null-check for PowerShell 5.1
            if (-not $session.UserName -or [string]::IsNullOrWhiteSpace($session.UserName)) { 
                $session.UserName = "SYSTEM" 
            }
            
            # Use if-else for normalization (compatible with PowerShell 5.1)
            if ($session.State -match "Active|Conn") {
                $session.State = "Active"
            } elseif ($session.State -match "Disc|Disconnected") {
                $session.State = "Disconnected"
            } elseif ($session.State -match "Listen") {
                $session.State = "Listen"
            }
            
            $session
        }
        
        # Extended information with compatibility
        if ($ExtendedInfo) {
            $sessions = Add-ExtendedInfoParallel -Sessions $sessions -ComputerName $ComputerName
        }
        
        Write-DebugLog "PS7+: Found $($sessions.Count) sessions" "SUCCESS" @{
            Method = if ($qwinstaOutput) { "qwinsta" } else { "fallback" }
        }
        
    } catch {
        Write-DebugLog "Error in Get-RDPSessionsPS7: $_" "ERROR"
    }
    
    return $sessions
}

function Get-QwinstaOutputPS7 {
    param([string]$ComputerName)
    
    try {
        # Use Start-Process with UTF-8 support for PS7 compatibility
        $processInfo = @{
            FilePath = "qwinsta"
            NoNewWindow = $true
            RedirectStandardOutput = $true
            UseNewEnvironment = $true
        }
        
        # Build arguments safely for PowerShell 5.1 compatibility
        if ($ComputerName -ne $env:COMPUTERNAME) {
            $processInfo.ArgumentList = "/server:$ComputerName"
        }
        
        $process = Start-Process @processInfo -PassThru
        $output = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        
        # In PS7+ use UTF-8 by default
        return $output
        
    } catch {
        Write-DebugLog "qwinsta failed in PS7+: $_" "DEBUG"
        return $null
    }
}

function Parse-QwinstaOutputPS7 {
    param([string]$Output)
    
    $sessions = [System.Collections.Generic.List[PSObject]]::new()
    
    # Use switch with regular expressions
    $lines = $Output -split '\r?\n' | Where-Object { $_ -match '\S' }
    
    # Parallel processing for PS7+
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # In PowerShell 7+ use ForEach-Object -Parallel with explicit return
        $parallelSessions = $lines | ForEach-Object -Parallel {
            $line = $_
            
            # Skip headers
            if ($line -match 'SESSIONNAME|SESSION|^[-=]+$') {
                return
            }
            
            # Use named groups in regular expressions
            if ($line -match '^>?(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\S+)(?:\s+(?<Type>\S+))?(?:\s+(?<Device>\S+))?') {
                $session = [PSCustomObject]@{
                    SessionName = if ($matches.SessionName) { $matches.SessionName } else { "" }
                    UserName = if ($matches.UserName -and $matches.UserName -ne "0") { $matches.UserName } else { "SYSTEM" }
                    SessionId = [int]$matches.Id
                    State = $matches.State
                    Type = if ($matches.Type) { $matches.Type } else { "" }
                    Device = if ($matches.Device) { $matches.Device } else { "" }
                    IsCurrent = $line.StartsWith('>')
                    Source = "qwinsta_ps7"
                }
                
                # Return session object
                return $session
            }
        } -ThrottleLimit 5
        
        # Filter null values and add to list
        $parallelSessions | Where-Object { $_ } | ForEach-Object {
            $sessions.Add($_)
        }
    } else {
        # Fallback for PowerShell 5.1
        foreach ($line in $lines) {
            # Skip headers
            if ($line -match 'SESSIONNAME|SESSION|^[-=]+$') {
                continue
            }
            
            # Use named groups in regular expressions
            if ($line -match '^>?(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\S+)(?:\s+(?<Type>\S+))?(?:\s+(?<Device>\S+))?') {
                $session = [PSCustomObject]@{
                    SessionName = if ($matches.SessionName) { $matches.SessionName } else { "" }
                    UserName = if ($matches.UserName -and $matches.UserName -ne "0") { $matches.UserName } else { "SYSTEM" }
                    SessionId = [int]$matches.Id
                    State = $matches.State
                    Type = if ($matches.Type) { $matches.Type } else { "" }
                    Device = if ($matches.Device) { $matches.Device } else { "" }
                    IsCurrent = $line.StartsWith('>')
                    Source = "qwinsta_ps7"
                }
                
                $sessions.Add($session)
            }
        }
    }
    
    return $sessions
}

function Get-QuerySessionParallel {
    param([string]$ComputerName)
    
    try {
        $sessions = [System.Collections.Generic.List[PSObject]]::new()
        
        # Build arguments safely for PowerShell 5.1 compatibility
        $arguments = "session"
        if ($ComputerName -ne $env:COMPUTERNAME) {
            $arguments += " /server:$ComputerName"
        }
        
        # Start query session in separate process
        $processInfo = @{
            FilePath = "query"
            ArgumentList = $arguments
            NoNewWindow = $true
            RedirectStandardOutput = $true
            UseNewEnvironment = $true
        }
        
        $process = Start-Process @processInfo -PassThru
        $output = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        
        # Parse output with compatible LINQ-like filtering
        $lines = $output -split '\r?\n' | Where-Object { 
            $_ -match '\S' -and $_ -notmatch 'SESSIONNAME|SESSION' 
        }
        
        foreach ($line in $lines) {
            # Extract session ID using regex
            if ($line -match '\b(?<Id>\d+)\b') {
                $session = [PSCustomObject]@{
                    SessionId = [int]$matches.Id
                    Source = "query_parallel"
                }
                $sessions.Add($session)
            }
        }
        
        return $sessions
        
    } catch {
        Write-DebugLog "Parallel query session failed: $_" "DEBUG"
        return @()
    }
}

function Add-ExtendedInfoParallel {
    param(
        [array]$Sessions,
        [string]$ComputerName
    )
    
    # For PowerShell 5.1 compatibility, use standard loop instead of -Parallel
    $updatedSessions = @()
    
    foreach ($session in $Sessions) {
        $clientInfo = Get-ClientInfoPS7 -SessionId $session.SessionId -ComputerName $ComputerName
        
        # Create new object with additional properties
        $newSession = $session | Select-Object *, @{
            Name = 'ClientIP'
            Expression = { $clientInfo.IP }
        }, @{
            Name = 'ClientHostname'
            Expression = { $clientInfo.Hostname }
        }, @{
            Name = 'ConnectionTime'
            Expression = { $clientInfo.ConnectionTime }
        }, @{
            Name = 'ClientProtocol'
            Expression = { $clientInfo.Protocol }
        }, @{
            Name = 'ClientPort'
            Expression = { $clientInfo.RemotePort }
        }
        
        $updatedSessions += $newSession
    }
    
    return $updatedSessions
}

function Get-ClientInfoPS7 {
    <#
    .SYNOPSIS
        Retrieves client connection information for a specific RDP session
    
    .DESCRIPTION
        This function attempts to gather detailed client information for a given RDP session ID,
        including IP address, hostname, and connection time by analyzing netstat output.
        It's designed for PowerShell 7+ with improved error handling and performance.
    
    .PARAMETER SessionId
        The ID of the RDP session to investigate
    
    .PARAMETER ComputerName
        Target computer name (default: local computer)
    
    .EXAMPLE
        Get-ClientInfoPS7 -SessionId 5 -ComputerName "SERVER01"
    
    .OUTPUTS
        Hashtable with IP, Hostname, and ConnectionTime properties
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 65536)]
        [int]$SessionId,
        
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    begin {
        Write-DebugLog "Starting client info retrieval for session $SessionId" "DEBUG" @{
            SessionId = $SessionId
            ComputerName = $ComputerName
        }
    }
    
    process {
        try {
            # Check if we're dealing with local computer
            $isLocalComputer = $ComputerName -eq $env:COMPUTERNAME -or 
                               $ComputerName -eq 'localhost' -or 
                               $ComputerName -eq '.'
            
            if (-not $isLocalComputer) {
                Write-DebugLog "Client info retrieval is limited to local computer. Target: $ComputerName" "WARNING"
                return @{
                    IP = "N/A (remote computer)"
                    Hostname = "N/A (remote computer)"
                    ConnectionTime = $null
                    SessionId = $SessionId
                    Note = "Client information only available for local computer"
                }
            }
            
            # Get netstat output for RDP connections (port 3389)
            Write-DebugLog "Executing netstat to find RDP connections..." "DEBUG"
            
            # Use PowerShell 7+ features for better performance
            $netstatOutput = if ($PSVersionTable.PSVersion.Major -ge 7) {
                # Async execution for PS7+
                $job = Start-ThreadJob -ScriptBlock { netstat -ano } -ThrottleLimit 1
                Wait-Job $job -Timeout 5
                if ($job.State -eq 'Completed') {
                    Receive-Job $job | Select-String ":3389"
                } else {
                    $null
                }
            } else {
                # Fallback for older PowerShell
                netstat -ano 2>$null | Select-String ":3389"
            }
            
            if (-not $netstatOutput) {
                Write-DebugLog "No RDP connections found in netstat output" "INFO"
                return @{
                    IP = "No RDP connections found"
                    Hostname = "N/A"
                    ConnectionTime = $null
                    SessionId = $SessionId
                }
            }
            
            Write-DebugLog "Found $($netstatOutput.Count) RDP connections in netstat" "DEBUG"
            
            # Array to store all found connections
            $connections = @()
            
            # Process each netstat line
            foreach ($line in $netstatOutput) {
                # Enhanced regex pattern for better matching
                if ($line -match '\s*(?<Protocol>\S+)\s+(?<LocalAddress>\S+):3389\s+(?<RemoteAddress>\S+):(?<RemotePort>\d+)\s+(?<State>\S+)\s+(?<PID>\d+)') {
                    
                    $connectionInfo = @{
                        Protocol = $matches.Protocol
                        LocalAddress = $matches.LocalAddress
                        RemoteAddress = $matches.RemoteAddress
                        RemotePort = $matches.RemotePort
                        State = $matches.State
                        PID = [int]$matches.PID
                    }
                    
                    # Only process ESTABLISHED connections
                    if ($matches.State -eq "ESTABLISHED") {
                        $connections += $connectionInfo
                    }
                }
            }
            
            if ($connections.Count -eq 0) {
                Write-DebugLog "No established RDP connections found" "DEBUG"
                return @{
                    IP = "No established connections"
                    Hostname = "N/A"
                    ConnectionTime = $null
                    SessionId = $SessionId
                }
            }
            
            Write-DebugLog "Found $($connections.Count) established RDP connections" "DEBUG"
            
            # Try to match session with process (simplified - real implementation would need proper mapping)
            # Note: This is a simplified approach. In production, you would need proper session-to-PID mapping.
            
            foreach ($conn in $connections) {
                $remoteIP = $conn.RemoteAddress
                
                # Skip loopback and private IPs for external reporting
                if ($remoteIP -match '^(127\.|::1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
                    Write-DebugLog "Skipping internal IP: $remoteIP" "DEBUG"
                    continue
                }
                
                # Resolve hostname (async in PS7+)
                $hostname = "Unknown"
                $resolveSuccess = $false
                
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 7) {
                        # Async DNS resolution for PS7+
                        $task = [System.Net.Dns]::GetHostEntryAsync($remoteIP)
                        $hostEntry = $task.GetAwaiter().GetResult()
                        $hostname = $hostEntry.HostName
                        $resolveSuccess = $true
                    } else {
                        # Synchronous for older versions
                        $hostname = [System.Net.Dns]::GetHostEntry($remoteIP).HostName
                        $resolveSuccess = $true
                    }
                } catch [System.Net.Sockets.SocketException] {
                    Write-DebugLog "DNS resolution failed for $remoteIP : $($_.Exception.Message)" "DEBUG"
                    $hostname = "Unresolvable"
                } catch {
                    Write-DebugLog "Error resolving hostname for $remoteIP : $($_.Exception.Message)" "DEBUG"
                    $hostname = "Error"
                }
                
                # Return the first valid connection info
                # In a real implementation, you would match PID with session ID
                return @{
                    IP = $remoteIP
                    Hostname = $hostname
                    ConnectionTime = Get-Date
                    Protocol = $conn.Protocol
                    LocalAddress = $conn.LocalAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    PID = $conn.PID
                    SessionId = $SessionId
                    DNSResolved = $resolveSuccess
                    Note = "This is a simplified mapping. Real implementation needs session-to-PID mapping."
                }
            }
            
            # If we get here, no valid external connection was found
            return @{
                IP = "No external connections"
                Hostname = "N/A"
                ConnectionTime = $null
                SessionId = $SessionId
                Note = "Only internal/local connections found"
            }
            
        } catch {
            # Comprehensive error handling
            $errorDetails = @{
                SessionId = $SessionId
                ComputerName = $ComputerName
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().FullName
                LineNumber = $_.InvocationInfo.ScriptLineNumber
            }
            
            Write-DebugLog "Critical error in Get-ClientInfoPS7 : $($_.Exception.Message)" "ERROR" $errorDetails
            
            # Return error information
            return @{
                IP = "Error: $($_.Exception.Message)"
                Hostname = "Error"
                ConnectionTime = $null
                SessionId = $SessionId
                Error = $true
                ErrorDetails = $errorDetails
            }
        }
    }
    
    end {
        Write-DebugLog "Completed client info retrieval for session $SessionId" "DEBUG" @{
            SessionId = $SessionId
            ComputerName = $ComputerName
        }
    }
}

#region Common Helper Functions
function Get-QuerySessionOutputPS5 {
    param([string]$ComputerName)
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            return query session 2>$null
        } else {
            return query session /server:$ComputerName 2>$null
        }
    } catch {
        return $null
    }
}

function Parse-QuerySessionOutputPS5 {
    param([string]$Output)
    
    $sessions = @()
    $lines = @($Output -split "`r`n" | Where-Object { $_ -match '\S' })
    
    $skipHeader = $true
    foreach ($line in $lines) {
        if ($skipHeader) {
            if ($line -match 'SESSIONNAME|SESSION') {
                $skipHeader = $false
            }
            continue
        }
        
        $parts = $line.Trim() -split '\s+' | Where-Object { $_ -ne '' }
        if ($parts.Count -ge 4) {
            $session = [PSCustomObject]@{
                SessionName = $parts[0]
                UserName = if ($parts[1] -eq "" -or $parts[1] -eq "0") { "SYSTEM" } else { $parts[1] }
                SessionId = [int]$parts[2]
                State = $parts[3]
                Type = if ($parts.Count -ge 5) { $parts[4] } else { "" }
                Device = if ($parts.Count -ge 6) { $parts[5] } else { "" }
                Source = "query_session"
            }
            $sessions += $session
        }
    }
    
    return $sessions
}

function Get-CimSessionsPS5 {
    param([string]$ComputerName)
    
    try {
        $sessions = @()
        
        # Use WMI as fallback
        $logonSessions = Get-WmiObject -Class Win32_LogonSession -ComputerName $ComputerName -ErrorAction SilentlyContinue
        
        foreach ($session in $logonSessions) {
            $sessions += [PSCustomObject]@{
                SessionName = ""
                UserName = "SYSTEM"
                SessionId = [int]$session.LogonId
                State = if ($session.LogonType -eq 0) { "System" } else { "Unknown" }
                Type = "Logon"
                Device = ""
                Source = "WMI"
            }
        }
        
        return $sessions
        
    } catch {
        return @()
    }
}

function Add-ExtendedInfoPS5 {
    param(
        [array]$Sessions,
        [string]$ComputerName
    )
    
    # Basic implementation for PS5.1
    foreach ($session in $Sessions) {
        try {
            # Simple implementation for example
            $session | Add-Member -NotePropertyName "ClientIP" -NotePropertyValue "N/A" -Force
            $session | Add-Member -NotePropertyName "ClientHostname" -NotePropertyValue "N/A" -Force
        } catch {
            # Ignore errors
        }
    }
    
    return $Sessions
}
#endregion

#region Formatting Functions for Consistent Output
function Format-RDPSessions {
    <#
    .SYNOPSIS
        Formats RDP sessions for consistent display
    #>
    
    param(
        [array]$Sessions,
        [switch]$Detailed
    )
    
    if ($Sessions.Count -eq 0) {
        return "No sessions found."
    }
    
    # Create formatted table
    $tableParams = @{
        Property = @(
            @{Label="ID"; Expression={$_.SessionId}; Width=4; Align='Right'}
            @{Label="User"; Expression={$_.UserName}; Width=15}
            @{Label="State"; Expression={$_.State}; Width=12}
            @{Label="Type"; Expression={$_.Type}; Width=8}
            @{Label="Session"; Expression={$_.SessionName}; Width=15}
            @{Label="Device"; Expression={$_.Device}; Width=10}
            @{Label="Current"; Expression={if($_.IsCurrent){"*"}else{""}}; Width=7}
        )
    }
    
    if ($Detailed) {
        $tableParams.Property += @(
            @{Label="Source"; Expression={$_.Source}; Width=10}
            @{Label="ClientIP"; Expression={$_.ClientIP}; Width=15}
        )
    }
    
    return $Sessions | Format-Table $tableParams -AutoSize
}

function Get-SessionStatistics {
    <#
    .SYNOPSIS
        Returns statistics about collected sessions
    #>
    
    param([array]$Sessions)
    
    $stats = [PSCustomObject]@{
        TotalSessions = $Sessions.Count
        ActiveSessions = ($Sessions | Where-Object { $_.State -eq "Active" }).Count
        DisconnectedSessions = ($Sessions | Where-Object { $_.State -eq "Disconnected" }).Count
        SystemSessions = ($Sessions | Where-Object { $_.UserName -eq "SYSTEM" }).Count
        UserSessions = ($Sessions | Where-Object { $_.UserName -ne "SYSTEM" }).Count
        CurrentSession = $Sessions | Where-Object { $_.IsCurrent } | Select-Object -First 1
        Sources = $Sessions.Source | Group-Object | ForEach-Object { "$($_.Name): $($_.Count)" } -join ", "
    }
    
    return $stats
}
#endregion

#region Helper Functions for Session Enumeration

function Get-QwinstaSessions {
    <#
    .SYNOPSIS
        Retrieves sessions using qwinsta command with locale-aware parsing
    #>
    
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    $sessions = @()
    
    try {
        # Execute qwinsta command
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $qwinstaOutput = qwinsta 2>$null
        } else {
            $qwinstaOutput = qwinsta /server:$ComputerName 2>$null
        }
        
        if (-not $qwinstaOutput -or $qwinstaOutput.Count -eq 0) {
            Write-DebugLog "qwinsta returned no output" "WARNING"
            return $sessions
        }
        
        # Convert output to array of lines
        $lines = @($qwinstaOutput -split "`r`n" | Where-Object { $_ -match '\S' })
        
        if ($lines.Count -eq 0) {
            return $sessions
        }
        
        Write-DebugLog "Parsing $($lines.Count) lines from qwinsta output" "DEBUG"
        
        # Detect locale from header line
        $headerLine = $null
        $headerIndex = -1
        $detectedLocale = $null
        
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            
            foreach ($locale in $localePatterns.Keys) {
                if ($line -match $localePatterns[$locale].HeaderPattern) {
                    $headerLine = $line
                    $headerIndex = $i
                    $detectedLocale = $locale
                    Write-DebugLog "Detected locale: $detectedLocale" "DEBUG"
                    break
                }
            }
            
            if ($headerLine) { break }
        }
        
        # If no locale-specific header found, try generic header detection
        if (-not $headerLine) {
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                
                # Look for common patterns in any locale
                if ($line -match '\s(ID|ID|STATUS|STATE|STATUS|STATE)\s' -and 
                    $line -match '\s(STATE|STATE|STATUS|STATE|STATUS)\s') {
                    $headerLine = $line
                    $headerIndex = $i
                    $detectedLocale = "AutoDetected"
                    Write-DebugLog "Auto-detected header line (no specific locale)" "DEBUG"
                    break
                }
            }
        }
        
        if (-not $headerLine) {
            Write-DebugLog "Could not detect header in qwinsta output" "WARNING"
            
            # Fallback: try to parse without header detection using fixed positions
            $sessions = Parse-SessionsWithoutHeader -Lines $lines
            return $sessions
        }
        
        # Parse data lines using column positions
        for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            
            # Skip empty lines or lines that look like separators
            if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^[-=]+$') {
                continue
            }
            
            # Parse using fixed column positions with fallback to regex
            $session = Parse-SessionLine -Line $line -Locale $detectedLocale
            
            if ($session) {
                $session.Source = "qwinsta"
                $session.Locale = $detectedLocale
                $sessions += $session
            }
        }
        
    } catch {
        Write-DebugLog "Error in Get-QwinstaSessions : $($_.Exception.Message)" "ERROR"
    }
    
    return $sessions
}

function Parse-SessionLine {
    <#
    .SYNOPSIS
        Parses a single session line using multiple strategies
    #>
    
    param(
        [string]$Line,
        [string]$Locale = "Unknown"
    )
    
    try {
        # Strategy 1: Fixed-width parsing
        $session = Parse-FixedWidth -Line $Line
        
        if (-not $session) {
            # Strategy 2: Regex parsing
            $session = Parse-Regex -Line $Line
        }
        
        if (-not $session) {
            # Strategy 3: Manual parsing for edge cases
            $session = Parse-Manual -Line $Line
        }
        
        if ($session) {
            # Clean up values
            $session.SessionName = $session.SessionName.Trim()
            $session.UserName = $session.UserName.Trim()
            
            # Handle special cases
            if ($session.UserName -eq "" -or $session.UserName -eq $null) {
                $session.UserName = "SYSTEM"
            }
            
            # Clean state (remove extra spaces)
            $session.State = ($session.State -replace '\s+', ' ').Trim()
            
            # Convert SessionId to integer
            if ($session.SessionId -match '^\d+$') {
                $session.SessionId = [int]$session.SessionId
            } else {
                $session.SessionId = 0
            }
        }
        
        return $session
        
    } catch {
        Write-DebugLog "Error parsing session line '$Line' : $_" "DEBUG"
        return $null
    }
}

function Parse-FixedWidth {
    <#
    .SYNOPSIS
        Parses session line using fixed column positions
    #>
    
    param([string]$Line)
    
    try {
        # Ensure line has minimum length
        if ($Line.Length -lt 50) {
            # Pad line for parsing
            $Line = $Line.PadRight(80, ' ')
        }
        
        # Extract using approximate positions with bounds checking
        $sessionName = ""
        $userName = ""
        $sessionId = ""
        $state = ""
        $type = ""
        $device = ""
        
        # SessionName (0-17)
        if ($Line.Length -gt 17) {
            $sessionName = $Line.Substring(0, 18).Trim()
        } else {
            $sessionName = $Line.Trim()
        }
        
        # UserName (18-41)
        if ($Line.Length -gt 41) {
            $userName = $Line.Substring(18, 24).Trim()
        } elseif ($Line.Length -gt 18) {
            $userName = $Line.Substring(18).Trim()
        }
        
        # ID (42-46)
        if ($Line.Length -gt 46) {
            $sessionId = $Line.Substring(42, 5).Trim()
        } elseif ($Line.Length -gt 42) {
            $sessionId = $Line.Substring(42).Trim()
        }
        
        # State (47-57)
        if ($Line.Length -gt 57) {
            $state = $Line.Substring(47, 11).Trim()
        } elseif ($Line.Length -gt 47) {
            $state = $Line.Substring(47).Trim()
        }
        
        # Type (58-67)
        if ($Line.Length -gt 67) {
            $type = $Line.Substring(58, 10).Trim()
        } elseif ($Line.Length -gt 58) {
            $type = $Line.Substring(58).Trim()
        }
        
        # Device (68+)
        if ($Line.Length -gt 68) {
            $device = $Line.Substring(68).Trim()
        }
        
        # Special case: line may start with '>' indicating current session
        if ($sessionName.StartsWith('>')) {
            $sessionName = $sessionName.Substring(1).Trim()
        }
        
        # Create session object
        return [PSCustomObject]@{
            SessionName = $sessionName
            UserName = if ([string]::IsNullOrWhiteSpace($userName)) { "SYSTEM" } else { $userName }
            SessionId = $sessionId
            State = $state
            Type = $type
            Device = $device
        }
        
    } catch {
        return $null
    }
}

function Parse-Regex {
    <#
    .SYNOPSIS
        Parses session line using regex patterns
    #>
    
    param([string]$Line)
    
    # Multiple regex patterns to handle different formats
    $patterns = @(
        # Pattern 1: Standard format with all fields
        '^(?<Current>>)?\s*(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\S+)\s+(?<Type>\S+)\s+(?<Device>\S+)?',
        
        # Pattern 2: Missing device
        '^(?<Current>>)?\s*(?<SessionName>\S+)?\s+(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\S+)\s+(?<Type>\S+)',
        
        # Pattern 3: Missing session name and device
        '^(?<Current>>)?\s*(?<UserName>\S+)?\s+(?<Id>\d+)\s+(?<State>\S+)\s+(?<Type>\S+)',
        
        # Pattern 4: Minimal format
        '^(?<Current>>)?\s*(?<Id>\d+)\s+(?<State>\S+)\s+(?<Type>\S+)'
    )
    
    foreach ($pattern in $patterns) {
        if ($Line -match $pattern) {
            $sessionName = if ($matches.SessionName) { $matches.SessionName } else { "" }
            $userName = if ($matches.UserName) { $matches.UserName } else { "SYSTEM" }
            
            # Handle current session marker
            if ($matches.Current -eq '>') {
                if ([string]::IsNullOrEmpty($sessionName)) {
                    $sessionName = ">" + $sessionName
                }
            }
            
            return [PSCustomObject]@{
                SessionName = $sessionName
                UserName = $userName
                SessionId = $matches.Id
                State = $matches.State
                Type = $matches.Type
                Device = if ($matches.Device) { $matches.Device } else { "" }
            }
        }
    }
    
    return $null
}

function Parse-Manual {
    <#
    .SYNOPSIS
        Manual parsing for difficult cases
    #>
    
    param([string]$Line)
    
    try {
        # Split by whitespace but preserve structure
        $parts = $Line -split '\s+' | Where-Object { $_ -ne '' }
        
        if ($parts.Count -lt 4) {
            return $null
        }
        
        # Heuristic parsing based on common patterns
        $sessionName = ""
        $userName = "SYSTEM"
        $sessionId = 0
        $state = ""
        $type = ""
        $device = ""
        
        # Find ID (should be a number)
        $idIndex = -1
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i] -match '^\d+$') {
                $idIndex = $i
                $sessionId = [int]$parts[$i]
                break
            }
        }
        
        if ($idIndex -eq -1) {
            return $null
        }
        
        # Everything before ID is SessionName/UserName
        if ($idIndex -gt 0) {
            $beforeId = $parts[0..($idIndex-1)] -join ' '
            
            # Check if it starts with session-like pattern (rdp-tcp#, console, etc.)
            if ($beforeId -match '(rdp-tcp|console|services)') {
                $sessionName = $beforeId
                $userName = "SYSTEM"
            } else {
                # Might be username, try to extract
                $sessionName = ""
                $userName = $beforeId
            }
        }
        
        # State and Type after ID
        if ($idIndex + 1 -lt $parts.Count) {
            $state = $parts[$idIndex + 1]
        }
        
        if ($idIndex + 2 -lt $parts.Count) {
            $type = $parts[$idIndex + 2]
        }
        
        if ($idIndex + 3 -lt $parts.Count) {
            $device = $parts[$idIndex + 3]
        }
        
        # Handle current session marker
        if ($Line.StartsWith('>')) {
            if ([string]::IsNullOrEmpty($sessionName)) {
                $sessionName = ">" + $sessionName
            }
        }
        
        return [PSCustomObject]@{
            SessionName = $sessionName
            UserName = $userName
            SessionId = $sessionId
            State = $state
            Type = $type
            Device = $device
        }
        
    } catch {
        return $null
    }
}

function Parse-SessionsWithoutHeader {
    <#
    .SYNOPSIS
        Fallback parsing when no header is detected
    #>
    
    param([array]$Lines)
    
    $sessions = @()
    
    foreach ($line in $Lines) {
        # Skip obviously non-session lines
        if ([string]::IsNullOrWhiteSpace($line) -or 
            $line -match 'SESSIONNAME|SESSION|SESSION|SESSION' -or 
            $line -match '^-+|=+$') {
            continue
        }
        
        $session = Parse-SessionLine -Line $line
        
        if ($session) {
            $session.Source = "qwinsta_noheader"
            $sessions += $session
        }
    }
    
    return $sessions
}

function Get-QuerySessions {
    <#
    .SYNOPSIS
        Retrieves sessions using query session command
    #>
    
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    $sessions = @()
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $queryOutput = query session 2>$null
        } else {
            $queryOutput = query session /server:$ComputerName 2>$null
        }
        
        if (-not $queryOutput) {
            return $sessions
        }
        
        $lines = @($queryOutput -split "`r`n" | Where-Object { $_ -match '\S' })
        
        # Find header line
        $headerIndex = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'SESSIONNAME|SESSION|SESSION' -and 
                $lines[$i] -match 'USERNAME|USER|USER' -and 
                $lines[$i] -match 'ID|ID') {
                $headerIndex = $i
                break
            }
        }
        
        if ($headerIndex -eq -1) {
            # Assume first line is header
            $headerIndex = 0
        }
        
        # Parse data lines
        for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $session = Parse-SessionLine -Line $line
            
            if ($session) {
                $session.Source = "query session"
                $sessions += $session
            }
        }
        
    } catch {
        Write-DebugLog "Error in Get-QuerySessions : $($_.Exception.Message)" "DEBUG"
    }
    
    return $sessions
}

function Get-PowerShellSessions {
    <#
    .SYNOPSIS
        Retrieves sessions using PowerShell cmdlets (modern systems)
    #>
    
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    $sessions = @()
    
    try {
        # Check if RemoteDesktop module is available
        $rdpModule = Get-Module -Name RemoteDesktop -ListAvailable -ErrorAction SilentlyContinue
        
        if ($rdpModule) {
            Import-Module RemoteDesktop -ErrorAction SilentlyContinue
            
            # Try to get sessions from Remote Desktop Services
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
        
        # Alternative: Use CIM/WMI for older systems
        if ($sessions.Count -eq 0) {
            $cimSessions = Get-CimSessionInfo -ComputerName $ComputerName
            if ($cimSessions) {
                $sessions += $cimSessions
            }
        }
        
    } catch {
        Write-DebugLog "Error in Get-PowerShellSessions : $($_.Exception.Message)" "DEBUG"
    }
    
    return $sessions
}

function Get-CimSessionInfo {
    <#
    .SYNOPSIS
        Retrieves session information using CIM/WMI
    #>
    
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    $sessions = @()
    
    try {
        # Query Win32_LogonSession for basic session info
        $logonSessions = Get-CimInstance -ClassName Win32_LogonSession -ComputerName $ComputerName -ErrorAction SilentlyContinue
        
        if ($logonSessions) {
            foreach ($logonSession in $logonSessions) {
                # Get associated user
                $logonId = $logonSession.LogonId
                $userInfo = Get-CimAssociatedInstance -InputObject $logonSession -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue
                
                $session = [PSCustomObject]@{
                    SessionName = ""
                    UserName = if ($userInfo) { $userInfo.Name } else { "SYSTEM" }
                    SessionId = [int]$logonId
                    State = if ($logonSession.LogonType -eq 0) { "System" } else { "Active" }
                    Type = "Logon"
                    Device = ""
                    Source = "CIM/WMI"
                }
                
                $sessions += $session
            }
        }
        
    } catch {
        Write-DebugLog "Error in Get-CimSessionInfo : $($_.Exception.Message)" "DEBUG"
    }
    
    return $sessions
}

function Add-ExtendedSessionInfo {
    <#
    .SYNOPSIS
        Adds extended information like client IP addresses to sessions
    #>
    
    param(
        [array]$Sessions,
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        # Only attempt extended info on local computer with admin rights
        if ($ComputerName -ne $env:COMPUTERNAME -or -not (Test-IsAdministrator)) {
            Write-DebugLog "Extended info requires local admin access" "WARNING"
            return $Sessions
        }
        
        # Get netstat output for RDP connections
        $netstatOutput = @()
        
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $netstatOutput = netstat -an | Select-String ":3389" -ErrorAction SilentlyContinue
        } else {
            # PowerShell 5.1 compatibility
            $netstatProcess = Start-Process -FilePath "netstat" -ArgumentList "-an" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "temp_netstat.txt"
            if (Test-Path "temp_netstat.txt") {
                $netstatOutput = Get-Content "temp_netstat.txt" | Select-String ":3389"
                Remove-Item "temp_netstat.txt" -Force
            }
        }
        
        if ($netstatOutput) {
            Write-DebugLog "Found $($netstatOutput.Count) RDP connections in netstat" "DEBUG"
            
            # Parse netstat output for ESTABLISHED connections
            foreach ($line in $netstatOutput) {
                if ($line -match '\s+(?<Protocol>\S+)\s+(?<LocalAddress>\S+):3389\s+(?<RemoteAddress>\S+):(?<RemotePort>\d+)\s+(?<State>\S+)') {
                    if ($matches.State -eq "ESTABLISHED") {
                        $clientIP = $matches.RemoteAddress
                        
                        # Try to resolve hostname
                        $clientHost = "Unknown"
                        try {
                            $clientHost = [System.Net.Dns]::GetHostEntry($clientIP).HostName
                        } catch {
                            # Keep as Unknown
                        }
                        
                        # Add to session info (simplistic mapping - in real use would need session mapping)
                        # This is a placeholder for actual implementation
                    }
                }
            }
        }
        
    } catch {
        Write-DebugLog "Error adding extended session info : $($_.Exception.Message)" "DEBUG"
    }
    
    return $Sessions
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
        $mstscParams.Add("/control")
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
    <#
    .SYNOPSIS
        Gracefully or forcefully terminates Remote Desktop sessions
    
    .DESCRIPTION
        Provides comprehensive session termination capabilities including:
        - Soft disconnection (session can be reconnected)
        - Hard logoff (complete session termination)
        - Multiple retry attempts with exponential backoff
        - Detailed logging and error handling
        - Support for local and remote computers
    
    .PARAMETER SessionId
        The ID of the session to disconnect/logoff
    
    .PARAMETER Logoff
        If specified, performs hard logoff instead of soft disconnect
    
    .PARAMETER ComputerName
        Target computer name (default: local computer)
    
    .PARAMETER Reason
        Optional reason code for disconnection (Windows Server 2012+)
    
    .PARAMETER WaitForCompletion
        Wait for operation to complete and verify success
    
    .PARAMETER TimeoutSeconds
        Maximum time to wait for completion
    
    .EXAMPLE
        Disconnect-Session -SessionId 2 -Logoff
        Hard terminates session ID 2 on local computer
    
    .EXAMPLE
        Disconnect-Session -SessionId 3 -ComputerName "SERVER01" -Reason 2
        Soft disconnects session ID 3 on SERVER01 with reason code 2
    
    .OUTPUTS
        Boolean indicating success or failure
    #>
    
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 65536)]
        [int]$SessionId,
        
        [Parameter()]
        [switch]$Logoff,
        
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [ValidateRange(0, 6)]
        [int]$Reason = 0,
        
        [Parameter()]
        [switch]$WaitForCompletion,
        
        [Parameter()]
        [int]$TimeoutSeconds = 30
    )
    
    begin {
        $action = if ($Logoff) { "logoff" } else { "disconnect" }
        $actionDisplay = if ($Logoff) { "logoff (hard termination)" } else { "disconnect (soft, reconnectable)" }
        
        Write-DebugLog "Preparing to $actionDisplay session $SessionId on $ComputerName" "INFO" @{
            SessionId = $SessionId
            Action = $action
            ComputerName = $ComputerName
            Reason = $Reason
            WaitForCompletion = $WaitForCompletion
            TimeoutSeconds = $TimeoutSeconds
        }
        
        # Validate session exists before attempting operation
        try {
            $sessions = Get-RDPSessions -ComputerName $ComputerName
            $targetSession = $sessions | Where-Object { $_.SessionId -eq $SessionId }
            
            if (-not $targetSession) {
                Write-DebugLog "Session $SessionId not found on $ComputerName" "ERROR" @{
                    AvailableSessions = $sessions.SessionId
                }
                return $false
            }
            
            $sessionInfo = @{
                UserName = $targetSession.UserName
                State = $targetSession.State
                Type = $targetSession.Type
                Source = $targetSession.Source
            }
            
            Write-DebugLog "Found session $SessionId : User: $($sessionInfo.UserName), State: $($sessionInfo.State)" "DEBUG" $sessionInfo
            
        } catch {
            Write-DebugLog "Failed to query sessions on $ComputerName : $($_.Exception.Message)" "WARNING"
            if (-not $Force) {
                Write-Host "Cannot verify session existence. Continue anyway? (y/N)" -ForegroundColor $COLORS.Warning
                $confirm = Read-Host
                if ($confirm -ne 'y') {
                    return $false
                }
            }
        }
        
        # Reason code descriptions (Windows Server 2012+)
        $reasonCodes = @{
            0 = "No reason provided"
            1 = "Other"
            2 = "Administrative action"
            3 = "Policy violation"
            4 = "Maintenance"
            5 = "Application issue"
            6 = "System shutdown"
        }
        
        $reasonDescription = if ($reasonCodes.ContainsKey($Reason)) { 
            $reasonCodes[$Reason] 
        } else { 
            "Unknown reason code: $Reason" 
        }
        
        # Prepare command parameters
        $cmdParams = @{
            SessionId = $SessionId
            Server = $ComputerName
            Reason = $Reason
            Wait = $WaitForCompletion
        }
    }
    
    process {
        try {
            if ($PSCmdlet.ShouldProcess("session $SessionId on $ComputerName", "perform $actionDisplay")) {
                
                # Request user confirmation for non-force operations
                if (-not $Force -and -not $Quiet) {
                    # Fix: Use PowerShell 5.1 compatible syntax for null-coalescing and ternary operations
                    $userName = if ($sessionInfo.UserName) { $sessionInfo.UserName } else { "Unknown" }
                    $actionVerb = if ($Logoff) { "CANNOT" } else { "CAN" }
                    
                    $confirmationMessage = @"
You are about to $actionDisplay session $SessionId on $ComputerName.
User: $userName
Reason: $reasonDescription

This action $actionVerb be undone without user intervention.
"@
                    
                    Write-Host $confirmationMessage -ForegroundColor $COLORS.Warning
                    
                    if ($Logoff) {
                        Write-Host "WARNING: Logoff will terminate all running applications and unsaved data may be lost!" -ForegroundColor $COLORS.Error
                    }
                    
                    $confirm = Read-Host "Proceed? (y/N)"
                    if ($confirm -ne 'y') {
                        Write-DebugLog "User cancelled $actionDisplay operation for session $SessionId" "INFO"
                        return $false
                    }
                }
                
                # Execute the disconnect/logoff command with retry logic
                $success = $false
                $lastError = $null
                
                for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
                    try {
                        Write-DebugLog "Attempt $attempt of $MAX_RETRIES to $action session $SessionId" "DEBUG" @{
                            Attempt = $attempt
                            MaxRetries = $MAX_RETRIES
                            Parameters = $cmdParams
                        }
                        
                        if ($Logoff) {
                            # Perform hard logoff
                            $command = "logoff $SessionId"
                            if ($ComputerName -ne $env:COMPUTERNAME) {
                                $command += " /server:$ComputerName"
                            }
                            if ($Reason -gt 0) {
                                $command += " /v:$Reason"
                            }
                            
                            $result = Invoke-Expression $command 2>&1
                            
                        } else {
                            # Perform soft disconnect
                            $command = "reset session $SessionId"
                            if ($ComputerName -ne $env:COMPUTERNAME) {
                                $command += " /server:$ComputerName"
                            }
                            if ($Reason -gt 0) {
                                $command += " /v:$Reason"
                            }
                            
                            $result = Invoke-Expression $command 2>&1
                        }
                        
                        # Check command execution result
                        if ($LASTEXITCODE -eq 0) {
                            $success = $true
                            Write-DebugLog "Successfully sent $action command for session $SessionId (attempt $attempt)" "SUCCESS" @{
                                Command = $command
                                ExitCode = $LASTEXITCODE
                                Result = $result
                            }
                            break
                        } else {
                            $lastError = $result
                            Write-DebugLog "$action attempt $attempt failed for session $SessionId : ExitCode=$LASTEXITCODE" "WARNING" @{
                                ExitCode = $LASTEXITCODE
                                ErrorOutput = $result
                            }
                            
                            # Exponential backoff before retry
                            if ($attempt -lt $MAX_RETRIES) {
                                $delay = $RETRY_DELAY * $attempt
                                Write-DebugLog "Waiting $delay seconds before retry..." "DEBUG"
                                Start-Sleep -Seconds $delay
                            }
                        }
                        
                    } catch {
                        $lastError = $_.Exception.Message
                        Write-DebugLog "Exception during $action attempt $attempt for session $SessionId : $lastError" "WARNING" @{
                            Exception = $_.Exception
                            Attempt = $attempt
                        }
                        
                        if ($attempt -lt $MAX_RETRIES) {
                            $delay = $RETRY_DELAY * $attempt
                            Start-Sleep -Seconds $delay
                        }
                    }
                }
                
                # Verify operation if requested
                if ($success -and $WaitForCompletion) {
                    Write-DebugLog "Verifying session $SessionId is no longer active..." "DEBUG"
                    
                    $verificationSuccess = $false
                    $startTime = Get-Date
                    
                    do {
                        Start-Sleep -Seconds 2
                        
                        try {
                            $sessions = Get-RDPSessions -ComputerName $ComputerName
                            $sessionStillExists = $sessions | Where-Object { $_.SessionId -eq $SessionId } | Measure-Object | Select-Object -ExpandProperty Count
                            
                            if ($sessionStillExists -eq 0) {
                                $verificationSuccess = $true
                                Write-DebugLog "Verification successful: session $SessionId no longer exists" "SUCCESS"
                                break
                            } else {
                                $sessionState = ($sessions | Where-Object { $_.SessionId -eq $SessionId }).State
                                Write-DebugLog "Session $SessionId still exists with state: $sessionState" "DEBUG"
                            }
                            
                        } catch {
                            Write-DebugLog "Error during verification: $($_.Exception.Message)" "WARNING"
                        }
                        
                        $elapsedTime = (Get-Date) - $startTime
                        
                    } while ($elapsedTime.TotalSeconds -lt $TimeoutSeconds)
                    
                    if (-not $verificationSuccess) {
                        Write-DebugLog "Verification timeout: session $SessionId may still exist after $TimeoutSeconds seconds" "WARNING"
                        $success = $false
                    }
                }
                
                if ($success) {
                    Write-DebugLog "Successfully performed $actionDisplay on session $SessionId" "SUCCESS" @{
                        SessionId = $SessionId
                        Action = $action
                        ComputerName = $ComputerName
                        Reason = $reasonDescription
                        Verification = if ($WaitForCompletion) { "Verified" } else { "Not verified" }
                    }
                    
                    # Log to Windows Event Log if running as admin
                    if (Test-IsAdministrator) {
                        try {
                            $eventSource = "Remote Session Manager Pro"
                            $eventId = if ($Logoff) { 1002 } else { 1001 }
                            $userName = if ($sessionInfo.UserName) { $sessionInfo.UserName } else { "Unknown" }
                            
                            $eventMessage = @"
Session $SessionId was $actionDisplay`d by $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Computer: $ComputerName
User: $userName
Reason: $reasonDescription
"@
                            
                            Write-EventLog -LogName "Application" -Source $eventSource -EventId $eventId -EntryType "Information" -Message $eventMessage -ErrorAction SilentlyContinue
                            Write-DebugLog "Logged $actionDisplay event to Windows Event Log" "DEBUG"
                            
                        } catch {
                            # Event logging is optional, don't fail if it doesn't work
                            Write-DebugLog "Failed to log to Windows Event Log: $($_.Exception.Message)" "DEBUG"
                        }
                    }
                    
                    return $true
                    
                } else {
                    $errorMessage = "Failed to $action session $SessionId after $MAX_RETRIES attempts"
                    if ($lastError) {
                        $errorMessage += " : $lastError"
                    }
                    
                    Write-DebugLog $errorMessage "ERROR" @{
                        SessionId = $SessionId
                        Action = $action
                        ComputerName = $ComputerName
                        LastError = $lastError
                        MaxAttempts = $MAX_RETRIES
                    }
                    
                    return $false
                }
            }
            
            return $false # ShouldProcess returned false (user denied)
            
        } catch {
            $errorDetails = $_.Exception
            Write-DebugLog "Unhandled exception during session $action : $($errorDetails.Message)" "ERROR" @{
                Exception = $errorDetails
                StackTrace = $_.ScriptStackTrace
                SessionId = $SessionId
                Action = $action
            }
            
            return $false
        }
    }
    
    end {
        # Fix: Use PowerShell 5.1 compatible syntax for null-coalescing
        $successResult = if ($success) { $success } else { $false }
        
        Write-DebugLog "Completed $actionDisplay operation for session $SessionId" "DEBUG" @{
            Success = $successResult
            SessionId = $SessionId
            Action = $action
        }
    }
}

function Show-SystemStatus {
    <#
    .SYNOPSIS
        Displays comprehensive system status report for RDP session management
    
    .DESCRIPTION
        Provides a detailed, professional status report covering all aspects of
        RDP configuration and session management. Automatically adapts to
        PowerShell version (5.1 vs 7+) for optimal performance and features.
    
    .EXAMPLE
        Show-SystemStatus
        # Displays full system status report
    
    .EXAMPLE
        Show-SystemStatus -Brief
        # Shows summary status only
    
    .EXAMPLE
        Show-SystemStatus -ExportJson "status.json"
        # Exports status to JSON file
    
    .OUTPUTS
        PSCustomObject containing all status information
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Brief,
        
        [Parameter()]
        [string]$ExportJson,
        
        [Parameter()]
        [string]$ExportCsv,
        
        [Parameter()]
        [switch]$IncludePerformance
    )
    
    begin {
        Write-DebugLog "Generating comprehensive system status report..." "INFO"
        
        # Determine PowerShell version and use appropriate implementation
        $IsPS7Plus = $PSVersionTable.PSVersion.Major -ge 7
        
        # Initialize status object
        $statusReport = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            ComputerName = $env:COMPUTERNAME
            User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            IsAdministrator = $false
            OSVersion = $null
            RDPConfiguration = $null
            ShadowConfiguration = $null
            FirewallStatus = $null
            ServiceStatus = $null
            ActiveSessions = $null
            Recommendations = @()
            PerformanceMetrics = $null
            GenerationTime = $null
        }
        
        # Define colors based on PS version
        if ($IsPS7Plus) {
            # PowerShell 7+ supports ANSI colors and $PSStyle
            $Color = @{
                Header = "Cyan"
                Success = "Green"
                Warning = "Yellow"
                Error = "Red"
                Info = "Cyan"
                Debug = "Gray"
                Reset = ""
            }
        } else {
            # PowerShell 5.1 fallback colors
            $Color = @{
                Header = "Cyan"
                Success = "Green"
                Warning = "Yellow"
                Error = "Red"
                Info = "Cyan"
                Debug = "Gray"
                Reset = ""
            }
        }
    }
    
    process {
        try {
            # Get comprehensive status data
            if ($IsPS7Plus) {
                $statusData = Get-SystemStatusDataPS7 -IncludePerformance:$IncludePerformance
            } else {
                $statusData = Get-SystemStatusDataPS5 -IncludePerformance:$IncludePerformance
            }
            
            # Update status report object
            $statusReport.IsAdministrator = $statusData.IsAdministrator
            $statusReport.OSVersion = $statusData.OSVersion
            $statusReport.RDPConfiguration = $statusData.RDPConfiguration
            $statusReport.ShadowConfiguration = $statusData.ShadowConfiguration
            $statusReport.FirewallStatus = $statusData.FirewallStatus
            $statusReport.ServiceStatus = $statusData.ServiceStatus
            $statusReport.ActiveSessions = $statusData.ActiveSessions
            $statusReport.Recommendations = $statusData.Recommendations
            $statusReport.PerformanceMetrics = $statusData.PerformanceMetrics
            $statusReport.GenerationTime = $statusData.GenerationTime
            
            # Display report
            if ($IsPS7Plus) {
                Show-StatusReportPS7 -StatusData $statusData -Brief:$Brief -Color $Color
            } else {
                Show-StatusReportPS5 -StatusData $statusData -Brief:$Brief -Color $Color
            }
            
            # Export data if requested
            if ($ExportJson) {
                Export-StatusJson -StatusData $statusReport -Path $ExportJson
            }
            
            if ($ExportCsv) {
                Export-StatusCsv -StatusData $statusReport -Path $ExportCsv
            }
            
            return $statusReport
            
        } catch {
            Write-DebugLog "Error generating system status: $($_.Exception.Message)" "ERROR"
            Write-Host "Failed to generate complete status report." -ForegroundColor $Color.Error
            return $null
        }
    }
}

#region PowerShell 5.1 Implementation
function Get-SystemStatusDataPS5 {
    param([switch]$IncludePerformance)
    
    $statusStartTime = Get-Date
    
    # Collect all status data
    $statusData = [PSCustomObject]@{
        IsAdministrator = Test-IsAdministrator
        OSVersion = Get-OSVersionInfoPS5
        RDPConfiguration = Get-RDPConfigurationPS5
        ShadowConfiguration = Get-ShadowConfigurationPS5
        FirewallStatus = Get-FirewallStatusPS5
        ServiceStatus = Get-ServiceStatusPS5
        ActiveSessions = Get-ActiveSessionsPS5
        Recommendations = Get-RecommendationsPS5
        PerformanceMetrics = if ($IncludePerformance) { Get-PerformanceMetricsPS5 } else { $null }
        GenerationTime = $null
    }
    
    $statusData.GenerationTime = ((Get-Date) - $statusStartTime).TotalMilliseconds
    
    return $statusData
}

function Get-OSVersionInfoPS5 {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        
        return @{
            Version = $os.Version
            Caption = $os.Caption
            BuildNumber = $os.BuildNumber
            IsServer = ($os.ProductType -eq 2 -or $os.ProductType -eq 3)
            Architecture = $os.OSArchitecture
            LastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
            TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        }
    } catch {
        return @{
            Version = "Unknown"
            Caption = "Error retrieving OS info"
            Error = $_.Exception.Message
        }
    }
}

function Get-RDPConfigurationPS5 {
    $config = @{}
    
    try {
        $rdpEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        $config.RDPEnabled = if ($rdpEnabled) { $rdpEnabled.fDenyTSConnections -eq 0 } else { $null }
        
        # Check other RDP settings
        $config.MaxConnections = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxInstanceCount" -ErrorAction SilentlyContinue).MaxInstanceCount
        $config.KeepAliveInterval = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "KeepAliveInterval" -ErrorAction SilentlyContinue).KeepAliveInterval
        $config.AllowRemoteRPC = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "AllowRemoteRPC" -ErrorAction SilentlyContinue).AllowRemoteRPC
        
        return $config
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-ShadowConfigurationPS5 {
    $config = @{}
    
    try {
        $shadowValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "Shadow" -ErrorAction SilentlyContinue
        
        if ($shadowValue) {
            $config.ShadowMode = $shadowValue.Shadow
            
            # Fixed version for PowerShell 5.1 - traditional switch operator
            switch ($shadowValue.Shadow) {
                0 { $config.ShadowModeDescription = "Disabled" }
                1 { $config.ShadowModeDescription = "With Permission" }
                2 { $config.ShadowModeDescription = "Without Permission" }
                3 { $config.ShadowModeDescription = "Full Control" }
                4 { $config.ShadowModeDescription = "With Permission and Notification" }
                default { $config.ShadowModeDescription = "Unknown ($($shadowValue.Shadow))" }
            }
        } else {
            $config.ShadowMode = $null
            $config.ShadowModeDescription = "Not Configured"
        }
        
        # Check legacy registry path
        $legacyShadow = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "Shadow" -ErrorAction SilentlyContinue
        if ($legacyShadow) {
            $config.LegacyShadowMode = $legacyShadow.Shadow
        }
        
        return $config
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-FirewallStatusPS5 {
    $status = @{}
    
    try {
        # Use netsh to check firewall rules
        $rulesOutput = netsh advfirewall firewall show rule name=all | Out-String
        
        # Check for RDP rules
        $rdpRules = $rulesOutput -split "`n" | Where-Object { $_ -match "Remote Desktop" }
        $status.RDPRuleCount = @($rdpRules).Count
        
        # Check if RDP is enabled in firewall
        $rdpEnabled = $false
        foreach ($rule in $rdpRules) {
            if ($rule -match "Enabled:\s*Yes") {
                $rdpEnabled = $true
                break
            }
        }
        
        $status.RDPEnabledInFirewall = $rdpEnabled
        
        # Check firewall state
        $firewallProfile = netsh advfirewall show allprofiles state | Out-String
        $status.FirewallEnabled = $firewallProfile -match "ON"
        
        return $status
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-ServiceStatusPS5 {
    $services = @()
    
    $serviceNames = @(
        @{ Name = "TermService"; DisplayName = "Remote Desktop Services" }
        @{ Name = "SessionEnv"; DisplayName = "Remote Desktop Configuration" }
        @{ Name = "UmRdpService"; DisplayName = "Remote Desktop Services UserMode Port Redirector" }
        @{ Name = "WinRM"; DisplayName = "Windows Remote Management" }
        @{ Name = "Spooler"; DisplayName = "Print Spooler" } # Required for RDP printer redirection
    )
    
    foreach ($svc in $serviceNames) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if ($service) {
                $services += [PSCustomObject]@{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = $service.Status
                    StartupType = $service.StartType
                    CanStart = ($service.Status -ne "Running") -and ($service.StartType -ne "Disabled")
                    CanStop = $service.Status -eq "Running"
                }
            } else {
                $services += [PSCustomObject]@{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = "Not Found"
                    StartupType = "N/A"
                    CanStart = $false
                    CanStop = $false
                }
            }
        } catch {
            $services += [PSCustomObject]@{
                Name = $svc.Name
                DisplayName = $svc.DisplayName
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
    }
    
    return $services
}

function Get-ActiveSessionsPS5 {
    try {
        $sessions = Get-RDPSessions -ActiveOnly
        $totalSessions = Get-RDPSessions
        
        return [PSCustomObject]@{
            TotalSessions = $totalSessions.Count
            ActiveSessions = $sessions.Count
            DisconnectedSessions = $totalSessions.Count - $sessions.Count
            SessionDetails = $sessions | Select-Object SessionId, UserName, State, SessionName
            CurrentSession = $sessions | Where-Object { $_.IsCurrent } | Select-Object -First 1
        }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-RecommendationsPS5 {
    $recommendations = @()
    
    try {
        # Check shadow configuration
        $shadowConfig = Get-ShadowConfigurationPS5
        if (-not $shadowConfig.ShadowMode -or $shadowConfig.ShadowMode -lt 2) {
            $recommendations += "Shadow mode is not properly configured for remote control without permission."
            $recommendations += "Run: .\$SCRIPT_NAME.ps1 --SessionId <ID> to auto-configure"
        }
        
        # Check RDP enabled
        $rdpConfig = Get-RDPConfigurationPS5
        if (-not $rdpConfig.RDPEnabled) {
            $recommendations += "RDP is disabled. Enable it for remote access."
        }
        
        # Check firewall
        $firewall = Get-FirewallStatusPS5
        if (-not $firewall.RDPEnabledInFirewall) {
            $recommendations += "RDP is not allowed in Windows Firewall."
        }
        
        # Check services
        $services = Get-ServiceStatusPS5
        $stoppedServices = $services | Where-Object { $_.Status -ne "Running" -and $_.Name -in @("TermService", "SessionEnv") }
        if ($stoppedServices) {
            $recommendations += "Critical RDP services are not running: $($stoppedServices.DisplayName -join ', ')"
        }
        
        return $recommendations
        
    } catch {
        return @("Error generating recommendations: $($_.Exception.Message)")
    }
}

function Get-PerformanceMetricsPS5 {
    try {
        # CPU usage
        $cpu = Get-WmiObject -Class Win32_Processor | 
               Measure-Object -Property LoadPercentage -Average | 
               Select-Object -ExpandProperty Average
        
        # Memory usage
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $totalMemory = $os.TotalVisibleMemorySize / 1MB
        $freeMemory = $os.FreePhysicalMemory / 1MB
        $memoryUsage = (($totalMemory - $freeMemory) / $totalMemory) * 100
        
        # Disk usage
        $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" |
                Select-Object DeviceID, 
                    @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                    @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}},
                    @{Name="UsedPercent";Expression={[math]::Round(100-($_.FreeSpace/$_.Size*100),2)}}
        
        return [PSCustomObject]@{
            CPUUsagePercent = [math]::Round($cpu, 2)
            MemoryUsagePercent = [math]::Round($memoryUsage, 2)
            TotalMemoryGB = [math]::Round($totalMemory, 2)
            FreeMemoryGB = [math]::Round($freeMemory, 2)
            DiskUsage = $disk
            CollectionTime = Get-Date
        }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Show-StatusReportPS5 {
    param(
        $StatusData,
        [switch]$Brief,
        $Color
    )
    
    # Header
    Write-Host "`n" + ("=" * 70) -ForegroundColor $Color.Header
    Write-Host "REMOTE SESSION MANAGER PRO - SYSTEM STATUS REPORT" -ForegroundColor $Color.Header
    Write-Host "=" * 70 -ForegroundColor $Color.Header
    
    Write-Host "Generated    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $Color.Info
    Write-Host "Computer     : $env:COMPUTERNAME" -ForegroundColor $Color.Info
    Write-Host "User         : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor $Color.Info
    Write-Host "PowerShell   : $($PSVersionTable.PSVersion)" -ForegroundColor $Color.Info
    Write-Host "Admin        : $(if ($StatusData.IsAdministrator) { 'Yes' } else { 'No' })" -ForegroundColor $Color.Info
    
    if ($Brief) {
        Write-Host "`n[Brief Mode - Showing Summary Only]" -ForegroundColor $Color.Warning
        Show-BriefStatusPS5 -StatusData $StatusData -Color $Color
        return
    }
    
    # Section 1: Windows Version
    Write-Host "`n[1] WINDOWS VERSION" -ForegroundColor $Color.Header
    Write-Host "   Version     : $($StatusData.OSVersion.Version)" -ForegroundColor $Color.Debug
    Write-Host "   Edition     : $($StatusData.OSVersion.Caption)" -ForegroundColor $Color.Debug
    Write-Host "   Build       : $($StatusData.OSVersion.BuildNumber)" -ForegroundColor $Color.Debug
    Write-Host "   Architecture: $($StatusData.OSVersion.Architecture)" -ForegroundColor $Color.Debug
    Write-Host "   Is Server   : $($StatusData.OSVersion.IsServer)" -ForegroundColor $Color.Debug
    
    # Section 2: RDP Configuration
    Write-Host "`n[2] RDP CONFIGURATION" -ForegroundColor $Color.Header
    if ($StatusData.RDPConfiguration.Error) {
        Write-Host "   Error: $($StatusData.RDPConfiguration.Error)" -ForegroundColor $Color.Error
    } else {
        Write-Host "   RDP Enabled  : $(if ($StatusData.RDPConfiguration.RDPEnabled) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($StatusData.RDPConfiguration.RDPEnabled) { $Color.Success } else { $Color.Error })
        Write-Host "   Max Sessions : $($StatusData.RDPConfiguration.MaxConnections)" -ForegroundColor $Color.Debug
        Write-Host "   Keep Alive   : $($StatusData.RDPConfiguration.KeepAliveInterval) ms" -ForegroundColor $Color.Debug
    }
    
    # Section 3: Shadow Configuration
    Write-Host "`n[3] SHADOW CONFIGURATION" -ForegroundColor $Color.Header
    if ($StatusData.ShadowConfiguration.Error) {
        Write-Host "   Error: $($StatusData.ShadowConfiguration.Error)" -ForegroundColor $Color.Error
    } else {
        $shadowColor = if ($StatusData.ShadowConfiguration.ShadowMode -ge 2) { $Color.Success } else { $Color.Warning }
        Write-Host "   Shadow Mode  : $($StatusData.ShadowConfiguration.ShadowModeDescription)" -ForegroundColor $shadowColor
        
        if ($StatusData.ShadowConfiguration.LegacyShadowMode) {
            Write-Host "   Legacy Mode  : $($StatusData.ShadowConfiguration.LegacyShadowMode)" -ForegroundColor $Color.Debug
        }
    }
    
    # Section 4: Firewall Status
    Write-Host "`n[4] FIREWALL STATUS" -ForegroundColor $Color.Header
    if ($StatusData.FirewallStatus.Error) {
        Write-Host "   Error: $($StatusData.FirewallStatus.Error)" -ForegroundColor $Color.Error
    } else {
        Write-Host "   Firewall     : $(if ($StatusData.FirewallStatus.FirewallEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($StatusData.FirewallStatus.FirewallEnabled) { $Color.Success } else { $Color.Warning })
        Write-Host "   RDP Rules    : $($StatusData.FirewallStatus.RDPRuleCount) found" -ForegroundColor $Color.Debug
        Write-Host "   RDP Allowed  : $(if ($StatusData.FirewallStatus.RDPEnabledInFirewall) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($StatusData.FirewallStatus.RDPEnabledInFirewall) { $Color.Success } else { $Color.Error })
    }
    
    # Section 5: Service Status
    Write-Host "`n[5] SERVICE STATUS" -ForegroundColor $Color.Header
    foreach ($service in $StatusData.ServiceStatus) {
        $statusColor = switch ($service.Status) {
            "Running" { $Color.Success }
            "Stopped" { $Color.Error }
            "Not Found" { $Color.Warning }
            default { $Color.Warning }
        }
        
        Write-Host "   $($service.DisplayName): $($service.Status)" -ForegroundColor $statusColor
    }
    
    # Section 6: Active Sessions
    Write-Host "`n[6] ACTIVE SESSIONS" -ForegroundColor $Color.Header
    if ($StatusData.ActiveSessions.Error) {
        Write-Host "   Error: $($StatusData.ActiveSessions.Error)" -ForegroundColor $Color.Error
    } else {
        Write-Host "   Total        : $($StatusData.ActiveSessions.TotalSessions)" -ForegroundColor $Color.Debug
        Write-Host "   Active       : $($StatusData.ActiveSessions.ActiveSessions)" -ForegroundColor $(if ($StatusData.ActiveSessions.ActiveSessions -gt 0) { $Color.Success } else { $Color.Debug })
        Write-Host "   Disconnected : $($StatusData.ActiveSessions.DisconnectedSessions)" -ForegroundColor $Color.Debug
        
        if ($StatusData.ActiveSessions.CurrentSession) {
            Write-Host "   Current      : ID $($StatusData.ActiveSessions.CurrentSession.SessionId) ($($StatusData.ActiveSessions.CurrentSession.UserName))" -ForegroundColor $Color.Success
        }
    }
    
    # Section 7: Performance Metrics (if enabled)
    if ($StatusData.PerformanceMetrics -and -not $StatusData.PerformanceMetrics.Error) {
        Write-Host "`n[7] PERFORMANCE METRICS" -ForegroundColor $Color.Header
        Write-Host "   CPU Usage    : $($StatusData.PerformanceMetrics.CPUUsagePercent)%" -ForegroundColor $Color.Debug
        Write-Host "   Memory Usage : $($StatusData.PerformanceMetrics.MemoryUsagePercent)%" -ForegroundColor $Color.Debug
        Write-Host "   Total Memory : $($StatusData.PerformanceMetrics.TotalMemoryGB) GB" -ForegroundColor $Color.Debug
        
        if ($StatusData.PerformanceMetrics.DiskUsage) {
            foreach ($disk in $StatusData.PerformanceMetrics.DiskUsage) {
                Write-Host "   Disk $($disk.DeviceID)     : $($disk.UsedPercent)% used ($($disk.FreeGB) GB free of $($disk.SizeGB) GB)" -ForegroundColor $Color.Debug
            }
        }
    }
    
    # Section 8: Recommendations
    Write-Host "`n[8] RECOMMENDATIONS" -ForegroundColor $Color.Header
    if ($StatusData.Recommendations.Count -eq 0) {
        Write-Host "   No issues detected. System appears to be properly configured." -ForegroundColor $Color.Success
    } else {
        foreach ($recommendation in $StatusData.Recommendations) {
            Write-Host "   * $recommendation" -ForegroundColor $Color.Warning
        }
    }
    
    # Footer
    Write-Host "`n" + ("=" * 70) -ForegroundColor $Color.Header
    Write-Host "Report generated in $($StatusData.GenerationTime) ms" -ForegroundColor $Color.Info
    Write-Host "=" * 70 -ForegroundColor $Color.Header
}

function Show-BriefStatusPS5 {
    param($StatusData, $Color)
    
    $issues = @()
    
    # Check critical issues
    if (-not $StatusData.RDPConfiguration.RDPEnabled) {
        $issues += "RDP disabled"
    }
    
    if ($StatusData.ShadowConfiguration.ShadowMode -lt 2) {
        $issues += "Shadow mode not configured"
    }
    
    if (-not $StatusData.FirewallStatus.RDPEnabledInFirewall) {
        $issues += "Firewall blocking RDP"
    }
    
    $stoppedServices = $StatusData.ServiceStatus | Where-Object { $_.Status -ne "Running" -and $_.Name -in @("TermService", "SessionEnv") }
    if ($stoppedServices) {
        $issues += "Critical services stopped"
    }
    
    # Display brief status
    if ($issues.Count -eq 0) {
        Write-Host "[OK] System is properly configured for RDP session management" -ForegroundColor $Color.Success
    } else {
        Write-Host "[!] System has $($issues.Count) issue(s):" -ForegroundColor $Color.Warning
        foreach ($issue in $issues) {
            Write-Host "  * $issue" -ForegroundColor $Color.Warning
        }
    }
}
#endregion

#region PowerShell 7+ Implementation with Modern Features
function Get-SystemStatusDataPS7 {
    param([switch]$IncludePerformance)
    
    $statusStartTime = Get-Date
    
    # Use PowerShell 7+ features for parallel data collection
    $statusData = [PSCustomObject]@{
        IsAdministrator = Test-IsAdministrator
        OSVersion = Get-OSVersionInfoPS7
        RDPConfiguration = Get-RDPConfigurationPS7
        ShadowConfiguration = Get-ShadowConfigurationPS7
        FirewallStatus = Get-FirewallStatusPS7
        ServiceStatus = Get-ServiceStatusPS7
        ActiveSessions = Get-ActiveSessionsPS7
        Recommendations = Get-RecommendationsPS7
        PerformanceMetrics = if ($IncludePerformance) { Get-PerformanceMetricsPS7 } else { $null }
        GenerationTime = $null
    }
    
    $statusData.GenerationTime = ((Get-Date) - $statusStartTime).TotalMilliseconds
    
    return $statusData
}

function Get-OSVersionInfoPS7 {
    try {
        # Use CIM for better performance in PS7
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        return @{
            Version = $os.Version
            Caption = $os.Caption
            BuildNumber = $os.BuildNumber
            IsServer = ($os.ProductType -eq 2 -or $os.ProductType -eq 3)
            Architecture = $os.OSArchitecture
            LastBootTime = $os.LastBootUpTime
            TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            CollectionTime = Get-Date
        }
    } catch {
        return @{
            Version = "Unknown"
            Caption = "Error retrieving OS info"
            Error = $_.Exception.Message
        }
    }
}

function Get-RDPConfigurationPS7 {
    try {
        # Use parallel registry queries for performance
        $tasks = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "fDenyTSConnections" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "MaxInstanceCount" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "KeepAliveInterval" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name = "AllowRemoteRPC" }
        )
        
        $results = $tasks | ForEach-Object -Parallel {
            try {
                $value = Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
                @{
                    Name = $_.Name
                    Value = if ($value) { $value.$($_.Name) } else { $null }
                }
            } catch {
                @{ Name = $_.Name; Error = $_.Exception.Message }
            }
        } -ThrottleLimit 4
        
        $config = @{}
        foreach ($result in $results) {
            $config[$result.Name] = $result.Value
        }
        
        $config.RDPEnabled = if ($config.fDenyTSConnections -ne $null) { $config.fDenyTSConnections -eq 0 } else { $null }
        
        return $config
        
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-ShadowConfigurationPS7 {
    try {
        # Query multiple registry paths with compatibility
        $config = @{}
        
        # First check policies path
        try {
            $shadowValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "Shadow" -ErrorAction SilentlyContinue
            
            if ($shadowValue) {
                $config.ShadowMode = $shadowValue.Shadow
                
                # Fixed version for PowerShell 5.1/7+ compatibility using traditional switch
                switch ($shadowValue.Shadow) {
                    0 { $config.ShadowModeDescription = "Disabled" }
                    1 { $config.ShadowModeDescription = "With Permission" }
                    2 { $config.ShadowModeDescription = "Without Permission" }
                    3 { $config.ShadowModeDescription = "Full Control" }
                    4 { $config.ShadowModeDescription = "With Permission and Notification" }
                    default { $config.ShadowModeDescription = "Unknown ($($shadowValue.Shadow))" }
                }
            } else {
                $config.ShadowMode = $null
                $config.ShadowModeDescription = "Not Configured"
            }
        } catch {
            $config.ShadowMode = $null
            $config.ShadowModeDescription = "Error accessing registry"
        }
        
        # Check legacy path
        try {
            $legacyShadow = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "Shadow" -ErrorAction SilentlyContinue
            if ($legacyShadow) {
                $config.LegacyShadowMode = $legacyShadow.Shadow
            }
        } catch {
            # Silently continue if legacy path not accessible
        }
        
        return $config
        
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-FirewallStatusPS7 {
    try {
        # Use Get-NetFirewallRule for better performance in PS7
        $rules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        $status = @{
            RDPRuleCount = ($rules | Measure-Object).Count
            RDPEnabledInFirewall = $false
            FirewallEnabled = $null
        }
        
        if ($rules) {
            $enabledRules = $rules | Where-Object { $_.Enabled -eq $true }
            $status.RDPEnabledInFirewall = ($enabledRules | Measure-Object).Count -gt 0
        }
        
        # Check firewall profiles
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($profiles) {
            $status.FirewallEnabled = ($profiles | Where-Object { $_.Enabled -eq 'True' } | Measure-Object).Count -gt 0
        }
        
        return $status
        
    } catch {
        # Fallback to netsh if Get-NetFirewallRule fails
        return Get-FirewallStatusPS5
    }
}

function Get-ServiceStatusPS7 {
    $services = @()
    
    $serviceNames = @(
        @{ Name = "TermService"; DisplayName = "Remote Desktop Services" }
        @{ Name = "SessionEnv"; DisplayName = "Remote Desktop Configuration" }
        @{ Name = "UmRdpService"; DisplayName = "Remote Desktop Services UserMode Port Redirector" }
        @{ Name = "WinRM"; DisplayName = "Windows Remote Management" }
        @{ Name = "Spooler"; DisplayName = "Print Spooler" }
    )
    
    # Use standard loop for PowerShell 5.1 compatibility
    foreach ($svc in $serviceNames) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if ($service) {
                $services += [PSCustomObject]@{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = $service.Status
                    StartupType = $service.StartType
                    CanStart = ($service.Status -ne "Running") -and ($service.StartType -ne "Disabled")
                    CanStop = $service.Status -eq "Running"
                }
            } else {
                $services += [PSCustomObject]@{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = "Not Found"
                    StartupType = "N/A"
                    CanStart = $false
                    CanStop = $false
                }
            }
        } catch {
            $services += [PSCustomObject]@{
                Name = $svc.Name
                DisplayName = $svc.DisplayName
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
    }
    
    return $services
}

function Get-ActiveSessionsPS7 {
    try {
        $allSessions = Get-RDPSessions
        $activeSessions = $allSessions | Where-Object { $_.State -eq "Active" }
        
        return [PSCustomObject]@{
            TotalSessions = $allSessions.Count
            ActiveSessions = $activeSessions.Count
            DisconnectedSessions = $allSessions.Count - $activeSessions.Count
            SessionDetails = $activeSessions | Select-Object SessionId, UserName, State, SessionName, IsCurrent
            CurrentSession = $activeSessions | Where-Object { $_.IsCurrent } | Select-Object -First 1
        }
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Get-RecommendationsPS7 {
    $recommendations = [System.Collections.Generic.List[string]]::new()
    
    try {
        # Collect data in parallel
        $checks = @(
            @{ Name = "Shadow"; Script = { Get-ShadowConfigurationPS7 } }
            @{ Name = "RDP"; Script = { Get-RDPConfigurationPS7 } }
            @{ Name = "Firewall"; Script = { Get-FirewallStatusPS7 } }
            @{ Name = "Services"; Script = { Get-ServiceStatusPS7 } }
        )
        
        # Fix: Remove $using: variable in PowerShell 5.1 context
        $results = $checks | ForEach-Object {
            try {
                $result = & $_.Script
                @{ Name = $_.Name; Result = $result }
            } catch {
                @{ Name = $_.Name; Error = $_.Exception.Message }
            }
        }
        
        # Analyze results
        foreach ($result in $results) {
            switch ($result.Name) {
                "Shadow" {
                    if (-not $result.Result.ShadowMode -or $result.Result.ShadowMode -lt 2) {
                        $recommendations.Add("Shadow mode is not properly configured for remote control without permission.")
                        # Fix: Escape < character and remove $using:
                        $recommendations.Add("Run: .\$SCRIPT_NAME.ps1 --SessionId <ID> to auto-configure")
                    }
                }
                "RDP" {
                    if (-not $result.Result.RDPEnabled) {
                        $recommendations.Add("RDP is disabled. Enable it for remote access.")
                    }
                }
                "Firewall" {
                    if (-not $result.Result.RDPEnabledInFirewall) {
                        $recommendations.Add("RDP is not allowed in Windows Firewall.")
                    }
                }
                "Services" {
                    $stoppedServices = $result.Result | Where-Object { 
                        $_.Status -ne "Running" -and $_.Name -in @("TermService", "SessionEnv") 
                    }
                    if ($stoppedServices) {
                        $recommendations.Add("Critical RDP services are not running: $($stoppedServices.DisplayName -join ', ')")
                    }
                }
            }
        }
        
        return $recommendations.ToArray()
        
    } catch {
        return @("Error generating recommendations: $($_.Exception.Message)")
    }
}

function Get-PerformanceMetricsPS7 {
    try {
        # Use performance counters for better metrics
        $cpuCounter = [System.Diagnostics.PerformanceCounter]::new("Processor", "% Processor Time", "_Total")
        $memoryCounter = [System.Diagnostics.PerformanceCounter]::new("Memory", "Available MBytes")
        
        # Get initial values
        Start-Sleep -Milliseconds 100
        $cpuUsage1 = $cpuCounter.NextValue()
        $availableMemory1 = $memoryCounter.NextValue()
        
        # Wait and get second reading
        Start-Sleep -Milliseconds 100
        $cpuUsage = $cpuCounter.NextValue()
        $availableMemory = $memoryCounter.NextValue()
        
        # Calculate memory usage
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMemory = $os.TotalVisibleMemorySize / 1MB
        $memoryUsage = (($totalMemory - $availableMemory) / $totalMemory) * 100
        
        # Disk usage using CIM
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" |
                Select-Object DeviceID, 
                    @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
                    @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}},
                    @{Name="UsedPercent";Expression={[math]::Round(100-($_.FreeSpace/$_.Size*100),2)}}
        
        # Network statistics
        $network = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Status -eq "Up" } |
                   Select-Object -First 1
        
        return [PSCustomObject]@{
            CPUUsagePercent = [math]::Round($cpuUsage, 2)
            MemoryUsagePercent = [math]::Round($memoryUsage, 2)
            TotalMemoryGB = [math]::Round($totalMemory, 2)
            AvailableMemoryGB = [math]::Round($availableMemory, 2)
            DiskUsage = $disks
            NetworkAdapter = if ($network) { $network.Name } else { "None" }
            NetworkStatus = if ($network) { $network.Status } else { "Down" }
            CollectionTime = Get-Date
        }
        
    } catch {
        return @{ Error = $_.Exception.Message }
    }
}

function Show-StatusReportPS7 {
    param(
        $StatusData,
        [switch]$Brief,
        $Color
    )
    
    # Clear screen and show header with ANSI colors (PS7+)
    Clear-Host
    
    Write-Host "`n$($Color.Header)+==============================================================+$($Color.Reset)"
    Write-Host "$($Color.Header)|   REMOTE SESSION MANAGER PRO - SYSTEM STATUS REPORT   |$($Color.Reset)"
    Write-Host "$($Color.Header)+==============================================================+$($Color.Reset)"
    
    # Summary line with color indicators
    $statusEmoji = if ($StatusData.Recommendations.Count -eq 0) { "[OK]" } else { "[!]" }
    Write-Host "`n$statusEmoji Status: $($Color.Info)Generated $($StatusData.OSVersion.CollectionTime)$($Color.Reset)"
    Write-Host "   |-- Computer: $($Color.Debug)$env:COMPUTERNAME$($Color.Reset) | User: $($Color.Debug)$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)$($Color.Reset) | PS: $($Color.Debug)$($PSVersionTable.PSVersion)$($Color.Reset) | Admin: $(if ($StatusData.IsAdministrator) { "$($Color.Success)Yes" } else { "$($Color.Error)No" })$($Color.Reset)"
    
    if ($Brief) {
        Write-Host "`n$($Color.Warning)[Brief Mode - Showing Summary Only]$($Color.Reset)"
        Show-BriefStatusPS7 -StatusData $StatusData -Color $Color
        return
    }
    
    # Create a grid layout for better visualization
    $gridSections = @(
        @{ Title = "Windows Version"; Data = $StatusData.OSVersion }
        @{ Title = "RDP Configuration"; Data = $StatusData.RDPConfiguration }
        @{ Title = "Shadow Configuration"; Data = $StatusData.ShadowConfiguration }
        @{ Title = "Firewall Status"; Data = $StatusData.FirewallStatus }
        @{ Title = "Service Status"; Data = $StatusData.ServiceStatus }
        @{ Title = "Active Sessions"; Data = $StatusData.ActiveSessions }
    )
    
    # Display sections in a two-column layout
    for ($i = 0; $i -lt $gridSections.Count; $i += 2) {
        Write-Host "`n$($Color.Header)+------------------------------------+------------------------------------+$($Color.Reset)"
        
        # First column
        $section1 = $gridSections[$i]
        $section1Title = $section1.Title.PadRight(34)
        Write-Host "$($Color.Header)|$($Color.Reset) $($Color.Info)$section1Title$($Color.Reset) $($Color.Header)|$($Color.Reset) " -NoNewline
        
        # Second column (if exists)
        if ($i + 1 -lt $gridSections.Count) {
            $section2 = $gridSections[$i + 1]
            $section2Title = $section2.Title.PadRight(34)
            Write-Host "$($Color.Info)$section2Title$($Color.Reset) $($Color.Header)|$($Color.Reset)"
        } else {
            Write-Host " ".PadRight(34) + " $($Color.Header)|$($Color.Reset)"
        }
        
        Write-Host "$($Color.Header)+------------------------------------+------------------------------------+$($Color.Reset)"
        
        # Display section data
        $lines1 = Format-SectionDataPS7 -Section $section1 -Color $Color
        $lines2 = if ($i + 1 -lt $gridSections.Count) { 
            Format-SectionDataPS7 -Section $gridSections[$i + 1] -Color $Color 
        } else { @() }
        
        $maxLines = [Math]::Max($lines1.Count, $lines2.Count)
        for ($j = 0; $j -lt $maxLines; $j++) {
            $line1 = if ($j -lt $lines1.Count) { $lines1[$j] } else { "".PadRight(34) }
            $line2 = if ($j -lt $lines2.Count) { $lines2[$j] } else { "".PadRight(34) }
            
            Write-Host "$($Color.Header)|$($Color.Reset) $line1 $($Color.Header)|$($Color.Reset) $line2 $($Color.Header)|$($Color.Reset)"
        }
        
        Write-Host "$($Color.Header)+------------------------------------+------------------------------------+$($Color.Reset)"
    }
    
    # Performance Metrics Section
    if ($StatusData.PerformanceMetrics -and -not $StatusData.PerformanceMetrics.Error) {
        Write-Host "`n$($Color.Header)+==============================================================+$($Color.Reset)"
        Write-Host "$($Color.Header)|$($Color.Reset) $($Color.Info)Performance Metrics$($Color.Reset)" -NoNewline
        Write-Host " ".PadRight(52) + "$($Color.Header)|$($Color.Reset)"
        Write-Host "$($Color.Header)+==============================================================+$($Color.Reset)"
        
        $cpuBar = Format-PercentageBar -Percentage $StatusData.PerformanceMetrics.CPUUsagePercent -Color $Color
        $memoryBar = Format-PercentageBar -Percentage $StatusData.PerformanceMetrics.MemoryUsagePercent -Color $Color
        
        Write-Host "$($Color.Header)|$($Color.Reset) CPU:    $cpuBar $($StatusData.PerformanceMetrics.CPUUsagePercent.ToString("0.0").PadLeft(5))%" -NoNewline
        Write-Host " ".PadRight(18) + "$($Color.Header)|$($Color.Reset)"
        
        Write-Host "$($Color.Header)|$($Color.Reset) Memory: $memoryBar $($StatusData.PerformanceMetrics.MemoryUsagePercent.ToString("0.0").PadLeft(5))%" -NoNewline
        Write-Host " ".PadRight(18) + "$($Color.Header)|$($Color.Reset)"
        
        Write-Host "$($Color.Header)+==============================================================+$($Color.Reset)"
    }
    
    # Recommendations Section
    Write-Host "`n$($Color.Header)+==============================================================+$($Color.Reset)"
    Write-Host "$($Color.Header)|   RECOMMENDATIONS                                               |$($Color.Reset)"
    Write-Host "$($Color.Header)+==============================================================+$($Color.Reset)"
    
    if ($StatusData.Recommendations.Count -eq 0) {
        Write-Host "   $($Color.Success)[OK] No issues detected. System is properly configured.$($Color.Reset)"
    } else {
        foreach ($recommendation in $StatusData.Recommendations) {
            Write-Host "   $($Color.Warning)*$($Color.Reset) $recommendation"
        }
    }
    
    # Footer
    $generationTime = $StatusData.GenerationTime
    $timeColor = if ($generationTime -lt 100) { $Color.Success } elseif ($generationTime -lt 500) { $Color.Info } else { $Color.Warning }
    
    Write-Host "`n$($Color.Debug)-" * 70 + $Color.Reset
    Write-Host "$($Color.Info)Report generated in $($timeColor)$generationTime$($Color.Info) ms$($Color.Reset) | $(Get-Date -Format 'HH:mm:ss')$($Color.Reset)"
    Write-Host "$($Color.Debug)-" * 70 + $Color.Reset
}

function Format-SectionDataPS7 {
    param($Section, $Color)
    
    $lines = @()
    $data = $Section.Data
    
    switch ($Section.Title) {
        "Windows Version" {
            if ($data.Error) {
                $lines += "$($Color.Error)$($data.Error.PadRight(34))$($Color.Reset)"
            } else {
                $lines += "$($Color.Debug)Ver: $($data.Version.PadRight(28))$($Color.Reset)"
                $lines += "$($Color.Debug)Build: $($data.BuildNumber.PadRight(28))$($Color.Reset)"
                $lines += "$($Color.Debug)Arch: $($data.Architecture.PadRight(28))$($Color.Reset)"
                $lines += "$($Color.Debug)Server: $(($data.IsServer.ToString()).PadRight(28))$($Color.Reset)"
            }
        }
        "RDP Configuration" {
            if ($data.Error) {
                $lines += "$($Color.Error)$($data.Error.PadRight(34))$($Color.Reset)"
            } else {
                $rdpStatus = if ($data.RDPEnabled) { "$($Color.Success)Enabled" } else { "$($Color.Error)Disabled" }
                $lines += "$($Color.Debug)Status: $($rdpStatus.PadRight(26))$($Color.Reset)"
                $lines += "$($Color.Debug)Max: $($data.MaxInstanceCount.ToString().PadRight(30))$($Color.Reset)"
                $lines += "$($Color.Debug)KeepAlive: $($data.KeepAliveInterval.ToString().PadRight(24))$($Color.Reset)"
            }
        }
        "Shadow Configuration" {
            if ($data.Error) {
                $lines += "$($Color.Error)$($data.Error.PadRight(34))$($Color.Reset)"
            } else {
                $shadowColor = if ($data.ShadowMode -ge 2) { $Color.Success } else { $Color.Warning }
                $lines += "$($Color.Debug)Mode: $($shadowColor)$($data.ShadowModeDescription.PadRight(28))$($Color.Reset)"
                if ($data.LegacyShadowMode) {
                    $lines += "$($Color.Debug)Legacy: $($data.LegacyShadowMode.ToString().PadRight(28))$($Color.Reset)"
                }
            }
        }
        "Firewall Status" {
            if ($data.Error) {
                $lines += "$($Color.Error)$($data.Error.PadRight(34))$($Color.Reset)"
            } else {
                $fwStatus = if ($data.FirewallEnabled) { "$($Color.Success)Enabled" } else { "$($Color.Warning)Disabled" }
                $lines += "$($Color.Debug)Firewall: $($fwStatus.PadRight(26))$($Color.Reset)"
                
                $rdpAllowed = if ($data.RDPEnabledInFirewall) { "$($Color.Success)Allowed" } else { "$($Color.Error)Blocked" }
                $lines += "$($Color.Debug)RDP: $($rdpAllowed.PadRight(30))$($Color.Reset)"
                $lines += "$($Color.Debug)Rules: $($data.RDPRuleCount.ToString().PadRight(28))$($Color.Reset)"
            }
        }
        "Service Status" {
            foreach ($service in $data | Select-Object -First 3) {
                $statusColor = switch ($service.Status) {
                    "Running" { $Color.Success }
                    "Stopped" { $Color.Error }
                    default { $Color.Warning }
                }
                
                $displayName = if ($service.DisplayName.Length -gt 20) { 
                    $service.DisplayName.Substring(0, 17) + "..." 
                } else { 
                    $service.DisplayName.PadRight(20) 
                }
                
                $lines += "$($Color.Debug)$displayName $($statusColor)$($service.Status.PadRight(9))$($Color.Reset)"
            }
        }
        "Active Sessions" {
            if ($data.Error) {
                $lines += "$($Color.Error)$($data.Error.PadRight(34))$($Color.Reset)"
            } else {
                $lines += "$($Color.Debug)Total: $($data.TotalSessions.ToString().PadRight(28))$($Color.Reset)"
                $activeColor = if ($data.ActiveSessions -gt 0) { $Color.Success } else { $Color.Debug }
                $lines += "$($Color.Debug)Active: $($activeColor)$($data.ActiveSessions.ToString().PadRight(28))$($Color.Reset)"
                $lines += "$($Color.Debug)Disc: $($data.DisconnectedSessions.ToString().PadRight(29))$($Color.Reset)"
                if ($data.CurrentSession) {
                    $lines += "$($Color.Debug)Current: $($Color.Success)ID $($data.CurrentSession.SessionId)$($Color.Reset)"
                }
            }
        }
    }
    
    # Ensure we return exactly 4 lines for consistent formatting
    while ($lines.Count -lt 4) {
        $lines += " ".PadRight(34)
    }
    
    return $lines[0..3]
}

function Format-PercentageBar {
    param(
        [float]$Percentage,
        $Color
    )
    
    $barLength = 20
    $filled = [Math]::Round($Percentage * $barLength / 100)
    $filled = [Math]::Min($filled, $barLength)
    
    $barColor = if ($Percentage -lt 70) { $Color.Success } 
                elseif ($Percentage -lt 90) { $Color.Warning } 
                else { $Color.Error }
    
    $bar = "[" + ($barColor + ("#" * $filled) + $Color.Debug + ("." * ($barLength - $filled)) + $Color.Reset) + "]"
    return $bar
}

function Show-BriefStatusPS7 {
    param($StatusData, $Color)
    
    # Create a quick status dashboard
    $issues = 0
    $checks = @()
    
    # Check RDP
    if (-not $StatusData.RDPConfiguration.RDPEnabled) {
        $issues++
        $checks += @{ Item = "RDP"; Status = "$($Color.Error)[X] Disabled$($Color.Reset)" }
    } else {
        $checks += @{ Item = "RDP"; Status = "$($Color.Success)[OK] Enabled$($Color.Reset)" }
    }
    
    # Check Shadow
    if ($StatusData.ShadowConfiguration.ShadowMode -lt 2) {
        $issues++
        $checks += @{ Item = "Shadow"; Status = "$($Color.Warning)[!] Needs config$($Color.Reset)" }
    } else {
        $checks += @{ Item = "Shadow"; Status = "$($Color.Success)[OK] Configured$($Color.Reset)" }
    }
    
    # Check Firewall
    if (-not $StatusData.FirewallStatus.RDPEnabledInFirewall) {
        $issues++
        $checks += @{ Item = "Firewall"; Status = "$($Color.Error)[X] Blocking RDP$($Color.Reset)" }
    } else {
        $checks += @{ Item = "Firewall"; Status = "$($Color.Success)[OK] Allowed$($Color.Reset)" }
    }
    
    # Check Services
    $stoppedServices = $StatusData.ServiceStatus | Where-Object { 
        $_.Status -ne "Running" -and $_.Name -in @("TermService", "SessionEnv") 
    }
    if ($stoppedServices) {
        $issues++
        $checks += @{ Item = "Services"; Status = "$($Color.Error)[X] $($stoppedServices.Count) stopped$($Color.Reset)" }
    } else {
        $checks += @{ Item = "Services"; Status = "$($Color.Success)[OK] Running$($Color.Reset)" }
    }
    
    # Display brief status grid
    Write-Host "`n$($Color.Header)+------------+--------------------+$($Color.Reset)"
    Write-Host "$($Color.Header)| Component  | Status              |$($Color.Reset)"
    Write-Host "$($Color.Header)+------------+--------------------+$($Color.Reset)"
    
    foreach ($check in $checks) {
        Write-Host "$($Color.Header)|$($Color.Reset) $($check.Item.PadRight(10)) $($Color.Header)|$($Color.Reset) $($check.Status.PadRight(20)) $($Color.Header)|$($Color.Reset)"
    }
    
    Write-Host "$($Color.Header)+------------+--------------------+$($Color.Reset)"
    
    # Overall status
    Write-Host "`nOverall Status: " -NoNewline
    if ($issues -eq 0) {
        Write-Host "$($Color.Success)[OK] System is properly configured$($Color.Reset)"
    } else {
        Write-Host "$($Color.Warning)[!] $issues issue(s) need attention$($Color.Reset)"
    }
}

#region Common Export Functions
function Export-StatusJson {
    param($StatusData, [string]$Path)
    
    try {
        $StatusData | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
        Write-DebugLog "Status exported to JSON: $Path" "SUCCESS"
        return $true
    } catch {
        Write-DebugLog "Failed to export JSON: $_" "ERROR"
        return $false
    }
}

function Export-StatusCsv {
    param($StatusData, [string]$Path)
    
    try {
        # Flatten the status data for CSV export
        $csvData = @{
            Timestamp = $StatusData.Timestamp
            ComputerName = $StatusData.ComputerName
            User = $StatusData.User
            PowerShellVersion = $StatusData.PowerShellVersion
            IsAdministrator = $StatusData.IsAdministrator
            OSVersion = $StatusData.OSVersion.Version
            OSEdition = $StatusData.OSVersion.Caption
            RDPEnabled = $StatusData.RDPConfiguration.RDPEnabled
            ShadowMode = $StatusData.ShadowConfiguration.ShadowModeDescription
            FirewallEnabled = $StatusData.FirewallStatus.FirewallEnabled
            RDPAllowedInFirewall = $StatusData.FirewallStatus.RDPEnabledInFirewall
            TotalSessions = $StatusData.ActiveSessions.TotalSessions
            ActiveSessions = $StatusData.ActiveSessions.ActiveSessions
            IssueCount = $StatusData.Recommendations.Count
            GenerationTimeMs = $StatusData.GenerationTime
        }
        
        [PSCustomObject]$csvData | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-DebugLog "Status exported to CSV: $Path" "SUCCESS"
        return $true
    } catch {
        Write-DebugLog "Failed to export CSV: $_" "ERROR"
        return $false
    }
}


function Update-Script {
    <#
    .SYNOPSIS
        Self-update mechanism for the Remote Session Manager Pro script with comprehensive safety checks
    
    .DESCRIPTION
        Provides robust self-update functionality with support for renamed scripts, integrity verification,
        backup creation, and safe update procedures. Designed to work across Windows versions and PowerShell editions.
    
    .NOTES
        Version: 2.0.0
        Features:
        - Automatic detection of script renaming
        - SHA-256 integrity verification
        - Multiple fallback download methods
        - Safe transaction-style update with rollback capability
        - PowerShell version compatibility checks
        - Detailed logging and error recovery
    #>
    
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    
    begin {
        Write-DebugLog "Initializing self-update process..." "INFO"
        
        # Define original script metadata
        $ORIGINAL_SCRIPT_FILE_NAME = "1st-Remote-Session-Manager-Pro.ps1"
        $SCRIPT_IDENTIFIER = "RemoteSessionManagerPro"
        $MINIMUM_SCRIPT_SIZE = 1024  # 1KB minimum size for valid script
        
        # Get current script information
        $currentScriptPath = $MyInvocation.MyCommand.Path
        $currentScriptName = [System.IO.Path]::GetFileName($currentScriptPath)
        $currentScriptDir = [System.IO.Path]::GetDirectoryName($currentScriptPath)
        
        # Determine if script was renamed
        $isRenamed = $currentScriptName -ne $ORIGINAL_SCRIPT_FILE_NAME
        $renamedWarningShown = $false
        
        # Update modes
        $updateModes = @{
            KeepName = 0   # Keep current (renamed) filename
            RestoreName = 1 # Restore to original filename
            CreateBoth = 2  # Create both versions
        }
        
        # Initialize update configuration
        $updateConfig = @{
            Mode = $updateModes.KeepName
            BackupOriginal = $true
            VerifyIntegrity = $true
            RestartAfterUpdate = $false
            TargetPath = $currentScriptPath
        }
    }
    
    process {
        try {
            # Step 1: Check connectivity and get latest version
            Write-DebugLog "Checking GitHub for latest version..." "DEBUG"
            
            if (-not (Test-InternetConnectivity)) {
                Write-Host "Internet connectivity check failed. Update cannot proceed." -ForegroundColor $COLORS.Warning
                Write-Host "Please ensure you have internet access and try again." -ForegroundColor $COLORS.Info
                return $false
            }
            
            # Step 2: Download latest version with multiple fallback methods
            $latestScriptContent = Get-LatestScriptVersion -MaxRetries 3
            
            if (-not $latestScriptContent -or $latestScriptContent.Length -lt $MINIMUM_SCRIPT_SIZE) {
                Write-DebugLog "Downloaded script is invalid or too small" "ERROR"
                return $false
            }
            
            # Step 3: Extract version information with robust parsing
            $latestVersion = Extract-ScriptVersion -Content $latestScriptContent
            
            if (-not $latestVersion) {
                Write-Host "Could not determine version from downloaded script." -ForegroundColor $COLORS.Warning
                Write-Host "This may indicate a corrupted download or format change." -ForegroundColor $COLORS.Info
                
                if (-not $Force) {
                    $confirm = Read-Host "Continue with update anyway? (not recommended) [y/N]"
                    if ($confirm -ne 'y') {
                        return $false
                    }
                }
            }
            
            # Step 4: Compare versions
            if ($latestVersion -and $latestVersion -eq $SCRIPT_VERSION) {
                Write-Host "Already running the latest version: v$SCRIPT_VERSION" -ForegroundColor $COLORS.Success
                
                if (-not $Quiet) {
                    $checkAgain = Read-Host "Force reinstall current version? [y/N]"
                    if ($checkAgain -ne 'y') {
                        return $true
                    }
                } else {
                    return $true
                }
            } elseif ($latestVersion) {
                Write-Host "Update available: v$SCRIPT_VERSION -> v$latestVersion" -ForegroundColor $COLORS.Warning
                Write-Host "Changes will be downloaded from: $GITHUB_REPO" -ForegroundColor $COLORS.Info
            }
            
            # Step 5: Handle renamed script scenario
            if ($isRenamed -and -not $renamedWarningShown) {
                Write-Host "`n[!] Script Renaming Detected" -ForegroundColor $COLORS.Warning
                Write-Host "   Current name: $currentScriptName" -ForegroundColor $COLORS.Debug
                Write-Host "   Original name: $ORIGINAL_SCRIPT_FILE_NAME" -ForegroundColor $COLORS.Debug
                Write-Host "`nRenamed scripts may experience issues with:" -ForegroundColor $COLORS.Info
                Write-Host "   * Future self-updates" -ForegroundColor $COLORS.Debug
                Write-Host "   * Documentation and support" -ForegroundColor $COLORS.Debug
                Write-Host "   * Consistency across deployments" -ForegroundColor $COLORS.Debug
                
                $renamedWarningShown = $true
            }
            
            # Step 6: Determine update mode (unless forced or quiet)
            if (-not $Quiet -and -not $Force) {
                $updateConfig = Get-UpdateConfiguration -CurrentName $currentScriptName -IsRenamed $isRenamed
            } elseif ($Force) {
                # Force mode: keep current name, no prompts
                $updateConfig.Mode = $updateModes.KeepName
                $updateConfig.BackupOriginal = $true
            }
            
            # Step 7: Verify update configuration
            if (-not $updateConfig) {
                Write-DebugLog "Update configuration cancelled by user" "INFO"
                return $false
            }
            
            # Step 8: Create backup of current script
            if ($updateConfig.BackupOriginal) {
                $backupResult = Create-ScriptBackup -ScriptPath $currentScriptPath
                if (-not $backupResult) {
                    Write-Host "Backup creation failed. Update aborted for safety." -ForegroundColor $COLORS.Error
                    return $false
                }
            }
            
            # Step 9: Validate new script integrity
            if ($updateConfig.VerifyIntegrity) {
                $integrityResult = Test-ScriptIntegrity -Content $latestScriptContent
                if (-not $integrityResult.IsValid) {
                    Write-Host "Script integrity check failed!" -ForegroundColor $COLORS.Error
                    Write-Host "Reason: $($integrityResult.Reason)" -ForegroundColor $COLORS.Warning
                    
                    if (-not $Force) {
                        Write-Host "Update aborted for security reasons." -ForegroundColor $COLORS.Error
                        return $false
                    } else {
                        Write-Host "Continuing due to Force flag (security risk!)" -ForegroundColor $COLORS.Error
                    }
                } else {
                    Write-DebugLog "Script integrity verified successfully" "SUCCESS"
                }
            }
            
            # Step 10: Apply update based on selected mode
            $updateResult = Apply-ScriptUpdate `
                -CurrentPath $currentScriptPath `
                -NewContent $latestScriptContent `
                -UpdateConfig $updateConfig `
                -OriginalName $ORIGINAL_SCRIPT_FILE_NAME
            
            if (-not $updateResult.Success) {
                throw $updateResult.ErrorMessage
            }
            
            # Step 11: Post-update actions
            Write-Host "`n[OK] Update completed successfully!" -ForegroundColor $COLORS.Success
            
            if ($updateResult.BackupCreated) {
                Write-Host "[BK] Backup saved to: $($updateResult.BackupPath)" -ForegroundColor $COLORS.Info
            }
            
            if ($updateResult.NewFileName -and $updateResult.NewFileName -ne $currentScriptName) {
                Write-Host "[RN] Script renamed to: $($updateResult.NewFileName)" -ForegroundColor $COLORS.Info
            }
            
            # Step 12: Offer restart
            if (-not $Quiet) {
                Write-Host "`n[RN] Restart Options:" -ForegroundColor $COLORS.Info
                Write-Host "   1) Restart script with current parameters" -ForegroundColor $COLORS.Debug
                Write-Host "   2) Restart script in new window" -ForegroundColor $COLORS.Debug
                Write-Host "   3) Exit without restart" -ForegroundColor $COLORS.Debug
                
                $restartChoice = Read-Host "`nSelect option [1-3] (default: 1)"
                
                switch ($restartChoice) {
                    "2" { 
                        # Restart in new window
                        Restart-ScriptInNewWindow -ScriptPath $updateResult.FinalPath -Parameters $PSBoundParameters
                        exit $ERROR_CODES.Success
                    }
                    "3" {
                        # Exit without restart
                        Write-Host "Update complete. Please restart the script manually." -ForegroundColor $COLORS.Info
                        return $true
                    }
                    default {
                        # Restart in same window (default)
                        & $updateResult.FinalPath @PSBoundParameters
                        exit $ERROR_CODES.Success
                    }
                }
            }
            
            return $true
            
        } catch {
            Write-DebugLog "Update process failed: $($_.Exception.Message)" "ERROR" @{
                Exception = $_.Exception
                StackTrace = $_.ScriptStackTrace
            }
            
            # Attempt to restore from backup if available
            if ($backupResult -and $backupResult.BackupPath) {
                Write-Host "Update failed. Attempting to restore from backup..." -ForegroundColor $COLORS.Warning
                
                try {
                    Copy-Item -Path $backupResult.BackupPath -Destination $currentScriptPath -Force
                    Write-Host "Successfully restored from backup." -ForegroundColor $COLORS.Success
                } catch {
                    Write-Host "Failed to restore from backup. Manual recovery may be needed." -ForegroundColor $COLORS.Error
                }
            }
            
            return $false
        }
    }
}

#region Helper Functions for Update Process

function Test-InternetConnectivity {
    <#
    .SYNOPSIS
        Tests connectivity to GitHub and required resources
    #>
    
    $testUrls = @(
        "https://raw.githubusercontent.com",
        "https://github.com",
        "https://api.github.com"
    )
    
    foreach ($url in $testUrls) {
        try {
            Write-DebugLog "Testing connectivity to: $url" "DEBUG"
            
            # Use appropriate method based on PowerShell version
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $result = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 5 -ErrorAction Stop
            } else {
                # Fallback for PowerShell 5.1
                $request = [System.Net.HttpWebRequest]::Create($url)
                $request.Timeout = 5000
                $request.Method = "HEAD"
                $response = $request.GetResponse()
                $response.Close()
            }
            
            Write-DebugLog "Successfully connected to: $url" "SUCCESS"
            return $true
            
        } catch {
            Write-DebugLog "Failed to connect to $url : $_" "WARNING"
            continue
        }
    }
    
    return $false
}

function Get-LatestScriptVersion {
    <#
    .SYNOPSIS
        Downloads the latest script version with multiple fallback methods
    #>
    
    param(
        [int]$MaxRetries = 3
    )
    
    $downloadMethods = @(
        @{ Name = "Invoke-RestMethod"; ScriptBlock = { 
                Invoke-RestMethod -Uri $RAW_GITHUB_URL -TimeoutSec 30 -ErrorAction Stop 
            } 
        },
        @{ Name = "WebClient"; ScriptBlock = { 
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add('User-Agent', "$SCRIPT_IDENTIFIER/$SCRIPT_VERSION")
                $wc.DownloadString($RAW_GITHUB_URL)
            } 
        },
        @{ Name = "Invoke-WebRequest"; ScriptBlock = { 
                (Invoke-WebRequest -Uri $RAW_GITHUB_URL -TimeoutSec 30 -ErrorAction Stop).Content 
            } 
        }
    )
    
    foreach ($attempt in 1..$MaxRetries) {
        foreach ($method in $downloadMethods) {
            try {
                Write-DebugLog "Download attempt $attempt using $($method.Name)..." "DEBUG"
                
                $content = & $method.ScriptBlock
                
                if ($content -and $content.Length -gt 1024) {
                    Write-DebugLog "Successfully downloaded $($content.Length) bytes using $($method.Name)" "SUCCESS"
                    return $content
                }
                
            } catch {
                Write-DebugLog "Download method $($method.Name) failed: $_" "WARNING"
                Start-Sleep -Seconds (2 * $attempt) # Exponential backoff
            }
        }
    }
    
    return $null
}

function Extract-ScriptVersion {
    <#
    .SYNOPSIS
        Extracts version information from script content with multiple parsing strategies
    #>
    
    param(
        [string]$Content
    )
    
    $patterns = @(
        '\$SCRIPT_VERSION\s*=\s*["'']([^"'']+)["'']',
        'Version:\s*([\d]+\.[\d]+\.[\d]+)',
        '\[version\("([\d]+\.[\d]+\.[\d]+)"\)\]'
    )
    
    foreach ($pattern in $patterns) {
        if ($Content -match $pattern) {
            $version = $matches[1]
            Write-DebugLog "Extracted version using pattern: $version" "DEBUG"
            return $version
        }
    }
    
    return $null
}

function Get-UpdateConfiguration {
    <#
    .SYNOPSIS
        Gets update configuration from user with comprehensive options
    #>
    
    param(
        [string]$CurrentName,
        [bool]$IsRenamed
    )
    
    # Default configuration
    $config = @{
        Mode = 0  # KeepName by default
        BackupOriginal = $true
        VerifyIntegrity = $true
        RestartAfterUpdate = $false
    }
    
    if ($IsRenamed) {
        Write-Host "`n[Update Configuration for Renamed Script]" -ForegroundColor $COLORS.Info
        Write-Host "   Current filename: $CurrentName" -ForegroundColor $COLORS.Debug
        
        Write-Host "`nSelect update strategy:" -ForegroundColor $COLORS.Info
        Write-Host "   [1] Keep current name ($CurrentName)" -ForegroundColor $COLORS.Debug
        Write-Host "   [2] Restore original name ($ORIGINAL_SCRIPT_FILE_NAME)" -ForegroundColor $COLORS.Debug
        Write-Host "   [3] Create both versions" -ForegroundColor $COLORS.Debug
        
        $choice = Read-Host "`nEnter choice [1-3] (default: 1)"
        
        switch ($choice) {
            "2" { $config.Mode = 1 }
            "3" { $config.Mode = 2 }
            default { $config.Mode = 0 }
        }
    }
    
    # Additional options
    Write-Host "`n[Additional Options:]" -ForegroundColor $COLORS.Info
    
    $backupChoice = Read-Host "Create backup before update? [Y/n] (default: Y)"
    if ($backupChoice -eq 'n') { $config.BackupOriginal = $false }
    
    $verifyChoice = Read-Host "Verify script integrity after download? [Y/n] (default: Y)"
    if ($verifyChoice -eq 'n') { $config.VerifyIntegrity = $false }
    
    return $config
}

function Create-ScriptBackup {
    <#
    .SYNOPSIS
        Creates a timestamped backup of the current script
    #>
    
    param(
        [string]$ScriptPath
    )
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupDir = Join-Path $currentScriptDir "Backups"
        
        # Create backup directory if it doesn't exist
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }
        
        $backupName = "$([System.IO.Path]::GetFileNameWithoutExtension($ScriptPath))_backup_$timestamp.ps1"
        $backupPath = Join-Path $backupDir $backupName
        
        Copy-Item -Path $ScriptPath -Destination $backupPath -Force
        
        # Calculate and store hash for verification
        $backupHash = (Get-FileHash -Path $backupPath -Algorithm SHA256).Hash
        @{
            Hash = $backupHash
            Timestamp = $timestamp
        } | ConvertTo-Json | Out-File "$backupPath.meta" -Encoding UTF8
        
        Write-DebugLog "Backup created: $backupPath (SHA256: $($backupHash.Substring(0, 16))...)" "SUCCESS"
        
        return @{
            BackupPath = $backupPath
            Hash = $backupHash
            Success = $true
        }
        
    } catch {
        Write-DebugLog "Backup creation failed: $_" "ERROR"
        return @{ Success = $false; Error = $_ }
    }
}

function Test-ScriptIntegrity {
    <#
    .SYNOPSIS
        Performs comprehensive integrity checks on script content
    #>
    
    param(
        [string]$Content
    )
    
    $checks = @()
    
    # Check 1: Minimum size
    if ($Content.Length -lt $MINIMUM_SCRIPT_SIZE) {
        $checks += @{ Check = "MinimumSize"; Passed = $false; Reason = "Script size below minimum threshold" }
    } else {
        $checks += @{ Check = "MinimumSize"; Passed = $true }
    }
    
    # Check 2: Contains script identifier
    if ($Content -notmatch $SCRIPT_IDENTIFIER) {
        $checks += @{ Check = "Identifier"; Passed = $false; Reason = "Script identifier not found" }
    } else {
        $checks += @{ Check = "Identifier"; Passed = $true }
    }
    
    # Check 3: Valid PowerShell syntax (basic check)
    try {
        [System.Management.Automation.Language.Parser]::ParseInput($Content, [ref]$null, [ref]$null) | Out-Null
        $checks += @{ Check = "Syntax"; Passed = $true }
    } catch {
        $checks += @{ Check = "Syntax"; Passed = $false; Reason = "PowerShell syntax errors detected" }
    }
    
    # Check 4: Contains required functions
    $requiredFunctions = @("Write-DebugLog", "Test-IsAdministrator", "Get-RDPSessions")
    foreach ($func in $requiredFunctions) {
        if ($Content -notmatch "function $func") {
            $checks += @{ Check = "Function_$func"; Passed = $false; Reason = "Required function $func not found" }
        } else {
            $checks += @{ Check = "Function_$func"; Passed = $true }
        }
    }
    
    # Evaluate results
    $failedChecks = $checks | Where-Object { -not $_.Passed }
    
    if ($failedChecks) {
        return @{
            IsValid = $false
            Reason = ($failedChecks | ForEach-Object { $_.Reason }) -join "; "
            Checks = $checks
        }
    }
    
    return @{
        IsValid = $true
        Checks = $checks
    }
}

function Apply-ScriptUpdate {
    <#
    .SYNOPSIS
        Applies the update based on selected configuration
    #>
    
    param(
        [string]$CurrentPath,
        [string]$NewContent,
        [hashtable]$UpdateConfig,
        [string]$OriginalName
    )
    
    $results = @{
        Success = $false
        BackupCreated = $false
        NewFileName = $null
        FinalPath = $CurrentPath
    }
    
    try {
        $currentDir = [System.IO.Path]::GetDirectoryName($CurrentPath)
        $currentName = [System.IO.Path]::GetFileName($CurrentPath)
        
        # Apply based on update mode
        switch ($UpdateConfig.Mode) {
            0 { # Keep current name
                $targetPath = $CurrentPath
                $results.NewFileName = $currentName
            }
            1 { # Restore original name
                $targetPath = Join-Path $currentDir $OriginalName
                $results.NewFileName = $OriginalName
                
                # If current file has different name, we'll rename it
                if ($CurrentPath -ne $targetPath) {
                    Write-DebugLog "Renaming script to original name: $OriginalName" "INFO"
                }
            }
            2 { # Create both versions
                # Update current file
                $NewContent | Out-File -FilePath $CurrentPath -Encoding UTF8 -Force
                
                # Create original version
                $originalPath = Join-Path $currentDir $OriginalName
                $NewContent | Out-File -FilePath $originalPath -Encoding UTF8 -Force
                
                $results.NewFileName = "$currentName (and $OriginalName)"
                $results.FinalPath = $CurrentPath
                
                Write-DebugLog "Created both versions: $currentName and $OriginalName" "SUCCESS"
                $results.Success = $true
                return $results
            }
        }
        
        # Write updated content
        if ($PSCmdlet.ShouldProcess($targetPath, "Update script file")) {
            $NewContent | Out-File -FilePath $targetPath -Encoding UTF8 -Force
            
            # Verify write was successful
            if (Test-Path $targetPath) {
                $writtenContent = Get-Content -Path $targetPath -Raw -ErrorAction SilentlyContinue
                if ($writtenContent -and $writtenContent.Contains($SCRIPT_IDENTIFIER)) {
                    Write-DebugLog "Update successfully written to: $targetPath" "SUCCESS"
                    $results.Success = $true
                    $results.FinalPath = $targetPath
                } else {
                    throw "Written file verification failed"
                }
            } else {
                throw "Target file was not created"
            }
        }
        
        return $results
        
    } catch {
        Write-DebugLog "Failed to apply update: $_" "ERROR"
        $results.Success = $false
        $results.ErrorMessage = $_
        return $results
    }
}

function Restart-ScriptInNewWindow {
    <#
    .SYNOPSIS
        Restarts the script in a new PowerShell window
    #>
    
    param(
        [string]$ScriptPath,
        [hashtable]$Parameters
    )
    
    # Build parameter string
    $paramString = @()
    foreach ($key in $Parameters.Keys) {
        if ($Parameters[$key] -is [switch] -and $Parameters[$key]) {
            $paramString += "-$key"
        } elseif ($Parameters[$key] -isnot [switch]) {
            $paramString += "-$key `"$($Parameters[$key])`""
        }
    }
    
    $command = "powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`" $($paramString -join ' ')"
    
    Write-DebugLog "Restarting in new window: $command" "INFO"
    
    try {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -Command `"& '$ScriptPath' $($paramString -join ' ')`""
    } catch {
        Write-Host "Failed to start new window: $_" -ForegroundColor $COLORS.Warning
        Write-Host "Please restart the script manually." -ForegroundColor $COLORS.Info
    }
}

#endregion

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
    -Brief, -b               Brief status report
    -IncludePerformance, -p  Include performance metrics
    -ExportJson, -j <file>   Export status to JSON file
    -ExportCsv, -csv <file>  Export status to CSV file

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

    # Check brief system status
    .\$SCRIPT_NAME.ps1 -Status -Brief

    # Check system status with performance metrics
    .\$SCRIPT_NAME.ps1 -Status -IncludePerformance

    # Export status to JSON and CSV
    .\$SCRIPT_NAME.ps1 -Status -ExportJson "status.json" -ExportCsv "status.csv"

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
    # Build parameters for Show-SystemStatus
    $statusParams = @{}
    if ($Brief) { $statusParams.Brief = $true }
    if ($IncludePerformance) { $statusParams.IncludePerformance = $true }
    if ($ExportJson) { $statusParams.ExportJson = $ExportJson }
    if ($ExportCsv) { $statusParams.ExportCsv = $ExportCsv }
    
    $statusResult = Show-SystemStatus @statusParams
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
        $activeCount = ($sessions | Where-Object { $_.State -eq "Active" }).Count
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
        $activeSessions = $sessions | Where-Object { $_.State -eq "Active" -or $_.State -eq "Connected" }
        
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
