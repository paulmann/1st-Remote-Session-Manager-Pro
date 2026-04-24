#requires -Version 7.0
using namespace System.Text
using namespace System.Collections.Generic
using namespace System.Management.Automation

<#
.SYNOPSIS
    RDP Session Analyzer Pro - Advanced RDP session management and analysis tool
.DESCRIPTION
    Professional tool for analyzing RDP sessions, correlating IP addresses, 
    and generating comprehensive reports in multiple formats.
    Features real-time monitoring, IP mapping, and modern HTML reporting.
.AUTHOR
    Mikhail Deynekin [deynekin.com]
.REPOSITORY
    https://github.com/paulmann/1st-Remote-Session-Manager-Pro/
.VERSION
    3.0.1
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Analyze', 'Export', 'Test', 'Monitor', 'Summary', 'GetSessions', 'GetConnections')]
    [string]$Command = 'Analyze',
    
    [Parameter()]
    [ValidateSet('Table', 'List', 'Json', 'Csv', 'Xml', 'Html', 'Text', 'Yaml', 'Markdown', 'PSObject', 'PSXml')]
    [string]$Format = 'Table',
    
    [Parameter()]
    [string]$OutputFile,
    
    [Parameter()]
    [string[]]$Properties,
    
    [Parameter()]
    [string]$UserName,
    
    [Parameter()]
    [string]$SessionName,
    
    [Parameter()]
    [nullable[int]]$SessionId,
    
    [Parameter()]
    [ValidateSet('Active', 'Disc', 'Disconnected', 'Listening', 'Unknown')]
    [string[]]$State = @('Active'),
    
    [Parameter()]
    [switch]$IncludeConsole = $true,
    
    [Parameter()]
    [switch]$IncludeServices,
    
    [Parameter()]
    [switch]$ExcludeCurrent,
    
    [Parameter()]
    [string]$SortBy = 'SessionId',
    
    [Parameter()]
    [switch]$Descending,
    
    [Parameter()]
    [int]$Limit,
    
    [Parameter()]
    [int]$HoursBack = 24,
    
    [Parameter()]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter()]
    [switch]$UseQwinsta = $true,
    
    [Parameter()]
    [switch]$UseNetstat = $true,
    
    [Parameter()]
    [int]$Interval = 10,
    
    [Parameter()]
    [int]$MonitorCount = 0,
    
    [Parameter()]
    [switch]$Clipboard,
    
    [Parameter()]
    [switch]$Quiet,
    
    [Parameter()]
    [switch]$VerboseOutput,
    
    [Parameter()]
    [switch]$DebugMode,
    
    [Parameter()]
    [switch]$ForceAdmin,
    
    [Parameter()]
    [string[]]$InternalIPRanges,
    
    [Parameter()]
    [switch]$SkipLoopback = $true,
    
    [Parameter()]
    [switch]$SkipIPv6 = $true,
    
    [Parameter()]
    [switch]$SkipZeroIP = $true,
    
    [Parameter()]
    [switch]$SkipBroadcast = $true,
    
    [Parameter()]
    [int]$MatchTimeThreshold = 30,
    
    [Parameter()]
    [switch]$EnableIPMapping = $true,
    
    [Parameter()]
    [switch]$EnableNetstatMapping = $true,
    
    [Parameter()]
    [switch]$EnableEventLogMapping = $true,
    
    [Parameter()]
    [switch]$EnableAdvancedMatching = $true,
    
    [Parameter()]
    [switch]$NoColor,

    [Parameter()]
    [string]$HtmlTemplatePath
)

# Script configuration with default values
[Hashtable]$Script:Config = @{
    DebugEnabled = $false
    ColorOutput = $true
    ShowProgress = $true
    EventLogHoursBack = $HoursBack
    SecurityEventIDs = @(4624, 4634, 4647, 4778, 4779)
    TerminalServicesEventIDs = @(21, 22, 23, 24, 25, 1149)
    MaxEvents = 1000
    InternalIPRanges = @(
        '192\.168\.'
        '10\.'
        '172\.(1[6-9]|2[0-9]|3[0-1])\.'
    )
    MaxSessions = 100
    SkipLoopback = $true
    SkipIPv6 = $true
    SkipZeroIP = $true
    SkipBroadcast = $true
    QwinstaEncoding = 'cp866'
    TimeWindowHours = $HoursBack
    MatchTimeThreshold = $MatchTimeThreshold
    EnableIPMapping = $true
    EnableNetstatMapping = $true
    EnableEventLogMapping = $true
    EnableAdvancedMatching = $true
    UseProcessMatching = $true
    UseUserMatching = $true
    UseSessionMatching = $true
    UseTimeMatching = $true
    UseRecentConnections = $true
    DefaultEncoding = 'UTF8'
    OutputWidth = 120
    HtmlTemplatePath = if ($HtmlTemplatePath) { $HtmlTemplatePath } else { Join-Path $PSScriptRoot "rdp-report-template.html" }
}

# Apply debug settings if DebugMode is enabled
if ($DebugMode) {
    $Script:Config.DebugEnabled = $true
    $DebugPreference = 'Continue'
}

# Apply color settings
if ($NoColor) {
    $Script:Config.ColorOutput = $false
}

# Apply custom hours back setting
if ($HoursBack -ne 24) {
    $Script:Config.EventLogHoursBack = $HoursBack
    $Script:Config.TimeWindowHours = $HoursBack
}

# Apply custom internal IP ranges
if ($InternalIPRanges -and $InternalIPRanges.Count -gt 0) {
    $Script:Config.InternalIPRanges = $InternalIPRanges
}

# Apply skip settings
if ($PSBoundParameters.ContainsKey('SkipLoopback')) {
    $Script:Config.SkipLoopback = $SkipLoopback
}

if ($PSBoundParameters.ContainsKey('SkipIPv6')) {
    $Script:Config.SkipIPv6 = $SkipIPv6
}

if ($PSBoundParameters.ContainsKey('SkipZeroIP')) {
    $Script:Config.SkipZeroIP = $SkipZeroIP
}

if ($PSBoundParameters.ContainsKey('SkipBroadcast')) {
    $Script:Config.SkipBroadcast = $SkipBroadcast
}

# Apply matching threshold
if ($MatchTimeThreshold -ne 30) {
    $Script:Config.MatchTimeThreshold = $MatchTimeThreshold
}

# Apply mapping settings
if ($PSBoundParameters.ContainsKey('EnableIPMapping')) {
    $Script:Config.EnableIPMapping = $EnableIPMapping
}

if ($PSBoundParameters.ContainsKey('EnableNetstatMapping')) {
    $Script:Config.EnableNetstatMapping = $EnableNetstatMapping
}

if ($PSBoundParameters.ContainsKey('EnableEventLogMapping')) {
    $Script:Config.EnableEventLogMapping = $EnableEventLogMapping
}

if ($PSBoundParameters.ContainsKey('EnableAdvancedMatching')) {
    $Script:Config.EnableAdvancedMatching = $EnableAdvancedMatching
}

# Enums for session states and types
enum SessionState {
    Active
    Disconnected
    Listening
    Disc
    Unknown
}

enum SessionType {
    RDP
    Console
    Services
    Listener
    Unknown
}

try {
    $enCulture = [System.Globalization.CultureInfo]'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $enCulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture   = $enCulture
} catch {
}
$env:LANG   = 'en-US'
$env:LC_ALL = 'en-US'

<#
.SYNOPSIS
    Represents an RDP session
.DESCRIPTION
    Contains all properties of an RDP session including user, state, and IP information
#>
class RdpSession {
    [string] $ComputerName
    [string] $SessionName
    [string] $UserName
    [int] $SessionId
    [SessionState] $State
    [SessionType] $Type
    [bool] $IsCurrent
    [string] $Device
    [datetime] $CreatedAt
    [nullable[datetime]] $LastInput
    [string] $ClientName
    [string] $ClientAddress
    [string] $Source
    [string] $IPAddress
    [datetime] $Timestamp
    
    RdpSession() {
        $this.CreatedAt = [datetime]::UtcNow
        $this.Timestamp = [datetime]::Now
    }
    
    [Hashtable] ToHashtable() {
        return [Ordered]@{
            ComputerName = $this.ComputerName
            SessionId    = $this.SessionId
            SessionName  = $this.SessionName
            UserName     = $this.UserName
            State        = $this.State.ToString()
            Type         = $this.Type.ToString()
            IsCurrent    = $this.IsCurrent
            Device       = $this.Device
            CreatedAt    = $this.CreatedAt.ToString('o')
            LastInput    = if ($this.LastInput) { $this.LastInput.Value.ToString('o') } else { $null }
            ClientInfo   = if ($this.ClientName) { "$($this.ClientName)/$($this.ClientAddress)" } else { $null }
            Source       = $this.Source
            IPAddress    = $this.IPAddress
            Timestamp    = $this.Timestamp.ToString('o')
        }
    }
    
    [PSCustomObject] ToPSObject() {
        return [PSCustomObject]$this.ToHashtable()
    }
    
    [string] ToString() {
        return "[$($this.SessionId)] $($this.UserName)@$($this.SessionName) ($($this.State))"
    }
}

<#
.SYNOPSIS
    Represents an RDP connection from event logs
.DESCRIPTION
    Contains connection information extracted from Windows event logs
#>
class RdpConnection {
    [datetime] $Time
    [int] $EventID
    [string] $User
    [string] $IP
    [string] $SessionID
    [string] $Type
    [string] $Source
    [bool] $IsActive
    [string] $QwinstaSessionID
    
    [Hashtable] ToHashtable() {
        return [Ordered]@{
            Time              = $this.Time.ToString('o')
            EventID           = $this.EventID
            User              = $this.User
            IP                = $this.IP
            SessionID         = $this.SessionID
            QwinstaSessionID  = $this.QwinstaSessionID
            Type              = $this.Type
            Source            = $this.Source
            IsActive          = $this.IsActive
        }
    }
    
    [PSCustomObject] ToPSObject() {
        return [PSCustomObject]$this.ToHashtable()
    }
}

<#
.SYNOPSIS
    Represents a match between a session and an IP address
.DESCRIPTION
    Contains matching information with confidence levels for IP correlation
#>
class RdpMatch {
    [string] $SessionName
    [string] $Username
    [int] $SessionId
    [string] $SessionState
    [string] $SessionType
    [datetime] $SessionTime
    [string] $MatchedIP
    [nullable[datetime]] $MatchedTime
    [string] $MatchedType
    [string] $MatchedSource
    [nullable[double]] $TimeDifference
    [string] $Confidence
    
    [Hashtable] ToHashtable() {
        return [Ordered]@{
            SessionName   = $this.SessionName
            Username      = $this.Username
            SessionId     = $this.SessionId
            SessionState  = $this.SessionState
            SessionType   = $this.SessionType
            SessionTime   = $this.SessionTime.ToString('o')
            MatchedIP     = $this.MatchedIP
            MatchedTime   = if ($this.MatchedTime) { $this.MatchedTime.Value.ToString('o') } else { $null }
            MatchedType   = $this.MatchedType
            MatchedSource = $this.MatchedSource
            TimeDifference = $this.TimeDifference
            Confidence    = $this.Confidence
        }
    }
    
    [PSCustomObject] ToPSObject() {
        return [PSCustomObject]$this.ToHashtable()
    }
}

<#
.SYNOPSIS
    Represents the complete analysis result
.DESCRIPTION
    Contains all sessions, connections, matches, and statistics from the analysis
#>
class AnalysisResult {
    [RdpSession[]] $Sessions
    [RdpConnection[]] $Connections
    [RdpMatch[]] $Matches
    [datetime] $AnalysisTime
    [string] $ComputerName
    [hashtable] $Statistics
    
    AnalysisResult() {
        $this.AnalysisTime = [datetime]::Now
        $this.ComputerName = $env:COMPUTERNAME
        $this.Statistics = @{}
    }
    
    [void] CalculateStatistics() {
        $this.Statistics = @{
            TotalSessions    = $this.Sessions.Count
            TotalConnections = $this.Connections.Count
            TotalMatches     = $this.Matches.Count
            MatchedSessions  = ($this.Matches | Where-Object { $_.Confidence -ne 'None' }).Count
            HighConfidence   = ($this.Matches | Where-Object { $_.Confidence -eq 'High' }).Count
            MediumConfidence = ($this.Matches | Where-Object { $_.Confidence -eq 'Medium' }).Count
            LowConfidence    = ($this.Matches | Where-Object { $_.Confidence -eq 'Low' }).Count
            ActiveSessions   = ($this.Sessions | Where-Object { $_.State -eq [SessionState]::Active }).Count
            RDPSessions      = ($this.Sessions | Where-Object { $_.Type -eq [SessionType]::RDP }).Count
            ConsoleSessions  = ($this.Sessions | Where-Object { $_.Type -eq [SessionType]::Console }).Count
            UniqueIPs        = ($this.Connections | Select-Object -ExpandProperty IP -Unique | Where-Object { $_ -ne 'N/A' }).Count
            InternalIPs      = ($this.Connections | Where-Object { 
                $_.IP -ne 'N/A' -and $this.IsInternalIP($_.IP)
            } | Select-Object -ExpandProperty IP -Unique).Count
            ExternalIPs      = ($this.Connections | Where-Object { 
                $_.IP -ne 'N/A' -and -not $this.IsInternalIP($_.IP)
            } | Select-Object -ExpandProperty IP -Unique).Count
        }
    }
    
    [bool] IsInternalIP([string]$ip) {
        foreach ($range in $Script:Config.InternalIPRanges) {
            if ($ip -match "^${range}") {
                return $true
            }
        }
        return $false
    }
    
    [hashtable] ToHashtable() {
        $this.CalculateStatistics()
        
        return [Ordered]@{
            AnalysisTime = $this.AnalysisTime.ToString('o')
            ComputerName = $this.ComputerName
            Statistics   = $this.Statistics
            Sessions     = $this.Sessions | ForEach-Object { $_.ToHashtable() }
            Connections  = $this.Connections | ForEach-Object { $_.ToHashtable() }
            Matches      = $this.Matches | ForEach-Object { $_.ToHashtable() }
        }
    }
    
    [PSCustomObject] ToPSObject() {
        return [PSCustomObject]@{
            PSTypeName   = 'AnalysisResult'
            AnalysisTime = $this.AnalysisTime
            ComputerName = $this.ComputerName
            Statistics   = [PSCustomObject]$this.Statistics
            Sessions     = $this.Sessions | ForEach-Object { $_.ToPSObject() }
            Connections  = $this.Connections | ForEach-Object { $_.ToPSObject() }
            Matches      = $this.Matches | ForEach-Object { $_.ToPSObject() }
        }
    }
}

<#
.SYNOPSIS
    Writes debug information when debug mode is enabled
.DESCRIPTION
    Outputs formatted debug messages with timestamps and optional data
#>
function Write-DebugInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [object]$Data = $null
    )
    
    if ($Script:Config.DebugEnabled) {
        $timestamp = Get-Date -Format "HH:mm:ss.fff"
        $color = if ($Message -match 'error|fail|invalid|skip') { 'DarkRed' } else { 'Gray' }
        Write-Host "[DEBUG ${timestamp}] ${Message}" -ForegroundColor ${color}
        
        if (${Data} -ne $null) {
            if (${Data} -is [hashtable]) {
                Write-Host "  Hashtable:" -ForegroundColor DarkGray
                ${Data}.GetEnumerator() | Select-Object -First 5 | ForEach-Object {
                    Write-Host "    $($_.Key): $($_.Value)" -ForegroundColor DarkGray
                }
            }
            else {
                Write-Host "  Data: ${Data}" -ForegroundColor DarkGray
            }
        }
    }
}

<#
.SYNOPSIS
    Checks if the current session has administrator privileges
.DESCRIPTION
    Returns $true if running as administrator, $false otherwise
#>
function Test-Administrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-DebugInfo "Error checking admin rights: ${_}"
        return $false
    }
}

<#
.SYNOPSIS
    Gets the local IPv4 address of the computer
.DESCRIPTION
    Retrieves the primary non-loopback IPv4 address of the local machine
    using ipconfig/Get-NetIPAddress
#>
function Get-LocalIPv4Address {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq '.') {
            # Local computer - use Get-NetIPAddress
            $ipAddress = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $_.InterfaceAlias -notlike "*Loopback*" -and 
                    $_.PrefixOrigin -ne 'WellKnown' -and
                    $_.IPAddress -notmatch '^169\.254\.' -and
                    $_.IPAddress -notmatch '^127\.'
                } | 
                Sort-Object InterfaceIndex | 
                Select-Object -First 1 -ExpandProperty IPAddress
            
            if ($ipAddress) {
                Write-DebugInfo "Local IPv4 address found: ${ipAddress}"
                return $ipAddress
            }
            
            # Fallback to ipconfig
            $ipconfigResult = ipconfig | Where-Object { $_ -match 'IPv4 Address.*:\s*(\d+\.\d+\.\d+\.\d+)' }
            if ($ipconfigResult -and $ipconfigResult -match '(\d+\.\d+\.\d+\.\d+)') {
                $ipAddress = $matches[1]
                if ($ipAddress -notmatch '^127\.' -and $ipAddress -ne '0.0.0.0') {
                    Write-DebugInfo "Local IPv4 address found via ipconfig: ${ipAddress}"
                    return $ipAddress
                }
            }
        } 
        else {
            # Remote computer - attempt to get IP via CIM
            try {
                $session = New-CimSession -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($session) {
                    $ipAddress = Get-NetIPAddress -CimSession $session -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $_.InterfaceAlias -notlike "*Loopback*" -and 
                            $_.PrefixOrigin -ne 'WellKnown' -and
                            $_.IPAddress -notmatch '^169\.254\.' -and
                            $_.IPAddress -notmatch '^127\.'
                        } | 
                        Sort-Object InterfaceIndex | 
                        Select-Object -First 1 -ExpandProperty IPAddress
                    
                    if ($ipAddress) {
                        Write-DebugInfo "Remote IPv4 address found for ${ComputerName}: ${ipAddress}"
                        return $ipAddress
                    }
                }
            }
            catch {
                Write-DebugInfo "Failed to get remote IP for ${ComputerName}: ${_}"
            }
        }
        
        Write-DebugInfo "No suitable local IPv4 address found"
        return 'Local Machine'
    }
    catch {
        Write-DebugInfo "Get-LocalIPv4Address error: ${_}"
        return 'Local Machine'
    }
}

<#
.SYNOPSIS
    Validates if a string is a valid IP address
.DESCRIPTION
    Checks various IP address formats and filters invalid ones based on configuration
#>
function Test-IsValidIP {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )
    
    if ([string]::IsNullOrWhiteSpace(${IP})) {
        Write-DebugInfo "IP is null or whitespace"
        return $false
    }
    
    if (${IP} -match '^(\d+\.\d+\.\d+\.\d+):\d+$') {
        ${IP} = $matches[1]
        Write-DebugInfo "Removed port from IP: ${IP}"
    }
    
    $invalidPatterns = @(
        '^\d+\.\d+\.\d+\.\d+\.\d+'
        '^\d+\.\d+\.\d+\.[0-9]{4,}'
        '^\d+\.\d+\.\d{4,}\.'
        '^fe80:'
        '^::'
    )
    
    if ($Script:Config.SkipZeroIP -and ${IP} -eq '0.0.0.0') {
        return $false
    }
    
    if ($Script:Config.SkipLoopback -and ${IP} -match '^127\.') {
        return $false
    }
    
    if ($Script:Config.SkipBroadcast -and ${IP} -eq '255.255.255.255') {
        return $false
    }
    
    if ($Script:Config.SkipIPv6 -and ${IP} -match ':') {
        return $false
    }
    
    foreach ($pattern in $invalidPatterns) {
        if (${IP} -match ${pattern}) {
            return $false
        }
    }
    
    if (${IP} -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        $octets = $matches[1..4]
        foreach ($octet in $octets) {
            $num = 0
            if (-not [int]::TryParse($octet, [ref]$num)) {
                return $false
            }
            
            if ($num -gt 255 -or $num -lt 0) {
                return $false
            }
        }
        
        if (${IP} -match '^224\.|^240\.|^169\.254\.') {
            return $false
        }
        
        Write-DebugInfo "Valid IPv4 detected: ${IP}"
        return $true
    }
    
    if (-not $Script:Config.SkipIPv6 -and ${IP} -match '^[0-9a-fA-F:]+$' -and ${IP} -notmatch '^[0-9\.]+$') {
        try {
            $null = [System.Net.IPAddress]::Parse(${IP})
            Write-DebugInfo "Valid IPv6 detected: ${IP}"
            return $true
        }
        catch {
            Write-DebugInfo "Invalid IPv6 format: ${IP}"
            return $false
        }
    }
    
    Write-DebugInfo "IP ${IP} doesn't match any valid pattern"
    return $false
}

<#
.SYNOPSIS
    Formats IP addresses for display with internal/external classification
.DESCRIPTION
    Adds INT: or EXT: prefix to IP addresses based on internal range configuration
#>
function Format-IPForDisplay {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )
    
    if (-not (Test-IsValidIP ${IP})) {
        Write-DebugInfo "Invalid IP for display: ${IP}"
        return 'N/A'
    }
    
    foreach ($range in $Script:Config.InternalIPRanges) {
        if (${IP} -match "^${range}") {
            return "INT:${IP}"
        }
    }
    
    return "EXT:${IP}"
}

<#
.SYNOPSIS
    Checks if an IP address is within internal ranges
.DESCRIPTION
    Compares IP against configured internal IP ranges
#>
function IsInternalIP {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )
    
    if (-not (Test-IsValidIP ${IP})) {
        return $false
    }
    
    foreach ($range in $Script:Config.InternalIPRanges) {
        if (${IP} -match "^${range}") {
            return $true
        }
    }
    
    return $false
}

<#
.SYNOPSIS
    Retrieves RDP sessions using qwinsta/query session command
.DESCRIPTION
    Parses output from qwinsta to get current RDP session information
    Handles both English and Russian system locales
#>
function Get-RdpSessionsViaQwinsta {
    [CmdletBinding()]
    [OutputType([RdpSession[]])]
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        Write-DebugInfo "Getting RDP sessions via qwinsta"
        
        $sessions = [List[RdpSession]]::new()
        
        $attempts = @(
            @{Command = 'chcp 866 && qwinsta'; Encoding = 'cp866'}
            @{Command = 'query session'; Encoding = 'cp866'}
            @{Command = 'chcp 1252 && qwinsta'; Encoding = 'cp1252'}
            @{Command = 'cmd /c "chcp 1252 && qwinsta"'; Encoding = '1252'}
        )
        
        foreach ($attempt in $attempts) {
            try {
                $command = ${attempt}.Command
                $encoding = ${attempt}.Encoding
                
                Write-DebugInfo "Attempting: ${command} with encoding ${encoding}"
                
                $result = if (${command} -match '^cmd') {
                    Invoke-Expression ${command} 2>$null
                }
                else {
                    & { Invoke-Expression ${command} } 2>$null
                }
                
                if ($result -and $result -match 'SESSIONNAME|SESSION') {
                    if (${encoding} -and ${encoding} -ne 'cp866') {
                        $encodingObj = [Text.Encoding]::GetEncoding(${encoding})
                        $bytes = $encodingObj.GetBytes(($result | Out-String))
                        $result = [Text.Encoding]::UTF8.GetString($bytes)
                    }
                    
                    $lines = if ($result -is [string]) {
                        $result -split '\r?\n'
                    }
                    else {
                        $result
                    }
                    
                    Write-DebugInfo "Successfully retrieved $($lines.Count) lines"
                    
                    foreach ($line in $lines) {
                        if ([string]::IsNullOrWhiteSpace($line) -or 
                            $line -match '^[\s-]*(SESSIONNAME|SESSION|USERNAME|USER|#)') {
                            continue
                        }
                        
                        $originalLine = $line
                        
                        $isCurrent = $line -match '^[>тЖТ]'
                        if ($isCurrent) {
                            $line = $line.Substring(1).TrimStart()
                        }
                        
                        $line = $line.Trim()
                        
                        if ($line -match '^(?<SessionName>\S+)\s+(?<UserName>.+?)\s+(?<SessionId>\d+)\s+(?<State>\S+)(?:\s+(?<Device>.*))?$') {
                            $sessionName = $matches['SessionName'].Trim()
                            $userName = $matches['UserName'].Trim()
                            $sessionId = [int]$matches['SessionId']
                            
if ($sessionId -eq 65536 -and $sessionName -like 'rdp-tcp*') {
    $sessionType = [SessionType]::Listener
}
elseif ($sessionName -eq 'services') {
    $sessionType = [SessionType]::Services
}
elseif ($sessionName -eq 'console') {
    $sessionType = [SessionType]::Console
}
elseif ($sessionName -like 'rdp-tcp#*') {
    $sessionType = [SessionType]::RDP
}
elseif ($sessionName -like 'rdp-tcp*') {
    $sessionType = [SessionType]::Listener
}
else {
    $sessionType = [SessionType]::Unknown
}
                            
                            $state = $matches['State'].Trim()
                            $stateEnglish = switch -Regex ($state) {
                                'Active|╨Р╨║╤В╨╕╨▓╨╜╨╛' { [SessionState]::Active }
                                'Disc|╨Ф╨╕╤Б╨║' { [SessionState]::Disc }
                                'Disconnected|╨Ю╤В╨║╨╗╤О╤З╨╡╨╜╨╛' { [SessionState]::Disconnected }
                                'Listening|╨Я╤А╨╕╨╡╨╝' { [SessionState]::Listening }
                                default { [SessionState]::Unknown }
                            }
                            
                            $sessionType = switch -Wildcard ($sessionName) {
                                'services' { [SessionType]::Services }
                                'console' { [SessionType]::Console }
                                'rdp-tcp#*' { [SessionType]::RDP }
                                'rdp-tcp' { [SessionType]::Listener }
                                default { [SessionType]::Unknown }
                            }
                            
                            $login = $userName
                            if ($userName -match '\\') {
                                $domain, $login = $userName.Split('\')
                            }
                            
                            $session = [RdpSession]@{
                                ComputerName = ${ComputerName}
                                SessionId    = $sessionId
                                SessionName  = $sessionName
                                UserName     = $login
                                State        = $stateEnglish
                                Type         = $sessionType
                                IsCurrent    = $isCurrent
                                Source       = 'qwinsta'
                                Timestamp    = Get-Date
                            }
                            
                            # Set IP address based on session type
                            if ($sessionType -eq [SessionType]::Console) {
                                # Console sessions always use local machine IP
                                $session.IPAddress = Get-LocalIPv4Address -ComputerName $ComputerName
                                Write-DebugInfo "Console session detected, using local IP: $($session.IPAddress)"
                            } else {
                                $session.IPAddress = 'N/A'
                            }
                            
                            $sessions.Add($session)
                            Write-DebugInfo "Parsed session: ${sessionName} (${login}) ID: ${sessionId} State: ${stateEnglish} Type: ${sessionType}"
                        }
                    }
                    
                    if ($sessions.Count -gt 0) {
                        Write-DebugInfo "Successfully parsed $($sessions.Count) sessions"
                        return $sessions.ToArray()
                    }
                }
            }
            catch {
                Write-DebugInfo "Attempt failed: ${_}"
            }
        }
        
        Write-DebugInfo "All attempts failed or no sessions found"
        return @()
    }
    catch {
        Write-DebugInfo "Get-RdpSessionsViaQwinsta error: ${_}"
        return @()
    }
}

<#
.SYNOPSIS
    Retrieves active RDP connections using netstat with username mapping
.DESCRIPTION
    Uses Get-NetTCPConnection to find established RDP connections (port 3389)
    and attempts to map them to usernames via process owner
#>
function Get-ActiveRdpConnectionsViaNetstat {
    [CmdletBinding()]
    [OutputType([RdpConnection[]])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    try {
        Write-DebugInfo "Getting active RDP connections via netstat with session mapping"

        $connections = [System.Collections.Generic.List[RdpConnection]]::new()

        $activeSessions = Get-RdpSessionsViaQwinsta -ComputerName $ComputerName |
            Where-Object {
                $_.State -eq [SessionState]::Active -and
                $_.Type  -eq [SessionType]::RDP
            } |
            Sort-Object SessionId

        $tcpConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq 3389 -or $_.RemotePort -eq 3389 } |
            Sort-Object RemoteAddress, RemotePort

        Write-DebugInfo "Active RDP sessions: $($activeSessions.Count)"
        Write-DebugInfo "Established RDP TCP connections: $($tcpConnections.Count)"

        $sessionIndex = 0

        foreach ($conn in $tcpConnections) {
            try {
                $userName = 'Active Connection'
                $qwinstaSessionID = 'N/A'

                if ($sessionIndex -lt $activeSessions.Count) {
                    $qwinstaSessionID = [string]$activeSessions[$sessionIndex].SessionId
                    $userName = if ($activeSessions[$sessionIndex].UserName) {
                        $activeSessions[$sessionIndex].UserName
                    } else {
                        'Active Connection'
                    }
                    $sessionIndex++
                }

                $connection = [RdpConnection]::new()
                $connection.Time = Get-Date
                $connection.EventID = 0
                $connection.User = $userName
                $connection.IP = $conn.RemoteAddress
                $connection.SessionID = 'N/A'
                $connection.QwinstaSessionID = $qwinstaSessionID
                $connection.Type = 'Active Connection'
                $connection.Source = 'Netstat'
                $connection.IsActive = $true

                $connections.Add($connection)

                Write-DebugInfo "Netstat connection mapped: IP=$($conn.RemoteAddress), User=$userName, SessionID=$qwinstaSessionID"
            }
            catch {
                Write-DebugInfo "Error processing netstat connection: $($_.Exception.Message)"
            }
        }

        Write-DebugInfo "Found $($connections.Count) RDP connections via netstat"
        return $connections.ToArray()
    }
    catch {
        Write-DebugInfo "Get-ActiveRdpConnectionsViaNetstat error: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Retrieves RDP connections from Windows event logs with session ID extraction
.DESCRIPTION
    Extracts RDP connection information from Security and TerminalServices event logs
    Requires administrator privileges
#>
function Get-RdpConnectionsFromEventLogs {
    [CmdletBinding()]
    [OutputType([RdpConnection[]])]
    param(
        [Parameter()]
        [int]$HoursBack = $Script:Config.EventLogHoursBack
    )
    
    $isAdmin = Test-Administrator
    Write-DebugInfo "Getting RDP connections from event logs (HoursBack: ${HoursBack}, Admin: ${isAdmin})"
    
    $connections = [List[RdpConnection]]::new()
    
    if (-not $isAdmin) {
        Write-DebugInfo "Skipping event log check - admin privileges required"
        return $connections.ToArray()
    }
    
    Write-DebugInfo "Starting Security log check"
    try {
        $securityEvents = Get-WinEvent -LogName "Security" -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -ge (Get-Date).AddHours(-${HoursBack}) } |
            Where-Object { $_.Id -in $Script:Config.SecurityEventIDs } |
            Select-Object -First $Script:Config.MaxEvents
        
        Write-DebugInfo "Found Security events: $($securityEvents.Count)"
        
        foreach ($event in $securityEvents) {
            try {
                $xml = [xml]$event.ToXml()
                $data = @{}
                
                foreach ($item in $xml.Event.EventData.Data) {
                    $data[$item.Name] = $item.'#text'
                }
                
                $ip = $null
                $user = $null
                $sessionId = $null
                $logonId = $null
                
                switch ($event.Id) {
                    4624 {
                        if ($data['LogonType'] -eq '10') {
                            $ip = $data['IpAddress']
                            $user = $data['TargetUserName']
                            $sessionId = $data['TargetLogonId']
                            $logonId = $data['TargetLogonId']
                        }
                    }
                    4778 {
                        $ip = $data['ClientAddress']
                        $user = $data['TargetUserName']
                        $sessionId = $data['LogonID']
                        $logonId = $data['LogonID']
                    }
                    4779 {
                        $ip = $data['ClientAddress']
                        $user = $data['TargetUserName']
                        $sessionId = $data['LogonID']
                        $logonId = $data['LogonID']
                    }
                }
                
                if ($ip -and (Test-IsValidIP $ip)) {
                    # Convert hex session ID to decimal for qwinsta compatibility
                    $qwinstaSessionID = 'N/A'
                    if ($logonId -and $logonId -match '0x([0-9a-fA-F]+)') {
                        try {
                            $hexValue = $matches[1]
                            $decimalValue = [Convert]::ToInt32($hexValue, 16)
                            $qwinstaSessionID = $decimalValue
                        }
                        catch {
                            Write-DebugInfo "Failed to convert session ID: ${logonId}"
                        }
                    }
                    
                    $connection = [RdpConnection]@{
                        Time             = $event.TimeCreated
                        EventID          = $event.Id
                        User             = if ($user) { $user } else { 'Unknown' }
                        IP               = $ip
                        SessionID        = $sessionId
                        QwinstaSessionID = $qwinstaSessionID
                        Type             = switch ($event.Id) {
                            4624 { 'Logon' }
                            4778 { 'Reconnect' }
                            4779 { 'Disconnect' }
                            default { 'Security' }
                        }
                        Source           = 'Security'
                        IsActive         = $false
                    }
                    
                    $connections.Add($connection)
                    Write-DebugInfo "Event log connection: User=${user}, IP=${ip}, SessionID=${sessionId}, QwinstaID=${qwinstaSessionID}"
                }
            }
            catch {
                Write-DebugInfo "Error parsing Security event $($event.Id): ${_}"
            }
        }
    }
    catch {
        Write-DebugInfo "Security log access failed: ${_}"
    }
    
    Write-DebugInfo "Starting TerminalServices RemoteConnectionManager log check"
    try {
        $tsEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -ErrorAction SilentlyContinue | 
            Where-Object { $_.TimeCreated -ge (Get-Date).AddHours(-${HoursBack}) } |
            Where-Object { $_.Id -in $Script:Config.TerminalServicesEventIDs } |
            Select-Object -First $Script:Config.MaxEvents
        
        Write-DebugInfo "Found TerminalServices RemoteConnectionManager events: $($tsEvents.Count)"
        
        foreach ($event in $tsEvents) {
            try {
                $ip = $null
                $user = $null
                $sessionId = $null
                $qwinstaSessionID = 'N/A'
                
                switch ($event.Id) {
                    21 {
                        if ($event.Properties.Count -ge 6) {
                            $user = $event.Properties[1].Value
                            $sessionId = $event.Properties[4].Value
                            $ip = $event.Properties[6].Value
                            
                            # Terminal Services events often have session ID directly
                            if ($sessionId -and $sessionId -match '^\d+$') {
                                $qwinstaSessionID = $sessionId
                            }
                        }
                    }
                    1149 {
                        if ($event.Properties.Count -ge 4) {
                            $user = $event.Properties[1].Value
                            $sessionId = $event.Properties[2].Value
                            $ip = $event.Properties[3].Value
                            
                            if ($sessionId -and $sessionId -match '^\d+$') {
                                $qwinstaSessionID = $sessionId
                            }
                        }
                    }
                    default {
                        if ($event.Message -match 'Client Address:\s*(\S+)') {
                            $ip = $matches[1].Trim()
                        }
                        if ($event.Message -match 'User:\s*([^\s\r\n]+)') {
                            $user = $matches[1]
                        }
                        if ($event.Message -match 'Session ID:\s*(\d+)') {
                            $qwinstaSessionID = $matches[1]
                        }
                    }
                }
                
                if ($ip -and (Test-IsValidIP $ip)) {
                    $connection = [RdpConnection]@{
                        Time             = $event.TimeCreated
                        EventID          = $event.Id
                        User             = if ($user) { $user } else { 'Unknown' }
                        IP               = $ip
                        SessionID        = $sessionId
                        QwinstaSessionID = $qwinstaSessionID
                        Type             = 'RDP Session'
                        Source           = 'TerminalServices-RCM'
                        IsActive         = $false
                    }
                    
                    $connections.Add($connection)
                    Write-DebugInfo "TerminalServices connection: User=${user}, IP=${ip}, SessionID=${sessionId}, QwinstaID=${qwinstaSessionID}"
                }
            }
            catch {
                Write-DebugInfo "Error parsing TerminalServices event $($event.Id): ${_}"
            }
        }
    }
    catch {
        Write-DebugInfo "TerminalServices RemoteConnectionManager log access failed: ${_}"
    }
    
    return $connections.ToArray()
}

<#
.SYNOPSIS
    Retrieves all RDP connections from multiple sources
.DESCRIPTION
    Combines connections from event logs and active netstat connections
#>
function Get-AllRdpConnections {
    [CmdletBinding()]
    [OutputType([RdpConnection[]])]
    param(
        [Parameter()]
        [int]$HoursBack = $Script:Config.EventLogHoursBack,
        
        [Parameter()]
        [switch]$ForceAdmin = $false,
        
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    $isAdmin = Test-Administrator
    Write-DebugInfo "Administrator check result: ${isAdmin}"
    
    if (-not $isAdmin -and $ForceAdmin) {
        Write-Host "`n[ERROR] Administrator privileges required!" -ForegroundColor Red
        return @()
    }
    
    try {
        $allConnections = [List[RdpConnection]]::new()
        
        if ($Script:Config.EnableEventLogMapping) {
            $eventConnections = Get-RdpConnectionsFromEventLogs -HoursBack ${HoursBack}
            foreach ($conn in $eventConnections) {
                $allConnections.Add($conn)
            }
        }
        
        if ($Script:Config.EnableNetstatMapping) {
            Write-DebugInfo "Getting active network connections for correlation"
            $activeConnections = Get-ActiveRdpConnectionsViaNetstat -ComputerName ${ComputerName}
            foreach ($conn in $activeConnections) {
                $allConnections.Add($conn)
            }
        }
        
        $uniqueConnections = $allConnections | 
            Sort-Object Time -Unique | 
            Sort-Object Time -Descending
        
        Write-DebugInfo "Total unique connections found: $($uniqueConnections.Count)"
        return $uniqueConnections
    }
    catch {
        Write-DebugInfo "Get-AllRdpConnections error: ${_}"
        return @()
    }
}

<#
.SYNOPSIS
    Retrieves current RDP sessions
.DESCRIPTION
    Gets active sessions using qwinsta command
#>
function Get-CurrentRDPSessions {
    [CmdletBinding()]
    [OutputType([RdpSession[]])]
    param(
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [switch]$UseQwinsta = $true
    )
    
    try {
        Write-DebugInfo "Getting current RDP sessions"
        
        $allSessions = [List[RdpSession]]::new()
        
        if ($UseQwinsta) {
            $qwinstaSessions = Get-RdpSessionsViaQwinsta -ComputerName ${ComputerName}
            foreach ($session in $qwinstaSessions) {
                $allSessions.Add($session)
            }
            Write-DebugInfo "qwinsta found $($qwinstaSessions.Count) sessions"
        }
        
$uniqueSessions = $allSessions |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.SessionName) -or
        -not [string]::IsNullOrWhiteSpace($_.UserName) -or
        $_.SessionId -ge 0
    } |
    Sort-Object SessionId, SessionName -Unique |
    Sort-Object SessionId
        
        Write-DebugInfo "Total unique sessions found: $($uniqueSessions.Count)"
        return $uniqueSessions
    }
    catch {
        Write-DebugInfo "Get-CurrentRDPSessions error: ${_}"
        return @()
    }
}

<#
.SYNOPSIS
    Matches RDP sessions with IP addresses
.DESCRIPTION
    Correlates sessions with IP addresses from connections using various matching strategies
    and confidence levels
#>
function Match-SessionsWithIPs {
    [CmdletBinding()]
    [OutputType([RdpMatch[]])]
    param(
        [Parameter(Mandatory)]
        [RdpSession[]]$Sessions,
        
        [Parameter(Mandatory)]
        [RdpConnection[]]$Connections,
        
        [Parameter()]
        [int]$TimeWindowHours = 24
    )
    
    try {
        Write-DebugInfo "Matching configuration" @{
            TimeWindowHours = ${TimeWindowHours}
            SessionsCount   = ${Sessions}.Count
            ConnectionsCount = ${Connections}.Count
        }
        
        $matches = [List[RdpMatch]]::new()
        $now = Get-Date
        $timeWindowStart = $now.AddHours(-${TimeWindowHours})
        
        $connectionsByUser = @{}
        $activeConnections = @()
        $recentConnections = @()
        
        foreach ($conn in $Connections) {
            if ($conn.User -and $conn.User -ne 'Active Connection' -and $conn.User -ne 'Unknown') {
                if (-not $connectionsByUser.ContainsKey($conn.User)) {
                    $connectionsByUser[$conn.User] = [List[RdpConnection]]::new()
                }
                $connectionsByUser[$conn.User].Add($conn)
            }
            
            if ($conn.IsActive) {
                $activeConnections += $conn
            }
            
            if ($conn.Time -ge $timeWindowStart) {
                $recentConnections += $conn
            }
        }
        
        Write-DebugInfo "Connection groups" @{
            Users   = $connectionsByUser.Count
            Active  = $activeConnections.Count
            Recent  = $recentConnections.Count
        }
        
        foreach ($session in $Sessions) {
            $sessionUser = $session.UserName
            $sessionId = $session.SessionId
            $sessionTime = $session.Timestamp
            $sessionType = $session.Type
            
            $matchedIP = $session.IPAddress  # Use already set IP for console sessions
            $matchedTime = $null
            $matchedType = 'Session IP'
            $matchedSource = 'Session Data'
            $timeDifference = $null
            $confidence = 'High'
            
            Write-DebugInfo "Processing session: ${sessionUser} (ID: ${sessionId}, Type: ${sessionType})"
            
            # For console sessions, we already have the IP from Get-LocalIPv4Address
            if ($sessionType -eq [SessionType]::Console) {
                $match = [RdpMatch]@{
                    SessionName   = $session.SessionName
                    Username      = $session.UserName
                    SessionId     = $session.SessionId
                    SessionState  = $session.State.ToString()
                    SessionType   = $session.Type.ToString()
                    SessionTime   = $sessionTime
                    MatchedIP     = $matchedIP
                    MatchedTime   = $sessionTime
                    MatchedType   = 'Console Session'
                    MatchedSource = 'Local Machine IP'
                    TimeDifference = 0
                    Confidence    = 'High'
                }
                
                $matches.Add($match)
                continue
            }
            
            # For non-console sessions, use the existing matching logic
            $matchedIP = 'N/A'
            $matchedTime = $null
            $matchedType = 'No match'
            $matchedSource = 'N/A'
            $timeDifference = $null
            $confidence = 'None'
            
            if ($Script:Config.UseUserMatching -and $sessionUser -and $connectionsByUser.ContainsKey($sessionUser)) {
                $userConnections = $connectionsByUser[$sessionUser] | 
                    Where-Object { $_.Time -ge $timeWindowStart } |
                    Sort-Object Time -Descending
                
                if ($userConnections.Count -gt 0) {
                    $bestMatch = $userConnections[0]
                    $matchedIP = $bestMatch.IP
                    $matchedTime = $bestMatch.Time
                    $matchedType = $bestMatch.Type
                    $matchedSource = $bestMatch.Source
                    $timeDifference = [Math]::Round(($sessionTime - $bestMatch.Time).TotalMinutes, 2)
                    $confidence = if ($timeDifference -le $Script:Config.MatchTimeThreshold) { 'High' } else { 'Medium' }
                    
                    Write-DebugInfo "Matched by user: ${sessionUser} -> ${matchedIP} (Confidence: ${confidence}, TimeDiff: ${timeDifference} min)"
                }
            }
            
            if ($confidence -eq 'None' -and $activeConnections.Count -gt 0 -and $sessionType -eq [SessionType]::RDP) {
                $sortedActiveConnections = $activeConnections | Sort-Object Time -Descending
                
                $externalIP = $sortedActiveConnections | 
                    Where-Object { 
                        $_.IP -and $_.IP -ne 'N/A' -and
                        -not (IsInternalIP $_.IP)
                    } |
                    Select-Object -First 1
                
                $internalIP = $sortedActiveConnections | 
                    Where-Object { 
                        $_.IP -and $_.IP -ne 'N/A' -and
                        (IsInternalIP $_.IP)
                    } |
                    Select-Object -First 1
                
                if ($externalIP) {
                    $matchedIP = $externalIP.IP
                    $matchedSource = 'Active External Connection'
                    $confidence = 'Medium'
                    Write-DebugInfo "Matched by external active connection: ${sessionUser} -> ${matchedIP}"
                }
                elseif ($internalIP) {
                    $matchedIP = $internalIP.IP
                    $matchedSource = 'Active Internal Connection'
                    $confidence = 'Medium'
                    Write-DebugInfo "Matched by internal active connection: ${sessionUser} -> ${matchedIP}"
                }
            }
            
            if ($confidence -eq 'None' -and $recentConnections.Count -gt 0 -and $Script:Config.EnableAdvancedMatching) {
                $ipGroups = $recentConnections | 
                    Where-Object { $_.IP -and $_.IP -ne 'N/A' } |
                    Group-Object IP |
                    Sort-Object Count -Descending
                
                if ($ipGroups.Count -gt 0) {
                    $mostCommonIP = $ipGroups[0]
                    $matchedIP = $mostCommonIP.Name
                    $matchedSource = 'Most Recent Common IP'
                    $confidence = 'Low'
                    Write-DebugInfo "Matched by most common recent IP: ${sessionUser} -> ${matchedIP} (Count: $($mostCommonIP.Count))"
                }
            }
            
            $match = [RdpMatch]@{
                SessionName   = $session.SessionName
                Username      = $session.UserName
                SessionId     = $session.SessionId
                SessionState  = $session.State.ToString()
                SessionType   = $session.Type.ToString()
                SessionTime   = $sessionTime
                MatchedIP     = $matchedIP
                MatchedTime   = $matchedTime
                MatchedType   = $matchedType
                MatchedSource = $matchedSource
                TimeDifference = $timeDifference
                Confidence    = $confidence
            }
            
            $matches.Add($match)
        }
        
        Write-DebugInfo "Total matches found: $($matches.Count)"
        return $matches.ToArray()
    }
    catch {
        Write-DebugInfo "Match-SessionsWithIPs error: ${_}"
        return @()
    }
}

<#
.SYNOPSIS
    Performs comprehensive RDP analysis
.DESCRIPTION
    Collects sessions, connections, and performs IP matching
#>
function Get-RdpAnalysis {
    [CmdletBinding()]
    [OutputType([AnalysisResult])]
    param(
        [Parameter()]
        [int]$HoursBack = $Script:Config.EventLogHoursBack,
        
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [switch]$UseQwinsta = $true,
        
        [Parameter()]
        [switch]$UseNetstat = $true,
        
        [Parameter()]
        [switch]$ForceAdmin = $false
    )
    
    try {
        Write-DebugInfo "Starting RDP analysis"
        
        $result = [AnalysisResult]::new()
        $result.ComputerName = ${ComputerName}
        
        Write-DebugInfo "Collecting RDP connections"
        $connections = Get-AllRdpConnections -HoursBack ${HoursBack} -ComputerName ${ComputerName} -ForceAdmin:${ForceAdmin}
        $result.Connections = $connections
        
        Write-DebugInfo "Getting current RDP sessions"
        $sessions = Get-CurrentRDPSessions -ComputerName ${ComputerName} -UseQwinsta:${UseQwinsta}
        $result.Sessions = $sessions
        
        if ($Script:Config.EnableIPMapping -and $sessions.Count -gt 0 -and $connections.Count -gt 0) {
            Write-DebugInfo "Matching sessions with IP addresses"
            $matches = Match-SessionsWithIPs -Sessions $sessions -Connections $connections -TimeWindowHours $Script:Config.TimeWindowHours
            $result.Matches = $matches
        }
        
        $result.CalculateStatistics()
        
        Write-DebugInfo "Analysis completed successfully"
        return $result
    }
    catch {
        Write-DebugInfo "Get-RdpAnalysis error: ${_}"
        return $null
    }
}

<#
.SYNOPSIS
    Formats analysis results as table output
.DESCRIPTION
    Creates formatted table output for console display with session ID column
#>
function Format-TableOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result
    )
    
    $output = [StringBuilder]::new()
    
    if (-not $Quiet) {
        [void]$output.AppendLine("╔══════════════════════════════════════════════════════════════════╗")
        [void]$output.AppendLine("║               RDP SESSION ANALYSIS REPORT                       ║")
        [void]$output.AppendLine("║                     $(Get-Date -Format 'HH:mm:ss dd.MM.yyyy')                       ║")
        [void]$output.AppendLine("╚══════════════════════════════════════════════════════════════════╝`n")
    }
    
    [void]$output.AppendLine("STATISTICS:")
    [void]$output.AppendLine("===========")
    [void]$output.AppendLine("Total Sessions:     $($Result.Statistics.TotalSessions)")
    [void]$output.AppendLine("Total Connections:  $($Result.Statistics.TotalConnections)")
    [void]$output.AppendLine("Matched Sessions:   $($Result.Statistics.MatchedSessions)")
    [void]$output.AppendLine("Active Sessions:    $($Result.Statistics.ActiveSessions)")
    [void]$output.AppendLine("RDP Sessions:       $($Result.Statistics.RDPSessions)")
    [void]$output.AppendLine("Console Sessions:   $($Result.Statistics.ConsoleSessions)")
    [void]$output.AppendLine("Unique IPs:         $($Result.Statistics.UniqueIPs)")
    [void]$output.AppendLine("Internal IPs:       $($Result.Statistics.InternalIPs)")
    [void]$output.AppendLine("External IPs:       $($Result.Statistics.ExternalIPs)`n")
    
    if ($Result.Sessions.Count -gt 0) {
        [void]$output.AppendLine("CURRENT RDP SESSIONS:")
        [void]$output.AppendLine("=====================")
        
        $sessionTable = $Result.Sessions | ForEach-Object {
            [PSCustomObject]@{
                Session   = $_.SessionName
                Username  = $_.UserName
                ID        = $_.SessionId
                State     = $_.State
                Type      = $_.Type
                Current   = if ($_.IsCurrent) { '►' } else { '' }
                IP        = if ($_.IPAddress) { Format-IPForDisplay $_.IPAddress } else { 'N/A' }
                Source    = $_.Source
            }
        }
        
        [void]$output.AppendLine(($sessionTable | Format-Table -AutoSize | Out-String))
    } else {
        [void]$output.AppendLine("CURRENT RDP SESSIONS: No active sessions found`n")
    }
    
    if ($Result.Matches.Count -gt 0) {
        [void]$output.AppendLine("MATCHED SESSIONS WITH IP ADDRESSES:")
        [void]$output.AppendLine("==================================")
        
        $matchTable = $Result.Matches | ForEach-Object {
            [PSCustomObject]@{
                Session      = $_.SessionName
                Username     = $_.Username
                ID           = $_.SessionId
                SessionState = $_.SessionState
                Type         = $_.SessionType
                MatchedIP    = Format-IPForDisplay $_.MatchedIP
                TimeDiff     = if ($_.TimeDifference) { "$($_.TimeDifference) min" } else { 'N/A' }
                Confidence   = $_.Confidence
                Source       = $_.MatchedSource
            }
        }
        
        [void]$output.AppendLine(($matchTable | Format-Table -AutoSize | Out-String))
    }

# Build quick lookup from current sessions for resolving SessionId in RECENT block.
# We index by two keys:
#   1) exact user name as returned by qwinsta (may include domain)
#   2) short user name (part after '\'), lowercased
$sessionIndex = @{}

foreach ($s in $Result.Sessions) {
    # Try to derive a reasonable "identity" for the session
    $names = @()

    if (-not [string]::IsNullOrWhiteSpace($s.UserName)) {
        $names += $s.UserName
        $names += ($s.UserName -split '\\')[-1]
    }

    if (-not [string]::IsNullOrWhiteSpace($s.SessionName)) {
        $names += $s.SessionName
    }

    foreach ($n in $names) {
        $key = $n.ToLower()
        if (-not $sessionIndex.ContainsKey($key)) {
            $sessionIndex[$key] = $s.SessionId
        }
    }
}

if ($Result.Connections.Count -gt 0) {
    [void]$output.AppendLine("RECENT RDP CONNECTIONS (Last ${HoursBack} hours):")
    [void]$output.AppendLine("==============================================")

    $connectionTable = $Result.Connections |
        Sort-Object Time -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            # 1) Prefer explicit QwinstaSessionID if it was resolved earlier
            $qwinstaId = if ($_.QwinstaSessionID -and $_.QwinstaSessionID -ne 'N/A') {
                $_.QwinstaSessionID
            } else {
                $null
            }

            # 2) Try to resolve SessionId from current qwinsta snapshot by username
            $lookupId = $null
            if (-not $qwinstaId -and $_.User) {
                $fullUser  = $_.User
                $shortUser = ($fullUser -split '\\')[-1]

                $fullKey  = $fullUser.ToLower()
                $shortKey = $shortUser.ToLower()

                if ($sessionIndex.ContainsKey($fullKey)) {
                    $lookupId = $sessionIndex[$fullKey]
                }
                elseif ($sessionIndex.ContainsKey($shortKey)) {
                    $lookupId = $sessionIndex[$shortKey]
                }
            }

            [pscustomobject]@{
                Time      = $_.Time.ToString('HH:mm:ss dd.MM')
                User      = $_.User
                IP        = Format-IPForDisplay -IP $_.IP
                Type      = $_.Type
                EventID   = $_.EventID
                SessionID = if ($qwinstaId) {
                                $qwinstaId
                            }
                            elseif ($lookupId) {
                                $lookupId
                            }
                            else {
                                'N/A'
                            }
                Source    = $_.Source
                Active    = if ($_.IsActive) { 'Yes' } else { 'No' }
            }
        }

    $tableString = $connectionTable |
        Format-Table -AutoSize -Property Time, User, IP, Type, EventID, SessionID, Source, Active |
        Out-String

    [void]$output.AppendLine($tableString)
}    
    return $output.ToString()
}

<#
.SYNOPSIS
    Formats analysis results as list output
.DESCRIPTION
    Creates formatted list output for console display with proper variable interpolation
#>
function Format-ListOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result
    )
    
    $output = [StringBuilder]::new()
    
    [void]$output.AppendLine("RDP SESSION ANALYSIS REPORT")
    [void]$output.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$output.AppendLine("Computer:  $($Result.ComputerName)")
    [void]$output.AppendLine("=" * 60)
    [void]$output.AppendLine()
    
    [void]$output.AppendLine("STATISTICS:")
    foreach ($stat in $Result.Statistics.GetEnumerator()) {
        [void]$output.AppendLine("  $($stat.Key): $($stat.Value)")
    }
    [void]$output.AppendLine()
    
    if ($Result.Sessions.Count -gt 0) {
        [void]$output.AppendLine("SESSIONS:")
        foreach ($session in $Result.Sessions) {
            [void]$output.AppendLine("  • Session $($session.SessionId)")
            [void]$output.AppendLine("    Name:    $($session.SessionName)")
            [void]$output.AppendLine("    User:    $($session.UserName)")
            [void]$output.AppendLine("    State:   $($session.State)")
            [void]$output.AppendLine("    Type:    $($session.Type)")
            [void]$output.AppendLine("    IP:      $(if ($session.IPAddress) { Format-IPForDisplay $session.IPAddress } else { 'N/A' })")
            [void]$output.AppendLine("    Source:  $($session.Source)")
            if ($session.IsCurrent) {
                [void]$output.AppendLine("    Current: Yes")
            }
            [void]$output.AppendLine()
        }
    } else {
        [void]$output.AppendLine("SESSIONS: No active sessions found`n")
    }
    
    if ($Result.Matches.Count -gt 0) {
        [void]$output.AppendLine("IP MATCHES:")
        foreach ($match in $Result.Matches) {
            [void]$output.AppendLine("  • $($match.SessionName) ($($match.Username))")
            [void]$output.AppendLine("    Session ID: $($match.SessionId)")
            [void]$output.AppendLine("    State:      $($match.SessionState)")
            [void]$output.AppendLine("    Type:       $($match.SessionType)")
            [void]$output.AppendLine("    Matched IP: $(Format-IPForDisplay $match.MatchedIP)")
            [void]$output.AppendLine("    Confidence: $($match.Confidence)")
            [void]$output.AppendLine("    Source:     $($match.MatchedSource)")
            if ($match.TimeDifference) {
                [void]$output.AppendLine("    Time Diff:  $($match.TimeDifference) min")
            }
            [void]$output.AppendLine()
        }
    }
    
    if ($Result.Connections.Count -gt 0) {
        [void]$output.AppendLine("RECENT RDP CONNECTIONS:")
        foreach ($conn in $Result.Connections | Select-Object -First 10) {
            [void]$output.AppendLine("  • $($conn.Time.ToString('yyyy-MM-dd HH:mm:ss'))")
            [void]$output.AppendLine("    User:      $($conn.User)")
            [void]$output.AppendLine("    IP:        $(Format-IPForDisplay $conn.IP)")
            [void]$output.AppendLine("    Type:      $($conn.Type)")
            [void]$output.AppendLine("    Event ID:  $($conn.EventID)")
            [void]$output.AppendLine("    Session ID: $(if ($conn.QwinstaSessionID -and $conn.QwinstaSessionID -ne 'N/A') { $conn.QwinstaSessionID } else { 'N/A' })")
            [void]$output.AppendLine("    Source:    $($conn.Source)")
            [void]$output.AppendLine("    Active:    $(if ($conn.IsActive) { 'Yes' } else { 'No' })")
            [void]$output.AppendLine()
        }
    }
    
    return $output.ToString()
}

<#
.SYNOPSIS
    Formats analysis results as text output
.DESCRIPTION
    Creates simple text output (alias for List output)
#>
function Format-TextOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result
    )
    
    return Format-ListOutput -Result $Result
}

<#
.SYNOPSIS
    Formats analysis results as markdown
.DESCRIPTION
    Creates markdown formatted output with badges and tables
#>
function Format-MarkdownOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result
    )
    
    $output = [StringBuilder]::new()
    
    [void]$output.AppendLine("# RDP Session Analysis Report")
    [void]$output.AppendLine()
    [void]$output.AppendLine("**Computer:** $($Result.ComputerName)  ")
    [void]$output.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  ")
    [void]$output.AppendLine("**Analysis Time:** $($Result.AnalysisTime.ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$output.AppendLine()
    
    [void]$output.AppendLine("## Statistics")
    [void]$output.AppendLine()
    [void]$output.AppendLine("| Metric | Value |")
    [void]$output.AppendLine("|--------|-------|")
    foreach ($stat in $Result.Statistics.GetEnumerator()) {
        [void]$output.AppendLine("| $($stat.Key) | $($stat.Value) |")
    }
    [void]$output.AppendLine()
    
    if ($Result.Sessions.Count -gt 0) {
        [void]$output.AppendLine("## Current Sessions")
        [void]$output.AppendLine()
        [void]$output.AppendLine("| Session | User | ID | State | Type | IP | Current | Source |")
        [void]$output.AppendLine("|---------|------|----|-------|------|----|---------|--------|")
        
        foreach ($session in $Result.Sessions) {
            $currentMark = if ($session.IsCurrent) { '►' } else { '' }
            $ipDisplay = if ($session.IPAddress) { Format-IPForDisplay $session.IPAddress } else { 'N/A' }
            [void]$output.AppendLine("| $($session.SessionName) | $($session.UserName) | $($session.SessionId) | $($session.State) | $($session.Type) | $ipDisplay | $currentMark | $($session.Source) |")
        }
        [void]$output.AppendLine()
    }
    
    if ($Result.Matches.Count -gt 0) {
        [void]$output.AppendLine("## IP Matches")
        [void]$output.AppendLine()
        [void]$output.AppendLine("| Session | User | ID | State | Type | IP | Confidence | Source |")
        [void]$output.AppendLine("|---------|------|----|-------|------|----|------------|--------|")
        
        foreach ($match in $Result.Matches) {
            $ipDisplay = Format-IPForDisplay $match.MatchedIP
            $confidenceBadge = switch ($match.Confidence) {
                'High' { '🟢' }
                'Medium' { '🟡' }
                'Low' { '🔴' }
                default { '⚪' }
            }
            [void]$output.AppendLine("| $($match.SessionName) | $($match.Username) | $($match.SessionId) | $($match.SessionState) | $($match.SessionType) | $ipDisplay | $confidenceBadge $($match.Confidence) | $($match.MatchedSource) |")
        }
        [void]$output.AppendLine()
    }
    
    [void]$output.AppendLine("---")
    [void]$output.AppendLine("*Generated by RDP Session Analyzer Pro v3.0.1*  ")
    [void]$output.AppendLine("*Author: Mikhail Deynekin [deynekin.com]*  ")
    [void]$output.AppendLine("*Repository: https://github.com/paulmann/1st-Remote-Session-Manager-Pro/*")
    
    return $output.ToString()
}

<#
.SYNOPSIS
    Reads HTML template from file and replaces placeholders with actual data
.DESCRIPTION
    Uses template-based approach for HTML generation with proper variable substitution
#>
function Format-HtmlOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result,
        
        [Parameter()]
        [int]$HoursBack = 24
    )
    
    try {
        # Read template from file
        $templatePath = $Script:Config.HtmlTemplatePath
        Write-DebugInfo "Loading HTML template from: ${templatePath}"
        
        if (-not (Test-Path $templatePath)) {
            Write-Warning "HTML template not found at ${templatePath}. Using fallback template."
            return Get-FallbackHtml -Result $Result -HoursBack $HoursBack
        }
        
        $template = Get-Content $templatePath -Raw -Encoding UTF8
        
        # Replace global placeholders
        $replacements = @{
            '{ComputerName}' = $Result.ComputerName
            '{CurrentTime}' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            '{AnalysisTime}' = $Result.AnalysisTime.ToString('HH:mm:ss')
            '{HoursBack}' = $HoursBack
            '{TotalSessions}' = $Result.Statistics.TotalSessions
            '{ActiveSessions}' = $Result.Statistics.ActiveSessions
            '{MatchedSessions}' = $Result.Statistics.MatchedSessions
            '{UniqueIPs}' = $Result.Statistics.UniqueIPs
            '{RDPSessions}' = $Result.Statistics.RDPSessions
            '{ConsoleSessions}' = $Result.Statistics.ConsoleSessions
            '{InternalIPs}' = $Result.Statistics.InternalIPs
            '{ExternalIPs}' = $Result.Statistics.ExternalIPs
            '{TotalConnections}' = $Result.Statistics.TotalConnections
            '{HighConfidence}' = $Result.Statistics.HighConfidence
            '{MediumConfidence}' = $Result.Statistics.MediumConfidence
            '{LowConfidence}' = $Result.Statistics.LowConfidence
        }
        
        foreach ($key in $replacements.Keys) {
            $template = $template.Replace($key, $replacements[$key])
        }
        
        # Generate sessions table if sessions exist
        if ($Result.Sessions.Count -gt 0) {
            $sessionsHtml = [StringBuilder]::new()
            foreach ($session in $Result.Sessions) {
                $stateColor = switch ($session.State.ToString()) {
                    'Active' { 'text-green-600 bg-green-50' }
                    'Disconnected' { 'text-red-600 bg-red-50' }
                    'Listening' { 'text-yellow-600 bg-yellow-50' }
                    default { 'text-gray-600 bg-gray-50' }
                }
                
                $typeColor = switch ($session.Type.ToString()) {
                    'RDP' { 'text-blue-600 bg-blue-50' }
                    'Console' { 'text-purple-600 bg-purple-50' }
                    'Services' { 'text-gray-600 bg-gray-50' }
                    default { 'text-gray-600 bg-gray-50' }
                }
                
                $ipClass = 'ip-internal'
                $ipDisplay = 'N/A'
                
                if ($session.IPAddress -and $session.IPAddress -ne 'N/A') {
                    if ($session.Type -eq [SessionType]::Console) {
                        $ipClass = 'console-ip'
                        $ipDisplay = "CONSOLE: $($session.IPAddress)"
                    } elseif (IsInternalIP $session.IPAddress) {
                        $ipClass = 'ip-internal'
                        $ipDisplay = "INT: $($session.IPAddress)"
                    } else {
                        $ipClass = 'ip-external'
                        $ipDisplay = "EXT: $($session.IPAddress)"
                    }
                }
                
                $currentIcon = if ($session.IsCurrent) { '<i class="fas fa-play-circle text-green-500 ml-1" title="Current Session"></i>' } else { '' }
                
                [void]$sessionsHtml.AppendLine(@"
<tr class="table-row $(if ($session.IsCurrent) { 'current-session' } else { '' })">
    <td class="px-6 py-4 whitespace-nowrap">
        <div class="flex items-center">
            <div class="ml-4">
                <div class="text-sm font-medium text-gray-900">$($session.SessionName)</div>
                <div class="text-sm text-gray-500">Source: $($session.Source)</div>
            </div>
        </div>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <div class="text-sm text-gray-900">$($session.UserName)</div>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-primary-100 text-primary-800">
            $($session.SessionId)
        </span>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full $stateColor">
            $($session.State)
        </span>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full $typeColor">
            $($session.Type)$currentIcon
        </span>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <span class="$ipClass text-sm">
            $ipDisplay
        </span>
    </td>
    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        $($session.Timestamp.ToString('HH:mm:ss'))
    </td>
</tr>
"@)
            }
            $template = $template.Replace('<!-- SESSIONS_ROWS -->', $sessionsHtml.ToString())
        } else {
            $template = $template.Replace('<!-- SESSIONS_ROWS -->', 
                '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">No active sessions found</td></tr>')
        }
        
        # Generate matches table if matches exist
        if ($Result.Matches.Count -gt 0) {
            $matchesHtml = [StringBuilder]::new()
            foreach ($match in $Result.Matches) {
                $confidenceBadge = switch ($match.Confidence) {
                    'High' { '<span class="badge badge-high"><i class="fas fa-check-circle mr-1"></i>High</span>' }
                    'Medium' { '<span class="badge badge-medium"><i class="fas fa-exclamation-triangle mr-1"></i>Medium</span>' }
                    'Low' { '<span class="badge badge-low"><i class="fas fa-exclamation-circle mr-1"></i>Low</span>' }
                    default { '<span class="badge badge-none"><i class="fas fa-question-circle mr-1"></i>None</span>' }
                }
                
                $ipClass = 'ip-internal'
                $ipDisplay = 'N/A'
                
                if ($match.MatchedIP -and $match.MatchedIP -ne 'N/A') {
                    if ($match.SessionType -eq 'Console') {
                        $ipClass = 'console-ip'
                        $ipDisplay = "CONSOLE: $($match.MatchedIP)"
                    } elseif (IsInternalIP $match.MatchedIP) {
                        $ipClass = 'ip-internal'
                        $ipDisplay = "INT: $($match.MatchedIP)"
                    } else {
                        $ipClass = 'ip-external'
                        $ipDisplay = "EXT: $($match.MatchedIP)"
                    }
                }
                
                $timeDiff = if ($match.TimeDifference) { "$([math]::Round($match.TimeDifference, 1)) min" } else { 'N/A' }
                
                [void]$matchesHtml.AppendLine(@"
<tr class="table-row">
    <td class="px-6 py-4 whitespace-nowrap">
        <div class="text-sm font-medium text-gray-900">$($match.SessionName)</div>
        <div class="text-sm text-gray-500">$($match.SessionType)</div>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <div class="text-sm text-gray-900">$($match.Username)</div>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <span class="px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">
            $($match.SessionId)
        </span>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        <span class="$ipClass">
            $ipDisplay
        </span>
    </td>
    <td class="px-6 py-4 whitespace-nowrap">
        $confidenceBadge
    </td>
    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        $($match.MatchedSource)
    </td>
    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        $timeDiff
    </td>
</tr>
"@)
            }
            $template = $template.Replace('<!-- MATCHES_ROWS -->', $matchesHtml.ToString())
        } else {
            $template = $template.Replace('<!-- MATCHES_ROWS -->', 
                '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">No IP matches found</td></tr>')
        }
        
        # Generate connections cards
        if ($Result.Connections.Count -gt 0) {
            $connectionsHtml = [StringBuilder]::new()
            $recentConnections = $Result.Connections | Sort-Object Time -Descending | Select-Object -First 9
            
            foreach ($conn in $recentConnections) {
                $icon = switch ($conn.Type) {
                    'Logon' { 'fas fa-sign-in-alt text-green-500' }
                    'Disconnect' { 'fas fa-sign-out-alt text-red-500' }
                    'Reconnect' { 'fas fa-redo-alt text-blue-500' }
                    'Active Connection' { 'fas fa-plug text-yellow-500' }
                    default { 'fas fa-link text-gray-500' }
                }
                
                $ipDisplay = Format-IPForDisplay $conn.IP
                $ipClass = if ($ipDisplay -match '^INT:') { 'ip-internal' } else { 'ip-external' }
                $rowClass = if ($conn.IsActive) { 'bg-green-100 text-green-800' } else { 'bg-gray-100 text-gray-800' }
                $StatusText = if ($conn.IsActive) { 'Active' } else { 'Historical' }
                $sessionIdDisplay = if ($conn.QwinstaSessionID -and $conn.QwinstaSessionID -ne 'N/A') { $conn.QwinstaSessionID } else { 'N/A' }
                $EventIDText = if ($conn.EventID -ne 0) { "<div class='flex items-center'><i class='fas fa-id-badge text-gray-400 mr-3 w-5'></i><span class='text-gray-700'>Event ID: $($conn.EventID)</span></div>" } else { '' }
                $SessionIDText = if ($sessionIdDisplay -ne 'N/A') { "<div class='flex items-center'><i class='fas fa-hashtag text-gray-400 mr-3 w-5'></i><span class='text-gray-700'>Session ID: $sessionIdDisplay</span></div>" } else { '' }

                [void]$connectionsHtml.AppendLine(@"
<div class="bg-white rounded-xl shadow-md p-6 border border-gray-100 hover:shadow-lg transition-shadow duration-200">
    <div class="flex items-start justify-between mb-4">
        <div>
            <div class="flex items-center mb-2">
                <i class="$icon text-xl mr-3"></i>
                <h3 class="text-lg font-semibold text-gray-800">$($conn.Type)</h3>
            </div>
            <p class="text-sm text-gray-500">$($conn.Time.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        </div>
        <span class="px-3 py-1 text-xs font-semibold rounded-full $rowClass">
            $StatusText
        </span>
    </div>
    
    <div class="space-y-3">
        <div class="flex items-center">
            <i class="fas fa-user text-gray-400 mr-3 w-5"></i>
            <span class="text-gray-700">$($conn.User)</span>
        </div>
        <div class="flex items-center">
            <i class="fas fa-ip-address text-gray-400 mr-3 w-5"></i>
            <span class="$ipClass">$ipDisplay</span>
        </div>
        <div class="flex items-center">
            <i class="fas fa-database text-gray-400 mr-3 w-5"></i>
            <span class="text-gray-700">Source: $($conn.Source)</span>
        </div>
        $EventIDText
        $SessionIDText
    </div>
</div>
"@)
            }
            $template = $template.Replace('<!-- CONNECTIONS_CARDS -->', $connectionsHtml.ToString())
            $template = $template.Replace('{ConnectionsCount}', $recentConnections.Count.ToString())
            $template = $template.Replace('{TotalConnectionsCount}', $Result.Connections.Count.ToString())
        } else {
            $template = $template.Replace('<!-- CONNECTIONS_CARDS -->', 
                '<div class="col-span-3 text-center py-8 text-gray-500">No recent connections found</div>')
        }
        
        return $template
    }
    catch {
        Write-DebugInfo "Error generating HTML from template: ${_}"
        return Get-FallbackHtml -Result $Result -HoursBack $HoursBack
    }
}

<#
.SYNOPSIS
    Provides fallback HTML when template is not available
.DESCRIPTION
    Generates basic HTML output when template file is missing
#>
function Get-FallbackHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result,
        
        [Parameter()]
        [int]$HoursBack = 24
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RDP Session Analysis Report - $($Result.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .stat-card { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .table th { background-color: #3498db; color: white; }
        .ip-int { background: #d6eaf8; color: #1b4f72; padding: 2px 5px; border-radius: 3px; }
        .ip-ext { background: #fcf3cf; color: #7d6608; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>RDP Session Analysis Report</h1>
        <p>Computer: $($Result.ComputerName)</p>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <h2>Statistics</h2>
    <div class="stat-card">
        Total Sessions: $($Result.Statistics.TotalSessions) | 
        Active Sessions: $($Result.Statistics.ActiveSessions) | 
        Total Connections: $($Result.Statistics.TotalConnections) | 
        Unique IPs: $($Result.Statistics.UniqueIPs)
    </div>
    
    <h2>Recent RDP Connections (Last ${HoursBack} hours)</h2>
    <table class="table">
        <thead>
            <tr>
                <th>Time</th>
                <th>User</th>
                <th>IP Address</th>
                <th>Type</th>
                <th>Session ID</th>
                <th>Source</th>
                <th>Active</th>
            </tr>
        </thead>
        <tbody>
"@

    if ($Result.Connections.Count -gt 0) {
        foreach ($conn in $Result.Connections | Sort-Object Time -Descending | Select-Object -First 10) {
            $ipDisplay = Format-IPForDisplay $conn.IP
            $ipClass = if ($ipDisplay -match '^INT:') { 'ip-int' } else { 'ip-ext' }
            $sessionIdDisplay = if ($conn.QwinstaSessionID -and $conn.QwinstaSessionID -ne 'N/A') { $conn.QwinstaSessionID } else { 'N/A' }
            
            $html += @"
            <tr>
                <td>$($conn.Time.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                <td>$($conn.User)</td>
                <td><span class="$ipClass">$ipDisplay</span></td>
                <td>$($conn.Type)</td>
                <td>$sessionIdDisplay</td>
                <td>$($conn.Source)</td>
                <td>$(if ($conn.IsActive) { 'Yes' } else { 'No' })</td>
            </tr>
"@
        }
    } else {
        $html += '<tr><td colspan="7" style="text-align: center;">No connections found</td></tr>'
    }
    
    $html += @"
        </tbody>
    </table>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #7f8c8d;">
        <p>Generated by RDP Session Analyzer Pro v3.0.1</p>
        <p>Author: Mikhail Deynekin [deynekin.com]</p>
        <p>Repository: https://github.com/paulmann/1st-Remote-Session-Manager-Pro/</p>
    </div>
</body>
</html>
"@
    
    return $html
}

<#
.SYNOPSIS
    Exports analysis results to various formats
.DESCRIPTION
    Handles export to multiple formats including JSON, CSV, XML, HTML, etc.
#>
function Export-AnalysisResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AnalysisResult]$Result,
        
        [Parameter(Mandatory)]
        [ValidateSet('Table', 'List', 'Json', 'Csv', 'Xml', 'Html', 'Text', 'Yaml', 'Markdown', 'PSObject', 'PSXml')]
        [string]$Format,
        
        [Parameter()]
        [string]$Path,
        
        [Parameter()]
        [switch]$Clipboard,
        
        [Parameter()]
        [switch]$Quiet,
        
        [Parameter()]
        [int]$HoursBack = 24
    )
    
    try {
        Write-DebugInfo "Exporting analysis result in format: ${Format}"
        
        $content = $null
        
        switch ($Format) {
            'Table' {
                $content = Format-TableOutput -Result $Result
            }
            
            'List' {
                $content = Format-ListOutput -Result $Result
            }
            
            'Text' {
                $content = Format-TextOutput -Result $Result
            }
            
            'Markdown' {
                $content = Format-MarkdownOutput -Result $Result
            }
            
            'Html' {
                $content = Format-HtmlOutput -Result $Result -HoursBack $HoursBack
            }
            
            'Json' {
                $content = $Result.ToHashtable() | ConvertTo-Json -Depth 10
            }
            
            'Csv' {
                $allData = [List[PSCustomObject]]::new()
                
                foreach ($session in $Result.Sessions) {
                    $allData.Add([PSCustomObject]@{
                        DataType = 'Session'
                        SessionName = $session.SessionName
                        UserName = $session.UserName
                        SessionId = $session.SessionId
                        State = $session.State.ToString()
                        Type = $session.Type.ToString()
                        IsCurrent = $session.IsCurrent
                        Source = $session.Source
                        IPAddress = $session.IPAddress
                        Timestamp = $session.Timestamp.ToString('o')
                    })
                }
                
                foreach ($conn in $Result.Connections) {
                    $allData.Add([PSCustomObject]@{
                        DataType = 'Connection'
                        Time = $conn.Time.ToString('o')
                        EventID = $conn.EventID
                        User = $conn.User
                        IP = $conn.IP
                        SessionID = $conn.SessionID
                        QwinstaSessionID = $conn.QwinstaSessionID
                        Type = $conn.Type
                        Source = $conn.Source
                        IsActive = $conn.IsActive
                    })
                }
                
                foreach ($match in $Result.Matches) {
                    $allData.Add([PSCustomObject]@{
                        DataType = 'Match'
                        SessionName = $match.SessionName
                        Username = $match.Username
                        SessionId = $match.SessionId
                        SessionState = $match.SessionState
                        SessionType = $match.SessionType
                        SessionTime = $match.SessionTime.ToString('o')
                        MatchedIP = $match.MatchedIP
                        MatchedTime = if ($match.MatchedTime) { $match.MatchedTime.Value.ToString('o') } else { $null }
                        MatchedType = $match.MatchedType
                        MatchedSource = $match.MatchedSource
                        TimeDifference = $match.TimeDifference
                        Confidence = $match.Confidence
                    })
                }
                
                $content = $allData | ConvertTo-Csv -NoTypeInformation
            }
            
            'Xml' {
                $content = $Result.ToHashtable() | ConvertTo-Xml -Depth 10 -NoTypeInformation
            }
            
            'Yaml' {
                if (Get-Module -ListAvailable -Name PowerShell-Yaml) {
                    Import-Module PowerShell-Yaml -ErrorAction SilentlyContinue
                    $content = $Result.ToHashtable() | ConvertTo-Yaml
                }
                else {
                    Write-Warning "PowerShell-Yaml module required for YAML export. Install with: Install-Module PowerShell-Yaml"
                    return $false
                }
            }
            
            'PSObject' {
                $content = $Result.ToPSObject()
            }
            
            'PSXml' {
                $tempPath = [System.IO.Path]::GetTempFileName()
                $Result.ToPSObject() | Export-Clixml -Path $tempPath -Depth 10
                $content = Get-Content $tempPath -Raw
                Remove-Item $tempPath -Force
            }
        }
        
        if ($null -eq $content) {
            Write-Error "Failed to generate content in format: ${Format}"
            return $false
        }
        
        if ($Clipboard) {
            if ($Format -in @('PSObject', 'PSXml')) {
                Write-Warning "Clipboard export not supported for ${Format} format"
                return $false
            }
            
            Set-Clipboard $content
            if (-not $Quiet) {
                Write-Host "✓ ${Format} copied to clipboard" -ForegroundColor Green
            }
            return $true
        }
        elseif ($Path) {
            if ($Format -in @('PSObject', 'PSXml')) {
                $Result.ToPSObject() | Export-Clixml -Path $Path -Depth 10 -Force
            }
            else {
                $content | Set-Content -Path $Path -Encoding UTF8 -Force
            }
            
            if (-not $Quiet) {
                Write-Host "✓ Exported to ${Path}" -ForegroundColor Green
            }
            return $true
        }
        else {
            return $content
        }
    }
    catch {
        Write-DebugInfo "Export-AnalysisResult error: ${_}"
        return $false
    }
}

<#
.SYNOPSIS
    Gets comprehensive RDP analysis result
.DESCRIPTION
    Main function to perform RDP analysis and return results
.EXAMPLE
    Get-RdpAnalysisResult -HoursBack 48
    Get-RdpAnalysisResult -ComputerName "SERVER01" -UseQwinsta:$false
    Get-RdpAnalysisResult | Export-AnalysisResult -Format Json -Path "analysis.json"
#>
function Get-RdpAnalysisResult {
    [CmdletBinding()]
    [OutputType([AnalysisResult])]
    param(
        [Parameter()]
        [int]$HoursBack = $Script:Config.EventLogHoursBack,
        
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [switch]$UseQwinsta = $true,
        
        [Parameter()]
        [switch]$UseNetstat = $true,
        
        [Parameter()]
        [switch]$ForceAdmin = $false,
        
        [Parameter()]
        [switch]$Quiet
    )
    
    $result = Get-RdpAnalysis -HoursBack $HoursBack -ComputerName $ComputerName -UseQwinsta:$UseQwinsta -UseNetstat:$UseNetstat -ForceAdmin:$ForceAdmin
    
    if ($null -eq $result) {
        Write-Error "Failed to get RDP analysis result"
        return $null
    }
    
    if (-not $Quiet) {
        Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║               RDP ANALYSIS COMPLETED                           ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host "Summary:" -ForegroundColor Cyan
        Write-Host "  • Sessions found: $($result.Sessions.Count)" -ForegroundColor Gray
        Write-Host "  • Connections found: $($result.Connections.Count)" -ForegroundColor Gray
        Write-Host "  • IP matches: $(($result.Matches | Where-Object { $_.Confidence -ne 'None' }).Count)" -ForegroundColor Gray
        Write-Host "  • Analysis time: $($result.AnalysisTime.ToString('HH:mm:ss'))" -ForegroundColor Gray
    }
    
    return $result
}

<#
.SYNOPSIS
    Exports RDP analysis results to various formats
.DESCRIPTION
    Exports the complete RDP analysis to multiple formats including
    JSON, CSV, XML, HTML, Markdown, YAML, and PowerShell object formats.
.EXAMPLE
    Export-RdpAnalysis -Format Json -Path "analysis.json"
    Get-RdpAnalysisResult | Export-RdpAnalysis -Format Html -Path "report.html"
    Export-RdpAnalysis -Format Csv -Clipboard
#>
function Export-RdpAnalysis {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(ParameterSetName = 'File', Mandatory)]
        [Parameter(ParameterSetName = 'Clipboard')]
        [ValidateSet('Json', 'Csv', 'Xml', 'Html', 'Text', 'Yaml', 'Markdown', 'PSObject', 'PSXml')]
        [string]$Format = 'Json',
        
        [Parameter(ParameterSetName = 'File', Mandatory)]
        [string]$Path,
        
        [Parameter(ParameterSetName = 'Clipboard')]
        [switch]$Clipboard,
        
        [Parameter(ValueFromPipeline)]
        [AnalysisResult]$InputObject,
        
        [Parameter()]
        [switch]$Quiet,
        
        [Parameter()]
        [int]$HoursBack = 24
    )
    
    begin {
        $analysisResult = $null
    }
    
    process {
        if ($InputObject) {
            $analysisResult = $InputObject
        }
    }
    
    end {
        if (-not $analysisResult) {
            $analysisResult = Get-RdpAnalysisResult -Quiet:$true -HoursBack $HoursBack
        }
        
        if ($null -eq $analysisResult) {
            Write-Error "No analysis result to export"
            return $false
        }
        
        $params = @{
            Result   = $analysisResult
            Format   = $Format
            Quiet    = $Quiet
            HoursBack = $HoursBack
        }
        
        if ($Clipboard) {
            $params.Clipboard = $true
        }
        else {
            $params.Path = $Path
        }
        
        return Export-AnalysisResult @params
    }
}

<#
.SYNOPSIS
    Monitor RDP sessions in real-time
.DESCRIPTION
    Continuously monitors RDP sessions and displays changes in real-time.
    Useful for tracking session activity and detecting new connections.
.EXAMPLE
    Monitor-RdpSessions -Interval 5
    Monitor-RdpSessions -Interval 10 -MonitorCount 20
#>
function Monitor-RdpSessions {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Interval = 10,
        
        [Parameter()]
        [int]$MonitorCount = 0,
        
        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter()]
        [switch]$Quiet
    )
    
    $iteration = 0
    $previousSessions = @()
    $previousMatches = @()
    
    Clear-Host
    
    while ($true) {
        if ($MonitorCount -gt 0 -and $iteration -ge $MonitorCount) {
            break
        }
        
        $iteration++
        $currentTime = Get-Date -Format 'HH:mm:ss'
        
        Write-Host "`e[96m╔══════════════════════════════════════════════════════════════════╗`e[0m"
        Write-Host "`e[96m║           RDP SESSION MONITOR - ${currentTime}                      ║`e[0m"
        Write-Host "`e[96m║                    Iteration: ${iteration}                          ║`e[0m"
        Write-Host "`e[96m╚══════════════════════════════════════════════════════════════════╝`e[0m`n"
        
        $result = Get-RdpAnalysisResult -ComputerName $ComputerName -Quiet:$true
        
        if ($result -and $result.Sessions.Count -gt 0) {
            if ($previousSessions.Count -gt 0) {
                $newSessions = $result.Sessions | Where-Object { 
                    $_.SessionId -notin $previousSessions.SessionId 
                }
                
                $removedSessions = $previousSessions | Where-Object { 
                    $_.SessionId -notin $result.Sessions.SessionId 
                }
                
                if ($newSessions.Count -gt 0 -or $removedSessions.Count -gt 0) {
                    Write-Host "`e[93m[ Changes ]`e[0m" -ForegroundColor Yellow
                    
                    foreach ($new in $newSessions) {
                        Write-Host "  `e[92m+`e[0m Session $($new.SessionId) added: $($new.UserName) ($($new.SessionName))" -ForegroundColor Green
                    }
                    
                    foreach ($removed in $removedSessions) {
                        Write-Host "  `e[91m-`e[0m Session $($removed.SessionId) removed: $($removed.UserName) ($($removed.SessionName))" -ForegroundColor Red
                    }
                    
                    Write-Host ""
                }
            }
            
            Write-Host "`e[94m[ Current Sessions ]`e[0m" -ForegroundColor Cyan
            $result.Sessions | ForEach-Object {
                $color = if ($_.IsCurrent) { "`e[92m" } else { "`e[97m" }
                $typeColor = switch ($_.Type) {
                    'RDP' { "`e[94m" }
                    'Console' { "`e[93m" }
                    'Services' { "`e[90m" }
                    default { "`e[97m" }
                }
                
                $stateColor = switch ($_.State) {
                    'Active' { "`e[92m" }
                    'Disconnected' { "`e[91m" }
                    'Listening' { "`e[93m" }
                    default { "`e[97m" }
                }
                
                $currentMarker = if ($_.IsCurrent) { "`e[92m►`e[0m" } else { " " }
                
                $ipDisplay = if ($_.IPAddress) { 
                    if ($_.Type -eq 'Console') {
                        "CONSOLE: $($_.IPAddress)"
                    } else {
                        Format-IPForDisplay $_.IPAddress
                    }
                } else { 'N/A' }
                
                Write-Host ("{0} {1}{2,-15}`e[0m {3}{4,-15}`e[0m {5}{6,5}`e[0m {7}{8,-12}`e[0m {9}{10}`e[0m {11}`e[0m" -f 
                    $currentMarker,
                    $typeColor,
                    $_.SessionName,
                    $color,
                    $_.UserName,
                    "`e[95m",
                    $_.SessionId,
                    $stateColor,
                    $_.State,
                    $typeColor,
                    $_.Type,
                    $ipDisplay)
            }
            
            if ($result.Matches.Count -gt 0) {
                Write-Host "`n`e[94m[ IP Matches ]`e[0m" -ForegroundColor Cyan
                $result.Matches | ForEach-Object {
                    if ($_.Confidence -ne 'None') {
                        $confidenceColor = switch ($_.Confidence) {
                            'High' { "`e[92m" }
                            'Medium' { "`e[93m" }
                            'Low' { "`e[91m" }
                            default { "`e[97m" }
                        }
                        
                        $ipDisplay = if ($_.SessionType -eq 'Console') {
                            "CONSOLE: $($_.MatchedIP)"
                        } else {
                            Format-IPForDisplay $_.MatchedIP
                        }
                        
                        Write-Host "  ${confidenceColor}$($_.SessionName)`e[0m ($($_.Username)) -> ${ipDisplay} (${confidenceColor}$($_.Confidence)`e[0m)"
                    }
                }
            }
            
            $previousSessions = $result.Sessions
            $previousMatches = $result.Matches
        }
        else {
            Write-Host "`e[93mNo active RDP sessions found`e[0m" -ForegroundColor Yellow
        }
        
        Write-Host "`n`e[90m[ Auto-refresh in ${Interval}s | Ctrl+C to exit ]`e[0m`n"
        
        Start-Sleep -Seconds $Interval
        Clear-Host
    }
}

<#
.SYNOPSIS
    Test the RDP Analyzer functionality
.DESCRIPTION
    Runs comprehensive tests to verify all components of the RDP Analyzer
    are working correctly.
.EXAMPLE
    Test-RdpAnalyzer
    Test-RdpAnalyzer -All
#>
function Test-RdpAnalyzer {
    [CmdletBinding()]
    param(
        [switch]$All,
        [switch]$Connectivity,
        [switch]$Parsing,
        [switch]$Export,
        [switch]$Matching
    )
    
    $tests = [List[PSCustomObject]]::new()
    
    if (-not ($All -or $Connectivity -or $Parsing -or $Export -or $Matching)) {
        $All = $true
    }
    
    if ($All -or $Connectivity) {
        Write-Host "`n[ Connectivity Tests ]" -ForegroundColor Cyan
        
        try {
            $result = qwinsta 2>&1
            $tests.Add([PSCustomObject]@{
                Test    = 'qwinsta command'
                Result  = if ($result -and $result -notlike '*not recognized*') { 'PASS' } else { 'FAIL' }
                Details = if ($result -like '*not recognized*') { 'Command not found' } else { 'Available' }
            })
        }
        catch {
            $tests.Add([PSCustomObject]@{
                Test    = 'qwinsta command'
                Result  = 'FAIL'
                Details = $_.Exception.Message
            })
        }
        
        $isAdmin = Test-Administrator
        $tests.Add([PSCustomObject]@{
            Test    = 'Administrator privileges'
            Result  = if ($isAdmin) { 'PASS' } else { 'WARN' }
            Details = if ($isAdmin) { 'Running as administrator' } else { 'Limited functionality available' }
        })
    }
    
    if ($All -or $Parsing) {
        Write-Host "`n[ Parsing Tests ]" -ForegroundColor Cyan
        
        try {
            $sessions = Get-CurrentRDPSessions -UseQwinsta:$true
            $tests.Add([PSCustomObject]@{
                Test    = 'Session parsing'
                Result  = 'PASS'
                Details = "Found $($sessions.Count) sessions"
            })
        }
        catch {
            $tests.Add([PSCustomObject]@{
                Test    = 'Session parsing'
                Result  = 'FAIL'
                Details = $_.Exception.Message
            })
        }
        
        try {
            $connections = Get-AllRdpConnections -HoursBack 1
            $tests.Add([PSCustomObject]@{
                Test    = 'Connection parsing'
                Result  = 'PASS'
                Details = "Found $($connections.Count) connections"
            })
        }
        catch {
            $tests.Add([PSCustomObject]@{
                Test    = 'Connection parsing'
                Result  = 'FAIL'
                Details = $_.Exception.Message
            })
        }
        
        # Test console session IP detection
        try {
            $localIP = Get-LocalIPv4Address
            $tests.Add([PSCustomObject]@{
                Test    = 'Local IP detection'
                Result  = if ($localIP -and $localIP -ne 'N/A') { 'PASS' } else { 'WARN' }
                Details = if ($localIP -and $localIP -ne 'N/A') { "Local IP: ${localIP}" } else { 'Could not detect local IP' }
            })
        }
        catch {
            $tests.Add([PSCustomObject]@{
                Test    = 'Local IP detection'
                Result  = 'FAIL'
                Details = $_.Exception.Message
            })
        }
    }
    
    if ($All -or $Matching) {
        Write-Host "`n[ Matching Tests ]" -ForegroundColor Cyan
        
        try {
            $sessions = Get-CurrentRDPSessions -UseQwinsta:$true | Select-Object -First 3
            $connections = Get-AllRdpConnections -HoursBack 1 | Select-Object -First 5
            
            if ($sessions.Count -gt 0 -and $connections.Count -gt 0) {
                $matches = Match-SessionsWithIPs -Sessions $sessions -Connections $connections -TimeWindowHours 1
                $tests.Add([PSCustomObject]@{
                    Test    = 'IP matching'
                    Result  = 'PASS'
                    Details = "Generated $($matches.Count) matches"
                })
            }
            else {
                $tests.Add([PSCustomObject]@{
                    Test    = 'IP matching'
                    Result  = 'WARN'
                    Details = 'Insufficient data for matching test'
                })
            }
        }
        catch {
            $tests.Add([PSCustomObject]@{
                Test    = 'IP matching'
                Result  = 'FAIL'
                Details = $_.Exception.Message
            })
        }
    }
    
    if ($All -or $Export) {
        Write-Host "`n[ Export Tests ]" -ForegroundColor Cyan
        
        $tempDir = Join-Path $env:TEMP "rdp-analyzer-test-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        try {
            $result = Get-RdpAnalysisResult -Quiet:$true -HoursBack 1
            
            if ($result) {
                Export-RdpAnalysis -Result $result -Format Json -Path "${tempDir}\test.json" -Quiet
                $tests.Add([PSCustomObject]@{
                    Test    = 'JSON export'
                    Result  = if (Test-Path "${tempDir}\test.json") { 'PASS' } else { 'FAIL' }
                    Details = "${tempDir}\test.json"
                })
                
                Export-RdpAnalysis -Result $result -Format Csv -Path "${tempDir}\test.csv" -Quiet
                $tests.Add([PSCustomObject]@{
                    Test    = 'CSV export'
                    Result  = if (Test-Path "${tempDir}\test.csv") { 'PASS' } else { 'FAIL' }
                    Details = "${tempDir}\test.csv"
                })
                
                Export-RdpAnalysis -Result $result -Format Html -Path "${tempDir}\test.html" -Quiet
                $tests.Add([PSCustomObject]@{
                    Test    = 'HTML export'
                    Result  = if (Test-Path "${tempDir}\test.html") { 'PASS' } else { 'FAIL' }
                    Details = "${tempDir}\test.html"
                })
                
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                $tests.Add([PSCustomObject]@{
                    Test    = 'Export tests'
                    Result  = 'WARN'
                    Details = 'No data available for export tests'
                })
            }
        }
        catch {
            $tests.Add([PSCustomObject]@{
                Test    = 'Export tests'
                Result  = 'FAIL'
                Details = $_.Exception.Message
            })
        }
    }
    
    $tests | Format-Table -AutoSize
    
    $passed = ($tests | Where-Object { $_.Result -eq 'PASS' }).Count
    $warned = ($tests | Where-Object { $_.Result -eq 'WARN' }).Count
    $failed = ($tests | Where-Object { $_.Result -eq 'FAIL' }).Count
    $total = $tests.Count
    
    Write-Host "`nResults: ${passed}/${total} tests passed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } elseif ($failed -le 2) { 'Yellow' } else { 'Red' })
    
    if ($warned -gt 0) {
        Write-Host "Warnings: ${warned}" -ForegroundColor Yellow
    }
    
    if ($failed -gt 0) {
        Write-Host "Failures: ${failed}" -ForegroundColor Red
        return $false
    }
    
    return $true
}

# Main script execution
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($VerboseOutput) { $VerbosePreference = 'Continue' }
        if ($DebugMode) { 
            $Script:Config.DebugEnabled = $true
            $DebugPreference = 'Continue'
        }
        
        switch ($Command) {
            'Analyze' {
                $params = @{
                    HoursBack    = $HoursBack
                    ComputerName = $ComputerName
                    UseQwinsta   = $UseQwinsta
                    UseNetstat   = $UseNetstat
                    ForceAdmin   = $ForceAdmin
                    Quiet        = $Quiet
                }
                
                $result = Get-RdpAnalysisResult @params
                
                if ($result -and $Format -ne 'PSObject') {
                    $output = Export-AnalysisResult -Result $result -Format $Format -Quiet:$Quiet -HoursBack $HoursBack
                    if (-not $OutputFile -and -not $Clipboard) {
                        Write-Host $output
                    }
                }
                elseif ($result) {
                    return $result
                }
            }
            
            'Export' {
                if (-not $OutputFile -and -not $Clipboard) {
                    Write-Error "Export command requires either -OutputFile or -Clipboard parameter"
                    exit 1
                }
                
                $params = @{
                    Format = $Format
                    Quiet  = $Quiet
                    HoursBack = $HoursBack
                }
                
                if ($OutputFile) {
                    $params.Path = $OutputFile
                }
                
                if ($Clipboard) {
                    $params.Clipboard = $true
                }
                
                Export-RdpAnalysis @params
            }
            
            'Test' {
                Test-RdpAnalyzer -All
            }
            
            'Monitor' {
                Monitor-RdpSessions -Interval $Interval -MonitorCount $MonitorCount -ComputerName $ComputerName -Quiet:$Quiet
            }
            
            'Summary' {
                $result = Get-RdpAnalysisResult -HoursBack $HoursBack -ComputerName $ComputerName -Quiet:$true
                if ($result) {
                    $result.CalculateStatistics()
                    $result.Statistics | Format-List
                }
            }
            
            'GetSessions' {
                $sessions = Get-CurrentRDPSessions -ComputerName $ComputerName -UseQwinsta:$UseQwinsta
                return $sessions
            }
            
            'GetConnections' {
                $connections = Get-AllRdpConnections -HoursBack $HoursBack -ComputerName $ComputerName -ForceAdmin:$ForceAdmin
                return $connections
            }
        }
        
        if ($OutputFile -and $Command -eq 'Analyze' -and $result) {
            Export-AnalysisResult -Result $result -Format $Format -Path $OutputFile -Quiet:$Quiet -HoursBack $HoursBack
        }
        
        if ($Clipboard -and $Command -eq 'Analyze' -and $result) {
            Export-AnalysisResult -Result $result -Format $Format -Clipboard -Quiet:$Quiet -HoursBack $HoursBack
        }
    }
    catch {
        Write-Host "`e[91mError: $($_.Exception.Message)`e[0m" -ForegroundColor Red
        if ($DebugPreference -eq 'Continue') {
            Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
        }
        exit 1
    }
}
else {
    Write-Verbose "RDP Session Analyzer Pro loaded as module"
    
    $functionsToExport = @(
        'Get-RdpAnalysisResult',
        'Export-RdpAnalysis',
        'Monitor-RdpSessions',
        'Test-RdpAnalyzer',
        'Get-CurrentRDPSessions',
        'Get-AllRdpConnections',
        'Match-SessionsWithIPs',
        'Export-AnalysisResult',
        'Format-TableOutput',
        'Format-ListOutput',
        'Format-MarkdownOutput',
        'Format-HtmlOutput',
        'Get-LocalIPv4Address'
    )
    
    $classesToExport = @(
        'RdpSession',
        'RdpConnection',
        'RdpMatch',
        'AnalysisResult'
    )
    
    $moduleInfo = @{
        ModuleVersion     = '3.0.1'
        GUID              = 'f8a7b9c0-d1e2-4f3a-b5c6-d7e8f9a0b1c2'
        Author            = 'Mikhail Deynekin [deynekin.com]'
        CompanyName       = 'IT Department'
        Copyright         = '(c) 2025. All rights reserved.'
        Description       = 'Professional RDP Session Management and Analysis Module'
        PowerShellVersion = '7.0'
        FunctionsToExport = $functionsToExport
        VariablesToExport = 'Config'
    }
    
    New-Variable -Name Config -Value $Script:Config -Scope Script -Force
}