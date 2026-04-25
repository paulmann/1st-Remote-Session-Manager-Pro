#Requires -Version 7.0
# ==============================================================
# Author : Mikhail Deynekin (mid1977@gmail.com) | deynekin.com
# Project: Remote Session Manager Pro
# Script : qwinsta-en.ps1
# Desc   : Robust locale-independent session enumerator for PS7+
#          Default path: qwinsta parser + English state normalization
#          Optional path: WTS API (disabled by default because some PS7/
#                         Windows builds return WTSEnumerateSessionsW 1722)
# Version: 1.4.0 | 2026-04-25
# ==============================================================

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,

    [ValidateSet('Object','Table','JSON','CSV','List')]
    [string]$Format = 'Object',

    [ValidateSet('All','Active','Connected','Disconnected','Listen','Shadow','Idle','Reset','Down','Init')]
    [string]$State = 'All',

    [switch]$IncludeSystem,

    [Alias('DebugMode')]
    [switch]$WtsDebugMode,

    [switch]$UseWtsApi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-WtsDebug {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data
    )

    $callerDebug = $false
    try {
        $var = Get-Variable -Name DebugMode -ErrorAction SilentlyContinue
        if ($null -ne $var -and $var.Value -eq $true) { $callerDebug = $true }
    }
    catch {}

    if (-not ($WtsDebugMode -or $callerDebug)) { return }

    $ts = Get-Date -Format 'HH:mm:ss.fff'

    if (Get-Command 'Write-DebugLog' -ErrorAction SilentlyContinue) {
        if ($Data) { Write-DebugLog "[WTS][$Stage] $Message" DEBUG $Data }
        else { Write-DebugLog "[WTS][$Stage] $Message" DEBUG }
        return
    }

    Write-Host "$ts [WTS][$Stage] $Message" -ForegroundColor Cyan
    if ($Data) {
        foreach ($k in ($Data.Keys | Sort-Object)) {
            Write-Host (("    {0,-18} = {1}") -f $k, $Data[$k]) -ForegroundColor DarkCyan
        }
    }
}

$script:WtsApiAvailable = $false
if ($UseWtsApi) {
    if (-not ([System.Management.Automation.PSTypeName]'WtsNative.Api').Type) {
        try {
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WtsNative {
    public enum ConnectState : int {
        Active = 0,
        Connected = 1,
        ConnectQuery = 2,
        Shadow = 3,
        Disconnected = 4,
        Idle = 5,
        Listen = 6,
        Reset = 7,
        Down = 8,
        Init = 9
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SESSION_INFO_W {
        public uint SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    public class WtsSession {
        public int SessionId { get; set; }
        public string SessionName { get; set; }
        public string UserName { get; set; }
        public string Domain { get; set; }
        public string ClientName { get; set; }
        public ConnectState State { get; set; }
        public string StateText { get; set; }
    }

    public static class Api {
        private const int WTS_USERNAME = 5;
        private const int WTS_DOMAINNAME = 7;
        private const int WTS_CLIENTNAME = 10;

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool WTSEnumerateSessionsW(IntPtr hServer, uint Reserved, uint Version, out IntPtr ppSessionInfo, out uint pCount);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool WTSQuerySessionInformationW(IntPtr hServer, uint SessionId, int WTSInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode)]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr WTSOpenServerW(string pServerName);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSCloseServer(IntPtr hServer);

        private static string QueryStr(IntPtr hServer, uint sid, int cls) {
            IntPtr buf;
            uint len;
            if (!WTSQuerySessionInformationW(hServer, sid, cls, out buf, out len))
                return string.Empty;
            try { return Marshal.PtrToStringUni(buf) ?? string.Empty; }
            finally { if (buf != IntPtr.Zero) WTSFreeMemory(buf); }
        }

        public static WtsSession[] GetSessions(string computer) {
            string serverName = string.IsNullOrWhiteSpace(computer) ||
                                computer == "." ||
                                computer.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                                computer.Equals("127.0.0.1") ||
                                computer.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase)
                                ? Environment.MachineName
                                : computer;

            IntPtr hServer = WTSOpenServerW(serverName);
            if (hServer == IntPtr.Zero)
                throw new InvalidOperationException("WTSOpenServerW('" + serverName + "') failed, Win32Error=" + Marshal.GetLastWin32Error());
            try {
                IntPtr pInfo;
                uint count;
                if (!WTSEnumerateSessionsW(hServer, 0, 1, out pInfo, out count))
                    throw new InvalidOperationException("WTSEnumerateSessionsW failed, Win32Error=" + Marshal.GetLastWin32Error());
                try {
                    int sz = Marshal.SizeOf(typeof(SESSION_INFO_W));
                    var list = new List<WtsSession>((int)count);
                    for (uint i = 0; i < count; i++) {
                        var si = (SESSION_INFO_W)Marshal.PtrToStructure(new IntPtr(pInfo.ToInt64() + (long)i * sz), typeof(SESSION_INFO_W));
                        var cs = (ConnectState)si.State;
                        list.Add(new WtsSession {
                            SessionId = (int)si.SessionId,
                            SessionName = Marshal.PtrToStringUni(si.pWinStationName) ?? string.Empty,
                            UserName = QueryStr(hServer, si.SessionId, WTS_USERNAME),
                            Domain = QueryStr(hServer, si.SessionId, WTS_DOMAINNAME),
                            ClientName = QueryStr(hServer, si.SessionId, WTS_CLIENTNAME),
                            State = cs,
                            StateText = cs.ToString()
                        });
                    }
                    return list.ToArray();
                }
                finally { WTSFreeMemory(pInfo); }
            }
            finally { WTSCloseServer(hServer); }
        }
    }
}
'@ -ErrorAction Stop
            $script:WtsApiAvailable = $true
        }
        catch {
            $script:WtsApiAvailable = $false
            Write-WtsDebug -Stage 'Init' -Message 'WTS API Add-Type failed; fallback only' -Data @{ Error = $_.Exception.Message }
        }
    }
    else {
        $script:WtsApiAvailable = $true
    }
}

$script:WtsStateMap = [ordered]@{
    'Активно' = 'Active'; 'Подключено' = 'Connected'; 'Диск' = 'Disconnected'; 'Прием' = 'Listen'; 'Тень' = 'Shadow'; 'Простой' = 'Idle';
    'Active' = 'Active'; 'Conn' = 'Connected'; 'Connected' = 'Connected'; 'Disconnected' = 'Disconnected'; 'Disc' = 'Disconnected'; 'Listen' = 'Listen'; 'Listening' = 'Listen'; 'Shadow' = 'Shadow'; 'Idle' = 'Idle'; 'Reset' = 'Reset'; 'Down' = 'Down'; 'Init' = 'Init';
    'Aktiv' = 'Active'; 'Getrennt' = 'Disconnected'; 'Warten' = 'Listen'
}

function ConvertTo-WtsStateEn {
    [CmdletBinding()]
    param([string]$Raw)
    $key = if ($null -eq $Raw) { '' } else { $Raw.Trim() }
    if ([string]::IsNullOrWhiteSpace($key)) { return 'Unknown' }
    if ($script:WtsStateMap.Contains($key)) { return $script:WtsStateMap[$key] }
    return $key
}

function Get-WtsSessionType {
    [CmdletBinding()]
    param(
        [string]$SessionName,
        [string]$UserName,
        [string]$State
    )

    if ($State -eq 'Listen') { return 'Listener' }

    switch -Regex ($SessionName) {
        '^console$'     { return 'Console' }
        '^rdp-tcp#\d+$' { return 'RDP' }
        '^rdp-tcp$'     { return 'Listener' }
        '^services$'    { return 'Services' }
        '^$'            { if (-not [string]::IsNullOrWhiteSpace($UserName)) { return 'RDP' } else { return 'System' } }
        default         { return 'RDP' }
    }
}

function Get-QwinstaSessionsFallback {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param([string]$ComputerName = $env:COMPUTERNAME)

    Write-WtsDebug -Stage 'Fallback' -Message 'Running qwinsta fallback' -Data @{ ComputerName = $ComputerName }

    $raw = $null
    try {
        $raw = if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -in @('.', 'localhost', '127.0.0.1')) {
            @(qwinsta 2>$null)
        } else {
            @(qwinsta /server:$ComputerName 2>$null)
        }
    }
    catch {
        Write-WtsDebug -Stage 'Fallback' -Message 'qwinsta failed' -Data @{ Error = $_.Exception.Message }
        return @()
    }

    if ($null -eq $raw -or @($raw).Count -eq 0) {
        Write-WtsDebug -Stage 'Fallback' -Message 'qwinsta returned no lines'
        return @()
    }

    Write-WtsDebug -Stage 'Fallback' -Message 'Raw output captured' -Data @{
        LineCount = @($raw).Count
        Preview   = (@($raw) | Select-Object -First 6) -join ' || '
    }

    $headerLine = @($raw) | Where-Object { $_ -match '\bСЕАНС\b|\bSESSIONNAME\b' } | Select-Object -First 1
    if (-not $headerLine) {
        Write-WtsDebug -Stage 'Fallback' -Message 'Header not found'
        return @()
    }

    $headerIdx = [Array]::IndexOf(@($raw), $headerLine)

    $colSess  = [Math]::Max($headerLine.IndexOf('СЕАНС'),        $headerLine.IndexOf('SESSIONNAME'))
    $colUser  = [Math]::Max($headerLine.IndexOf('ПОЛЬЗОВАТЕЛЬ'), $headerLine.IndexOf('USERNAME'))
    $colId    = [Math]::Max($headerLine.IndexOf('ИД'),           $headerLine.IndexOf(' ID'))
    $colState = [Math]::Max($headerLine.IndexOf('СОСТОЯНИЕ'),    $headerLine.IndexOf('STATE'))

    if ($colSess  -lt 0) { $colSess  = 1 }
    if ($colUser  -lt 0) { $colUser  = 20 }
    if ($colId    -lt 0) { $colId    = 41 }
    if ($colState -lt 0) { $colState = 46 }

    $mySessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lines = @($raw | Select-Object -Skip ($headerIdx + 1))
    $lineNo = 0

    foreach ($line in $lines) {
        $lineNo++
        if ([string]::IsNullOrWhiteSpace($line)) {
            Write-WtsDebug -Stage 'Fallback' -Message 'Skip empty line' -Data @{ LineNo = $lineNo }
            continue
        }

        $isCurrent = $line.TrimStart().StartsWith('>')
        $padded = $line.PadRight(90)

        $sessName = if ($colSess -lt $padded.Length) { $padded.Substring($colSess, [Math]::Min($colUser - $colSess,  $padded.Length - $colSess)).Trim().TrimStart('>') } else { '' }
        $userName = if ($colUser -lt $padded.Length) { $padded.Substring($colUser, [Math]::Min($colId - $colUser,    $padded.Length - $colUser)).Trim() } else { '' }
        $idStr    = if ($colId   -lt $padded.Length) { $padded.Substring($colId,   [Math]::Min($colState - $colId,   $padded.Length - $colId)).Trim() } else { '' }
        $stateRaw = if ($colState -lt $padded.Length){ $padded.Substring($colState, [Math]::Min(16,                  $padded.Length - $colState)).Trim() } else { '' }

        $id = 0
        if (-not [int]::TryParse($idStr, [ref]$id)) {
            Write-WtsDebug -Stage 'Fallback' -Message 'Reject line: non-numeric ID' -Data @{ LineNo = $lineNo; IdStr = $idStr; Raw = $line.TrimEnd() }
            continue
        }

        $stateEn = ConvertTo-WtsStateEn -Raw $stateRaw
        $type = Get-WtsSessionType -SessionName $sessName -UserName $userName -State $stateEn
        $isSystem = ($id -eq 0 -or $stateEn -eq 'Listen' -or $type -in @('Listener','Services','System') -or ([string]::IsNullOrWhiteSpace($sessName) -and [string]::IsNullOrWhiteSpace($userName)))

        $obj = [PSCustomObject]@{
            SessionId   = $id
            SessionName = $sessName
            UserName    = $userName
            Domain      = ''
            ClientName  = ''
            State       = $stateEn
            Type        = $type
            IsSystem    = $isSystem
            IsCurrent   = ($id -eq $mySessionId -or $isCurrent)
        }
        $results.Add($obj)

        Write-WtsDebug -Stage 'Fallback' -Message 'Accepted session' -Data @{
            LineNo      = $lineNo
            SessionId   = $obj.SessionId
            SessionName = $obj.SessionName
            UserName    = $obj.UserName
            State       = $obj.State
            Type        = $obj.Type
            IsSystem    = $obj.IsSystem
            IsCurrent   = $obj.IsCurrent
        }
    }

    return @($results.ToArray())
}

function Get-WtsSessionsEn {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [ValidateSet('All','Active','Connected','Disconnected','Listen','Shadow','Idle','Reset','Down','Init')]
        [string]$State = 'All',
        [switch]$IncludeSystem
    )

    Write-WtsDebug -Stage 'GetSessions' -Message 'Start' -Data @{
        ComputerName  = $ComputerName
        State         = $State
        IncludeSystem = $IncludeSystem.IsPresent
        UseWtsApi     = $UseWtsApi.IsPresent
        ApiAvailable  = $script:WtsApiAvailable
    }

    $result = @()
    $dataSource = 'qwinsta/fallback'

    if ($UseWtsApi -and $script:WtsApiAvailable) {
        try {
            $raw = [WtsNative.Api]::GetSessions($ComputerName)
            $dataSource = 'wtsapi/native'
            $mySessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
            $result = @(
                foreach ($s in $raw) {
                    $type = Get-WtsSessionType -SessionName $s.SessionName -UserName $s.UserName -State $s.StateText
                    $isSystem = ($s.SessionId -eq 0 -or $s.State -eq [WtsNative.ConnectState]::Listen -or $type -in @('Listener','Services','System') -or ([string]::IsNullOrWhiteSpace($s.SessionName) -and [string]::IsNullOrWhiteSpace($s.UserName)))
                    [PSCustomObject]@{
                        SessionId   = $s.SessionId
                        SessionName = $s.SessionName
                        UserName    = $s.UserName
                        Domain      = $s.Domain
                        ClientName  = $s.ClientName
                        State       = $s.StateText
                        Type        = $type
                        IsSystem    = $isSystem
                        IsCurrent   = ($s.SessionId -eq $mySessionId)
                    }
                }
            )
        }
        catch {
            Write-WtsDebug -Stage 'GetSessions' -Message 'WTS API failed, switching to fallback' -Data @{ Error = $_.Exception.Message }
            Write-Warning "[qwinsta-en] WTS API failed: $($_.Exception.Message) — using qwinsta fallback"
            $result = @(Get-QwinstaSessionsFallback -ComputerName $ComputerName)
            $dataSource = 'qwinsta/fallback'
        }
    }
    else {
        $result = @(Get-QwinstaSessionsFallback -ComputerName $ComputerName)
    }

    Write-WtsDebug -Stage 'Filter' -Message 'Before filters' -Data @{ Count = @($result).Count; DataSource = $dataSource }

    if (-not $IncludeSystem) {
        $result = @($result | Where-Object { -not $_.IsSystem })
        Write-WtsDebug -Stage 'Filter' -Message 'After system exclusion' -Data @{ Count = @($result).Count }
    }

    if ($State -ne 'All') {
        $result = @($result | Where-Object { $_.State -eq $State })
        Write-WtsDebug -Stage 'Filter' -Message 'After state filter' -Data @{ State = $State; Count = @($result).Count }
    }

    Write-WtsDebug -Stage 'GetSessions' -Message 'Done' -Data @{ Count = @($result).Count; DataSource = $dataSource }
    return @($result)
}

function Format-WtsOutput {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][PSCustomObject[]]$Sessions,
        [ValidateSet('Object','Table','JSON','CSV','List')][string]$Format = 'Object'
    )

    begin { $all = [System.Collections.Generic.List[PSCustomObject]]::new() }
    process {
        if ($null -ne $Sessions) {
            foreach ($s in @($Sessions)) {
                if ($null -ne $s) { $all.Add($s) }
            }
        }
    }
    end {
        switch ($Format) {
            'Table' { $all | Format-Table -AutoSize -Property SessionId, SessionName, UserName, Domain, State, Type, ClientName, IsCurrent }
            'JSON'  { $all | ConvertTo-Json -Depth 5 }
            'CSV'   { $all | ConvertTo-Csv -NoTypeInformation }
            'List'  { $all | Format-List }
            default { @($all.ToArray()) }
        }
    }
}

function Get-ActiveSessionsPS7 {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param([string]$ComputerName = $env:COMPUTERNAME)

    try {
        $allSessions = @(Get-WtsSessionsEn -ComputerName $ComputerName -IncludeSystem)
        $display = @($allSessions | Where-Object { -not $_.IsSystem })
        $active  = @($display | Where-Object { $_.State -in @('Active','Connected') })
        $disc    = @($display | Where-Object { $_.State -eq 'Disconnected' })
        $current = $display | Where-Object { $_.IsCurrent } | Select-Object -First 1

        Write-WtsDebug -Stage 'ActiveSessions' -Message 'Counters computed' -Data @{
            Total = @($display).Count
            Active = @($active).Count
            Disconnected = @($disc).Count
            Current = if ($null -ne $current) { "ID=$($current.SessionId) User=$($current.UserName)" } else { 'none' }
        }

        [PSCustomObject]@{
            TotalSessions        = @($display).Count
            ActiveSessions       = @($active).Count
            DisconnectedSessions = @($disc).Count
            SessionDetails       = @($display | Select-Object SessionId, UserName, State, SessionName, Type, IsCurrent, Domain, ClientName)
            CurrentSession       = $current
            Source               = $dataSource
        }
    }
    catch {
        [PSCustomObject]@{
            TotalSessions        = 0
            ActiveSessions       = 0
            DisconnectedSessions = 0
            SessionDetails       = @()
            CurrentSession       = $null
            Error                = $_.Exception.Message
            Source               = 'error'
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-WtsDebug -Stage 'Main' -Message 'Standalone mode' -Data @{
        ComputerName = $ComputerName
        Format = $Format
        State = $State
        IncludeSystem = $IncludeSystem.IsPresent
        WtsDebugMode = $WtsDebugMode.IsPresent
        UseWtsApi = $UseWtsApi.IsPresent
    }

    @(Get-WtsSessionsEn -ComputerName $ComputerName -State $State -IncludeSystem:$IncludeSystem) | Format-WtsOutput -Format $Format
}
