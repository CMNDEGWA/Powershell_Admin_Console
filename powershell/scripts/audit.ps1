param(
    [ValidateSet('summary', 'audit')]
    [string]$Mode = 'audit'
)

$ErrorActionPreference = 'Stop'
$eventLogLimitPerChannel = 1000
$selectedEventLogs = @(
    'Security',
    'System',
    'Application',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-WindowsUpdateClient/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-PowerShell/Operational'
)

function Get-SystemSummary {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $processors = @(Get-CimInstance -ClassName Win32_Processor)
    $adapters = @()
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        try {
            $adapters = @(
                foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop)) {
                    $addresses = @(
                        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
                            Where-Object { $_.IPAddress } |
                            ForEach-Object {
                                [pscustomobject]@{
                                    address = $_.IPAddress
                                    family = $_.AddressFamily.ToString()
                                    prefixLength = $_.PrefixLength
                                }
                            }
                    )
                    [pscustomobject]@{
                        name = $adapter.Name
                        description = $adapter.InterfaceDescription
                        status = $adapter.Status.ToString()
                        macAddress = $adapter.MacAddress
                        linkSpeed = $adapter.LinkSpeed
                        addresses = $addresses
                    }
                }
            )
        }
        catch {
            $adapters = @()
        }
    }
    if ($adapters.Count -eq 0) {
        $adapters = @(
            foreach ($adapter in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
                $addresses = @(
                    foreach ($address in @($adapter.IPAddress)) {
                        if ($address) {
                            [pscustomobject]@{
                                address = $address
                                family = if ($address.Contains(':')) { 'IPv6' } else { 'IPv4' }
                                prefixLength = $null
                            }
                        }
                    }
                )
                [pscustomobject]@{
                    name = $adapter.Description
                    description = $adapter.Description
                    status = 'Up'
                    macAddress = $adapter.MACAddress
                    linkSpeed = $null
                    addresses = $addresses
                }
            }
        )
    }

    $rdpConfiguration = Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name fDenyTSConnections
    $rdpService = Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService'"
    $rdpFirewallRules = @()
    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        $rdpFirewallRules = @(
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'RemoteDesktop-*' } |
                ForEach-Object {
                    [pscustomobject]@{
                        name = $_.Name
                        enabled = $_.Enabled.ToString()
                        direction = $_.Direction.ToString()
                        profile = $_.Profile.ToString()
                    }
                }
        )
    }

    $bootTime = $operatingSystem.LastBootUpTime
    [pscustomobject]@{
        collectedAt = [DateTime]::UtcNow.ToString('o')
        hostname = $computerSystem.Name
        operatingSystem = [pscustomobject]@{
            caption = $operatingSystem.Caption
            edition = $operatingSystem.OperatingSystemSKU
            version = $operatingSystem.Version
            build = $operatingSystem.BuildNumber
            architecture = $operatingSystem.OSArchitecture
            powershellProcess64Bit = [Environment]::Is64BitProcess
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            lastBootTime = $bootTime.ToUniversalTime().ToString('o')
            uptimeSeconds = [math]::Max(0, [int]([DateTime]::UtcNow - $bootTime.ToUniversalTime()).TotalSeconds)
        }
        hardware = [pscustomobject]@{
            manufacturer = $computerSystem.Manufacturer
            model = $computerSystem.Model
            processorNames = @($processors | ForEach-Object { $_.Name.Trim() })
            logicalProcessors = $computerSystem.NumberOfLogicalProcessors
            memoryBytes = [int64]$computerSystem.TotalPhysicalMemory
        }
        networkAdapters = $adapters
        remoteDesktop = [pscustomobject]@{
            configuredEnabled = ($rdpConfiguration.fDenyTSConnections -eq 0)
            serviceState = $rdpService.State
            serviceStartMode = $rdpService.StartMode
            firewallRules = $rdpFirewallRules
            enabledInboundFirewallRule = (@(
                $rdpFirewallRules | Where-Object {
                    $_.enabled -eq 'True' -and $_.direction -eq 'Inbound'
                }
            ).Count -gt 0)
        }
        administrator = [Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Invoke-Collector {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        [pscustomobject]@{
            status = 'succeeded'
            data = (& $Action)
            errorCode = $null
        }
    }
    catch {
        $category = $_.CategoryInfo.Category.ToString()
        $status = if ($category -in @('PermissionDenied', 'SecurityError')) {
            'denied'
        }
        else {
            'failed'
        }
        [pscustomobject]@{
            status = $status
            data = $null
            errorCode = if ($status -eq 'denied') { 'access_denied' } else { 'collection_error' }
        }
    }
}

$machine = Get-SystemSummary
$isSupportedTarget = $machine.operatingSystem.caption -match '(?i)windows'

$sections = [ordered]@{}
if ($Mode -eq 'audit' -and $isSupportedTarget) {
    $sections.accountsAndGroups = Invoke-Collector 'accountsAndGroups' {
        $users = @(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, UserMayChangePassword, PrincipalSource)
        $groups = @(
            foreach ($group in @(Get-LocalGroup)) {
                $members = @(
                    try {
                        Get-LocalGroupMember -Group $group.Name -ErrorAction Stop |
                            ForEach-Object {
                                [pscustomobject]@{
                                    name = $_.Name
                                    sid = $_.SID.Value
                                    objectClass = $_.ObjectClass
                                    principalSource = $_.PrincipalSource
                                }
                            }
                    }
                    catch {
                        @([pscustomobject]@{ name = $null; errorCode = 'member_query_failed' })
                    }
                )
                [pscustomobject]@{ name = $group.Name; description = $group.Description; members = $members }
            }
        )
        [pscustomobject]@{ users = $users; groups = $groups }
    }

    $sections.services = Invoke-Collector 'services' {
        @(Get-CimInstance -ClassName Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName)
    }

    $sections.installedSoftware = Invoke-Collector 'installedSoftware' {
        $uninstallPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        @(
            foreach ($path in $uninstallPaths) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    ForEach-Object {
                        [pscustomobject]@{
                            name = $_.DisplayName
                            version = $_.DisplayVersion
                            publisher = $_.Publisher
                            installDate = $_.InstallDate
                            scope = if ($path -like 'HKCU:*') { 'currentUser' } else { 'machine' }
                        }
                    }
            }
        )
    }

    $sections.updates = Invoke-Collector 'updates' {
        $hotfixes = @(Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn)
        $history = @()
        $pending = @()
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $historyCount = [math]::Min(1000, $searcher.GetTotalHistoryCount())
            if ($historyCount -gt 0) {
                $history = @($searcher.QueryHistory(0, $historyCount) |
                    Select-Object Date, Title, Description, Operation, ResultCode, HResult)
            }
            $pendingResult = $searcher.Search('IsInstalled=0 and IsHidden=0')
            $pending = @(
                for ($index = 0; $index -lt $pendingResult.Updates.Count; $index++) {
                    $update = $pendingResult.Updates.Item($index)
                    [pscustomobject]@{ title = $update.Title; downloaded = $update.IsDownloaded }
                }
            )
        }
        catch {
            throw 'Windows Update history query failed'
        }
        [pscustomobject]@{ installedHotfixes = $hotfixes; updateHistory = $history; pendingUpdates = $pending }
    }

    $sections.firewall = Invoke-Collector 'firewall' {
        $profiles = @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen)
        $rules = @(
            foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore)) {
                $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $applicationFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Name = $rule.Name
                    DisplayName = $rule.DisplayName
                    Enabled = $rule.Enabled
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Profile = $rule.Profile
                    PolicyStoreSourceType = $rule.PolicyStoreSourceType
                    Protocol = $portFilter.Protocol
                    LocalPort = $portFilter.LocalPort
                    RemotePort = $portFilter.RemotePort
                    LocalAddress = $addressFilter.LocalAddress
                    RemoteAddress = $addressFilter.RemoteAddress
                    Program = $applicationFilter.Program
                    Service = $applicationFilter.Service
                }
            }
        )
        [pscustomobject]@{ profiles = $profiles; rules = $rules }
    }

    $sections.security = Invoke-Collector 'security' {
        $defender = $null
        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop |
                Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, NISEnabled, AntivirusSignatureLastUpdated
        }
        catch {
            $defender = [pscustomobject]@{ unavailable = $true }
        }
        $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA
        $secureBoot = $null
        try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBoot = $null }
        [pscustomobject]@{ defender = $defender; uacEnabled = ($uac.EnableLUA -eq 1); secureBootEnabled = $secureBoot }
    }

    $sections.scheduledTasks = Invoke-Collector 'scheduledTasks' {
        @(Get-ScheduledTask | ForEach-Object {
            [pscustomobject]@{
                taskName = $_.TaskName
                taskPath = $_.TaskPath
                state = $_.State.ToString()
                author = $_.Author
                principal = $_.Principal.UserId
                runLevel = $_.Principal.RunLevel.ToString()
                actions = @($_.Actions | ForEach-Object {
                    [pscustomobject]@{ execute = $_.Execute; arguments = $_.Arguments; workingDirectory = $_.WorkingDirectory }
                })
            }
        })
    }

    $sections.eventLogs = Invoke-Collector 'eventLogs' {
        @(
            foreach ($channel in $selectedEventLogs) {
                try {
                    $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
                    $records = @()
                    try {
                        $records = @(Get-WinEvent -LogName $channel -MaxEvents $eventLogLimitPerChannel -ErrorAction Stop)
                    }
                    catch {
                        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
                    }
                    $events = @($records | ForEach-Object {
                        $message = $_.Message
                        if ($message -and $message.Length -gt 600) { $message = $message.Substring(0, 600) }
                        [pscustomobject]@{
                            timeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
                            eventId = $_.Id
                            level = $_.LevelDisplayName
                            provider = $_.ProviderName
                            recordId = $_.RecordId
                            message = $message
                        }
                    })
                    [pscustomobject]@{
                        channel = $channel
                        status = 'succeeded'
                        enabled = $log.IsEnabled
                        recordCount = $log.RecordCount
                        collectedCount = $events.Count
                        truncated = ($log.RecordCount -gt $eventLogLimitPerChannel)
                        events = $events
                    }
                }
                catch {
                    [pscustomobject]@{ channel = $channel; status = 'failed'; errorCode = 'log_unavailable'; events = @() }
                }
            }
        )
    }
}

$payload = [pscustomobject]@{
    schemaVersion = 1
    mode = $Mode
    collectedAt = [DateTime]::UtcNow.ToString('o')
    supportedTarget = $isSupportedTarget
    machine = $machine
    sections = $sections
}
$payload | ConvertTo-Json -Depth 12 -Compress