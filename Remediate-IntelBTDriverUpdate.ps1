<#
.SYNOPSIS
    Hide and remove Intel Bluetooth driver updates 24.70.0.4 and 24.80.0.2.

.DESCRIPTION
    Intune remediation pair. Upload each file as its own script. Intune runs
    them with no arguments. The files differ only by the default -Mode and
    by PackageRole, which is written into the shared log:
      Detect-IntelBTDriverUpdate.ps1     default Detect
      Remediate-IntelBTDriverUpdate.ps1  default Remediate

    Intune starts the remediation script only when detection exits 1.
    A detection exit of 0 never starts remediation, so the log contains
    only Detect lines. Both scripts append to the same file.

    Exit 0 = compliant / remediation succeeded.
    Exit 1 = the blocked driver is still offered, downloaded, or staged,
             or the scan could not see Microsoft Update and the USO store.

    Intune settings:
      Run this script using the logged-on credentials : No   (SYSTEM)
      Enforce script signature check                  : No
      Run script in 64-bit PowerShell                 : Yes
      Schedule                                        : Daily, or hourly while a device is affected

    The script relaunches itself with 64-bit Windows PowerShell when a 32-bit
    host starts it. Do not paste it through chat; brackets in type names get stripped.

    Log: C:\temp\IntelBTDriverUpdate.txt

.NOTES
    Version 2.1.6
    A default IUpdateSearcher does not see every driver Settings shows. Settings
    and USO can offer a driver from Microsoft Update, as an optional (BrowseOnly /
    IsAssigned=0) driver, or from a stale USO UpdateStore record. Hiding through
    the PSWindowsUpdate module fails here with 0x800706BA; IUpdate.IsHidden does not.
#>
[CmdletBinding()]
param(
    [ValidateSet('Detect', 'Remediate', 'SelfTest')]
    [string]$Mode = 'Remediate'  # Intune default. The detection file ships with 'Detect'.
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# Windows PowerShell 5.1 on a 64-bit OS is required for WUA, pnputil, and the driver store.
# Intune is set to 64-bit; this covers a 32-bit host without asking the admin to reconfigure it.
if ($Mode -ne 'SelfTest' -and [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WinDir 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if ($PSCommandPath -and (Test-Path -LiteralPath $sysnative)) {
        & $sysnative -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -Mode $Mode
        if ($null -eq $LASTEXITCODE) { exit 1 }
        exit $LASTEXITCODE
    }
}

$script:ScriptVersion = '2.1.6'
$script:PackageRole = 'Remediate'
$script:BlockedVersions = @('24.70.0.4', '24.80.0.2')
$script:BluetoothClassGuid = 'e0cbf06c-cd8b-4647-bb8a-263b43f0f974'
$script:MicrosoftUpdateServiceId = '7971f918-a847-4430-9279-4a52d1efe18d'
$script:WindowsUpdateServiceId = '9482f4b4-e343-43b6-b170-9a65bc822c77'
$script:StoreServiceId = '855e8a7c-ecb4-4ca3-b045-1dfa50104289'
# Intune runs as SYSTEM. C:\temp is the log location operators look at.
$script:LogDir = 'C:\temp'
$script:LogFile = 'C:\temp\IntelBTDriverUpdate.txt'
# Pinned so the Windows Update agent is not collected while IsHidden is being set.
# Releasing the searcher early is what surfaces 0x800706BA on the hide path.
$script:ComPins = New-Object System.Collections.ArrayList
$script:UsoReadable = $false
$script:DriverStoreReadable = $false
$script:RegNodes = 0

$script:DriverCriteria = "IsInstalled=0 and Type='Driver' or IsInstalled=0 and Type='Driver' and IsAssigned=0 or IsInstalled=0 and Type='Driver' and BrowseOnly=1"
$script:SimpleDriverCriteria = @(
    "IsInstalled=0 and Type='Driver'",
    "IsInstalled=0 and Type='Driver' and IsAssigned=0",
    "IsInstalled=0 and Type='Driver' and BrowseOnly=1"
)

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    try {
        if (-not (Test-Path -LiteralPath $script:LogDir)) {
            New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
        }
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Initialize-Log {
    if (-not (Test-Path -LiteralPath $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }
    if ((Test-Path -LiteralPath $script:LogFile) -and (Get-Item -LiteralPath $script:LogFile).Length -gt 512KB) {
        $tail = @(Get-Content -LiteralPath $script:LogFile -Tail 1500 -ErrorAction SilentlyContinue)
        Set-Content -LiteralPath $script:LogFile -Value $tail -Encoding UTF8
    }
}

function Write-Status {
    param([int]$Code, [string]$Message)
    # Intune runs the remediation script only when detection exits 1.
    # Exit 0 leaves no Remediate block in the log because that script never starts.
    $suffix = ''
    if ($script:PackageRole -eq 'Detect') {
        if ($Code -eq 0) {
            $suffix = ' Remediation did not run.'
        } else {
            $suffix = ' Intune should run the remediation script next. That run appends role=Remediate to this log.'
        }
    }
    $limit = 1800 - $suffix.Length
    if ($Message.Length -gt $limit) {
        $Message = $Message.Substring(0, $limit) + '...[truncated]'
    }
    $Message += $suffix
    Write-Log "EXIT $Code $Message"
    Write-Output $Message
    exit $Code
}

function Get-NormalizedId {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value -replace '[{}]', '').ToLowerInvariant()
}

function ConvertTo-HexCode {
    param($ErrorRecord)
    try { return ('0x{0:X8}' -f $ErrorRecord.Exception.HResult) } catch { return '' }
}

function Test-RetryableCode {
    param([string]$Hex)
    $retryable = @(
        '0x8024001E', # WU_E_SERVICE_STOP
        '0x800706BA', # RPC_S_SERVER_UNAVAILABLE
        '0x80080005', # CO_E_SERVER_EXEC_FAILURE
        '0x80072EE2', # WININET_E_TIMEOUT
        '0x80072EE7', # WININET_E_NAME_NOT_RESOLVED
        '0x80072EFD', # WININET_E_CANNOT_CONNECT
        '0x80072EFE', # WININET_E_CONNECTION_ABORTED
        '0x80072EFF', # WININET_E_CONNECTION_RESET
        '0x8001010A', # RPC_E_SERVERCALL_RETRYLATER
        '0x80010001', # RPC_E_CALL_REJECTED
        '0x8024401C', # WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT
        '0x8024402C', # WU_E_PT_WINHTTP_NAME_NOT_RESOLVED
        '0x80240438'  # WU_E_PT_ENDPOINT_UNREACHABLE
    )
    return $retryable -contains $Hex
}

function Test-BlockedVersionText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    foreach ($version in $script:BlockedVersions) {
        $pattern = '(?<!\d)' + [regex]::Escape($version) + '(?!\d)'
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function Test-BlockedBluetoothText {
    param([string]$Text)
    # Whole-file AND is wrong for a USO database: the installed adapter name
    # and some other package's version can share one file. Require the version
    # and the Intel Bluetooth words in the same small window.
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $radius = 200
    foreach ($version in $script:BlockedVersions) {
        $pattern = '(?<!\d)' + [regex]::Escape($version) + '(?!\d)'
        $found = [regex]::Matches($Text, $pattern)
        foreach ($hit in $found) {
            $start = $hit.Index - $radius
            if ($start -lt 0) { $start = 0 }
            $length = $hit.Length + ($radius * 2)
            if (($start + $length) -gt $Text.Length) { $length = $Text.Length - $start }
            $window = $Text.Substring($start, $length)
            if ($window -notmatch 'Intel') { continue }
            if ($window -match 'Bluetooth') { return $true }
            if ($window -match [regex]::Escape($script:BluetoothClassGuid)) { return $true }
        }
    }
    return $false
}

function Get-BlockedMatchExcerpt {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $radius = 80
    foreach ($version in $script:BlockedVersions) {
        $pattern = '(?<!\d)' + [regex]::Escape($version) + '(?!\d)'
        $found = [regex]::Matches($Text, $pattern)
        foreach ($hit in $found) {
            $start = $hit.Index - $radius
            if ($start -lt 0) { $start = 0 }
            $length = $hit.Length + ($radius * 2)
            if (($start + $length) -gt $Text.Length) { $length = $Text.Length - $start }
            $window = $Text.Substring($start, $length)
            if ($window -notmatch 'Intel') { continue }
            if ($window -notmatch 'Bluetooth' -and $window -notmatch [regex]::Escape($script:BluetoothClassGuid)) { continue }
            $flat = ([regex]::Replace($window, '[^\x20-\x7E]', ' ') -replace '\s+', ' ').Trim()
            if ($flat.Length -gt 180) { $flat = $flat.Substring(0, 180) }
            return $flat
        }
    }
    return ''
}

function Get-FileMatchExcerpt {
    param([string]$Path)
    try { $bytes = [IO.File]::ReadAllBytes($Path) } catch { return '' }
    $samples = New-Object 'System.Collections.Generic.List[string]'
    [void]$samples.Add([Text.Encoding]::GetEncoding(28591).GetString($bytes))
    try { [void]$samples.Add([Text.Encoding]::Unicode.GetString($bytes)) } catch { }
    try { [void]$samples.Add([Text.Encoding]::BigEndianUnicode.GetString($bytes)) } catch { }
    foreach ($sample in $samples) {
        $excerpt = Get-BlockedMatchExcerpt $sample
        if (-not [string]::IsNullOrWhiteSpace($excerpt)) { return $excerpt }
    }
    return ''
}

function Test-BytesContainBlockedVersion {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $false }
    $latin = [Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    if (Test-BlockedVersionText $latin) { return $true }
    try {
        if (Test-BlockedVersionText ([Text.Encoding]::Unicode.GetString($Bytes))) { return $true }
    } catch { }
    try {
        if (Test-BlockedVersionText ([Text.Encoding]::BigEndianUnicode.GetString($Bytes))) { return $true }
    } catch { }
    return $false
}

function Test-BytesContainBlockedBluetooth {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $false }
    $samples = New-Object 'System.Collections.Generic.List[string]'
    [void]$samples.Add([Text.Encoding]::GetEncoding(28591).GetString($Bytes))
    try { [void]$samples.Add([Text.Encoding]::Unicode.GetString($Bytes)) } catch { }
    try { [void]$samples.Add([Text.Encoding]::BigEndianUnicode.GetString($Bytes)) } catch { }
    foreach ($sample in $samples) {
        if (Test-BlockedBluetoothText $sample) { return $true }
    }
    return $false
}

function Read-TextFlexible {
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
        return [Text.Encoding]::Unicode.GetString($bytes)
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        return [Text.Encoding]::UTF8.GetString($bytes)
    }
    $utf8 = [Text.Encoding]::UTF8.GetString($bytes)
    if (Test-BlockedBluetoothText $utf8) { return $utf8 }
    try {
        $utf16 = [Text.Encoding]::Unicode.GetString($bytes)
        if (Test-BlockedBluetoothText $utf16) { return $utf16 }
    } catch { }
    return $utf8
}

function Test-FileHasBlockedVersion {
    param([string]$Path)
    try {
        $info = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($info.Length -le 0 -or $info.Length -gt 32MB) { return $false }
        $bytes = [IO.File]::ReadAllBytes($Path)
    } catch { return $false }
    return (Test-BytesContainBlockedVersion $bytes)
}

function Test-FileHasBlockedBluetooth {
    param([string]$Path)
    try {
        $info = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($info.Length -le 0 -or $info.Length -gt 32MB) { return $false }
        $bytes = [IO.File]::ReadAllBytes($Path)
    } catch { return $false }
    return (Test-BytesContainBlockedBluetooth $bytes)
}

function Test-SafeChildPath {
    param([string]$Parent, [string]$Candidate)
    if ([string]::IsNullOrWhiteSpace($Parent) -or [string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    try {
        $parentFull = [IO.Path]::GetFullPath($Parent)
        $childFull = [IO.Path]::GetFullPath($Candidate)
    } catch { return $false }
    $sep = [IO.Path]::DirectorySeparatorChar
    $parentTrim = $parentFull.TrimEnd($sep)
    $childTrim = $childFull.TrimEnd($sep)
    if ([string]::Equals($parentTrim, $childTrim, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $prefix = $parentTrim + $sep
    return $childFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Remove-BlockedChild {
    param([string]$Parent, [string]$Candidate)
    if (-not (Test-SafeChildPath -Parent $Parent -Candidate $Candidate)) {
        throw "Refusing to delete $Candidate"
    }
    if (-not (Test-Path -LiteralPath $Candidate)) { return $true }
    $attempt = 0
    while ($attempt -lt 4) {
        $attempt++
        try {
            Remove-Item -LiteralPath $Candidate -Recurse -Force -Confirm:$false -ErrorAction Stop
            Write-Log "Deleted $Candidate"
            return $true
        } catch {
            if ($attempt -ge 4) { throw }
            Start-Sleep -Seconds 2
        }
    }
    return $false
}

function Join-ChildPath {
    param([string]$Parent, [string]$Child)
    $current = $Parent
    foreach ($part in @($Child -split '[\\/]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $current = Join-Path $current $part
    }
    return $current
}

function Get-UsoStoreRoot {
    if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { return $null }
    return (Join-ChildPath $env:ProgramData 'USOPrivate\UpdateStore')
}

function Get-UsoSidecarPaths {
    param([string]$Path)
    # store.db is SQLite. Deleting the db alone lets the service restore the
    # paused offer from store.db-wal or store.db-shm when usosvc starts.
    $paths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($suffix in @('-wal', '-shm', '-journal')) {
        [void]$paths.Add($Path + $suffix)
    }
    return @($paths.ToArray())
}

function Get-DownloadRoot {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { return $null }
    return (Join-ChildPath $env:SystemRoot 'SoftwareDistribution\Download')
}

function Get-TopDownloadFolder {
    param([string]$Root, [string]$FullName)
    $rootTrim = $Root.TrimEnd([char[]]@('\', '/'))
    $relative = $null
    foreach ($sep in @('\', '/')) {
        $candidate = $rootTrim + $sep
        if ($FullName.StartsWith($candidate, [StringComparison]::OrdinalIgnoreCase)) {
            $relative = $FullName.Substring($candidate.Length)
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($relative)) { return $null }
    $top = ($relative -split '[\\/]', 2)[0]
    if ([string]::IsNullOrWhiteSpace($top)) { return $null }
    $folder = Join-Path $Root $top
    if (-not (Test-SafeChildPath -Parent $Root -Candidate $folder)) { return $null }
    return $folder
}

function Get-UsoHits {
    $hits = New-Object 'System.Collections.Generic.List[string]'
    $root = Get-UsoStoreRoot
    if ([string]::IsNullOrWhiteSpace($root)) { return @() }
    if (-not (Test-Path -LiteralPath $root)) {
        $script:UsoReadable = $true
        Write-Log 'USO UpdateStore is not present'
        return @()
    }
    try {
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction Stop)
        $script:UsoReadable = $true
    } catch {
        $script:UsoReadable = $false
        Write-Log "Could not read USO UpdateStore: $($_.Exception.Message)"
        return @()
    }
    foreach ($file in $files) {
        if ($file.Length -gt 32MB) {
            Write-Log "Skipped large USO file $($file.FullName)"
            continue
        }
        # Version text alone is not enough. A shared store can mention 24.70.0.4
        # for a different package. Require Intel plus Bluetooth near that version.
        if (Test-FileHasBlockedBluetooth $file.FullName) {
            $excerpt = ''
            try { $excerpt = Get-FileMatchExcerpt $file.FullName } catch { }
            if ([string]::IsNullOrWhiteSpace($excerpt)) { $excerpt = 'matched, excerpt unreadable' }
            Write-Log "USO match $($file.Name): $excerpt"
            [void]$hits.Add($file.FullName)
        }
    }
    return @($hits.ToArray())
}

function Test-DownloadFileBlocked {
    param($File)
    $ext = $File.Extension.ToLowerInvariant()
    if (Test-BlockedVersionText $File.Name) { return $true }
    if ($ext -eq '.inf' -or $ext -eq '.xml' -or $ext -eq '.txt') {
        if ($File.Length -gt 5MB) { return $false }
        try { $text = Read-TextFlexible $File.FullName } catch { return $false }
        return (Test-BlockedBluetoothText $text)
    }
    return $false
}

function Test-CabSampleBlocked {
    param($File)
    try {
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $length = [int][Math]::Min([int64]2MB, [int64]$stream.Length)
            if ($length -le 0) { return $false }
            $buffer = New-Object byte[] $length
            [void]$stream.Read($buffer, 0, $buffer.Length)
        } finally { $stream.Dispose() }
        return (Test-BytesContainBlockedBluetooth $buffer)
    } catch { return $false }
}

function Get-BlockedDownloadFolders {
    $found = @{}
    $root = Get-DownloadRoot
    if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { return @() }
    $tops = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue)
    foreach ($top in $tops) {
        $folder = Get-TopDownloadFolder -Root $root -FullName $top.FullName
        if ([string]::IsNullOrWhiteSpace($folder) -or $found.ContainsKey($folder)) { continue }
        $files = @($top)
        if ($top.PSIsContainer) {
            $files = @(Get-ChildItem -LiteralPath $top.FullName -Recurse -File -Force -ErrorAction SilentlyContinue)
        }
        $matched = $false
        $cabs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($file in $files) {
            $ext = $file.Extension.ToLowerInvariant()
            if ($ext -eq '.cab' -or $ext -eq '.msu' -or $ext -eq '.esd') {
                if ($cabs.Count -lt 2) { [void]$cabs.Add($file) }
                continue
            }
            if (Test-DownloadFileBlocked $file) { $matched = $true; break }
        }
        if (-not $matched) {
            foreach ($cab in $cabs.ToArray()) {
                if (Test-CabSampleBlocked $cab) { $matched = $true; break }
            }
        }
        if ($matched) { $found[$folder] = $true }
    }
    return @($found.Keys)
}

function Get-ActiveBluetoothDrivers {
    $drivers = New-Object 'System.Collections.Generic.List[object]'
    $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{' + $script:BluetoothClassGuid + '}'
    if (-not (Test-Path -LiteralPath $classKey)) { return @() }
    foreach ($child in @(Get-ChildItem -LiteralPath $classKey -ErrorAction SilentlyContinue)) {
        if ($child.PSChildName -notmatch '^\d+$') { continue }
        $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }
        $infPath = [string]$props.InfPath
        [void]$drivers.Add([pscustomobject]@{
            DriverVersion    = [string]$props.DriverVersion
            ProviderName     = [string]$props.ProviderName
            DriverDesc       = [string]$props.DriverDesc
            InfPath          = $infPath
            InfName          = [IO.Path]::GetFileName($infPath)
            MatchingDeviceId = [string]$props.MatchingDeviceId
        })
    }
    return @($drivers.ToArray())
}

function Get-PnpUtilPackages {
    $packages = New-Object 'System.Collections.Generic.List[object]'
    $pnputil = Join-ChildPath $env:SystemRoot 'System32\pnputil.exe'
    if (-not (Test-Path -LiteralPath $pnputil)) { return @() }
    $output = & $pnputil /enum-drivers 2>&1 | Out-String
    if ($output -notmatch 'Published Name') { return @() }
    $blocks = $output -split '(?m)(?=Published Name\s*:)'
    foreach ($block in $blocks) {
        if ($block -notmatch 'Published Name') { continue }
        $published = ([regex]::Match($block, 'Published Name\s*:\s*(\S+)')).Groups[1].Value
        $provider = ([regex]::Match($block, 'Provider Name\s*:\s*(.+)')).Groups[1].Value.Trim()
        $className = ([regex]::Match($block, 'Class Name\s*:\s*(.+)')).Groups[1].Value.Trim()
        $classGuid = ([regex]::Match($block, 'Class GUID\s*:\s*(\S+)')).Groups[1].Value.Trim()
        $version = ([regex]::Match($block, 'Driver Version\s*:\s*(?:\d{1,2}/\d{1,2}/\d{4}\s+)?(\d+\.\d+\.\d+\.\d+)')).Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($published)) { continue }
        [void]$packages.Add([pscustomobject]@{
            Driver       = $published
            ProviderName = $provider
            ClassName    = $className
            ClassGuid    = $classGuid
            Version      = $version
            Inbox        = $false
        })
    }
    if ($packages.Count -gt 0) { $script:DriverStoreReadable = $true }
    return @($packages.ToArray())
}

function Get-DriverStorePackages {
    # pnputil returns the third-party store in seconds. Get-WindowsDriver -Online
    # walks the whole image and is the slow path when pnputil is unreadable.
    $fallback = @(Get-PnpUtilPackages)
    if ($script:DriverStoreReadable -and $fallback.Count -gt 0) {
        Write-Log "Driver store enumerated with pnputil ($($fallback.Count) packages)"
        return $fallback
    }
    $packages = New-Object 'System.Collections.Generic.List[object]'
    try {
        $drivers = @(Get-WindowsDriver -Online -ErrorAction Stop)
        $script:DriverStoreReadable = $true
        foreach ($driver in $drivers) {
            [void]$packages.Add([pscustomobject]@{
                Driver       = [string]$driver.Driver
                ProviderName = [string]$driver.ProviderName
                ClassName    = [string]$driver.ClassName
                ClassGuid    = [string]$driver.ClassGuid
                Version      = [string]$driver.Version
                Inbox        = [bool]$driver.Inbox
            })
        }
        return @($packages.ToArray())
    } catch {
        Write-Log "Get-WindowsDriver failed: $($_.Exception.Message)"
    }
    $fallback = @(Get-PnpUtilPackages)
    if ($fallback.Count -eq 0 -and -not $script:DriverStoreReadable) {
        Write-Log 'Driver store could not be enumerated'
    }
    return $fallback
}

function Get-StagedBlockedDrivers {
    param($ActiveDrivers)
    $inUse = @{}
    foreach ($driver in @($ActiveDrivers)) {
        if ($driver.InfName) { $inUse[$driver.InfName.ToLowerInvariant()] = $true }
    }
    $staged = New-Object 'System.Collections.Generic.List[object]'
    foreach ($package in @(Get-DriverStorePackages)) {
        $blob = (@($package.ProviderName, $package.ClassName, $package.ClassGuid, $package.Version, $package.Driver) -join "`n")
        if (-not (Test-BlockedBluetoothText $blob)) { continue }
        $name = [IO.Path]::GetFileName([string]$package.Driver)
        [void]$staged.Add([pscustomobject]@{
            Driver       = $name
            Version      = [string]$package.Version
            ProviderName = [string]$package.ProviderName
            ClassName    = [string]$package.ClassName
            InUse        = [bool]$inUse.ContainsKey($name.ToLowerInvariant())
            Inbox        = [bool]$package.Inbox
        })
    }
    return @($staged.ToArray())
}

function Get-ActiveSummary {
    param($ActiveDrivers)
    $intel = @($ActiveDrivers | Where-Object { $_.ProviderName -match 'Intel' -or $_.DriverDesc -match 'Intel' })
    if ($intel.Count -eq 0) { return 'Active Intel Bluetooth driver: none found' }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($driver in $intel) {
        $inf = if ($driver.InfName) { $driver.InfName } else { 'no-inf' }
        [void]$parts.Add("$($driver.DriverVersion) ($inf)")
    }
    return 'Active Intel Bluetooth driver: ' + ($parts -join ', ')
}

function Test-InternetUpdateBlocked {
    try {
        $policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
        if ($null -ne $policy -and $null -ne $policy.DoNotConnectToWindowsUpdateInternetLocations) {
            return ([int]$policy.DoNotConnectToWindowsUpdateInternetLocations -eq 1)
        }
    } catch { }
    return $false
}

function Write-EnvironmentLog {
    $userName = 'unknown'
    try { $userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }
    Write-Log "Version=$script:ScriptVersion Mode=$Mode User=$userName Process64=$([Environment]::Is64BitProcess) Versions=$($script:BlockedVersions -join ',')"
    $keys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    )
    foreach ($key in $keys) {
        try {
            if (-not (Test-Path -LiteralPath $key)) {
                Write-Log "Policy key missing: $key"
                continue
            }
            $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            $keep = '^(WUServer|WUStatusServer|TargetGroup|TargetGroupEnabled|DisableDualScan|DoNotConnectToWindowsUpdateInternetLocations|UseWUServer|NoAutoUpdate|AUOptions|UseUpdateClassPolicySource|AllowMUUpdateService|ExcludeWUDriversInQualityUpdate|AllowOptionalContent|SetPolicyDrivenUpdateSourceFor\w+|DriverUpdateEnrolled|PauseQualityUpdates|PauseFeatureUpdates)$'
            foreach ($property in @($props.PSObject.Properties)) {
                if ($property.Name -like 'PS*') { continue }
                if ($property.Name -notmatch $keep) { continue }
                if ($property.Value -is [byte[]]) { continue }
                $value = [string]$property.Value
                if ($value.Length -gt 300) { $value = $value.Substring(0, 300) }
                Write-Log "Policy $key $($property.Name)=$value"
            }
        } catch {
            Write-Log "Policy read failed ${key}: $($_.Exception.Message)"
        }
    }
}

function Write-RegistryHintsAt {
    param([string]$Path, [int]$Depth)
    if ($Depth -gt 5 -or $script:RegNodes -gt 1500) { return }
    $script:RegNodes++
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    foreach ($name in @($item.GetValueNames())) {
        $raw = $null
        try { $raw = $item.GetValue($name) } catch { continue }
        $text = ''
        if ($raw -is [byte[]]) {
            if ($raw.Length -gt 65536) { continue }
            try { $text = [Text.Encoding]::Unicode.GetString($raw) } catch { $text = '' }
            try { $text = $text + "`n" + [Text.Encoding]::GetEncoding(28591).GetString($raw) } catch { }
        } elseif ($null -ne $raw -and $raw -isnot [int] -and $raw -isnot [long]) {
            $text = [string]$raw
        }
        if (Test-BlockedBluetoothText $text) {
            Write-Log "Registry hint $Path name=$name"
        }
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        Write-RegistryHintsAt -Path $child.PSPath -Depth ($Depth + 1)
    }
}

function Write-RegistryHints {
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate',
        'HKLM:\SOFTWARE\Microsoft\WindowsUpdate'
    )) {
        Write-RegistryHintsAt -Path $root -Depth 0
    }
}

function Write-RecentUpdateEvents {
    try {
        $events = @(Get-WinEvent -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -MaxEvents 200 -ErrorAction Stop)
    } catch { return }
    foreach ($event in $events) {
        $message = [string]$event.Message
        if (-not (Test-BlockedBluetoothText $message)) { continue }
        $flat = ($message -replace '\s+', ' ').Trim()
        if ($flat.Length -gt 240) { $flat = $flat.Substring(0, 240) }
        Write-Log ("WU event {0} at {1:yyyy-MM-dd HH:mm}: {2}" -f $event.Id, $event.TimeCreated, $flat)
    }
}

function Get-ComProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    try { return $Object.$Name } catch { return $null }
}

function Get-ComItems {
    param($Collection)
    $items = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Collection) { return @() }
    $count = 0
    try { $count = [int]$Collection.Count } catch { return @() }
    for ($i = 0; $i -lt $count; $i++) {
        try { [void]$items.Add($Collection.Item($i)) } catch { }
    }
    return @($items.ToArray())
}

function Get-UpdateBlob {
    param($Update)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @('Title', 'Description', 'SupportUrl', 'DriverClass', 'DriverHardwareID', 'DriverManufacturer', 'DriverModel', 'DriverProvider')) {
        $value = Get-ComProperty $Update $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { [void]$parts.Add([string]$value) }
    }
    foreach ($category in @(Get-ComItems (Get-ComProperty $Update 'Categories'))) {
        $name = Get-ComProperty $category 'Name'
        $description = Get-ComProperty $category 'Description'
        if ($name) { [void]$parts.Add([string]$name) }
        if ($description) { [void]$parts.Add([string]$description) }
    }
    foreach ($child in @(Get-ComItems (Get-ComProperty $Update 'BundledUpdates'))) {
        foreach ($name in @('Title', 'Description', 'DriverClass', 'DriverHardwareID', 'DriverManufacturer', 'DriverModel', 'DriverProvider')) {
            $value = Get-ComProperty $child $name
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) { [void]$parts.Add([string]$value) }
        }
    }
    return ($parts -join "`n")
}

function Start-WuauservReady {
    $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($null -eq $service) { throw 'wuauserv is not installed' }
    if ($service.StartType -eq 'Disabled') { throw 'wuauserv is Disabled' }
    if ($service.Status -ne 'Running') {
        Start-Service -Name wuauserv -ErrorAction Stop
    }
    $service.Refresh()
    $service.WaitForStatus('Running', (New-TimeSpan -Seconds 60))
}

function Stop-UpdateStack {
    foreach ($name in @('usosvc', 'dosvc', 'bits', 'wuauserv')) {
        try { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue } catch { }
    }
    foreach ($processName in @('MoUsoCoreWorker', 'UsoClient', 'wuauclt')) {
        Get-Process -Name $processName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
}

function Start-UpdateStack {
    foreach ($name in @('bits', 'wuauserv', 'dosvc', 'usosvc')) {
        try {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $service) { continue }
            if ($service.StartType -eq 'Disabled') {
                Write-Log "$name is Disabled; startup type was left unchanged"
                continue
            }
            if ($service.Status -ne 'Running') {
                Start-Service -Name $name -ErrorAction SilentlyContinue
            }
            $service.Refresh()
            if ($name -eq 'wuauserv') {
                $service.WaitForStatus('Running', (New-TimeSpan -Seconds 60))
            }
        } catch {
            Write-Log "Could not start ${name}: $($_.Exception.Message)"
        }
    }
}

function Register-MicrosoftUpdateIfNeeded {
    param($ServiceManager)
    $target = Get-NormalizedId $script:MicrosoftUpdateServiceId
    foreach ($service in @(Get-ComItems (Get-ComProperty $ServiceManager 'Services'))) {
        $id = Get-NormalizedId ([string](Get-ComProperty $service 'ServiceID'))
        if ($id -eq $target) {
            Write-Log 'Microsoft Update is already registered'
            return $true
        }
    }
    if (Test-InternetUpdateBlocked) {
        Write-Log 'DoNotConnectToWindowsUpdateInternetLocations=1; not registering Microsoft Update'
        return $false
    }
    try {
        # 1 = asfAllowPendingRegistration, 2 = asfAllowOnlineRegistration.
        # Flag 4 (asfRegisterServiceWithAU) is omitted so Microsoft Update does not replace the AU service.
        [void]$ServiceManager.AddService2($script:MicrosoftUpdateServiceId, 3, $null)
        Write-Log 'Registered Microsoft Update for scanning (not as the Automatic Updates service)'
        return $true
    } catch {
        Write-Log ("AddService2 Microsoft Update failed {0}: {1}" -f (ConvertTo-HexCode $_), $_.Exception.Message)
        return $false
    }
}

function Get-SearchTargets {
    param($ServiceManager)
    $targets = New-Object 'System.Collections.Generic.List[object]'
    # Upgrade and the superseded catalog make each online search take minutes.
    # The offered driver is current, so neither is required to see it.
    [void]$targets.Add([pscustomobject]@{ Label = 'Default'; Selection = 0; ServiceId = ''; Upgrade = $false })
    [void]$targets.Add([pscustomobject]@{ Label = 'Windows Update'; Selection = 2; ServiceId = ''; Upgrade = $false })
    [void]$targets.Add([pscustomobject]@{ Label = 'Microsoft Update'; Selection = 3; ServiceId = $script:MicrosoftUpdateServiceId; Upgrade = $false })

    $known = @{
        (Get-NormalizedId $script:MicrosoftUpdateServiceId) = $true
        (Get-NormalizedId $script:WindowsUpdateServiceId)   = $true
        (Get-NormalizedId $script:StoreServiceId)           = $true
    }
    foreach ($service in @(Get-ComItems (Get-ComProperty $ServiceManager 'Services'))) {
        $name = [string](Get-ComProperty $service 'Name')
        $id = [string](Get-ComProperty $service 'ServiceID')
        $norm = Get-NormalizedId $id
        $isDefault = Get-ComProperty $service 'IsDefaultAUService'
        $isManaged = Get-ComProperty $service 'IsManaged'
        Write-Log "Service: Name='$name' Id=$id DefaultAU=$isDefault Managed=$isManaged"
        if ($known.ContainsKey($norm)) { continue }
        if ($name -match 'Store|DCat|Offline') {
            Write-Log "Skipping service $name"
            continue
        }
        if ([string]::IsNullOrWhiteSpace($norm)) { continue }
        [void]$targets.Add([pscustomobject]@{ Label = $name; Selection = 3; ServiceId = $norm; Upgrade = $false })
    }
    try {
        $au = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
        $wu = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
        if ($null -ne $au -and $null -ne $au.UseWUServer -and [int]$au.UseWUServer -eq 1 -and $null -ne $wu -and $wu.WUServer) {
            [void]$targets.Add([pscustomobject]@{ Label = 'Managed server'; Selection = 1; ServiceId = ''; Upgrade = $false })
            Write-Log "WSUS configured: $($wu.WUServer)"
        }
    } catch { }
    return @($targets.ToArray())
}

function Set-SearcherTarget {
    param($Searcher, $Target)
    $Searcher.ServerSelection = [int]$Target.Selection
    if ([int]$Target.Selection -eq 3) {
        $Searcher.ServiceID = [string]$Target.ServiceId
    }
    try { $Searcher.CanAutomaticallyUpgradeService = [bool]$Target.Upgrade } catch { }
    try { $Searcher.Online = $true } catch { }
    try { $Searcher.IncludePotentiallySupersededUpdates = $false } catch { }
}

function Invoke-OneSearch {
    param($Session, $Target, [string]$Criteria)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $searcher = $null
        try {
            Start-WuauservReady
            $searcher = $Session.CreateUpdateSearcher()
            [void]$script:ComPins.Add($searcher)
            Set-SearcherTarget -Searcher $searcher -Target $Target
            $selection = ''
            $serviceId = ''
            try { $selection = [string]$searcher.ServerSelection } catch { }
            try { $serviceId = [string]$searcher.ServiceID } catch { }
            Write-Log "Searcher '$($Target.Label)' selection=$selection service=$serviceId upgrade=$($Target.Upgrade) criteria=$Criteria"
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $result = $searcher.Search($Criteria)
            $sw.Stop()
            $code = 2
            try { $code = [int]$result.ResultCode } catch { $code = 2 }
            $updates = @(Get-ComItems (Get-ComProperty $result 'Updates'))
            Write-Log ("Search '{0}' result={1} updates={2} seconds={3:n1}" -f $Target.Label, $code, $updates.Count, $sw.Elapsed.TotalSeconds)
            if ($null -ne $result.Warnings) {
                foreach ($warning in @(Get-ComItems $result.Warnings)) {
                    $warningText = [string](Get-ComProperty $warning 'Message')
                    if ($warningText) { Write-Log "Search warning: $warningText" }
                }
            }
            if ($code -ge 4) { throw "Search result code $code" }
            return [pscustomobject]@{ Completed = $true; Updates = $updates; Error = ''; InvalidCriteria = $false }
        } catch {
            $hex = ConvertTo-HexCode $_
            $invalid = ($hex -eq '0x80240032' -or $hex -eq '0x80070057')
            Write-Log ("Search '{0}' attempt {1} failed {2}: {3}" -f $Target.Label, $attempt, $hex, $_.Exception.Message)
            $retry = ((Test-RetryableCode $hex) -or ($_.Exception.Message -match 'Search result code')) -and -not $invalid
            if ($invalid -or -not $retry -or $attempt -eq 3) {
                return [pscustomobject]@{
                    Completed       = $false
                    Updates         = @()
                    Error           = ("{0} {1}" -f $hex, $_.Exception.Message).Trim()
                    InvalidCriteria = [bool]$invalid
                }
            }
            Start-Sleep -Seconds 15
        }
    }
}

function Add-BlockedUpdate {
    param($Update, [string]$Label, [bool]$Hide, $Found)
    $title = [string](Get-ComProperty $Update 'Title')
    $description = [string](Get-ComProperty $Update 'Description')
    $quick = $title + "`n" + $description
    $typeText = [string](Get-ComProperty $Update 'Type')
    $isDriver = ($typeText -match 'Driver') -or ($typeText -eq '2')
    # The all-types catalog search returns every missing update. Skip software
    # updates that do not mention a blocked version before touching driver properties.
    if (-not $isDriver -and -not (Test-BlockedVersionText $quick)) { return $false }
    $blob = Get-UpdateBlob $Update
    if (-not (Test-BlockedBluetoothText $blob)) { return $false }
    $identity = Get-ComProperty $Update 'Identity'
    $id = Get-NormalizedId ([string](Get-ComProperty $identity 'UpdateID'))
    $rev = [string](Get-ComProperty $identity 'RevisionNumber')
    $key = if ($id) { "$id.$rev" } else { "title:$title" }
    if ($Found.ContainsKey($key)) {
        $existing = $Found[$key]
        if (-not ($Hide -and $existing.Action -eq 'HideFailed')) { return $false }
    }
    $wasHidden = [bool](Get-ComProperty $Update 'IsHidden')
    $downloaded = [bool](Get-ComProperty $Update 'IsDownloaded')
    $mandatory = [bool](Get-ComProperty $Update 'IsMandatory')
    $action = if ($wasHidden) { 'AlreadyHidden' } else { 'Offered' }
    $hideError = ''
    if ($Hide -and -not $wasHidden) {
        try {
            $Update.IsHidden = $true
            $wasHidden = [bool](Get-ComProperty $Update 'IsHidden')
            if ($wasHidden) {
                $action = 'Hidden'
            } else {
                $action = 'HideFailed'
                $hideError = 'IsHidden stayed false'
            }
        } catch {
            $action = 'HideFailed'
            $hideError = ("{0} {1}" -f (ConvertTo-HexCode $_), $_.Exception.Message).Trim()
            $wasHidden = [bool](Get-ComProperty $Update 'IsHidden')
        }
    }
    $Found[$key] = [pscustomobject]@{
        Key          = $key
        Title        = $title
        IsHidden     = $wasHidden
        IsDownloaded = $downloaded
        IsMandatory  = $mandatory
        Service      = $Label
        Action       = $action
        HideError    = $hideError
    }
    [void]$script:ComPins.Add($Update)
    Write-Log "Match $action on ${Label}: hidden=$wasHidden downloaded=$downloaded mandatory=$mandatory title='$title' id=$key"
    if ($hideError) { Write-Log "Hide error: $hideError" }
    return $true
}

function Invoke-TargetSearch {
    param($Session, $Target, [string]$Criteria, [bool]$Hide, $Found, [bool]$AllowFallback)
    $first = Invoke-OneSearch -Session $Session -Target $Target -Criteria $Criteria
    $collected = @()
    $completed = $false
    $errorText = ''
    if ($first.Completed) {
        $completed = $true
        $collected = @($first.Updates)
    } elseif ($AllowFallback -and $first.InvalidCriteria) {
        Write-Log "Combined driver criteria was rejected for $($Target.Label); searching each clause"
        $clauseErrors = New-Object 'System.Collections.Generic.List[string]'
        $allClauses = $true
        foreach ($simple in $script:SimpleDriverCriteria) {
            $one = Invoke-OneSearch -Session $Session -Target $Target -Criteria $simple
            if ($one.Completed) {
                $collected += @($one.Updates)
            } else {
                $allClauses = $false
                if ($one.Error) { [void]$clauseErrors.Add($one.Error) }
            }
        }
        # A missing clause can be the one Settings uses. Do not call that a completed search.
        $completed = $allClauses
        $errorText = ($clauseErrors -join '; ')
    } else {
        $errorText = $first.Error
    }
    $matchCount = 0
    foreach ($update in @($collected)) {
        if (Add-BlockedUpdate -Update $update -Label $Target.Label -Hide:$Hide -Found $Found) {
            $matchCount++
        }
    }
    Write-Log "Target $($Target.Label) new-blocked-matches=$matchCount completed=$completed"
    return [pscustomobject]@{ Completed = $completed; Error = $errorText }
}

function Invoke-UpdateScan {
    param([bool]$Hide)
    $found = @{}
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $muCompleted = $false
    $muError = ''
    $anyDriver = $false

    Start-WuauservReady
    $manager = New-Object -ComObject Microsoft.Update.ServiceManager
    [void]$script:ComPins.Add($manager)
    [void](Register-MicrosoftUpdateIfNeeded -ServiceManager $manager)
    $session = New-Object -ComObject Microsoft.Update.Session
    try { $session.ClientApplicationID = 'IntelBTDriverBlock' } catch { }
    [void]$script:ComPins.Add($session)

    foreach ($target in @(Get-SearchTargets -ServiceManager $manager)) {
        $outcome = Invoke-TargetSearch -Session $session -Target $target -Criteria $script:DriverCriteria -Hide:$Hide -Found $found -AllowFallback $true
        if ($target.Label -eq 'Microsoft Update') {
            $muCompleted = [bool]$outcome.Completed
            $muError = [string]$outcome.Error
        }
        if ($outcome.Completed) { $anyDriver = $true }
        elseif ($outcome.Error) { [void]$errors.Add("$($target.Label): $($outcome.Error)") }
    }

    return [pscustomobject]@{
        Updates                    = @($found.Values)
        MicrosoftUpdateCompleted   = $muCompleted
        MicrosoftUpdateError       = $muError
        AnyDriverSearchCompleted   = $anyDriver
        Errors                     = @($errors.ToArray())
    }
}

function Get-UsoSuppressFlag {
    return (Join-Path $script:LogDir 'uso-suppress-until.txt')
}

function Test-BlockedUpdatesHidden {
    param($Scan)
    $updates = @($Scan.Updates)
    if ($updates.Count -eq 0) { return $false }
    foreach ($update in $updates) {
        if (-not $update.IsHidden -or $update.IsDownloaded) { return $false }
    }
    return $true
}

function Test-UsoSuppressActive {
    param($Scan)
    if (-not (Test-BlockedUpdatesHidden $Scan)) { return $false }
    $flag = Get-UsoSuppressFlag
    if (-not (Test-Path -LiteralPath $flag)) { return $false }
    try { $text = [IO.File]::ReadAllText($flag).Trim() } catch { return $false }
    $until = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::RoundtripKind -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$until)) { return $false }
    return ($until.ToUniversalTime() -gt [datetime]::UtcNow)
}

function Set-UsoSuppressWindow {
    $until = [datetime]::UtcNow.AddHours(24).ToString('o')
    if (-not (Test-Path -LiteralPath $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }
    [IO.File]::WriteAllText((Get-UsoSuppressFlag), $until)
    Write-Log "Hidden update remains in USO text. Detection will ignore that text until $until"
}

function Get-UsoReplayFlag {
    return (Join-Path $script:LogDir 'uso-replay-until.txt')
}

function Test-TimeFlagActive {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try { $text = [IO.File]::ReadAllText($Path).Trim() } catch { return $false }
    $until = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::RoundtripKind -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$until)) { return $false }
    return ($until.ToUniversalTime() -gt [datetime]::UtcNow)
}

function Test-UsoReplayActive {
    return (Test-TimeFlagActive (Get-UsoReplayFlag))
}

function Set-UsoReplayWindow {
    $until = [datetime]::UtcNow.AddHours(24).ToString('o')
    if (-not (Test-Path -LiteralPath $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }
    [IO.File]::WriteAllText((Get-UsoReplayFlag), $until)
    Write-Log "USO rewrote the blocked text and Windows Update had no matching update. Another delete is skipped until $until"
}

function Get-ComplianceReasons {
    param($Scan, $Staged, $UsoHits, $DownloadFolders)
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    foreach ($update in @($Scan.Updates)) {
        $label = if ($update.Title) { $update.Title } else { $update.Key }
        if (-not $update.IsHidden) {
            $suffix = ''
            if ($update.Action -eq 'HideFailed') { $suffix = " Hide failed: $($update.HideError)" }
            if ($update.IsMandatory) { $suffix = $suffix + ' Update is mandatory.' }
            [void]$reasons.Add("Offered on $($update.Service): $label$suffix")
        } elseif ($update.IsDownloaded) {
            [void]$reasons.Add("Hidden but downloaded on $($update.Service): $label")
        }
    }
    foreach ($driver in @($Staged)) {
        if ($driver.InUse) {
            Write-Log "Blocked version is installed and in use ($($driver.Driver) $($driver.Version)); the live package was not removed"
            continue
        }
        [void]$reasons.Add("Staged driver $($driver.Driver) version $($driver.Version)")
    }
    $suppressUso = Test-UsoSuppressActive $Scan
    if ($suppressUso) {
        Write-Log 'USO still mentions a blocked version, and that update is already hidden. Not treating it as an offer during the suppress window.'
    }
    foreach ($hit in @($UsoHits)) {
        if ($suppressUso) { continue }
        [void]$reasons.Add("USO UpdateStore references a blocked version in $(Split-Path -Leaf $hit)")
    }
    foreach ($folder in @($DownloadFolders)) {
        [void]$reasons.Add("Downloaded payload folder $(Split-Path -Leaf $folder)")
    }
    if ($reasons.Count -eq 0) {
        if (-not $Scan.MicrosoftUpdateCompleted -and -not (Test-InternetUpdateBlocked)) {
            $why = if ($Scan.MicrosoftUpdateError) { $Scan.MicrosoftUpdateError } else { 'not completed' }
            [void]$reasons.Add("Inconclusive: Microsoft Update search did not complete ($why)")
        } elseif (-not $script:UsoReadable) {
            [void]$reasons.Add('Inconclusive: USO UpdateStore could not be read')
        } elseif (-not $script:DriverStoreReadable) {
            [void]$reasons.Add('Inconclusive: the driver store could not be enumerated')
        } elseif (-not $Scan.AnyDriverSearchCompleted) {
            [void]$reasons.Add("Inconclusive: no driver search completed ($($Scan.Errors -join '; '))")
        }
    }
    return @($reasons.ToArray())
}

function Remove-StagedBlockedDrivers {
    param($Staged)
    $removed = New-Object 'System.Collections.Generic.List[string]'
    $pnputil = Join-ChildPath $env:SystemRoot 'System32\pnputil.exe'
    foreach ($driver in @($Staged)) {
        if ($driver.InUse) {
            Write-Log "Left in-use driver $($driver.Driver) $($driver.Version)"
            continue
        }
        if ($driver.Inbox) {
            Write-Log "Left inbox driver $($driver.Driver)"
            continue
        }
        if ($driver.Driver -notmatch '^oem\d+\.inf$') {
            Write-Log "Left non-oem driver package $($driver.Driver)"
            continue
        }
        if (-not (Test-Path -LiteralPath $pnputil)) {
            Write-Log 'pnputil.exe was not found'
            continue
        }
        $output = & $pnputil /delete-driver $driver.Driver 2>&1
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            [void]$removed.Add($driver.Driver)
            Write-Log "Removed staged $($driver.Driver)"
        } else {
            Write-Log "pnputil /delete-driver $($driver.Driver) exited $code $($output -join ' ')"
        }
    }
    return @($removed.ToArray())
}

function Invoke-TargetedCleanup {
    param($DownloadFolders, $UsoHits)
    $removedDownloads = New-Object 'System.Collections.Generic.List[string]'
    $removedUso = New-Object 'System.Collections.Generic.List[string]'
    if (@($DownloadFolders).Count -eq 0 -and @($UsoHits).Count -eq 0) {
        return [pscustomobject]@{ Downloads = @(); Uso = @() }
    }
    Write-Log 'Stopping the update stack for targeted payload cleanup'
    Stop-UpdateStack
    $downloadRoot = Get-DownloadRoot
    foreach ($folder in @($DownloadFolders)) {
        try {
            if (Remove-BlockedChild -Parent $downloadRoot -Candidate $folder) {
                [void]$removedDownloads.Add($folder)
            }
        } catch {
            Write-Log "Download delete failed for ${folder}: $($_.Exception.Message)"
        }
    }
    $usoRoot = Get-UsoStoreRoot
    $usoTargets = New-Object 'System.Collections.Generic.List[string]'
    $seenUso = @{}
    foreach ($file in @($UsoHits)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        $key = $file.ToLowerInvariant()
        if (-not $seenUso.ContainsKey($key)) {
            $seenUso[$key] = $true
            [void]$usoTargets.Add($file)
        }
        foreach ($sidecar in @(Get-UsoSidecarPaths $file)) {
            $sideKey = $sidecar.ToLowerInvariant()
            if ($seenUso.ContainsKey($sideKey)) { continue }
            $seenUso[$sideKey] = $true
            if (Test-Path -LiteralPath $sidecar) { [void]$usoTargets.Add($sidecar) }
        }
    }
    foreach ($file in @($usoTargets)) {
        try {
            if (Remove-BlockedChild -Parent $usoRoot -Candidate $file) {
                [void]$removedUso.Add($file)
            }
        } catch {
            Write-Log "USO delete failed for ${file}: $($_.Exception.Message)"
        }
    }
    Start-UpdateStack
    return [pscustomobject]@{
        Downloads = @($removedDownloads.ToArray())
        Uso       = @($removedUso.ToArray())
    }
}

function Start-SettingsRefresh {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { return }
    $usoClient = Join-ChildPath $env:SystemRoot 'System32\UsoClient.exe'
    if (-not (Test-Path -LiteralPath $usoClient)) { return }
    # Both commands return before the scan finishes. The COM search is the verification.
    Start-Process -FilePath $usoClient -ArgumentList 'RefreshSettings' -WindowStyle Hidden | Out-Null
    Start-Process -FilePath $usoClient -ArgumentList 'StartInteractiveScan' -WindowStyle Hidden | Out-Null
    Start-Sleep -Seconds 10
}

function Get-ActionSummary {
    param($FirstScan, $SecondScan, $RemovedStaged, $RemovedDownloads, $RemovedUso, $ActiveDrivers)
    $actions = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($update in @(@($FirstScan.Updates) + @($SecondScan.Updates))) {
        if ($null -eq $update) { continue }
        if ($update.Action -ne 'Hidden') { continue }
        if ($seen.ContainsKey($update.Key)) { continue }
        $seen[$update.Key] = $true
        $title = if ($update.Title) { $update.Title } else { $update.Key }
        [void]$actions.Add("Hidden $title")
    }
    if (@($RemovedStaged).Count -gt 0) { [void]$actions.Add("Removed staged $(@($RemovedStaged) -join ', ')") }
    if (@($RemovedDownloads).Count -gt 0) { [void]$actions.Add("Cleared $(@($RemovedDownloads).Count) download folder(s)") }
    if (@($RemovedUso).Count -gt 0) { [void]$actions.Add("Cleared $(@($RemovedUso).Count) USO file(s)") }
    if ($actions.Count -eq 0) { [void]$actions.Add('No blocked Intel Bluetooth update was present') }
    [void]$actions.Add((Get-ActiveSummary $ActiveDrivers))
    return ($actions -join ' | ')
}

function Invoke-Detect {
    Write-Log "=== role=$script:PackageRole mode=$Mode version=$script:ScriptVersion ==="
    Write-EnvironmentLog
    $active = @(Get-ActiveBluetoothDrivers)
    foreach ($driver in $active) {
        Write-Log "Active BT: desc='$($driver.DriverDesc)' version=$($driver.DriverVersion) inf=$($driver.InfName) provider=$($driver.ProviderName) id=$($driver.MatchingDeviceId)"
    }
    try { Write-RegistryHints } catch { Write-Log "Registry hint scan failed: $($_.Exception.Message)" }
    try { Write-RecentUpdateEvents } catch { Write-Log "Event scan failed: $($_.Exception.Message)" }
    $scan = Invoke-UpdateScan -Hide $false
    $staged = @(Get-StagedBlockedDrivers $active)
    $uso = @(Get-UsoHits)
    $downloads = @(Get-BlockedDownloadFolders)
    $reasons = @(Get-ComplianceReasons -Scan $scan -Staged $staged -UsoHits $uso -DownloadFolders $downloads)
    $summary = Get-ActiveSummary $active
    if ($reasons.Count -gt 0) {
        Write-Status -Code 1 -Message ("Non-compliant: " + ($reasons -join ' | ') + " | $summary")
    }
    Write-Status -Code 0 -Message "Compliant: 24.70.0.4 and 24.80.0.2 are not offered, downloaded, or staged. $summary"
}

function Invoke-Remediate {
    Write-Log "=== role=$script:PackageRole mode=$Mode version=$script:ScriptVersion ==="
    Write-EnvironmentLog
    $active = @(Get-ActiveBluetoothDrivers)
    foreach ($driver in $active) {
        Write-Log "Active BT: desc='$($driver.DriverDesc)' version=$($driver.DriverVersion) inf=$($driver.InfName) provider=$($driver.ProviderName) id=$($driver.MatchingDeviceId)"
    }
    $scan = Invoke-UpdateScan -Hide $true
    $staged = @(Get-StagedBlockedDrivers $active)
    $uso = @(Get-UsoHits)
    $downloads = @(Get-BlockedDownloadFolders)
    $removableStaged = @($staged | Where-Object { -not $_.InUse -and -not $_.Inbox })
    # A previous run already deleted this USO text and the rescan wrote it back
    # while Windows Update had nothing to hide. Do not stop the update stack again.
    if ((Test-UsoReplayActive) -and @($scan.Updates).Count -eq 0 -and @($downloads).Count -eq 0 -and @($uso).Count -gt 0 -and $removableStaged.Count -eq 0) {
        Write-Log 'USO still has the blocked text after an earlier delete. Windows Update has no matching update. Leaving the update stack running.'
        Write-Status -Code 1 -Message 'Still present: the paused Intel Bluetooth driver is still in the local update list and Windows Update has no record to hide. Pause every approved version of that driver. Pausing only the newest one makes Windows offer the previous approved version. The update stack was not stopped again.'
    }
    $cleanup = Invoke-TargetedCleanup -DownloadFolders $downloads -UsoHits $uso
    $removedStaged = @(Remove-StagedBlockedDrivers $staged)
    $hidSomething = @($scan.Updates | Where-Object { $_.Action -eq 'Hidden' }).Count -gt 0
    # An interactive scan rebuilds the Settings list. When Windows Update had
    # nothing to hide, that scan is what puts the paused driver back on screen.
    if ($hidSomething -or @($cleanup.Downloads).Count -gt 0 -or @($removedStaged).Count -gt 0) {
        Start-SettingsRefresh
        $scan2 = Invoke-UpdateScan -Hide $true
    } else {
        Write-Log 'Not starting an update scan. Windows Update had no record to hide, and a scan puts the driver back into Settings.'
        Start-Sleep -Seconds 20
        $scan2 = $scan
    }
    $active2 = @(Get-ActiveBluetoothDrivers)
    $staged2 = @(Get-StagedBlockedDrivers $active2)
    $downloads2 = @(Get-BlockedDownloadFolders)
    $uso2 = @(Get-UsoHits)
    $offeredAgain = @($scan2.Updates | Where-Object { -not $_.IsHidden })
    $usoCameBack = $false
    if ($hidSomething -or @($cleanup.Downloads).Count -gt 0 -or @($removedStaged).Count -gt 0) {
        if (($uso2.Count -gt 0 -or $downloads2.Count -gt 0) -and $offeredAgain.Count -eq 0) {
            if (@($uso2).Count -gt 0 -and @($scan2.Updates).Count -eq 0 -and @($downloads2).Count -eq 0) {
                $usoCameBack = $true
            }
            $cleanup2 = Invoke-TargetedCleanup -DownloadFolders $downloads2 -UsoHits $uso2
            $uso2 = @(Get-UsoHits)
            $downloads2 = @(Get-BlockedDownloadFolders)
            $cleanup = [pscustomobject]@{
                Downloads = @(@($cleanup.Downloads) + @($cleanup2.Downloads))
                Uso       = @(@($cleanup.Uso) + @($cleanup2.Uso))
            }
        }
    } elseif (@($uso2).Count -gt 0 -or @($cleanup.Uso).Count -gt 0) {
        # Do not delete again and do not scan. The next scan puts the offer back.
        $usoCameBack = $true
    }
    $reasons = @(Get-ComplianceReasons -Scan $scan2 -Staged $staged2 -UsoHits $uso2 -DownloadFolders $downloads2)
    if ($usoCameBack) {
        Set-UsoReplayWindow
        $reasons = @(@($reasons) + @('Windows Update has no record to hide. The next scan puts this driver back while any version of it remains approved.'))
    }
    $summary = Get-ActionSummary -FirstScan $scan -SecondScan $scan2 -RemovedStaged $removedStaged -RemovedDownloads $cleanup.Downloads -RemovedUso $cleanup.Uso -ActiveDrivers $active2
    # A file that still contains the offer is what Settings shows. Do not report
    # success while that file remains. The 24-hour window is only for a later
    # detection, after the file was actually removed and the update is hidden.
    if ($reasons.Count -gt 0) {
        $policyNote = ''
        $unseen = @($reasons | Where-Object { $_ -like 'USO*' -or $_ -like 'Inconclusive:*' -or $_ -like '*Hide failed*' -or $_ -like '*mandatory*' })
        if ($unseen.Count -gt 0) {
            $policyNote = ' Pause every approved version of this Intel Bluetooth driver. Pausing only the newest version makes Windows offer the previous approved one.'
        }
        Write-Status -Code 1 -Message ("Still present: " + ($reasons -join ' | ') + " | $summary" + $policyNote)
    }
    if (@($cleanup.Uso).Count -gt 0 -and (Test-BlockedUpdatesHidden $scan2)) {
        Set-UsoSuppressWindow
    }
    Write-Status -Code 0 -Message "Remediated. $summary"
}

function Invoke-SelfTest {
    $failures = New-Object 'System.Collections.Generic.List[string]'
    function Assert-Self {
        param([bool]$Condition, [string]$Name)
        if (-not $Condition) {
            [void]$script:SelfTestFailures.Add($Name)
        }
    }
    $script:SelfTestFailures = $failures

    Assert-Self (Test-BlockedBluetoothText 'Intel Corporation Bluetooth Driver Update (24.70.0.4)') 'settings title 24.70'
    Assert-Self (Test-BlockedBluetoothText 'Intel Corporation - Bluetooth - 24.80.0.2') 'catalog title 24.80'
    Assert-Self (Test-BlockedBluetoothText 'Intel(R) Wireless Bluetooth(R) 24.70.0.4') 'wireless bluetooth'
    Assert-Self (Test-BlockedBluetoothText "Provider Intel`nClass Bluetooth`n24.70.0.4") 'split fields'
    Assert-Self (Test-BlockedBluetoothText ("Intel driver " + $script:BluetoothClassGuid + ' 24.80.0.2')) 'class guid'
    Assert-Self (-not (Test-BlockedBluetoothText 'Intel Corporation - Net - 24.70.0.3')) 'wifi other version'
    Assert-Self (-not (Test-BlockedBluetoothText 'Intel Corporation - Net - 24.70.0.4')) 'wifi same digits'
    Assert-Self (-not (Test-BlockedBluetoothText 'Intel Corporation Bluetooth Driver Update (23.10.0.1)')) 'unrelated bluetooth version'
    Assert-Self (-not (Test-BlockedBluetoothText 'Intel Bluetooth 24.70.0.40')) 'version boundary'
    Assert-Self (-not (Test-BlockedBluetoothText 'Bluetooth only 24.80.0.2')) 'missing intel'
    Assert-Self (-not (Test-BlockedBluetoothText 'Intel Bluetooth driver')) 'missing version'
    $far = 'Intel(R) Wireless Bluetooth(R)' + ('z' * 500) + '24.70.0.4'
    Assert-Self (-not (Test-BlockedBluetoothText $far)) 'tokens far apart'
    $near = 'Intel Wireless Bluetooth ' + ('n' * 40) + ' 24.70.0.4'
    Assert-Self (Test-BlockedBluetoothText $near) 'tokens within window'
    Assert-Self (Test-BlockedVersionText 'DriverVer=07/18/2026,24.70.0.4') 'inf driverver'
    Assert-Self (-not (Test-BlockedVersionText '24.70.0.40')) 'boundary helper'
    Assert-Self ((Get-NormalizedId '{7971F918-A847-4430-9279-4A52D1EFE18D}') -eq '7971f918-a847-4430-9279-4a52d1efe18d') 'guid normalize'
    $sidecars = @(Get-UsoSidecarPaths 'C:\ProgramData\USOPrivate\UpdateStore\store.db')
    Assert-Self ($sidecars -contains 'C:\ProgramData\USOPrivate\UpdateStore\store.db-wal') 'wal sidecar'
    Assert-Self ($sidecars -contains 'C:\ProgramData\USOPrivate\UpdateStore\store.db-shm') 'shm sidecar'
    Assert-Self ($sidecars -contains 'C:\ProgramData\USOPrivate\UpdateStore\store.db-journal') 'journal sidecar'

    $dir = Join-Path ([IO.Path]::GetTempPath()) ('ibt-selftest-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    try {
        $parent = Join-Path $dir 'Download'
        $child = Join-Path $parent 'guid'
        New-Item -ItemType Directory -Path $child -Force | Out-Null
        $evil = Join-Path $dir 'DownloadEvil'
        New-Item -ItemType Directory -Path $evil -Force | Out-Null
        $sibling = Join-Path $dir 'DataStore'
        New-Item -ItemType Directory -Path $sibling -Force | Out-Null
        Assert-Self (Test-SafeChildPath -Parent $parent -Candidate $child) 'child allowed'
        Assert-Self (-not (Test-SafeChildPath -Parent $parent -Candidate $parent)) 'parent refused'
        Assert-Self (-not (Test-SafeChildPath -Parent $parent -Candidate $evil)) 'prefix lookalike refused'
        Assert-Self (-not (Test-SafeChildPath -Parent $parent -Candidate $sibling)) 'datastore refused'

        $ascii = Join-Path $dir 'ascii.bin'
        [IO.File]::WriteAllText($ascii, 'record 24.70.0.4 end')
        Assert-Self (Test-FileHasBlockedVersion $ascii) 'ascii file'
        Assert-Self (-not (Test-FileHasBlockedBluetooth $ascii)) 'version-only file is not bluetooth'
        $utf16 = Join-Path $dir 'utf16.bin'
        [IO.File]::WriteAllBytes($utf16, [Text.Encoding]::Unicode.GetBytes('Intel Corporation Bluetooth Driver Update (24.80.0.2)'))
        Assert-Self (Test-FileHasBlockedVersion $utf16) 'utf16 file'
        Assert-Self (Test-FileHasBlockedBluetooth $utf16) 'utf16 bluetooth file'
        $clean = Join-Path $dir 'clean.bin'
        [IO.File]::WriteAllText($clean, 'Intel Bluetooth 23.10.0.1')
        Assert-Self (-not (Test-FileHasBlockedVersion $clean)) 'clean file'
        $boundary = Join-Path $dir 'boundary.bin'
        [IO.File]::WriteAllText($boundary, '24.70.0.40')
        Assert-Self (-not (Test-FileHasBlockedVersion $boundary)) 'boundary file'

        $savedRoot = $env:SystemRoot
        $env:SystemRoot = Join-Path $dir 'Windows'
        try {
            $root = Get-DownloadRoot
            $pkg = Join-Path $root 'pkg1'
            $wifi = Join-Path $root 'wifi'
            New-Item -ItemType Directory -Path $pkg -Force | Out-Null
            New-Item -ItemType Directory -Path $wifi -Force | Out-Null
            [IO.File]::WriteAllText((Join-Path $pkg 'ibtusb.inf'), "[Version]`r`nClass=Bluetooth`r`nProvider=Intel`r`nDriverVer=07/18/2026,24.70.0.4`r`n")
            [IO.File]::WriteAllText((Join-Path $wifi 'netw.inf'), "Provider=Intel`r`nClass=Net`r`nDriverVer=07/18/2026,24.70.0.3`r`n")
            $folders = @(Get-BlockedDownloadFolders)
            Assert-Self ($folders.Count -eq 1) 'one download folder'
            Assert-Self ((@($folders)[0]) -like '*pkg1') 'matched bluetooth package'
        } finally {
            $env:SystemRoot = $savedRoot
        }
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($script:SelfTestFailures.Count -gt 0) {
        Write-Output ("SelfTest failed: " + ($script:SelfTestFailures -join ' | '))
        exit 1
    }
    Write-Output 'SelfTest passed'
    exit 0
}

if ($Mode -eq 'SelfTest') {
    Invoke-SelfTest
}

try {
    Initialize-Log
    if ($Mode -eq 'Detect') {
        Invoke-Detect
    } elseif ($Mode -eq 'Remediate') {
        Invoke-Remediate
    } else {
        Write-Status -Code 1 -Message "Unknown mode $Mode"
    }
} catch {
    Write-Status -Code 1 -Message ("$Mode error: " + $_.Exception.Message)
}
