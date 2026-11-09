<#
.SYNOPSIS
    Install Intel Bluetooth 24.80.0.2, clear the cached Windows Update offer, and check again.

.DESCRIPTION
    Windows Update offers 24.70.0.4 and 24.80.0.2 only when they are newer than
    the installed Intel Bluetooth driver. This script downloads Intel's
    24.80.0 package from Intel, installs it quietly without rebooting, then
    renames SoftwareDistribution\DataStore and deletes the Update Orchestrator
    store. It starts the update stack and runs one check for updates.

    24.80.0.2 is installed instead of 24.70.0.4. Installing the older package
    after 24.80.0.2 would downgrade the adapter and make 24.80.0.2 applicable
    again. A newer approved driver, such as 24.90.0.3, can still be offered.

    The Intel installer is started with /quiet /norestart and
    REBOOT=ReallySuppress. This script does not reboot the PC.

    Run once as SYSTEM in 64-bit Windows PowerShell. Do not schedule it as the
    daily Intune remediation. It does not set ExcludeWUDriversInQualityUpdate,
    delete the download cache, or clear RebootRequired.

.NOTES
    Version 1.0.1
    Log: C:\temp\IntelBTDriverUpdate.txt
#>
[CmdletBinding()]
param(
    [ValidateSet('Apply', 'SelfTest')]
    [string]$Mode = 'Apply'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$script:ScriptVersion = '1.0.1'
$script:TargetVersion = [version]'24.80.0.2'
$script:PackageUrl = 'https://downloadmirror.intel.com/930964/BT-24.80.0-64UWD-Win10-Win11.exe'
$script:PackageSha512 = 'dd5335728d36d79c787c0592784e8c345f2c38d0ca245b5bcc50b1f99026e01b529b3921e20d7c26e16708354aa798839823dd591e86cf87a1803dc1a22e66c9'
$script:PackageName = 'BT-24.80.0-64UWD-Win10-Win11.exe'
$script:BlockedVersions = @('24.70.0.4', '24.80.0.2')
$script:BluetoothClassGuid = 'e0cbf06c-cd8b-4647-bb8a-263b43f0f974'
$script:LogPath = 'C:\temp\IntelBTDriverUpdate.txt'
$script:MedicTaskPath = '\Microsoft\Windows\WaaSMedic\'
$script:MedicTaskName = 'PerformRemediation'
$script:ServiceNames = @('WaaSMedicSvc', 'usosvc', 'dosvc', 'bits', 'wuauserv')

function Write-Log {
    param([string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Output $line
    if ($Mode -eq 'SelfTest') { return }
    try {
        $dir = Split-Path -Parent $script:LogPath
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    } catch {
        Write-Output ("{0} log write failed: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $_.Exception.Message)
    }
}

function ConvertTo-DriverVersion {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return [version]$Text.Trim() } catch { return $null }
}

function Test-HashEqual {
    param([string]$Actual, [string]$Expected)
    return ([string]::Equals($Actual.Trim(), $Expected.Trim(), [StringComparison]::OrdinalIgnoreCase))
}

function Test-OfferText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    foreach ($version in $script:BlockedVersions) {
        $start = 0
        while (($index = $Text.IndexOf($version, $start, [StringComparison]::Ordinal)) -ge 0) {
            $beforeOk = $index -eq 0 -or -not [char]::IsDigit($Text[$index - 1])
            $afterAt = $index + $version.Length
            $afterOk = $afterAt -ge $Text.Length -or -not [char]::IsDigit($Text[$afterAt])
            if ($beforeOk -and $afterOk) {
                $from = [Math]::Max(0, $index - 200)
                $length = [Math]::Min($Text.Length - $from, 200 + $version.Length + 200)
                $window = $Text.Substring($from, $length)
                $intel = $window.IndexOf('Intel', [StringComparison]::OrdinalIgnoreCase) -ge 0
                $bluetooth = $window.IndexOf('Bluetooth', [StringComparison]::OrdinalIgnoreCase) -ge 0
                $class = $window.IndexOf($script:BluetoothClassGuid, [StringComparison]::OrdinalIgnoreCase) -ge 0
                if (($intel -and $bluetooth) -or $class) { return $true }
            }
            $start = $index + $version.Length
        }
    }
    return $false
}

function Get-StorePath {
    return (Join-Path $env:ProgramData 'USOPrivate\UpdateStore\store.db')
}

function Read-StoreBytes {
    $path = Get-StorePath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $stream = $null
    try {
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $buffer = New-Object byte[] ([int]$stream.Length)
        $read = 0
        while ($read -lt $buffer.Length) {
            $got = $stream.Read($buffer, $read, $buffer.Length - $read)
            if ($got -le 0) { break }
            $read += $got
        }
        if ($read -lt $buffer.Length) {
            $exact = New-Object byte[] $read
            [Array]::Copy($buffer, $exact, $read)
            return $exact
        }
        return $buffer
    } catch {
        Write-Log "Could not read store.db: $($_.Exception.Message)"
        return $null
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-StoreHasOffer {
    $bytes = Read-StoreBytes
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return $false }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $texts = @(
        [Text.Encoding]::Unicode.GetString($bytes),
        [Text.Encoding]::BigEndianUnicode.GetString($bytes),
        $utf8.GetString($bytes),
        [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    )
    foreach ($text in $texts) {
        if (Test-OfferText $text) { return $true }
    }
    return $false
}

function Get-InstalledBluetoothVersions {
    $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.DeviceName -match 'Intel' -and $_.DeviceName -match 'Bluetooth' })
    $versions = New-Object System.Collections.Generic.List[version]
    foreach ($driver in $drivers) {
        $parsed = ConvertTo-DriverVersion $driver.DriverVersion
        if ($null -ne $parsed) { [void]$versions.Add($parsed) }
        Write-Log ("Installed: {0} {1} {2}" -f $driver.DeviceName, $driver.DriverVersion, $driver.InfName)
    }
    return $versions
}

function Wait-UpdateStackStopped {
    Stop-Service -Name $script:ServiceNames -Force -ErrorAction SilentlyContinue
    Get-Process -Name MoUsoCoreWorker, UsoClient, wuauclt, WaaSMedicAgent -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(120)
    do {
        $running = @(Get-Service -Name wuauserv, usosvc -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -ne 'Stopped' })
        if ($running.Count -eq 0) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    $still = @(Get-Service -Name wuauserv, usosvc -ErrorAction SilentlyContinue |
        ForEach-Object { '{0}={1}' -f $_.Name, $_.Status })
    Write-Log ("Update stack did not stop: " + ($still -join ', '))
    return $false
}

function Start-UpdateStack {
    $ok = $true
    foreach ($name in @('wuauserv', 'bits', 'dosvc', 'usosvc', 'WaaSMedicSvc')) {
        try {
            Start-Service -Name $name -ErrorAction Stop
        } catch {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $service -or $service.Status -ne 'Running') {
                if ($name -eq 'WaaSMedicSvc' -or $name -eq 'bits') {
                    Write-Log "$name was not started: $($_.Exception.Message)"
                } else {
                    Write-Log "Failed to start ${name}: $($_.Exception.Message)"
                    $ok = $false
                }
            }
        }
    }
    return $ok
}

function Set-MedicTask {
    param([bool]$Enable)
    $task = $null
    try {
        $task = Get-ScheduledTask -TaskPath $script:MedicTaskPath -TaskName $script:MedicTaskName -ErrorAction Stop
    } catch {
        Write-Log "Medic task was not read: $($_.Exception.Message)"
        return $false
    }
    if ($null -eq $task) {
        Write-Log "Medic task $($script:MedicTaskPath)$($script:MedicTaskName) was not found"
        return $false
    }
    try {
        if ($Enable) {
            Enable-ScheduledTask -TaskPath $script:MedicTaskPath -TaskName $script:MedicTaskName -ErrorAction Stop | Out-Null
            Write-Log 'Enabled Windows Update Medic task PerformRemediation'
        } else {
            Disable-ScheduledTask -TaskPath $script:MedicTaskPath -TaskName $script:MedicTaskName -ErrorAction Stop | Out-Null
            Write-Log 'Disabled Windows Update Medic task PerformRemediation'
        }
    } catch {
        Write-Log "Medic task was not changed: $($_.Exception.Message)"
        return $false
    }
    return $true
}

function Get-CurlPath {
    if (-not [Environment]::Is64BitProcess) {
        $native = Join-Path $env:WinDir 'SysNative\curl.exe'
        if (Test-Path -LiteralPath $native) { return $native }
    }
    $system = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (Test-Path -LiteralPath $system) { return $system }
    return $null
}

function Save-DriverPackage {
    $dir = 'C:\temp\IntelBTDriverPackages'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $dest = Join-Path $dir $script:PackageName
    if (Test-Path -LiteralPath $dest) {
        $existing = (Get-FileHash -LiteralPath $dest -Algorithm SHA512).Hash
        if (Test-HashEqual $existing $script:PackageSha512) {
            Write-Log "Using existing $($script:PackageName); the SHA512 matched"
            return $dest
        }
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Downloading $($script:PackageUrl)"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $curl = Get-CurlPath
    if ($curl) {
        $output = & $curl -fL --retry 3 --retry-delay 2 -A 'IntelBTDriverUpdate' -o $dest $script:PackageUrl 2>&1
        $code = $LASTEXITCODE
        $size = 0
        if (Test-Path -LiteralPath $dest) { $size = (Get-Item -LiteralPath $dest).Length }
        if ($code -eq 0 -and $size -gt 0) {
            Write-Log "curl.exe downloaded $size bytes"
        } else {
            $text = ($output | Out-String).Trim()
            if ($text.Length -gt 500) { $text = $text.Substring(0, 500) }
            [void]$errors.Add("curl.exe exit ${code}: $text")
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        }
    } else {
        [void]$errors.Add('curl.exe was not found')
    }
    if (-not (Test-Path -LiteralPath $dest)) {
        # Invoke-WebRequest under SYSTEM looks up the current user's Internet
        # Settings key. When that profile is not loaded, Windows returns
        # "The system cannot find the file specified" before any download.
        try {
            $proxy = [Net.WebRequest]::GetSystemWebProxy()
            $proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCredentials
            [Net.WebRequest]::DefaultWebProxy = $proxy
        } catch {
            Write-Log "Per-user proxy lookup failed: $($_.Exception.Message). Downloading without that proxy."
            [Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
        }
        $client = New-Object System.Net.WebClient
        try {
            $client.Headers['User-Agent'] = 'IntelBTDriverUpdate'
            $client.DownloadFile($script:PackageUrl, $dest)
        } catch {
            [void]$errors.Add("WebClient: $($_.Exception.Message)")
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        } finally {
            $client.Dispose()
        }
    }
    if (-not (Test-Path -LiteralPath $dest)) {
        throw ("Download failed. " + ($errors -join ' | '))
    }
    $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA512).Hash
    if (-not (Test-HashEqual $hash $script:PackageSha512)) {
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
        throw "SHA512 mismatch for $($script:PackageName)"
    }
    Write-Log "Downloaded $($script:PackageName) and the SHA512 matched"
    return $dest
}

function Install-DriverPackage {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Installer file was not found: $Path"
    }
    Write-Log "Installing $Path /quiet /norestart"
    $proc = Start-Process -FilePath $Path -ArgumentList '/quiet /norestart REBOOT=ReallySuppress' -Wait -PassThru -WindowStyle Hidden
    $code = $proc.ExitCode
    Write-Log "Installer exit code $code"
    if ($code -eq 0 -or $code -eq 3010) { return $true }
    Write-Log 'Installer failed. The update cache was not cleared.'
    return $false
}

function Clear-UpdateOfferCache {
    if (-not (Wait-UpdateStackStopped)) {
        throw 'Windows Update did not stop, so the update database was left in place'
    }
    $source = Join-Path $env:SystemRoot 'SoftwareDistribution\DataStore'
    if (Test-Path -LiteralPath $source) {
        $parent = Split-Path -Parent $source
        $stamp = Get-Date -Format 'yyyyMMddHHmmss'
        $name = "DataStore.bak-$stamp"
        $destination = Join-Path $parent $name
        $suffix = 1
        while (Test-Path -LiteralPath $destination) {
            $name = "DataStore.bak-$stamp-$suffix"
            $destination = Join-Path $parent $name
            $suffix++
        }
        Rename-Item -LiteralPath $source -NewName $name -ErrorAction Stop
        Write-Log "Renamed DataStore to $name"
    } else {
        Write-Log 'DataStore folder is not present'
    }
    $root = Join-Path $env:ProgramData 'USOPrivate\UpdateStore'
    if (Test-Path -LiteralPath $root) {
        $files = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'store.db' -or $_.Name -like 'store.db-*' })
        foreach ($file in $files) {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            Write-Log "Deleted $($file.FullName)"
        }
    }
}

function Invoke-SelfTest {
    $failures = New-Object 'System.Collections.Generic.List[string]'
    if ((ConvertTo-DriverVersion '24.80.0.2') -lt $script:TargetVersion) { [void]$failures.Add('target compare') }
    if ((ConvertTo-DriverVersion '24.70.0.4') -ge $script:TargetVersion) { [void]$failures.Add('older compare') }
    if ((ConvertTo-DriverVersion '24.80.0.2') -lt (ConvertTo-DriverVersion '24.70.0.4')) { [void]$failures.Add('order') }
    if (-not (Test-HashEqual $script:PackageSha512.ToUpperInvariant() $script:PackageSha512)) { [void]$failures.Add('hash case') }
    if (-not (Test-OfferText 'Intel Corporation Bluetooth Driver Update (24.70.0.4)')) { [void]$failures.Add('title') }
    if (Test-OfferText 'Intel Corporation - Net - 24.70.0.4') { [void]$failures.Add('wifi') }
    if ($failures.Count -gt 0) {
        Write-Output ("SelfTest failed: " + ($failures -join ' | '))
        exit 1
    }
    Write-Output 'SelfTest passed'
    exit 0
}

if ($Mode -eq 'SelfTest') { Invoke-SelfTest }

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WinDir 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if ($PSCommandPath -and (Test-Path -LiteralPath $sysnative)) {
        & $sysnative -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -Mode $Mode
        if ($null -eq $LASTEXITCODE) { exit 1 }
        exit $LASTEXITCODE
    }
}

$exitCode = 0
$taskDisabled = $false
$stackTouched = $false
try {
    Write-Log "=== Install-IntelBTDriverAndClear version=$script:ScriptVersion ==="
    $installed = @(Get-InstalledBluetoothVersions)
    if ($installed.Count -eq 0) {
        throw 'No installed Intel Bluetooth driver was found'
    }
    $needsInstall = @($installed | Where-Object { $_ -lt $script:TargetVersion }).Count -gt 0
    if (-not $needsInstall) {
        Write-Log 'Installed Intel Bluetooth driver is already 24.80.0.2 or newer'
    } else {
        $package = Save-DriverPackage
        if (-not (Set-MedicTask -Enable $false)) {
            Write-Log 'Continuing without a Medic task change'
        } else {
            $taskDisabled = $true
        }
        $stackTouched = $true
        if (-not (Wait-UpdateStackStopped)) {
            throw 'Windows Update did not stop before the driver install'
        }
        if (-not (Install-DriverPackage $package)) {
            throw 'Intel Bluetooth package did not install'
        }
        $installed = @(Get-InstalledBluetoothVersions)
        $stillOld = @($installed | Where-Object { $_ -lt $script:TargetVersion })
        if ($installed.Count -eq 0 -or $stillOld.Count -gt 0) {
            throw 'Installed Intel Bluetooth driver is still older than 24.80.0.2. The update cache was not cleared.'
        }
    }
    if (-not $stackTouched) {
        if (-not (Set-MedicTask -Enable $false)) {
            Write-Log 'Continuing without a Medic task change'
        } else {
            $taskDisabled = $true
        }
        $stackTouched = $true
    }
    Clear-UpdateOfferCache
    Write-Log 'Cached update offer removed. Starting one check for updates.'
} catch {
    $detail = $_.Exception.Message
    $lineNo = $_.InvocationInfo.ScriptLineNumber
    $command = $_.InvocationInfo.Line
    if ($command) { $command = $command.Trim() }
    Write-Log "Install-and-clear error (line ${lineNo}): $detail"
    if ($command) { Write-Log "Failed command: $command" }
    $exitCode = 1
} finally {
    if ($stackTouched) {
        if (-not (Start-UpdateStack)) { $exitCode = 1 }
    }
    if ($taskDisabled) {
        try {
            if (-not (Set-MedicTask -Enable $true)) { $exitCode = 1 }
        } catch {
            Write-Log ("Could not enable the Medic task: " + $_.Exception.Message)
            $exitCode = 1
        }
    }
}

if ($exitCode -eq 0) {
    $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
    if (Test-Path -LiteralPath $uso) {
        Start-Process -FilePath $uso -ArgumentList 'StartScan' -WindowStyle Hidden | Out-Null
        Write-Log 'Started UsoClient StartScan'
    } else {
        Write-Log 'UsoClient.exe was not found'
        $exitCode = 1
    }
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 15
        if (Test-StoreHasOffer) {
            Write-Log '24.70.0.4 or 24.80.0.2 is back in store.db after the check for updates'
            $exitCode = 1
            break
        }
    } while ((Get-Date) -lt $deadline)
    if ($exitCode -eq 0) {
        Write-Log 'Recheck did not put 24.70.0.4 or 24.80.0.2 back into store.db'
        Get-InstalledBluetoothVersions | Out-Null
    }
}

Write-Log "EXIT $exitCode"
exit $exitCode
