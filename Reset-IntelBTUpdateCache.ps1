<#
.SYNOPSIS
    Drop a stale Intel Bluetooth driver offer that Windows rebuilds from the local update database.

.DESCRIPTION
    Deleting USOPrivate\UpdateStore\store.db does not last. When the Update
    Orchestrator starts, it writes that file again from
    SoftwareDistribution\DataStore, even when Windows Update has no driver
    object to hide.

    Run this once, as SYSTEM, in 64-bit Windows PowerShell, on a machine that
    still shows Intel Bluetooth 24.70.0.4 or 24.80.0.2 after the driver is
    paused in every assigned Intune policy. Do not schedule it as the daily
    Intune remediation. The hide scripts do not rename DataStore.

    When store.db contains either version next to Intel Bluetooth text, or
    next to the Bluetooth class GUID, this script:
      1. Disables the Windows Update Medic task PerformRemediation.
      2. Stops the update stack.
      3. Renames SoftwareDistribution\DataStore to a timestamped backup.
      4. Deletes store.db and its SQLite sidecars.
      5. Starts the update stack and enables the Medic task again.

    It does not scan, remove the installed Bluetooth driver, delete the
    download cache, clear RebootRequired, or set
    ExcludeWUDriversInQualityUpdate. Renaming DataStore drops every other
    cached Windows Update entry until the next normal check. The backup
    folder is left in place.

.NOTES
    Version 1.0.0
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

$script:ScriptVersion = '1.0.0'
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

function Get-TextsFromBytes {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return @() }
    $utf8 = New-Object System.Text.UTF8Encoding $false
    return @(
        [Text.Encoding]::Unicode.GetString($Bytes),
        [Text.Encoding]::BigEndianUnicode.GetString($Bytes),
        $utf8.GetString($Bytes),
        [Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    )
}

function Test-BytesHaveOffer {
    param([byte[]]$Bytes)
    foreach ($text in @(Get-TextsFromBytes $Bytes)) {
        if (Test-OfferText $text) { return $true }
    }
    return $false
}

function Get-StorePath {
    return (Join-Path $env:ProgramData 'USOPrivate\UpdateStore\store.db')
}

function Get-DataStorePath {
    return (Join-Path $env:SystemRoot 'SoftwareDistribution\DataStore')
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
        Write-Log "Could not read store.db directly: $($_.Exception.Message)"
        return $null
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
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
                # WaaSMedicSvc and bits are normally stopped until triggered.
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
    $task = Get-ScheduledTask -TaskPath $script:MedicTaskPath -TaskName $script:MedicTaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        Write-Log "Medic task $($script:MedicTaskPath)$($script:MedicTaskName) was not found"
        return $false
    }
    if ($Enable) {
        Enable-ScheduledTask -TaskPath $script:MedicTaskPath -TaskName $script:MedicTaskName | Out-Null
        Write-Log 'Enabled Windows Update Medic task PerformRemediation'
    } else {
        Disable-ScheduledTask -TaskPath $script:MedicTaskPath -TaskName $script:MedicTaskName | Out-Null
        Write-Log 'Disabled Windows Update Medic task PerformRemediation'
    }
    return $true
}

function Remove-OrchestratorStore {
    $root = Join-Path $env:ProgramData 'USOPrivate\UpdateStore'
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Log 'UpdateStore folder is not present'
        return
    }
    $files = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'store.db' -or $_.Name -like 'store.db-*' })
    foreach ($file in $files) {
        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
        Write-Log "Deleted $($file.FullName)"
    }
    if ($files.Count -eq 0) { Write-Log 'No store.db file to delete' }
}

function Move-UpdateDatabase {
    $source = Get-DataStorePath
    if (-not (Test-Path -LiteralPath $source)) {
        Write-Log 'DataStore folder is not present'
        return $true
    }
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
    return $true
}

function Invoke-SelfTest {
    $failures = New-Object 'System.Collections.Generic.List[string]'
    function Assert-Self {
        param([bool]$Condition, [string]$Name)
        if (-not $Condition) { [void]$script:SelfTestFailures.Add($Name) }
    }
    $script:SelfTestFailures = $failures
    Assert-Self (Test-OfferText 'Intel Corporation Bluetooth Driver Update (24.70.0.4)') 'settings title'
    Assert-Self (Test-OfferText 'Intel Corporation - Bluetooth - 24.80.0.2') 'catalog title'
    Assert-Self (Test-OfferText ("Intel driver " + $script:BluetoothClassGuid + ' 24.80.0.2')) 'class guid'
    Assert-Self (-not (Test-OfferText 'Intel Corporation - Net - 24.70.0.4')) 'wifi same digits'
    Assert-Self (-not (Test-OfferText 'Intel Corporation - Net - 24.70.0.3')) 'wifi other version'
    Assert-Self (-not (Test-OfferText 'Intel Bluetooth 24.70.0.40')) 'version boundary'
    Assert-Self (-not (Test-OfferText 'Bluetooth only 24.80.0.2')) 'missing intel'
    $far = 'Intel(R) Wireless Bluetooth(R)' + ('z' * 500) + '24.70.0.4'
    Assert-Self (-not (Test-OfferText $far)) 'tokens far apart'
    $near = 'Intel Wireless Bluetooth ' + ('n' * 40) + ' 24.70.0.4'
    Assert-Self (Test-OfferText $near) 'tokens within window'
    $utf16 = [Text.Encoding]::Unicode.GetBytes('Intel Corporation Bluetooth Driver Update (24.70.0.4)')
    Assert-Self (Test-BytesHaveOffer $utf16) 'utf16 bytes'
    $wifi = [Text.Encoding]::Unicode.GetBytes('Intel Corporation - Net - 24.70.0.4')
    Assert-Self (-not (Test-BytesHaveOffer $wifi)) 'utf16 wifi'
    if ($script:SelfTestFailures.Count -gt 0) {
        Write-Output ("SelfTest failed: " + ($script:SelfTestFailures -join ' | '))
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
    Write-Log "=== Reset-IntelBTUpdateCache version=$script:ScriptVersion ==="
    $storePath = Get-StorePath
    if (-not (Test-Path -LiteralPath $storePath)) {
        Write-Log 'store.db is not present. No reset was done.'
        $exitCode = 0
    } else {
        $bytes = Read-StoreBytes
        if ($null -eq $bytes) {
            Write-Log 'store.db could not be read. No reset was done.'
            $exitCode = 1
        } elseif (-not (Test-BytesHaveOffer $bytes)) {
            Write-Log 'store.db does not contain Intel Bluetooth 24.70.0.4 or 24.80.0.2. No reset was done.'
            $exitCode = 0
        } else {
            Write-Log 'store.db contains a blocked Intel Bluetooth driver offer'
            if (-not (Set-MedicTask -Enable $false)) {
                Write-Log 'Continuing without a Medic task change'
            } else {
                $taskDisabled = $true
            }
            $stackTouched = $true
            if (-not (Wait-UpdateStackStopped)) {
                Write-Log 'Left the update database in place because Windows Update was still running'
                $exitCode = 1
            } else {
                Move-UpdateDatabase
                Remove-OrchestratorStore
                Write-Log 'Reset finished. The next normal Windows Update check rebuilds the other cached updates.'
                $exitCode = 0
            }
        }
    }
} catch {
    Write-Log ("Reset error: " + $_.Exception.Message)
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

if ($stackTouched -and $exitCode -eq 0) {
    $deadline = (Get-Date).AddSeconds(20)
    $rewritten = $false
    do {
        Start-Sleep -Seconds 2
        if (-not (Test-Path -LiteralPath (Get-StorePath))) { continue }
        $after = Read-StoreBytes
        if ($null -eq $after) { continue }
        $rewritten = $true
        if (Test-BytesHaveOffer $after) {
            Write-Log 'The blocked Intel Bluetooth offer is back in store.db'
            $exitCode = 1
        } else {
            Write-Log "store.db was rewritten ($($after.Length) bytes) without the blocked offer"
        }
        break
    } while ((Get-Date) -lt $deadline)
    if (-not $rewritten -and $exitCode -eq 0) {
        Write-Log 'store.db was still absent after the update stack started'
    }
}

Write-Log "EXIT $exitCode"
exit $exitCode
