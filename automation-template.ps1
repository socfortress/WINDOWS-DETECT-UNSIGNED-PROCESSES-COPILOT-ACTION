[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\Detect-Unsigned-Processes.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$StartTime = Get-Date

function Write-Log {
  param(
    [string]$Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO'
  )
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { Write-Verbose $line }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Test-DigitalSignature {
  param([string]$FilePath)
  try {
    if (Test-Path $FilePath) {
      $sig = Get-AuthenticodeSignature -FilePath $FilePath
      return $sig.Status -eq 'Valid'
    }
  } catch { return $false }
  return $false
}

Rotate-Log
Write-Log "=== SCRIPT START : Detect Unsigned Processes (AppData/Temp/Public) ==="

try {
  $Processes = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and (Test-Path $_.ExecutablePath) }

  $Items = @()
  foreach ($proc in $Processes) {
    $exe = $proc.ExecutablePath
    if ($exe -match 'Users\\[^\\]+\\AppData' -or $exe -match 'Users\\[^\\]+\\AppData\\Local\\Temp' -or $exe -match 'Users\\Public') {
      $flaggedReasons = @()

      if (-not (Test-DigitalSignature -FilePath $exe)) {
        $flaggedReasons += "Unsigned binary"
        Write-Log "Flagged: PID $($proc.ProcessId) ($exe) -> Unsigned" "WARN"
      }

      if ($flaggedReasons.Count -gt 0) {
        $Items += [PSCustomObject]@{
          process_id     = $proc.ProcessId
          name           = $proc.Name
          executable     = $exe
          command_line   = $proc.CommandLine
          flagged_reasons = $flaggedReasons
        }
      }
    }
  }

  $timestamp = (Get-Date).ToString('o')

  $FullReport = [PSCustomObject]@{
    host          = $HostName
    timestamp     = $timestamp
    action        = "detect_unsigned_processes"
    item_count    = $Items.Count
    processes     = $Items
  }

  $FlaggedReport = [PSCustomObject]@{
    host             = $HostName
    timestamp        = $timestamp
    action           = "detect_unsigned_processes_flagged"
    flagged_count    = $Items.Count
    flagged_processes = $Items
  }

  $FullReport   | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  $FlaggedReport | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000

  Write-Log "JSON reports (full + flagged) appended to $ARLog"

  Write-Host "`n=== Unsigned Process Scan Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Unsigned Processes Found: $($Items.Count)`n"
  if ($Items.Count -gt 0) {
    $Items | Select-Object process_id, name, executable | Format-Table -AutoSize
  } else {
    Write-Host "No unsigned binaries running from AppData/Temp/Public."
  }

}
catch {
  Write-Log $_.Exception.Message "ERROR"
  $ErrorObj = [PSCustomObject]@{
    host       = $HostName
    timestamp  = (Get-Date).ToString('o')
    action     = "detect_unsigned_processes"
    status     = "error"
    error      = $_.Exception.Message
  }
  $ErrorObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $duration = [int]((Get-Date) - $StartTime).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${duration}s ==="
}
