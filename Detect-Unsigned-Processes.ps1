[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\Detect-Unsigned-Processes.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$runStart  = Get-Date

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { Write-Verbose $line }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 { param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Test-DigitalSignatureSafe {
  param([string]$FilePath)
  try {
    if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
      $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
      return $sig.Status -eq 'Valid'
    }
  } catch {
    Write-Log ("Signature check error on {0}: {1}" -f $FilePath, $_.Exception.Message) 'WARN'
  }
  return $false
}

Rotate-Log
Write-Log "=== SCRIPT START : Detect Unsigned Processes (host=$HostName) ==="

$tsNow = To-ISO8601 (Get-Date)

try {
  $rxAppData = [regex]'\\Users\\[^\\]+\\AppData(\\|$)'
  $rxTemp    = [regex]'\\Users\\[^\\]+\\AppData\\Local\\Temp(\\|$)'
  $rxPublic  = [regex]'\\Users\\Public(\\|$)'

  $procs = Get-CimInstance Win32_Process -ErrorAction Stop |
           Where-Object { $_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath) }

  $checkedFiles = @{}   
  $findings     = @()

  foreach ($p in $procs) {
    $exe = $p.ExecutablePath
    if (-not ($rxTemp.IsMatch($exe) -or $rxAppData.IsMatch($exe) -or $rxPublic.IsMatch($exe))) { continue }

    if (-not $checkedFiles.ContainsKey($exe)) {
      $checkedFiles[$exe] = Test-DigitalSignatureSafe -FilePath $exe
    }
    $isSigned = [bool]$checkedFiles[$exe]

    if (-not $isSigned) {
      Write-Log ("Flagged: PID {0} ({1}) -> Unsigned" -f $p.ProcessId, $exe) 'WARN'
      $findings += [pscustomobject]@{
        pid          = $p.ProcessId
        process      = $p.Name
        executable   = $exe
        command_line = $p.CommandLine
        reasons      = @('unsigned_binary','user_writable_location')
      }
    }
  }

  $lines = New-Object System.Collections.ArrayList

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp        = $tsNow
    host             = $HostName
    action           = 'detect_unsigned_processes'
    copilot_action   = $true
    item             = 'verify_source'
    description      = 'Processes enumerated via CIM Win32_Process; limited to user-writable locations'
    source_processes = 'Win32_Process (CIM)'
    scanned_count    = ($procs | Measure-Object).Count
    unique_binaries  = $checkedFiles.Count
  }) )

  foreach ($f in $findings) {
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'detect_unsigned_processes'
      copilot_action = $true
      item           = 'finding'
      description    = "Unsigned process '$($f.process)' (PID $($f.pid)) in user-writable path"
      pid            = $f.pid
      process        = $f.process
      executable     = $f.executable
      command_line   = $f.command_line
      reasons        = $f.reasons
    }) )
  }

  if ($findings.Count -eq 0) {
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = 'detect_unsigned_processes'
      copilot_action = $true
      item           = 'status'
      status         = 'no_results'
      description    = 'No unsigned binaries detected in AppData, Temp, or Public'
    }) )
  }

  $summary = New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'detect_unsigned_processes'
    copilot_action = $true
    item           = 'summary'
    description    = 'Run summary and counts'
    total_flagged  = $findings.Count
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = ,$summary + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
  Write-Host "`n=== Unsigned Process Scan Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Unsigned Processes Found: $($findings.Count)`n"
  if ($findings.Count -gt 0) {
    $findings | Select-Object pid, process, executable | Format-Table -AutoSize
  } else {
    Write-Host "No unsigned binaries running in AppData, Temp, or Public."
  }
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'detect_unsigned_processes'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
