# PowerShell Detect Unsigned Processes Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for detecting unsigned processes running from suspicious locations such as AppData, Temp, or Public directories.

---

## Overview

The `Detect-Unsigned-Processes.ps1` script scans all running processes, identifies those executing from user AppData, Temp, or Public directories, checks for digital signatures, and flags unsigned binaries. All actions, results, and errors are logged in both a script log and an active-response log, making the script suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Flagging Logic**: Identifies unsigned binaries in suspicious locations
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\Detect-Unsigned-Processes.ps1 [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter | Type   | Default Value                                                    | Description                                  |
|-----------|--------|------------------------------------------------------------------|----------------------------------------------|
| `LogPath` | string | `$env:TEMP\Detect-Unsigned-Processes.log`                        | Path for execution logs                      |
| `ARLog`   | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\Detect-Unsigned-Processes.ps1

# Custom log path
.\Detect-Unsigned-Processes.ps1 -LogPath "C:\Logs\UnsignedProcScan.log"

# Integration with OSSEC/Wazuh active response
.\Detect-Unsigned-Processes.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Message` (string): The log message
- `Level` (ValidateSet): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamped output
- Color-coded console output
- File logging
- Verbose/debug support

**Usage**:
```powershell
Write-Log "Flagged: PID $($proc.ProcessId) ($exe) -> Unsigned" "WARN"
Write-Log "JSON reports (full + flagged) appended to $ARLog"
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

### `Test-DigitalSignature`
**Purpose**: Checks if a file (such as a process executable) is digitally signed.

**Parameters**:
- `FilePath` (string): Path to the executable

**Features**:
- Returns `$true` if the file is signed and valid, `$false` otherwise

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation
   - Start time logging

2. **Execution**
   - Enumerates all running processes with valid executable paths
   - Flags processes running from AppData, Temp, or Public directories
   - Checks for unsigned binaries
   - Logs findings

3. **Completion**
   - Outputs full inventory and flagged processes as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details as JSON

---

## JSON Output Format

### Full Report Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "detect_unsigned_processes",
  "item_count": 2,
  "processes": [
    {
      "process_id": 1234,
      "name": "malware.exe",
      "executable": "C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe",
      "command_line": "\"C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe\"",
      "flagged_reasons": ["Unsigned binary"]
    }
  ]
}
```

### Flagged Processes Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "detect_unsigned_processes_flagged",
  "flagged_count": 2,
  "flagged_processes": [
    {
      "process_id": 1234,
      "name": "malware.exe",
      "executable": "C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe",
      "command_line": "\"C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe\"",
      "flagged_reasons": ["Unsigned binary"]
    }
  ]
}
```

### Error Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:31:10.456Z",
  "action": "detect_unsigned_processes",
  "status": "error",
  "error": "Access is denied"
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the flagging logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Process Access Issues**: Some system processes may be inaccessible.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation and incident
