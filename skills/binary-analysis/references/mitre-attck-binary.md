# MITRE ATT&CK Technique Reference for Binary Analysis

Quick-reference mapping from binary indicators to ATT&CK tactics and techniques.
Use this when writing the "Import Analysis" section of a binary analysis report.

## Execution

| Indicator | Technique | ID |
|---|---|---|
| `WinExec`, `ShellExecute`, `CreateProcess` | Command and Scripting Interpreter | T1059 |
| `system()`, `popen()`, `execve()` | Unix Shell execution | T1059.004 |
| `PowerShell`, `-enc`, `-EncodedCommand` | PowerShell | T1059.001 |
| `VBScript`, `wscript`, `cscript` | Visual Basic | T1059.005 |

## Persistence

| Indicator | Technique | ID |
|---|---|---|
| `RegSetValueEx` + `Run` key | Registry Run Keys | T1547.001 |
| `CreateService`, `StartService` | Windows Service | T1543.003 |
| `crontab`, `/etc/cron.d/`, `rc.local` | Cron / RC Scripts | T1053.003 / T1037.004 |
| `~/.bashrc`, `~/.profile`, `/etc/profile.d/` | Unix Shell Config Modification | T1546.004 |
| `systemctl enable` | Systemd Service | T1543.002 |

## Privilege Escalation

| Indicator | Technique | ID |
|---|---|---|
| `OpenProcessToken`, `AdjustTokenPrivileges` | Token Impersonation | T1134 |
| `SetTokenInformation` | Access Token Manipulation | T1134.001 |
| `chmod +s`, SUID bit | Setuid / Setgid | T1548.001 |
| `sudo -n`, `sudo -S` | Sudo Abuse | T1548.003 |

## Defense Evasion

| Indicator | Technique | ID |
|---|---|---|
| UPX, Themida, VMProtect, custom packer | Obfuscated Files or Information | T1027 |
| High-entropy sections (>7.2) | Software Packing | T1027.002 |
| Base64 encoded payloads | Encoding | T1027.001 |
| `IsDebuggerPresent`, ptrace anti-debug | Debugger / VM Evasion | T1622 |
| Sandbox string checks (VirtualBox, VMware) | Virtualization/Sandbox Evasion | T1497 |
| `DeleteFileA(argv[0])`, self-wipe | Indicator Removal on Host | T1070 |
| `wevtutil cl`, `ClearEventLog` | Clear Windows Event Logs | T1070.001 |

## Credential Access

| Indicator | Technique | ID |
|---|---|---|
| `/etc/shadow`, `getspnam` | OS Credential Dumping: /etc/shadow | T1003.008 |
| `MiniDumpWriteDump`, `lsass.exe` | LSASS Memory Dump | T1003.001 |
| SAM, SYSTEM, SECURITY hive strings | SAM/LSA secrets | T1003.002 |
| `GetClipboardData` | Clipboard Data | T1115 |
| Keylogger APIs (`SetWindowsHookEx`) | Input Capture: Keylogging | T1056.001 |
| AWS key patterns (`AKIA...`) | Cloud Credential Access | T1552.005 |
| `.ssh/id_rsa`, `known_hosts` | SSH Private Keys | T1552.004 |

## Discovery

| Indicator | Technique | ID |
|---|---|---|
| `whoami`, `hostname`, `uname -a` | System Information Discovery | T1082 |
| `GetAdaptersInfo`, `ifconfig`, `ip addr` | Network Configuration Discovery | T1016 |
| `EnumProcesses`, `/proc/` listing | Process Discovery | T1057 |
| `GetComputerName`, `GetUserName` | System Owner/User Discovery | T1033 |
| `NetShareEnum`, `net share` | Network Share Discovery | T1135 |

## Lateral Movement

| Indicator | Technique | ID |
|---|---|---|
| `WNetOpenEnum`, `\\\\server\\share` | SMB / Windows Admin Shares | T1021.002 |
| `ssh` client strings, `libssh` | Remote Services: SSH | T1021.004 |
| `PsExec`, `ADMIN$` | SMB Execution | T1570 |
| `WMI`, `IWbemServices` | WMI | T1047 |
| `schtasks /create /s` | Remote Scheduled Task | T1053.005 |

## Collection

| Indicator | Technique | ID |
|---|---|---|
| `FindFirstFile` + archive strings | Archive Collected Data | T1560 |
| `GetClipboardData` | Clipboard Data | T1115 |
| Screenshot APIs (`BitBlt`, `GetDC`) | Screen Capture | T1113 |
| `RecordSound`, `waveInOpen` | Audio Capture | T1123 |

## Command and Control

| Indicator | Technique | ID |
|---|---|---|
| Hardcoded IP:port + `connect()` | Non-Standard Port | T1571 |
| `.onion` domain | Proxy: Tor | T1090.003 |
| HTTP `User-Agent` mimicry | Protocol Impersonation | T1001.003 |
| DNS TXT queries | DNS C2 | T1071.004 |
| HTTPS to non-standard port | Encrypted Channel | T1573 |
| Beacon / sleep loop patterns | Web Protocols C2 | T1071.001 |

## Exfiltration

| Indicator | Technique | ID |
|---|---|---|
| `curl --upload-file`, `wget --post-file` | Exfiltration Over Web Service | T1567 |
| FTP upload strings | Exfiltration Over Unencrypted Protocol | T1048.003 |
| DNS TXT exfiltration patterns | Exfiltration Over DNS | T1048.001 |
| Cloud storage strings (S3, Drive, Dropbox) | Exfiltration to Cloud Storage | T1567.002 |

## Impact

| Indicator | Technique | ID |
|---|---|---|
| `CryptEncrypt` + file extensions | Data Encrypted for Impact (ransomware) | T1486 |
| `dd` to `/dev/sd*` | Disk Wipe | T1561.001 |
| `shred`, `wipe` | File Deletion / Secure Wipe | T1485 |
| MBR write patterns | Disk Structure Wipe | T1561.002 |
| `fork bomb`, resource exhaustion | Resource Hijacking | T1496 |
