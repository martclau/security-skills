# MITRE ATT&CK Technique Reference for Office Document Analysis

Quick-reference mapping from Office document indicators to ATT&CK tactics and techniques.
Use this when writing the MITRE ATT&CK mapping section of an analysis report.

---

## Initial Access

| Indicator | Technique | ID |
|---|---|---|
| Malicious document delivered via email | Phishing: Spearphishing Attachment | T1566.001 |
| Malicious document link in email | Phishing: Spearphishing Link | T1566.002 |
| Document found on compromised website | Drive-by Compromise | T1189 |

---

## Execution

| Indicator | Technique | ID |
|---|---|---|
| VBA macro auto-execution (`AutoOpen`, `Document_Open`, etc.) | Office Application Startup: Office Template Macros | T1137.001 |
| DDEAUTO / DDE field in document | Inter-Process Communication: Dynamic Data Exchange | T1559.002 |
| User prompted to enable macros (social engineering) | User Execution: Malicious File | T1204.002 |
| Macro spawns `cmd.exe`, `powershell.exe`, etc. | Command and Scripting Interpreter | T1059 |
| PowerShell one-liner in macro | Command and Scripting Interpreter: PowerShell | T1059.001 |
| VBScript via `WScript.Shell` or `CreateObject` | Command and Scripting Interpreter: Visual Basic | T1059.005 |
| Equation Editor exploit (CVE-2017-11882, etc.) | Exploitation for Client Execution | T1203 |
| XLM / Excel 4.0 macro | Office Application Startup: Add-ins | T1137.006 |
| Macro calls Win32 API via `Declare` (P/Invoke) | Native API | T1106 |
| Shellcode in OLE `\objdata` or RTF heap spray | Exploitation for Client Execution | T1203 |

---

## Persistence

| Indicator | Technique | ID |
|---|---|---|
| Macro writes `HKCU\...\Run` or `HKLM\...\Run` | Boot/Logon Autostart: Registry Run Keys / Startup Folder | T1547.001 |
| Macro copies itself to Startup folder | Boot/Logon Autostart: Registry Run Keys / Startup Folder | T1547.001 |
| Macro installs scheduled task (`schtasks`) | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Macro drops and registers a COM object | Component Object Model Hijacking | T1546.015 |
| Macro writes to Office add-in location | Office Application Startup: Office Add-ins | T1137.006 |
| Macro modifies Normal.dotm template | Office Application Startup: Office Template Macros | T1137.001 |

---

## Defense Evasion

| Indicator | Technique | ID |
|---|---|---|
| VBA stomping (p-code differs from visible source) | Obfuscated Files or Information | T1027 |
| String concatenation / Chr() encoding | Obfuscated Files or Information | T1027 |
| Base64-encoded payload in macro | Obfuscated Files or Information: Encoding | T1027.013 |
| PowerShell `-EncodedCommand` | Obfuscated Files or Information: Encoding | T1027.013 |
| Password-protected document | Encrypted/Encoded File | T1027.013 |
| Encrypted macro project (VBA password) | Obfuscated Files or Information | T1027 |
| Extension / format mismatch (e.g., .doc that is RTF) | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Macro disables security alerts at runtime | Modify Registry / Impair Defenses | T1112 / T1562 |
| XLM macros in hidden sheet (XLSM/XLS) | Hide Artifacts: Hidden Files and Directories | T1564.001 |
| Sandbox / VM detection in macro | Virtualization/Sandbox Evasion | T1497 |

---

## Privilege Escalation

| Indicator | Technique | ID |
|---|---|---|
| `VirtualAlloc` + `WriteProcessMemory` + `CreateThread` in VBA | Process Injection | T1055 |
| Macro calls UAC bypass technique | Abuse Elevation Control Mechanism | T1548 |

---

## Discovery

| Indicator | Technique | ID |
|---|---|---|
| Macro calls `Environ()` (COMPUTERNAME, USERNAME, etc.) | System Information Discovery | T1082 |
| Macro enumerates running processes | Process Discovery | T1057 |
| Macro checks installed AV / security products | Security Software Discovery | T1518.001 |
| Macro reads files or directories | File and Directory Discovery | T1083 |
| Macro checks system language/locale (geo-fence evasion) | System Language Discovery | T1614.001 |

---

## Collection

| Indicator | Technique | ID |
|---|---|---|
| Macro reads clipboard | Clipboard Data | T1115 |
| Macro captures keystrokes (`SetWindowsHookEx`) | Input Capture: Keylogging | T1056.001 |
| Macro takes screenshots | Screen Capture | T1113 |
| Macro zips or archives files before exfil | Archive Collected Data: Archive via Utility | T1560.001 |

---

## Command and Control

| Indicator | Technique | ID |
|---|---|---|
| Macro downloads second-stage payload | Ingress Tool Transfer | T1105 |
| Hardcoded C2 URL in macro | Application Layer Protocol: Web Protocols | T1071.001 |
| C2 over DNS in macro | Application Layer Protocol: DNS | T1071.004 |
| Macro connects to public file hosting (Pastebin, ge.tt, raw GitHub) | Web Service | T1102 |
| Remote template load via `.rels` or RTF `\*\template` | Template Injection | T1221 |

---

## Exfiltration

| Indicator | Technique | ID |
|---|---|---|
| Macro POSTs data to external URL | Exfiltration Over C2 Channel | T1041 |
| Macro uses FTP for exfiltration | Exfiltration Over Unencrypted Protocol | T1048.003 |
| Macro emails data via SMTP | Exfiltration Over Alternative Protocol | T1048 |

---

## Format-Specific Technique Mapping

### OLE2 (.doc, .xls, .ppt)

| Finding | ATT&CK |
|---|---|
| VBA macro present | T1137.001 |
| Equation Editor CLSID | T1203 (CVE-2017-11882) |
| VBA stomping | T1027 |
| ActiveX / OLE object with CLSID | T1559.001 |
| SRP stream (stomping indicator) | T1027 |

### OOXML (.docx, .xlsx, .pptx, .docm, .xlsm, .pptm)

| Finding | ATT&CK |
|---|---|
| `vbaProject.bin` present | T1137.001 |
| `attachedTemplate` relationship pointing to external URL | T1221 |
| External link in `.rels` | T1221 / T1071.001 |
| XLM macros in worksheet | T1059 / T1137.006 |
| PE or HTA embedded in `embeddings/` | T1027 |

### RTF (.rtf)

| Finding | ATT&CK |
|---|---|
| `\*\template` pointing to external URL | T1221 (CVE-2017-0199) |
| OLE object in `\objdata` | T1203 |
| Shellcode in `\objdata` | T1203 / T1055 |
| Embedded OOXML (nested ZIP in hex data) | T1027 |

---

## Key CVEs for Office Exploitation

| CVE | Format | Technique | Description |
|---|---|---|---|
| CVE-2017-11882 | OLE2 | T1203 | Equation Editor stack buffer overflow; most exploited Office CVE |
| CVE-2018-0802 | OLE2 | T1203 | Equation Editor (EQNEDT32.EXE) second overflow variant |
| CVE-2017-0199 | RTF / OOXML | T1221 | Remote template download + HTA execution on open |
| CVE-2021-40444 | OOXML | T1203 | MSHTML remote code execution via ActiveX in Office docs |
| CVE-2022-30190 | OOXML | T1221 | Follina — ms-msdt URI scheme exploitation via external reference |
| CVE-2015-1641 | OLE2 | T1203 | Memory corruption in Word XML parser |
| CVE-2012-0158 | OLE2 | T1203 | ListView ActiveX buffer overflow |
