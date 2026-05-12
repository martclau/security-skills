---
name: office-analysis
description: >
  Analyze Microsoft Office documents from a security perspective. Use when the user provides
  a .doc, .docx, .xls, .xlsx, .ppt, .pptx, .docm, .xlsm, .pptm, .dot, .dotm, .rtf or similar
  Office file and asks to inspect it for malware, macros, exploits, or suspicious content.
  Trigger on phrases like "analyze this document", "check this Word file", "suspicious Office
  file", "macro analysis", "OLE analysis", "RTF analysis", "weaponized document", "phishing
  attachment", or "what does this document do".
---

# Microsoft Office Document Security Analysis Skill

This skill performs a structured static security analysis of Microsoft Office documents across
all three major format families: OLE2 compound binary (.doc, .xls, .ppt), OOXML ZIP-based
(.docx, .xlsx, .pptx, .docm, .xlsm, .pptm), and RTF (.rtf).

It works in six phases:

1. **Triage** — identify the true format, extract metadata, assess risk surface.
2. **Structural analysis** — enumerate internal streams, XML parts, or RTF objects by format.
3. **Macro and code extraction** — VBA, XLM/Excel 4.0, DDE, and p-code analysis.
4. **Deobfuscation** — resolve encoded strings, trace obfuscated logic.
5. **IOC extraction** — network indicators, file paths, registry keys, shellcode.
6. **Synthesis** — verdict, MITRE ATT&CK mapping, and recommended next steps.

---

## Step 0 — Validate input and create working directory

```bash
WORK_DIR=$(mktemp -d)
echo "Working directory: $WORK_DIR"
```

Ask the user for the file path if not already provided:

> "Please provide the full path to the Office document you'd like me to analyze."

Verify the file exists. Copy it to the working directory:

```bash
cp "<user-provided-path>" "$WORK_DIR/target"
```

Compute hashes for threat-intel lookups:

```bash
md5sum    "$WORK_DIR/target"
sha256sum "$WORK_DIR/target"
```

---

## Step 1 — Triage and format identification

Never trust the file extension. Confirm the true format from magic bytes and structure.

```bash
file "$WORK_DIR/target"
exiftool "$WORK_DIR/target"
```

Run `oleid` for a rapid overview:

```bash
oleid "$WORK_DIR/target"
```

`oleid` reports:
- Detected format (OLE2 / OOXML / RTF / encrypted)
- Encryption status
- VBA macro presence
- XLM macro presence
- External relationship links
- Document properties (author, last saved by, creation date)

Parse and record:

| Property | Value |
|---|---|
| True format | OLE2 / OOXML / RTF / encrypted |
| File extension | (as provided) |
| Extension matches format | yes / no |
| VBA macros present | yes / no |
| XLM macros present | yes / no |
| Encrypted / password-protected | yes / no |
| External links present | yes / no |
| Author / last-saved-by | (from metadata) |
| Creation / modification dates | (from metadata) |

If the file is **encrypted**, attempt decryption with the default password before continuing:

```bash
msoffcrypto-tool "$WORK_DIR/target" "$WORK_DIR/target_decrypted" -p VelvetSweatshop
# VelvetSweatshop is the well-known default Excel encryption password used by many malware families
cp "$WORK_DIR/target_decrypted" "$WORK_DIR/target" 2>/dev/null || true
```

If decryption fails, note it and ask the user for the password. Many malware samples use
`VelvetSweatshop` (Excel), `infected`, or `malware` as convention passwords.

Run the bundled triage helper to standardize output:

```bash
python3 <skill-path>/scripts/office_analyzer.py --triage "$WORK_DIR/target" \
    -o "$WORK_DIR/triage.json"
```

---

## Step 2 — Format-specific structural analysis

Based on the format detected in Step 1, run the appropriate sub-analysis.

### 2a. OLE2 — Compound Binary Format (.doc, .xls, .ppt, .dot, .xlt)

Enumerate all streams and storage objects:

```bash
oledump.py "$WORK_DIR/target"
```

Stream flags:
- `M` — contains decompressed VBA macro code
- `m` — contains VBA attributes only (no code body)
- No flag — data stream (may still contain shellcode or embedded objects)

Extract the full stream list to a file:

```bash
oledump.py "$WORK_DIR/target" > "$WORK_DIR/streams.txt"
cat "$WORK_DIR/streams.txt"
```

Check for specific high-interest streams:

```bash
# Equation Editor object (CVE-2017-11882 vessel)
python3 <skill-path>/scripts/office_analyzer.py --check-equation "$WORK_DIR/target"

# OLE objects and external link references
oleobj "$WORK_DIR/target" -d "$WORK_DIR/ole_objects/"

# Document metadata
olemeta "$WORK_DIR/target"
```

Flag if present:
- `Equation Native` stream — Equation Editor CLSID `0002CE02-...` is a CVE-2017-11882 indicator
- `SRP` streams — may contain cached/earlier version of VBA code (VBA stomping indicator)
- `\x01CompObj` — contains OLE object class GUID; look for unusual CLSIDs
- Embedded OLE objects referencing external HTTP/UNC paths

### 2b. OOXML — ZIP/XML Format (.docx, .xlsx, .pptx, .docm, .xlsm, .pptm)

List the ZIP archive contents:

```bash
zipdump.py "$WORK_DIR/target"
```

Extract all contents for inspection:

```bash
unzip -q "$WORK_DIR/target" -d "$WORK_DIR/ooxml_extracted/"
```

Inspect the content type manifest:

```bash
cat "$WORK_DIR/ooxml_extracted/[Content_Types].xml"
```

Flag unexpected content types (PE, HTA, JS, SWF, DLL).

Scan **all** relationship files for external references (template injection):

```bash
find "$WORK_DIR/ooxml_extracted/" -name "*.rels" | xargs grep -l "http" 2>/dev/null
find "$WORK_DIR/ooxml_extracted/" -name "*.rels" | xargs grep -i "Target=\"http" 2>/dev/null
```

The critical template injection indicator is a `.rels` entry of relationship type
`attachedTemplate` pointing to an external URL. This causes Word to fetch and execute
the remote template on document open, with no macro warning.

```bash
python3 <skill-path>/scripts/office_analyzer.py --check-rels "$WORK_DIR/ooxml_extracted/" \
    -o "$WORK_DIR/rels_report.json"
```

Inspect embedded content in `word/embeddings/` (or `xl/embeddings/`):

```bash
ls -lah "$WORK_DIR/ooxml_extracted/word/embeddings/" 2>/dev/null
ls -lah "$WORK_DIR/ooxml_extracted/xl/embeddings/" 2>/dev/null
file "$WORK_DIR/ooxml_extracted/word/embeddings/"* 2>/dev/null
```

Any PE files, HTA files, or OLE objects here should be extracted and analyzed separately.

For macro-enabled formats (.docm, .xlsm, .pptm), locate the embedded OLE VBA project:

```bash
file "$WORK_DIR/ooxml_extracted/word/vbaProject.bin" 2>/dev/null
# Analyze this OLE binary as its own OLE2 document (proceed to Step 2a logic)
oledump.py "$WORK_DIR/ooxml_extracted/word/vbaProject.bin"
```

### 2c. RTF — Rich Text Format (.rtf)

Parse RTF structure and list all control words and objects:

```bash
rtfdump.py "$WORK_DIR/target"
rtfdump.py "$WORK_DIR/target" --objects
```

Extract all embedded OLE objects:

```bash
rtfobj.py "$WORK_DIR/target" -d "$WORK_DIR/rtf_objects/"
```

Each extracted object should be typed with `file` and analyzed independently.

Check for remote template reference (CVE-2017-0199 and variants):

```bash
python3 <skill-path>/scripts/office_analyzer.py --check-rtf-template "$WORK_DIR/target"
```

The `\*\template` control word pointing to an external URL causes Word to fetch and load
the resource on open — no user interaction required.

Inspect `\objdata` blocks for shellcode patterns:

```bash
rtfdump.py "$WORK_DIR/target" --objects --hexdump | head -200
```

High-value RTF indicators:
- `\*\template http://` or `\*\template \\UNC\path` — remote template load
- `\object\objemb` with `\objclsid` `{00020820-...}` (Excel) or equation CLSID
- Large `\objdata` blocks — shellcode or embedded payload
- `\bin` control word with large byte count — embedded binary data
- Nested `\objdata` containing ZIP magic bytes (`PK\x03\x04`) — embedded OOXML

---

## Step 3 — Macro and code extraction

### 3a. VBA macros

Extract all VBA code with keyword analysis:

```bash
olevba "$WORK_DIR/target" --reveal
olevba "$WORK_DIR/target" -a   # analysis / keyword summary only
```

`olevba` flags:
- `AutoExec` — code runs automatically on open/close
- `Suspicious` — dangerous API calls detected
- `IOC` — network indicators, URLs, file paths
- `Hex String` — hex-encoded payload
- `Base64 String` — base64-encoded payload
- `Dridex` — known obfuscation pattern (string concatenation)
- `VBA stomping` — p-code/source mismatch

Save full VBA source:

```bash
olevba "$WORK_DIR/target" --decode > "$WORK_DIR/vba_source.txt"
```

Check rapid macro threat classification:

```bash
mraptor "$WORK_DIR/target"
```

`mraptor` verdict: `SUSPICIOUS`, `NOT SUSPICIOUS`, or `ERROR`.
`mraptor` checks: does the macro auto-execute? Does it write to disk? Does it execute programs?

### 3b. VBA stomping detection

VBA stomping replaces the visible VBA source code with benign content while leaving the
compiled p-code (bytecode) intact. Office executes p-code, not the visible source, so the
true payload is hidden from tools that only read source.

Check for stomping and extract p-code if present:

```bash
pcodedmp "$WORK_DIR/target" > "$WORK_DIR/pcode.txt" 2>&1
```

Compare the p-code disassembly against the VBA source from Step 3a. If they differ
significantly, the document is VBA-stomped. The p-code is the authoritative representation
of what Office will execute.

For deeper p-code reconstruction:

```bash
pcode2code "$WORK_DIR/target" > "$WORK_DIR/pcode_reconstructed.txt" 2>&1
```

### 3c. Excel 4.0 / XLM macros

XLM macros are stored as cell formulas in worksheets, not in VBA streams. They are
invisible to `olevba` and `oledump`. Use the dedicated tool:

```bash
xlmdeobfuscator --file "$WORK_DIR/target"
xlmdeobfuscator --file "$WORK_DIR/target" --with-ms-xlsb  # for .xlsb format
```

`xlmdeobfuscator` emulates the Excel calculation engine to reconstruct the full macro
execution flow, revealing hidden API calls, URLs, and commands.

### 3d. DDE / DDEAUTO fields

DDE (Dynamic Data Exchange) fields can execute arbitrary commands when the document is
opened, without any macro code.

```bash
msodde "$WORK_DIR/target"
```

Flag any `DDEAUTO` or `DDE` fields, especially those referencing:
- `cmd.exe`
- `powershell.exe`
- `wscript.exe`
- `mshta.exe`
- `\\attacker-host\share`

---

## Step 4 — Deobfuscation

### 4a. Automated deobfuscation with ViperMonkey

ViperMonkey emulates VBA execution to reconstruct obfuscated logic without running the payload:

```bash
vmonkey "$WORK_DIR/target" 2>&1 | tee "$WORK_DIR/vipermonkey.txt"
```

ViperMonkey will report:
- Resolved string values after concatenation/encoding
- API calls made during emulation
- Files written, processes spawned, URLs contacted (emulated)

Note: ViperMonkey is slow on heavily obfuscated samples. If it times out, proceed with
manual deobfuscation.

### 4b. Base64 and encoded blob extraction

```bash
base64dump.py "$WORK_DIR/vba_source.txt"
base64dump.py "$WORK_DIR/target"
```

### 4c. XOR-encoded string search

```bash
xorsearch "$WORK_DIR/target" "This program"   # common PE header string
xorsearch "$WORK_DIR/target" "powershell"
xorsearch "$WORK_DIR/target" "http"
```

### 4d. Manual deobfuscation approach

For heavily obfuscated VBA (from `$WORK_DIR/vba_source.txt`):

1. Read through the source looking for string-building patterns: `& Chr(x) &`, multi-variable
   concatenation chains, reversed strings, split/join patterns.
2. Identify and rename all variables by type prefix: `S_` for String, `L_` for Long, `O_` for Object.
3. Trace assignment chains — where does each variable's value come from?
4. Reconstruct the final string value passed to `Shell`, `CreateObject`, `Run`, `Exec`, etc.
5. The result reveals: dropped file path, download URL, PowerShell command, or shellcode blob.

Run the bundled deobfuscation helper for common patterns:

```bash
python3 <skill-path>/scripts/office_analyzer.py --deobfuscate "$WORK_DIR/vba_source.txt" \
    -o "$WORK_DIR/deobfuscated_iocs.json"
```

---

## Step 5 — IOC extraction

Consolidate all network and host indicators:

```bash
python3 <skill-path>/scripts/office_analyzer.py --iocs "$WORK_DIR/target" \
    --vba-source "$WORK_DIR/vba_source.txt" \
    --vipermonkey "$WORK_DIR/vipermonkey.txt" \
    -o "$WORK_DIR/iocs.json"
```

### Network IOCs to extract

- URLs (download cradles, C2 endpoints, template injection targets)
- IP addresses (hardcoded C2)
- Domain names
- UNC paths (`\\server\share`)
- DNS names used for data exfiltration

### Host IOCs to extract

- Dropped file paths (`%TEMP%`, `%APPDATA%`, `C:\Users\Public\`)
- Registry keys (persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
- Scheduled task names
- Mutex names
- Process names spawned (from ViperMonkey or static analysis)

### Optional: VirusTotal hash lookup

```bash
python3 <skill-path>/scripts/office_analyzer.py --vt-hash <SHA256> \
    -o "$WORK_DIR/vt_report.json"
```

Requires `VT_API_KEY` set as an environment variable. Never ask the user to paste the key
into the chat:

> "If you'd like a VirusTotal hash lookup, please run:
> `export VT_API_KEY='your-key-here'`
> (Free key at https://www.virustotal.com)"

---

## Step 6 — Synthesize and write the report

Combine all findings into a structured security assessment.

### Verdict

Use the most severe applicable verdict:

- **CLEAN** — No suspicious indicators found across all analysis phases.
- **LOW RISK** — Macros present but no auto-execution, no suspicious APIs, no network IOCs.
- **MEDIUM RISK** — Auto-executing macros or DDE fields; limited suspicious behavior with
  plausible benign explanation; or template/external link without confirmed malicious payload.
- **HIGH RISK** — Auto-executing macros with suspicious APIs (download + execute pattern),
  confirmed exploit object (Equation Editor), or template injection pointing to active URL.
- **MALICIOUS / DO NOT OPEN** — Confirmed malware (VT detection), active C2 IOCs, or
  converging indicators (auto-exec + download cradle + dropped payload + network callback).

### Report structure

1. **Executive summary** — one paragraph: what is this document and what is the risk level.
2. **File identification** — format, extension match, hashes, metadata (author, dates, software).
3. **Encryption / protection** — password-protected, how decrypted (or not), VBA password removed.
4. **Structural findings** — streams/parts enumerated; suspicious structures (Equation Editor,
   external .rels links, embedded binaries, RTF remote template).
5. **Macro analysis** — VBA presence, auto-execution triggers, `mraptor` verdict, XLM findings,
   DDE fields, VBA stomping assessment.
6. **Deobfuscation results** — resolved strings, ViperMonkey output, decoded payloads.
7. **IOC table** — all network and host indicators with source and confidence.
8. **MITRE ATT&CK mapping** — techniques observed, keyed to the reference in `references/`.
9. **VirusTotal result** — hash lookup result if performed.
10. **Verdict** — clear statement with confidence level.
11. **Recommended next steps** — what the analyst should do next.

### MITRE ATT&CK mapping

Reference `<skill-path>/references/mitre-attck-office.md` when mapping findings to techniques.
Key techniques for Office malware:

| Finding | Technique | ID |
|---|---|---|
| VBA macro auto-execution | Office Application Startup: Office Template Macros | T1137.001 |
| DDE field execution | Inter-Process Communication: Dynamic Data Exchange | T1559.002 |
| Remote template load | Template Injection | T1221 |
| User prompted to enable macros | User Execution: Malicious File | T1204.002 |
| Macro downloads payload | Ingress Tool Transfer | T1105 |
| Macro spawns PowerShell/cmd | Command and Scripting Interpreter | T1059 |
| Macro writes registry Run key | Boot/Logon Autostart: Registry Run Keys | T1547.001 |
| Equation Editor exploit | Exploitation for Client Execution | T1203 |
| VBA stomping | Obfuscated Files or Information | T1027 |
| String concatenation / Chr() | Obfuscated Files or Information: Indicator Removal | T1027 |

### Recommended next steps (by severity)

**For MEDIUM or higher:**
- Submit to sandbox for dynamic analysis: ANY.RUN (select Office version), Hybrid Analysis, Tria.ge.
- Search all IOCs (URLs, IPs, domains, hashes) against threat intel feeds.
- If XLM macros found, deobfuscate with `xlmdeobfuscator` and extract final payload URL.
- If VBA-stomped, disassemble p-code with `pcodedmp` / `pcode2code` for true macro content.

**For HIGH or MALICIOUS:**
- Do not open on a production system under any circumstances.
- Quarantine the file and preserve chain of custody.
- Check whether the document has been delivered to other users (email gateway, mail logs).
- Extract and analyze any dropped payloads discovered (treat as a new binary analysis task).
- Check Equation Editor CLSID and shellcode against CVE-2017-11882 and related signatures.
- Consider incident response if found on a production endpoint.

---

## Known limitations

Be transparent about these in every report:

1. **Static analysis only** — this skill does not open the document. Macro behavior observed by
   ViperMonkey is emulated, not live. Evasive malware with VM/sandbox detection may not reveal
   its full behavior statically.
2. **Packed or encrypted payloads** — if the final stage payload is encrypted or Base64-encoded
   inside the macro, and the decryption key is derived at runtime (e.g., from system properties),
   full reconstruction may not be possible statically.
3. **VBA stomping** — if p-code and source disagree, only p-code disassembly (via `pcodedmp`) is
   authoritative. P-code disassembly is harder to read than VBA source.
4. **XLM macros** — `xlmdeobfuscator` emulation is not complete; highly obfuscated XLM may
   partially resolve. Manual cell-by-cell tracing may be needed for complex samples.
5. **RTF parser tolerance** — RTF parsers vary widely; a document that appears clean to one tool
   may parse differently in Word. Malformed RTF is a known evasion technique. Always test
   suspicious RTF in an isolated VM.
6. **VirusTotal hash lookup only** — novel or slightly modified samples return no VT matches
   even if malicious. A clean VT result does not mean the document is safe.
7. **No network execution** — URLs found will not be fetched. Verify IOCs against threat intel
   feeds separately.

---

## Quick-reference: useful tools

| Tool | Purpose | Install |
|---|---|---|
| `oleid` | Initial triage: format, encryption, macro presence | `pip install oletools` |
| `olevba` | VBA extraction, keyword detection, IOC identification | `pip install oletools` |
| `oledump.py` | OLE stream enumeration and extraction | Didier Stevens tools |
| `oleobj` | Embedded OLE object and external link extraction | `pip install oletools` |
| `olemeta` | OLE metadata stream extraction | `pip install oletools` |
| `rtfdump.py` | RTF control word parsing and object listing | Didier Stevens tools |
| `rtfobj.py` | OLE object extraction from RTF | Didier Stevens tools |
| `msodde` | DDE/DDEAUTO field detection | `pip install oletools` |
| `mraptor` | Rapid macro threat classification | `pip install oletools` |
| `zipdump.py` | OOXML/ZIP archive inspection; YARA support | Didier Stevens tools |
| `ViperMonkey` | VBA macro emulation and deobfuscation | `pip install vipermonkey` |
| `xlmdeobfuscator` | Excel 4.0 / XLM macro emulation | `pip install XLMMacroDeobfuscator` |
| `pcodedmp` | VBA p-code disassembly (stomping detection) | `pip install pcodedmp` |
| `pcode2code` | P-code to VBA source reconstruction | `pip install pcode2code` |
| `msoffcrypto-tool` | Decrypt password-protected Office files | `pip install msoffcrypto-tool` |
| `evilclippy` | Remove VBA macro password protection | GitHub: outflanknl/EvilClippy |
| `exiftool` | File metadata (author, timestamps, software) | `apt install libimage-exiftool-perl` |
| `base64dump.py` | Base64 blob extraction and decoding | Didier Stevens tools |
| `xorsearch` | XOR/ROT/other-encoded string search | Didier Stevens tools |
| `binwalk` | Embedded file detection | `apt install binwalk` |
