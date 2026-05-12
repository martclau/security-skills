---
name: binary-analysis
description: >
  Analyze binaries from a security perspective. Use when the user provides an executable,
  shared library, firmware image, or other binary file and asks to inspect it for security
  issues, malware indicators, vulnerabilities, or reverse-engineering insights. Trigger on
  phrases like "analyze this binary", "check this executable", "suspicious binary",
  "reverse engineer", "malware sample", "ELF/PE/Mach-O analysis", or "what does this binary do".
---

# Binary Security Analysis Skill

This skill performs a structured security analysis of a binary file using static analysis
techniques, security-feature checks, and behavioral indicator review.

It works in five phases:

1. **Identification** -- determine file type, architecture, and format.
2. **Static analysis** -- strings, imports/exports, symbols, sections, entropy.
3. **Security features check** -- compiler mitigations (NX, ASLR, PIE, canaries, RELRO, etc.).
4. **Behavioral indicators** -- suspicious strings, known-bad patterns, YARA-style heuristics.
5. **Synthesis** -- verdict, risk summary, and recommended next steps.

---

## Step 0 -- Validate input and create working directory

```bash
WORK_DIR=$(mktemp -d)
echo "Working directory: $WORK_DIR"
```

Ask the user for the path to the binary if they haven't provided one:

> "Please provide the full path to the binary you'd like me to analyze."

Verify the file exists and is a regular file. If it is clearly a text file (e.g., a script),
note this and ask the user to confirm they want binary analysis or script analysis instead.

Copy the binary to the working directory so all tool output is isolated:

```bash
cp "<user-provided-path>" "$WORK_DIR/target"
```

---

## Step 1 -- Identify the binary

Run identification tools to establish the binary format, architecture, and basic metadata.

```bash
# File type and magic bytes
file "$WORK_DIR/target"

# SHA-256 hash (for threat intel lookups)
sha256sum "$WORK_DIR/target"

# File size
ls -lh "$WORK_DIR/target"
```

Parse and record:
- Format: ELF / PE (Windows) / Mach-O (macOS) / raw firmware / other
- Architecture: x86 / x86-64 / ARM / MIPS / RISC-V / etc.
- Endianness
- Bit width: 32 / 64
- Linked: dynamically or statically
- Stripped: yes/no (presence of symbol table)

---

## Step 2 -- Static analysis

### 2a. Strings extraction

```bash
# Extract printable strings (min length 6 to reduce noise)
strings -n 6 "$WORK_DIR/target" > "$WORK_DIR/strings.txt"
wc -l "$WORK_DIR/strings.txt"
```

Scan `strings.txt` for high-value indicators:
- URLs, IP addresses, domain names
- File paths (especially `/tmp`, `/dev/shm`, `/proc`, Windows temp paths)
- Registry keys (HKLM, HKCU)
- Shell commands (`bash -i`, `cmd.exe /c`, `powershell -enc`)
- Crypto-related keywords (wallet addresses, cipher names)
- Credentials or API key patterns
- Packer/protector signatures (UPX, MPRESS, Themida)

```bash
# Grep for common suspicious patterns
grep -iE '(http|ftp|tcp|udp)s?://' "$WORK_DIR/strings.txt"
grep -iE '(/tmp/|/dev/shm|/proc/self|\.onion)' "$WORK_DIR/strings.txt"
grep -iE '(cmd\.exe|powershell|wget|curl|chmod \+x|bash -[ic])' "$WORK_DIR/strings.txt"
grep -iE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})' "$WORK_DIR/strings.txt"
```

### 2b. ELF-specific analysis (Linux/Unix binaries)

Run only if `file` identified the target as ELF.

```bash
# Section headers
readelf -S "$WORK_DIR/target" 2>/dev/null

# Dynamic dependencies
readelf -d "$WORK_DIR/target" 2>/dev/null | grep NEEDED
ldd "$WORK_DIR/target" 2>/dev/null

# Imported symbols (dynamic)
readelf --dyn-syms "$WORK_DIR/target" 2>/dev/null

# All symbols (if not stripped)
nm -D "$WORK_DIR/target" 2>/dev/null | head -100

# Program headers
readelf -l "$WORK_DIR/target" 2>/dev/null
```

Interesting ELF sections to flag if present:
- `.upx` or `.packed` -- UPX-packed binary
- Unusually high entropy sections -- possible encryption or packing
- Missing `.symtab` -- stripped binary
- `.note.gnu.build-id` -- useful for matching to debug packages
- Writable and executable segments simultaneously -- strong red flag

### 2c. PE-specific analysis (Windows binaries)

Run only if `file` identified the target as PE (Windows executable or DLL).

Use `objdump` (from mingw or binutils) or `python3 -c "import pefile"` if available:

```bash
objdump -x "$WORK_DIR/target" 2>/dev/null | head -100
objdump -p "$WORK_DIR/target" 2>/dev/null | grep -A5 "Import"
```

If `pefile` is available:

```bash
python3 - <<'EOF'
import pefile, sys
pe = pefile.PE("$WORK_DIR/target")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
    for imp in entry.imports:
        print("  ", imp.name.decode() if imp.name else hex(imp.ordinal))
EOF
```

Interesting PE imports to flag:
- `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` -- process injection
- `OpenProcess` -- process manipulation
- `RegSetValueEx` -- registry persistence
- `CreateService` / `StartService` -- service installation
- `CryptEncrypt` / `CryptDecrypt` -- encryption (possible ransomware)
- `WSAStartup` / `connect` / `send` / `recv` -- network activity
- `InternetOpen` / `HttpSendRequest` -- HTTP communication
- `ShellExecute` / `WinExec` -- command execution

### 2d. Entropy analysis

High entropy (> 7.0) in a section often indicates packing, encryption, or compression.
Run the bundled script for per-section entropy:

```bash
python3 <skill-path>/scripts/binary_analyzer.py --entropy "$WORK_DIR/target"
```

---

## Step 3 -- Security features check

### ELF security features

```bash
# checksec (preferred if available)
checksec --file="$WORK_DIR/target" 2>/dev/null

# Manual fallback via readelf
python3 <skill-path>/scripts/binary_analyzer.py --checksec "$WORK_DIR/target"
```

Feature checklist for ELF:

| Feature        | Good state  | What it protects against                        |
|----------------|-------------|--------------------------------------------------|
| NX / DEP       | Enabled     | Code execution in data pages (stack/heap spray) |
| PIE            | Enabled     | Predictable load address (ROP/GOT overwrite)    |
| Stack canary   | Present     | Stack buffer overflows                           |
| RELRO          | Full        | GOT overwrites (partial RELRO = partial cover)  |
| FORTIFY_SOURCE | Enabled     | Some string/memory function overflows           |
| RUNPATH/RPATH  | Absent      | Library hijacking via relative RPATH            |

### PE security features

```bash
python3 <skill-path>/scripts/binary_analyzer.py --pe-security "$WORK_DIR/target"
```

Feature checklist for PE:

| Feature              | Good state | Notes                                            |
|----------------------|------------|--------------------------------------------------|
| ASLR (`/DYNAMICBASE`)| Enabled    | Randomized load address                         |
| DEP (`/NXCOMPAT`)    | Enabled    | Non-executable stack/heap                       |
| SafeSEH              | Enabled    | Structured exception handler validation         |
| Control Flow Guard   | Enabled    | Indirect call target validation                 |
| High Entropy VA      | Enabled    | 64-bit ASLR with wider entropy                  |
| Code Integrity       | Enabled    | Kernel-mode code signing enforcement            |
| Authenticode sig     | Present    | Signed binary; verify the signer                |

---

## Step 4 -- Behavioral indicators

Run the full heuristic scan with the bundled script:

```bash
python3 <skill-path>/scripts/binary_analyzer.py --heuristics "$WORK_DIR/target" \
    --strings "$WORK_DIR/strings.txt" \
    -o "$WORK_DIR/heuristics.json"
```

### Categories to assess

| Category              | What to look for                                              |
|-----------------------|---------------------------------------------------------------|
| `persistence`         | Cron strings, rc.local, registry Run keys, service creation  |
| `c2_communication`    | Hardcoded IPs, DGA-like domains, HTTP beaconing strings      |
| `anti_analysis`       | ptrace checks, VM/sandbox detection, timing tricks           |
| `privilege_escalation`| SUID strings, sudo, token impersonation imports              |
| `credential_access`   | /etc/shadow, SAM hive, LSASS references, keylogger APIs      |
| `lateral_movement`    | SMB, RDP, SSH client strings, PsExec-like patterns           |
| `defense_evasion`     | Packer signatures, self-deletion, log tampering strings      |
| `destructive`         | wipe/shred commands, MBR write patterns, ransomware strings  |
| `injection`           | Shellcode loader patterns, reflective DLL strings            |

### Optional: VirusTotal hash lookup

Look up the SHA-256 hash in VirusTotal threat intelligence (no upload required):

```bash
python3 <skill-path>/scripts/binary_analyzer.py --vt-hash <SHA256> \
    --no-color -o "$WORK_DIR/vt_report.json"
```

Requires `VT_API_KEY` set as an environment variable. Never ask the user to paste the key
into the chat:

> "If you'd like a VirusTotal hash lookup, please run:
> `export VT_API_KEY='your-key-here'`
> (Free key at https://www.virustotal.com)"

---

## Step 5 -- Synthesize and write the report

Combine all findings into a structured security assessment.

### Verdict

Use the most severe applicable verdict:

- **CLEAN** -- No suspicious indicators, all security features present.
- **LOW RISK** -- Missing some hardening features but no suspicious behavior indicators.
- **MEDIUM RISK** -- Missing multiple security features, or suspicious strings with plausible
  benign explanation.
- **HIGH RISK** -- Multiple suspicious indicators across categories, or missing critical
  security features with suspicious behavior patterns.
- **MALICIOUS / DO NOT EXECUTE** -- Confirmed malware (VT detection), or multiple converging
  indicators (network + persistence + anti-analysis + suspicious strings) without a credible
  benign explanation.

### Report structure

1. **Executive summary** -- one paragraph: what is this binary and what is the risk.
2. **File identification** -- format, arch, hash, size, strip status.
3. **Security features** -- table of enabled/disabled mitigations with risk commentary.
4. **String analysis** -- top suspicious strings with interpretation.
5. **Import analysis** -- suspicious API calls grouped by MITRE ATT&CK tactic.
6. **Entropy analysis** -- per-section results, packing assessment.
7. **Behavioral indicators** -- heuristic findings by category.
8. **VirusTotal result** -- hash lookup result if performed.
9. **Verdict** -- clear statement with confidence.
10. **Recommended next steps** -- what the analyst should do next.

### Recommended next steps (by severity)

**For MEDIUM or higher:**
- Submit to sandbox (Any.run, Hybrid Analysis, Cuckoo) for dynamic analysis.
- Decompile with Ghidra or Binary Ninja for deeper code review.
- Monitor with strace/ltrace if safe to run in an isolated VM.
- Search hash and strings against threat intel feeds.

**For HIGH or MALICIOUS:**
- Do not execute outside an air-gapped sandbox VM.
- Preserve the sample and chain of custody.
- Check for related indicators (similar hashes, C2 IPs, domains) across the environment.
- Consider incident response procedures if found on a production system.

---

## Known limitations

Be transparent about these in every report:

1. **Static analysis only** -- this skill does not execute the binary. Dynamic behaviors
   (runtime decryption, network calls, anti-analysis checks) will not be observed.
2. **Packed or encrypted binaries** -- if the binary is packed, most strings and imports will
   be inside the unpacked payload, invisible to static analysis. Entropy > 7.2 on the main
   code section is a strong indicator. Recommend unpacking (UPX -d for UPX; sandbox for custom
   packers) before re-analysis.
3. **Architecture support** -- `strings`, `readelf`, and `objdump` work on most ELF targets.
   Full PE analysis requires `pefile` (Python) or a Windows analysis environment.
4. **No taint tracking** -- the script cannot trace how data flows between functions. A
   credential read that is later exfiltrated will appear as two separate findings.
5. **VirusTotal hash lookup only** -- this skill uses hash-based lookup, not file upload, to
   preserve confidentiality of potentially sensitive samples. A novel or modified binary will
   return no VT matches even if it is malicious.
6. **YARA not included** -- for deeper signature-based matching, run the binary through a
   YARA ruleset (e.g., Yara-Rules project, CAPE signatures) separately.

---

## Quick-reference: useful tools

| Tool         | Purpose                                     | Install                        |
|--------------|---------------------------------------------|--------------------------------|
| `file`       | Magic-byte identification                   | Built-in on Linux/macOS        |
| `strings`    | Extract printable strings                   | Built-in on Linux/macOS        |
| `readelf`    | ELF header/section/symbol analysis          | binutils                       |
| `objdump`    | Disassembly and header dump                 | binutils                       |
| `nm`         | Symbol table listing                        | binutils                       |
| `ldd`        | Dynamic library dependencies                | Built-in on Linux              |
| `checksec`   | Security feature audit for ELF/PE           | `pip install checksec`         |
| `pefile`     | PE parsing in Python                        | `pip install pefile`           |
| `strace`     | System call tracing (dynamic)               | Built-in on Linux              |
| `ltrace`     | Library call tracing (dynamic)              | `apt install ltrace`           |
| `Ghidra`     | Full decompiler and reverse engineering IDE | ghidra.re                      |
| `radare2`    | CLI reverse engineering framework           | `apt install radare2`          |
| `YARA`       | Pattern-based malware signature matching    | `pip install yara-python`      |
| `ExifTool`   | Metadata extraction                         | `apt install libimage-exiftool`|
