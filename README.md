# Security Skills

A collection of Claude Code skills for security analysis, intelligence tradecraft, and research workflows.

## Skills

### skill-security-validator

Audits agent skill directories for security issues: malicious code, data exfiltration, prompt injection, obfuscation, credential theft, supply-chain attacks, and more.

**Trigger phrases:** "validate a skill", "audit a skill", "check a skill for security issues", "is this skill safe?"

**How it works:**

1. Automated pattern scan across 15+ threat categories (including two-line sliding window)
2. Optional VirusTotal scan for known malware signatures (requires `VT_API_KEY`)
3. Semantic analysis of `SKILL.md` for prompt injection and subtle manipulation
4. Synthesis into a structured report with a clear verdict (SAFE / REVIEW RECOMMENDED / DO NOT INSTALL)

**Location:** `.claude/skills/skill-security-validator/`

### analytic-tradecraft

Improves analytical reasoning using structured intelligence tradecraft for ambiguous, incomplete, or contested questions.

**Trigger phrases:** framing a problem, surfacing assumptions, comparing hypotheses, assessing evidence quality, writing intelligence-style assessments with explicit confidence levels.

**How it works:**

- Frames the analytic question and defines scope
- Surfaces and stress-tests working assumptions
- Generates competing hypotheses (including contrarian ones)
- Evaluates evidence quality and intelligence gaps
- Runs ACH-lite (Analysis of Competing Hypotheses) matrix
- Checks for cognitive bias and alternative perspectives
- Produces a structured assessment with bottom line, confidence, and signposts

**Location:** `.claude/skills/analytic-tradecraft/`

### alphaxiv-paper-lookup

Looks up any arxiv paper on alphaxiv.org to get a structured AI-generated overview — faster and more reliable than parsing a raw PDF.

**Trigger phrases:** sharing an arxiv URL or paper ID, asking to summarize or explain a research paper.

**How it works:**

1. Extracts the paper ID from a URL or bare ID
2. Fetches the machine-readable report from `alphaxiv.org/overview/{ID}.md`
3. Falls back to full paper text at `alphaxiv.org/abs/{ID}.md` if more detail is needed

**Location:** `.claude/skills/alphaxiv-paper-lookup/`

### office-analysis

Performs structured static security analysis of Microsoft Office documents across all three major format families: OLE2 (.doc, .xls, .ppt), OOXML (.docx, .xlsx, .pptx, macro-enabled variants), and RTF.

**Trigger phrases:** "analyze this document", "check this Word file", "suspicious Office file", "macro analysis", "OLE analysis", "RTF analysis", "weaponized document", "phishing attachment"

**How it works:**

1. Triage — identifies true format (never trusts extension), extracts metadata, decrypts if password-protected
2. Structural analysis — OLE2 stream enumeration, OOXML `.rels` external reference scanning, RTF object and control word inspection
3. Macro and code extraction — VBA (olevba), XLM/Excel 4.0 (xlmdeobfuscator), DDE fields (msodde), p-code for VBA-stomped documents (pcodedmp)
4. Deobfuscation — ViperMonkey VBA emulation, Base64/Chr()/XOR decoding, manual string tracing
5. IOC extraction — URLs, C2 indicators, dropped paths, registry keys, shellcode references
6. Optional VirusTotal hash lookup (requires `VT_API_KEY`)
7. Synthesizes findings into a structured report with MITRE ATT&CK mapping and a clear verdict (CLEAN / LOW / MEDIUM / HIGH RISK / MALICIOUS)

**Detected threats:** VBA macros, XLM macros, DDE fields, Equation Editor exploits (CVE-2017-11882), template injection (CVE-2017-0199, Follina/CVE-2022-30190), VBA stomping, RTF shellcode, embedded PE executables, OOXML external link abuse

**Location:** `.claude/skills/office-analysis/`

### binary-analysis

Performs a structured static security analysis of ELF, PE (Windows), and Mach-O binaries. Checks security mitigations, extracts suspicious strings and imports, runs behavioral heuristics, and optionally looks up the hash on VirusTotal.

**Trigger phrases:** "analyze this binary", "check this executable", "suspicious binary", "reverse engineer", "malware sample", "ELF/PE/Mach-O analysis", "what does this binary do"

**How it works:**

1. Identifies file type, architecture, and format
2. Extracts strings and scans for suspicious patterns (URLs, C2 indicators, credential patterns)
3. Analyzes ELF/PE headers, imports, exports, and section entropy
4. Checks compiler security mitigations (NX, PIE, stack canary, RELRO, ASLR, DEP, CFG)
5. Runs behavioral heuristics across MITRE ATT&CK-aligned categories (persistence, C2, anti-analysis, etc.)
6. Optional VirusTotal hash lookup (requires `VT_API_KEY`)
7. Synthesizes findings into a structured report with a clear verdict (CLEAN / LOW / MEDIUM / HIGH RISK / MALICIOUS)

**Location:** `.claude/skills/binary-analysis/`

### find-vulns

Scans source code files for security vulnerabilities, ranks them by severity, and produces a structured report with CWE IDs, root causes, proof-of-concept triggers, and suggested fixes.

**Trigger phrases:** "find vulnerabilities", "audit code for security", "do a security review", "check for buffer overflows", "CTF challenge", "pen-test this source", uploading a C/C++/Rust/Go/Python/JS file and asking for a security review.

**How it works:**

1. Identifies target file(s) and builds a mental model of trust boundaries and data flow
2. Hunts systematically across vulnerability categories: memory safety, integer issues, input validation, logic/design flaws, concurrency bugs, and language-specific issues
3. Ranks each finding CRITICAL / HIGH / MEDIUM / LOW
4. Produces a structured report per finding: type, CWE ID, function/line, root cause, exploit trigger, and fix
5. Ends with a summary table sorted by severity
6. Saves the report to a requested path or `vuln-report-<filename>.txt`

**Bundled CLI script:** `scripts/find-vulns.sh <source-file> [output-file]` — runs the skill headless via the Claude Code CLI with pre-approved tools and streaming progress output.

**Location:** `.claude/skills/find-vulns/`

### decompile-binaryninja

Decompiles a binary using Binary Ninja headless mode (HLIL / "Pseudo C" layer), writing one `.c` file per function under `<binary>.dec/`.

**Trigger phrases:** "decompile with BN", "decompile with Binary Ninja"

**How it works:**

1. Validates the binary path and clears any existing `.dec` output directory
2. Runs `scripts/decompile.py` via Binary Ninja's bundled `bnpython3` interpreter
3. Opens the binary with `binaryninja.load()`, waits for full analysis, then iterates `bv.functions`
4. Decompiles each function via `func.hlil`; functions with no HLIL (imports, data) are silently skipped
5. Writes pseudocode to `<binary>.dec/<funcname>@<ADDR>.c`, matching the haruspex naming convention

**Requirements:** Binary Ninja Commercial or above (headless requires a commercial license). Install path defaults to `~/Downloads/binaryninja/`; override with `BN_DIR`.

**Location:** `.claude/skills/decompile-binaryninja/`

### decompile-idapro

Decompiles a binary using IDA Pro 9.x idalib (headless) with the Hex-Rays decompiler, writing one `.c` file per non-thunk function under `<binary>.dec/`.

**Trigger phrases:** "decompile with IDA", "decompile with IDA Pro"

**How it works:**

1. Validates the binary path and clears any existing `.dec` output directory
2. Removes stale IDA sidecar files (`.id0/.id1/.id2/.nam/.til`) that cause "corrupted DB" errors
3. Opens the binary with `idapro.open_database(run_auto_analysis=True)` and waits for full analysis
4. Loads the architecture-appropriate Hex-Rays plugin (e.g. `hexx64` for x86-64) explicitly — required in headless/idalib mode
5. Iterates all functions, skips thunks (`FUNC_THUNK`), decompiles the rest via `ida_hexrays.decompile()`
6. Writes pseudocode to `<binary>.dec/<funcname>@<ADDR>.c`; license errors are fatal, other decompiler errors are skipped

**Requirements:** IDA Pro 9.x with a valid Hex-Rays decompiler license. Install path defaults to `~/.local/share/applications/IDA Professional 9.3/`.

**Location:** `.claude/skills/decompile-idapro/`

## Directory Structure

```
security-skills/
├── README.md
└── .claude/
    └── skills/
        ├── skill-security-validator/
        │   ├── SKILL.md
        │   └── scripts/
        │       ├── skill_validator.py
        │       └── vt_scan.py
        ├── analytic-tradecraft/
        │   ├── SKILL.md
        │   └── references/
        │       ├── book-synthesis.md
        │       └── output-template.md
        ├── alphaxiv-paper-lookup/
        │   └── SKILL.md
        ├── binary-analysis/
        │   ├── SKILL.md
        │   ├── scripts/
        │   │   └── binary_analyzer.py
        │   └── references/
        │       └── mitre-attck-binary.md
        ├── office-analysis/
        │   ├── SKILL.md
        │   ├── scripts/
        │   │   └── office_analyzer.py
        │   └── references/
        │       └── mitre-attck-office.md
        ├── find-vulns/
        │   ├── SKILL.md
        │   └── scripts/
        │       └── find-vulns.sh
        ├── decompile-binaryninja/
        │   ├── SKILL.md
        │   └── scripts/
        │       └── decompile.py
        └── decompile-idapro/
            ├── SKILL.md
            └── scripts/
                └── decompile.py
```
