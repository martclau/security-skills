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

**Location:** `skills/skill-security-validator/`

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

**Location:** `skills/analytic-tradecraft/`

### alphaxiv-paper-lookup

Looks up any arxiv paper on alphaxiv.org to get a structured AI-generated overview — faster and more reliable than parsing a raw PDF.

**Trigger phrases:** sharing an arxiv URL or paper ID, asking to summarize or explain a research paper.

**How it works:**

1. Extracts the paper ID from a URL or bare ID
2. Fetches the machine-readable report from `alphaxiv.org/overview/{ID}.md`
3. Falls back to full paper text at `alphaxiv.org/abs/{ID}.md` if more detail is needed

**Location:** `skills/alphaxiv-paper-lookup/`

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

**Location:** `skills/office-analysis/`

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

**Location:** `skills/binary-analysis/`

### asm-recon

Maps and continuously monitors the external attack surface of domains the user **owns**, emitting a dated JSON snapshot plus a human-readable `REPORT.md` that leads with a diff against the previous run. Defensive and owned-assets-only — it never port-scans, brute-forces credentials or directories, or probes for vulnerabilities.

**Trigger phrases:** "recon on our domain", "what's our external footprint", "attack-surface monitoring", "find our subdomains", "audit our DNS / mail / certs", "check for subdomain takeover", "are our nameservers leaking the zone", "external asset inventory", "what changed in our surface since last week".

**How it works:**

1. **Passive collection** — RDAP registration data, certificate-transparency subdomain discovery (crt.sh + CertSpotter, unioned so one source being down never zeroes out enumeration), and Team Cymru ASN/CIDR enrichment. No packets to the target.
2. **No-impact active collection** — resolves DNS for discovered hosts, one HTTP(S) GET per host (following redirects to fingerprint the *final* host), one TLS handshake, and reads `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, and the favicon.
3. **Mail posture** — derives SPF/DKIM/DMARC and flags spoofable domains.
4. **Zone-transfer audit** — attempts AXFR against each authoritative nameserver. This is a configuration audit, not an attack; a successful transfer is a finding.
5. **Auth-surface detection** — flags exposed login/SSO/VPN/webmail/admin endpoints via URL/redirect paths, body credential forms, HTTP `401`/`WWW-Authenticate` challenges, and vendor fingerprints, risk-tiered (remote-access/admin → MEDIUM, SSO/generic → INFO) with the matching evidence recorded.
6. **Risk callouts** — HIGH / MEDIUM / LOW / INFO findings (AXFR exposure, dangling-CNAME takeover candidates, email spoofability, expiring/expired TLS, exposed authentication surfaces).
7. Writes `<YYYY-MM-DD>.json` (the longitudinal record) and a diff-led `REPORT.md`, carrying forward `first_seen` dates across runs.

**Dependencies:** none — pure Python standard library. A bundled stdlib-only DNS client (`scripts/dnsmini.py`) handles record types and AXFR that `socket` can't; an optional `CERTSPOTTER_TOKEN` lifts certificate-transparency rate limits.

**Location:** `skills/asm-recon/`

### elf-expert

Provides deep expertise for inspecting, analyzing, and modifying ELF binaries and reasoning about the ELF format/ABI — a reference-heavy skill rather than a one-shot analyzer.

**Trigger phrases:** examining ELF headers/sections/segments/symbols/relocations/dynamic data, assessing hardening (NX, RELRO, PIE, canaries, FORTIFY, RPATH), using `readelf`/`objdump`/`nm`, modifying ELF files (`strip`, `objcopy`, `patchelf`), or writing/reviewing code that parses ELF.

**How it works:**

- Routes to the lightest tool for the job (`file` → `readelf` → `objdump`), escalating only as needed
- Treats `/usr/include/elf.h`, the System V gABI, per-architecture psABI supplements, and LLVM as ground truth over recall
- Carries a `checksec`-style hardening table derived from static ELF data
- Bundles reference files on format internals, `readelf`, `objdump`, modification workflows, and parser/library coding (pyelftools, LIEF, libelf, goblin)

**Location:** `skills/elf-expert/`

### dwarf-expert

Provides deep expertise for analyzing, parsing, creating, and reasoning about DWARF debug information and the DWARF standard (v3, v4, v5).

**Trigger phrases:** inspecting or extracting DWARF from a binary (`.debug_info`, `.debug_line`, `.debug_abbrev`, …), decoding DIEs/tags/attributes/forms, mapping addresses to source lines, interpreting DWARF expressions and location/range lists, split DWARF (`.dwo`/`.dwp`), using `dwarfdump`/`llvm-dwarfdump`/`readelf`, or writing/reviewing code that parses DWARF.

**How it works:**

- Leads with a core mental model (DIE tree → tags/attributes/forms; `.debug_abbrev` parsed before `.debug_info`)
- Treats the official DWARF standard, LLVM's `DebugInfo/DWARF`, libdwarf, and pyelftools as authoritative; cites which source confirms a fact
- Covers integrity verification and quality metrics (`llvm-dwarfdump --verify`, `--statistics`)
- Bundles reference files on the data model, section catalog, DWARF5 changes, line programs/expressions, `dwarfdump`, `readelf`, and parser coding

**Location:** `skills/dwarf-expert/`

### macho-expert

Provides deep expertise for inspecting, analyzing, and modifying Mach-O binaries — the executable format used by macOS and iOS.

**Trigger phrases:** examining headers, load commands, segments, symbol tables, or code signatures; identifying fat/universal binaries and slices; assessing hardening (PIE, canaries, ARC, encryption, hardened runtime, entitlements); using `otool`/`nm`/`codesign`/`lipo`/`dyld_info`; modifying with `lipo`/`install_name_tool`/`strip`/`vtool`; or "what's in this .dylib", "extract the arm64 slice".

**How it works:**

1. Starts from `file` to detect fat vs. thin (which changes how every later tool is invoked)
2. Routes across native Apple tools (`otool`, `codesign`), LLVM tools (`llvm-objdump --macho`), GNU binutils, and LIEF depending on what's installed — confirming a tool exists before recommending its invocation
3. Treats Apple SDK headers, `man` pages, LLVM `BinaryFormat/MachO.h`, and Apple's `dyld`/`cctools` as ground truth
4. Bundles a `macho_triage.py` script plus reference files on format internals, load commands, tools, and parser coding (LIEF, macholib, goblin)

**Location:** `skills/macho-expert/`

### yara-rule-authoring-review

Authors and reviews high-quality, import-free YARA detection rules that catch malware without drowning in false positives, enforcing a strict, opinionated house style.

**Trigger phrases:** "write/create a YARA rule", "review/audit/harden this rule", "make this tighter", "convert these IOCs/hashes to a signature", "debug false positives", or pasting strings/hashes and asking for "a rule to detect this".

**How it works:**

- Synthesizes Trail of Bits, Stairwell, and Neo23x0 guidance, then layers four non-negotiable house rules on top
- Requires six meta fields (`author`, `date`, `description`, `hash`, `reference`, `version`) in order on every rule
- Mandates a header check + filesize guard at the start of every condition to avoid false positives on swap files, memory dumps, and disk images
- Forbids all module imports — structural and magic-byte checks use raw `uint8/uint16/uint32` reads only
- Operates in two modes (author vs. review) with a copy-ready rule template and reference files on strings, conditions/performance, testing, a review rubric, and the style guide

**Location:** `skills/yara-rule-authoring-review/`

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

**Location:** `skills/find-vulns/`

### validate-vuln

Validates inbound vulnerability reports by verifying whether each finding is actually exploitable. Complements `find-vulns` — use `find-vulns` to generate a report, then `validate-vuln` to triage one.

**Trigger phrases:** "validate this vuln report", "is this exploitable?", "triage this report", "verify these findings", providing a `*.vuln.md` file for review.

**How it works:**

1. Reads the vulnerability report and extracts each finding's claimed type, severity, function, and trigger
2. Reads all referenced source files and builds a mental model of trust boundaries and data flow
3. Applies a three-gate test to each finding:
   - **Gate 1 — Is the bug real?** Confirms the code pattern exists and the report read types/APIs correctly
   - **Gate 2 — Is it attacker-reachable?** Traces the call graph from untrusted input to the vulnerable code, checking for intervening HMAC, encryption, auth, or bounds checks
   - **Gate 3 — Is the impact real?** Assesses whether triggering the bug yields meaningful security impact or is purely theoretical
4. Assigns each finding a verdict: CONFIRMED EXPLOITABLE, CONFIRMED BUG NOT EXPLOITABLE, FALSE POSITIVE, or INSUFFICIENT EVIDENCE
5. Assesses overall report quality (severity calibration, missed findings, call-graph analysis depth)
6. Saves the validation report alongside the original

**Location:** `skills/validate-vuln/`

### c-build-test-review

Reviews a C/C++ project's build configuration, compiler flags, assertion discipline, testing infrastructure, and analysis tooling against modern best practices, then produces an actionable, severity-ranked review (not a rewrite).

**Trigger phrases:** "are my GCC flags any good", "is this build secure", "harden this build", "what's missing from my C testing", "should I be using sanitizers", "review my Makefile/CMakeLists.txt", "how are `assert`/`static_assert` used here".

**How it works:**

1. Inventories the build system, compiler(s), language standard, configured phases, test framework, analyzers/sanitizers, and assertion usage
2. Evaluates four axes — compiler-flag hygiene, assertion discipline, testing infrastructure, analysis tooling — against each SDLC phase (build / debug / test / PGO / release), since a correct setting for one phase is wrong for another
3. Surfaces phase-mismatch hazards explicitly (e.g. `_FORTIFY_SOURCE` with `-O0`, `NDEBUG` in the test build, sanitizers left on in release)
4. Produces a structured review with findings categorized critical / important / nice-to-have, each justified and with a concrete replacement, plus a phase-by-phase recommended flag set

**Reference:** `references/worked-example.md` — a complete worked review of a small Makefile project, used to calibrate severity tiering and tone.

**Location:** `skills/c-build-test-review/`

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

**Location:** `skills/decompile-binaryninja/`

### android-masvs

Assesses an Android application against the OWASP Mobile Application Security Verification Standard (MASVS v2.0) and produces a structured findings report with MASVS controls, MASWE weaknesses, MASTG test IDs, severity ratings, and remediation guidance.

**Trigger phrases:** "audit an APK", "review an Android app for security", "run MASVS checks", "MAS assessment", "OWASP mobile audit", "check an Android app for vulnerabilities", uploading a `.apk`, `.aab`, `.xapk`, or Android project and asking for a security review.

**How it works:**

1. Identifies the target artifact (APK, AAB, XAPK, or Android project tree)
2. Unpacks and inventories contents using `apktool` and `jadx`: manifest, resources, smali, decompiled Java/Kotlin, native libraries, certificates
3. Checks all eight MASVS v2.0 control families: Storage, Cryptography, Authentication, Network, Platform, Code, Resilience, Privacy
4. Flags findings with MASVS control ID, MASWE weakness ID, MASTG test ID, severity, and remediation guidance
5. Notes dynamic checks that require a live device (Frida, traffic interception) rather than faking results
6. Produces a structured report with an executive summary, per-finding detail, and a severity summary table

**Location:** `skills/android-masvs/`

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

**Location:** `skills/decompile-idapro/`

## Directory Structure

```
security-skills/
├── README.md
├── .claude/
│   └── CLAUDE.md
├── docs/
│   └── finding-vulnerabilities-with-claude.md
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
    ├── asm-recon/
    │   ├── SKILL.md
    │   └── scripts/
    │       ├── recon.py
    │       └── dnsmini.py
    ├── elf-expert/
    │   ├── SKILL.md
    │   └── reference/
    │       ├── coding.md
    │       ├── format.md
    │       ├── modification.md
    │       ├── objdump.md
    │       └── readelf.md
    ├── dwarf-expert/
    │   ├── SKILL.md
    │   └── reference/
    │       ├── coding.md
    │       ├── data-model.md
    │       ├── dwarf5-changes.md
    │       ├── dwarfdump.md
    │       ├── line-and-expressions.md
    │       ├── readelf.md
    │       └── sections.md
    ├── macho-expert/
    │   ├── SKILL.md
    │   ├── scripts/
    │   │   └── macho_triage.py
    │   └── reference/
    │       ├── coding.md
    │       ├── format.md
    │       ├── load_commands.md
    │       └── tools.md
    ├── yara-rule-authoring-review/
    │   ├── SKILL.md
    │   ├── assets/
    │   │   └── rule_template.yar
    │   └── references/
    │       ├── conditions-and-performance.md
    │       ├── review-rubric.md
    │       ├── strings.md
    │       ├── style-guide.md
    │       └── testing.md
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
    ├── validate-vuln/
    │   └── SKILL.md
    ├── c-build-test-review/
    │   ├── SKILL.md
    │   └── references/
    │       └── worked-example.md
    ├── android-masvs/
    │   ├── SKILL.md
    │   ├── scripts/
    │   │   └── unpack_apk.sh
    │   └── references/
    │       ├── masvs-storage.md
    │       ├── masvs-crypto.md
    │       ├── masvs-auth.md
    │       ├── masvs-network.md
    │       ├── masvs-platform.md
    │       ├── masvs-code.md
    │       ├── masvs-resilience.md
    │       ├── masvs-privacy.md
    │       └── tools-setup.md
    ├── decompile-binaryninja/
    │   ├── SKILL.md
    │   └── scripts/
    │       └── decompile.py
    └── decompile-idapro/
        ├── SKILL.md
        └── scripts/
            └── decompile.py
```
