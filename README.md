# security-skills

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

---

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

---

### alphaxiv-paper-lookup

Looks up any arxiv paper on alphaxiv.org to get a structured AI-generated overview — faster and more reliable than parsing a raw PDF.

**Trigger phrases:** sharing an arxiv URL or paper ID, asking to summarize or explain a research paper.

**How it works:**
1. Extracts the paper ID from a URL or bare ID
2. Fetches the machine-readable report from `alphaxiv.org/overview/{ID}.md`
3. Falls back to full paper text at `alphaxiv.org/abs/{ID}.md` if more detail is needed

**Location:** `.claude/skills/alphaxiv-paper-lookup/`

---

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

---

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
        └── binary-analysis/
            ├── SKILL.md
            └── references/
                └── mitre-attck-binary.md
```
