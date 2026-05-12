#!/usr/bin/env python3
"""
Skill Validator v2 — Audits agent skill directories for potentially malicious behavior.

Improvements over v1 (based on security review):
  - Two-line sliding window catches patterns split across lines
  - Scans files by shebang (#!), not just extension
  - Flags unknown-extension files as suspicious
  - Extracts URLs from network calls for manual verification
  - New rules: raw sockets, os.environ, ctypes, file writes, zlib/gzip,
    codecs.decode, YAML !!python, reversed strings, __builtins__, globals/locals
  - importlib bumped to MEDIUM

Usage:
    python skill_validator.py /path/to/skill-folder          # validate one skill
    python skill_validator.py /path/to/skills --recursive     # validate all skills in tree
    python skill_validator.py /path/to/skill -o report.json   # JSON output
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


# ─── Severity ────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ─── Finding dataclass ───────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: Severity
    category: str
    message: str
    file: str
    line: Optional[int] = None
    snippet: str = ""
    extracted_urls: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        if not d["extracted_urls"]:
            del d["extracted_urls"]
        return d


# ─── Rule definitions ────────────────────────────────────────────────────────
# Each rule: (compiled regex, severity, category, description, multiline?)
# multiline=True means the pattern is tested against pairs of consecutive lines.

RULES: list[tuple[re.Pattern, Severity, str, str, bool]] = []

def rule(pattern: str, severity: Severity, category: str, description: str,
         flags: int = re.IGNORECASE, multiline: bool = False):
    RULES.append((re.compile(pattern, flags), severity, category, description, multiline))


# ── Network / Exfiltration ───────────────────────────────────────────────────
rule(r'\bcurl\b.*\b(POST|--data|--upload|-d\b|-F\b)',
     Severity.HIGH, "exfiltration",
     "curl with POST/data upload — may exfiltrate data to external server")
rule(r'\bwget\b.*(-O\s*-|--output-document)',
     Severity.MEDIUM, "network",
     "wget downloading content — verify the target URL is expected")
rule(r'\bcurl\b.*\|.*\b(bash|sh|python|perl|ruby|node)\b',
     Severity.CRITICAL, "remote_code_exec",
     "Pipe from curl into a shell/interpreter — classic remote code execution")
rule(r'\bwget\b.*\|.*\b(bash|sh|python|perl|ruby|node)\b',
     Severity.CRITICAL, "remote_code_exec",
     "Pipe from wget into a shell/interpreter — remote code execution")
rule(r'\bfetch\s*\(\s*["\']https?://',
     Severity.MEDIUM, "network",
     "JavaScript fetch() call — verify the target URL is legitimate")
rule(r'\brequests\.(get|post|put|patch|delete)\s*\(',
     Severity.MEDIUM, "network",
     "Python requests library call — verify the URL and data payload")
rule(r'\burllib\.request\.(urlopen|Request)\s*\(',
     Severity.MEDIUM, "network",
     "Python urllib usage — verify target URL and scheme restriction")
rule(r'\bhttpx\.\w+\s*\(',
     Severity.MEDIUM, "network",
     "Python httpx usage — verify target URL")
rule(r'\b(nc|ncat|netcat)\b.*(-e|-c|--exec)',
     Severity.CRITICAL, "remote_code_exec",
     "Netcat with exec flag — reverse shell / backdoor pattern")
rule(r'ngrok|localtunnel|bore\.pub|serveo\.net',
     Severity.HIGH, "network",
     "Tunnel service reference — may expose local services or exfiltrate data")

# ── Raw socket access (NEW — addresses review 1.5) ──────────────────────────
rule(r'\bsocket\.socket\s*\(',
     Severity.HIGH, "network",
     "Raw socket creation — can exfiltrate data bypassing all HTTP-level detection")
rule(r'\bsocket\.connect\s*\(',
     Severity.HIGH, "network",
     "Raw socket connect — direct TCP connection bypasses HTTP-level monitoring")
rule(r'\bsocket\.(send|sendall|sendto|recv|recvfrom)\s*\(',
     Severity.HIGH, "network",
     "Raw socket data transfer — low-level network I/O, verify purpose")

# ── Multi-line network evasion (NEW — addresses review 2.1) ─────────────────
rule(r'(curl|wget|requests\.|urllib|httpx|fetch\s*\().*https?://',
     Severity.MEDIUM, "network",
     "Network call with URL — verify destination is expected",
     multiline=True)

# ── Dangerous Shell Commands ─────────────────────────────────────────────────
rule(r'\beval\b.*\$',
     Severity.HIGH, "code_injection",
     "eval with variable expansion — command injection risk")
rule(r'\beval\s*\(',
     Severity.MEDIUM, "code_injection",
     "eval() call — dynamic code execution, common obfuscation vector")
rule(r'\bexec\s*\(',
     Severity.MEDIUM, "code_injection",
     "exec() call — arbitrary code execution")
rule(r'\bcompile\s*\(.*["\']exec["\']\s*\)',
     Severity.HIGH, "code_injection",
     "compile() with exec mode — dynamic code generation and execution")
rule(r'\b__import__\s*\(',
     Severity.MEDIUM, "code_injection",
     "Dynamic __import__() — may load unexpected modules at runtime")
rule(r'\bsubprocess\.(call|run|Popen|check_output)\s*\(.*shell\s*=\s*True',
     Severity.HIGH, "code_injection",
     "subprocess with shell=True — shell injection risk")
rule(r'\bos\.system\s*\(',
     Severity.MEDIUM, "code_injection",
     "os.system() — prefer subprocess with shell=False for safety")
rule(r'\bos\.popen\s*\(',
     Severity.MEDIUM, "code_injection",
     "os.popen() — legacy shell execution, injection risk")
rule(r'\brm\s+(-rf?|--recursive)\s+/',
     Severity.HIGH, "destructive",
     "Recursive delete from root or absolute path — destructive operation")
rule(r'\bchmod\b.*777',
     Severity.MEDIUM, "permissions",
     "chmod 777 — world-writable permissions, weakens security")
rule(r'\bdd\b.*\bof\s*=\s*/dev/',
     Severity.CRITICAL, "destructive",
     "dd writing to device — can destroy disk/partitions")

# ── Python sandbox escape / runtime manipulation (NEW — addresses review 1.2) ─
rule(r'\b__builtins__\b',
     Severity.HIGH, "code_injection",
     "__builtins__ access — can restore restricted built-in functions for sandbox escape")
rule(r'\b(globals|locals)\s*\(\s*\)',
     Severity.MEDIUM, "code_injection",
     "globals()/locals() access — runtime namespace manipulation")
rule(r'\btype\s*\(\s*["\']',
     Severity.MEDIUM, "code_injection",
     "type() as metaclass constructor — can create classes with arbitrary methods at runtime")
rule(r'\bctypes\b',
     Severity.HIGH, "code_injection",
     "ctypes usage — direct C-level memory access, can bypass all Python-level restrictions")
rule(r'\bimportlib\b',
     Severity.MEDIUM, "supply_chain",
     "Dynamic module import via importlib — verify what is being loaded at runtime")
rule(r'\bimportlib\.import_module\s*\(',
     Severity.MEDIUM, "supply_chain",
     "importlib.import_module() — dynamic module loading, verify the module name")

# ── Sensitive File Access ────────────────────────────────────────────────────
rule(r'~?/\.ssh/',
     Severity.HIGH, "credential_access",
     "Accesses SSH directory — may steal private keys")
rule(r'~?/\.aws/',
     Severity.HIGH, "credential_access",
     "Accesses AWS credentials directory")
rule(r'~?/\.gnupg/',
     Severity.HIGH, "credential_access",
     "Accesses GPG keyring directory")
rule(r'~?/\.config/(gcloud|azure)',
     Severity.HIGH, "credential_access",
     "Accesses cloud provider credential files")
rule(r'/etc/passwd',
     Severity.MEDIUM, "sensitive_file",
     "Reads /etc/passwd — system user enumeration")
rule(r'/etc/shadow',
     Severity.CRITICAL, "credential_access",
     "Reads /etc/shadow — password hash access")
rule(r'\.(env|env\.local|env\.prod)',
     Severity.HIGH, "credential_access",
     "References .env file — often contains secrets and API keys")
rule(r'(API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD)\s*=',
     Severity.HIGH, "credential_access",
     "Hardcoded credential or secret assignment")
rule(r'\bkeychain\b|\bkeyring\b',
     Severity.HIGH, "credential_access",
     "Accesses system keychain/keyring — may steal stored credentials")

# ── Environment variable harvesting (NEW — addresses review 1.6) ─────────────
rule(r'\bos\.environ\b(?!\.(copy|get\s*\(\s*["\']PATH))',
     Severity.MEDIUM, "credential_access",
     "os.environ access — environment may contain API keys, tokens, and credentials")
rule(r'\bos\.environ\s*\[\s*["\'].*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)',
     Severity.HIGH, "credential_access",
     "Reading specific secret from environment variable — verify this is needed")
rule(r'\bos\.getenv\s*\(\s*["\'].*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)',
     Severity.HIGH, "credential_access",
     "Reading specific secret from environment variable — verify this is needed")
rule(r'\bos\.environ\.items\s*\(\s*\)',
     Severity.HIGH, "credential_access",
     "Enumerating all environment variables — likely credential harvesting")

# ── File write operations (NEW — addresses review 1.4) ───────────────────────
rule(r'\bopen\s*\(.*["\']w["\']\s*\)|\bopen\s*\(.*["\']a["\']\s*\)',
     Severity.LOW, "file_write",
     "File opened for writing/appending — verify the destination path")
rule(r'\bopen\s*\(.*/etc/|/root/|/home/|~/',
     Severity.HIGH, "file_write",
     "File write to sensitive system path — verify this is needed and expected")
rule(r'\bshutil\.(copy|copy2|move|copytree)\s*\(',
     Severity.LOW, "file_write",
     "File copy/move operation — verify source and destination")
rule(r'\bPath\s*\(.*\)\s*\.\s*(write_text|write_bytes)\s*\(',
     Severity.LOW, "file_write",
     "pathlib write operation — verify the destination path")
rule(r'(open|write_text|write_bytes|shutil)\s*\(.*(/tmp/|tempfile)',
     Severity.MEDIUM, "file_write",
     "Writing to temp directory — may be a staging area for exfiltration",
     multiline=True)

# ── Obfuscation ──────────────────────────────────────────────────────────────
rule(r'\bbase64\b.*(decode|b64decode|atob|b85decode|b32decode|decodebytes)',
     Severity.MEDIUM, "obfuscation",
     "Base64/b85/b32 decoding — check what payload is being decoded")
rule(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}',
     Severity.HIGH, "obfuscation",
     "Long hex-escaped string — possibly obfuscated payload")
rule(r'\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){5,}',
     Severity.HIGH, "obfuscation",
     "Long unicode-escaped string — possibly obfuscated payload")
rule(r'String\.fromCharCode\s*\(',
     Severity.MEDIUM, "obfuscation",
     "String.fromCharCode — JS string obfuscation technique")
rule(r'chr\s*\(\s*\d+\s*\)(\s*\+\s*chr\s*\(\s*\d+\s*\)){3,}',
     Severity.HIGH, "obfuscation",
     "Chained chr() calls — Python string obfuscation")
rule(r'getattr\s*\(.*,\s*["\']__',
     Severity.MEDIUM, "obfuscation",
     "getattr with dunder attribute — potential sandbox escape")
rule(r'\[ *["\']_' r'_[a-z]+__["\'] *\]',
     Severity.MEDIUM, "obfuscation",
     "Bracket access to dunder attribute — may bypass restrictions")

# ── Additional obfuscation (NEW — addresses review 1.1) ─────────────────────
rule(r'\bcodecs\.decode\s*\(',
     Severity.MEDIUM, "obfuscation",
     "codecs.decode() — can decode ROT13, hex, and other encodings to hide payloads")
rule(r'["\']rot.?13["\']',
     Severity.HIGH, "obfuscation",
     "ROT13 encoding reference — commonly used to hide malicious strings")
rule(r'\bzlib\.(decompress|decompressobj)\s*\(',
     Severity.MEDIUM, "obfuscation",
     "zlib decompression — check what compressed payload is being extracted")
rule(r'\bgzip\.(decompress|open)\s*\(',
     Severity.MEDIUM, "obfuscation",
     "gzip decompression — check what compressed payload is being extracted")
rule(r'\[::\s*-1\s*\]',
     Severity.LOW, "obfuscation",
     "String reversal ([::-1]) — can hide malicious strings when combined with other techniques")
rule(r'\bbz2\.(decompress|open)\s*\(',
     Severity.MEDIUM, "obfuscation",
     "bz2 decompression — check what compressed payload is being extracted")
rule(r'\blzma\.(decompress|open)\s*\(',
     Severity.MEDIUM, "obfuscation",
     "lzma decompression — check what compressed payload is being extracted")

# ── Prompt Injection / Guardrail Override ─────────────────────────────────────
rule(r'ignore\s+(all\s+)?previous\s+instructions',
     Severity.CRITICAL, "prompt_injection",
     "Classic prompt injection — attempts to override system instructions")
rule(r'disregard\s+(all\s+)?(prior|above|previous)',
     Severity.CRITICAL, "prompt_injection",
     "Prompt injection — disregard prior instructions")
rule(r'you\s+are\s+now\s+(in\s+)?["\']?(DAN|jailbreak|unrestricted|god\s*mode)',
     Severity.CRITICAL, "prompt_injection",
     "Jailbreak attempt — tries to override AI safety constraints")
rule(r'<\s*/?\s*system\s*>',
     Severity.HIGH, "prompt_injection",
     "Fake system tag — attempts to inject system-level instructions")
rule(r'SYSTEM\s*:\s*you\s+(must|should|will|are)',
     Severity.HIGH, "prompt_injection",
     "Fake system prompt — tries to override assistant behavior")
rule(r'bypass\s+(all\s+)?(safety|filter|guardrail|restriction|content.?polic)',
     Severity.CRITICAL, "prompt_injection",
     "Explicit attempt to bypass safety guardrails")
rule(r'do\s+not\s+(reveal|share|disclose)\s+(your|the|these)\s+(system|instructions|prompt)',
     Severity.MEDIUM, "prompt_injection",
     "Instruction hiding directive — may be legitimate but review context")
rule(r'<\s*\|?(im_start|im_end|endoftext)\|?\s*>',
     Severity.CRITICAL, "prompt_injection",
     "Special token injection — attempts to manipulate model processing")
rule(r'(human|user|assistant)\s*:\s*\n',
     Severity.MEDIUM, "prompt_injection",
     "Role label injection — may try to fake conversation turns")

# ── Supply Chain / Runtime Downloads ──────────────────────────────────────────
rule(r'pip\s+install.*--index-url\s+(?!https://pypi\.org)',
     Severity.HIGH, "supply_chain",
     "pip install from non-standard index — could be typosquatting/malicious repo")
rule(r'npm\s+install.*--registry\s+(?!https://registry\.npmjs\.org)',
     Severity.HIGH, "supply_chain",
     "npm install from non-standard registry — verify the source")
rule(r'git\s+clone\b',
     Severity.LOW, "supply_chain",
     "git clone detected — verify the repository is trusted")

# ── YAML deserialization (NEW — addresses review 2.3) ────────────────────────
rule(r'!!python/',
     Severity.CRITICAL, "code_injection",
     "YAML !!python/ tag — arbitrary Python code execution via YAML deserialization")
rule(r'\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)',
     Severity.HIGH, "code_injection",
     "yaml.load() without SafeLoader — vulnerable to arbitrary code execution via YAML")
rule(r'\byaml\.unsafe_load\s*\(',
     Severity.HIGH, "code_injection",
     "yaml.unsafe_load() — explicitly allows arbitrary code execution via YAML")

# ── Persistence / Startup Modification ────────────────────────────────────────
rule(r'(crontab|/etc/cron)',
     Severity.HIGH, "persistence",
     "Cron job modification — may install persistent backdoor")
rule(r'~?/\.(bashrc|zshrc|profile|bash_profile)',
     Severity.HIGH, "persistence",
     "Modifies shell startup file — may inject persistent commands")
rule(r'/etc/(systemd|init\.d)',
     Severity.HIGH, "persistence",
     "Modifies system service — may install persistent backdoor")
rule(r'launchctl|LaunchAgents|LaunchDaemons',
     Severity.HIGH, "persistence",
     "macOS launch agent — may install persistent process")

# ── Privilege Escalation ──────────────────────────────────────────────────────
rule(r'\bsudo\b',
     Severity.MEDIUM, "privilege_escalation",
     "Uses sudo — verify this is necessary and scoped appropriately")
rule(r'\bsetuid\b|\bsetgid\b|\bSUID\b',
     Severity.HIGH, "privilege_escalation",
     "SUID/SGID reference — privilege escalation risk")

# ── Data Collection ──────────────────────────────────────────────────────────
rule(r'\b(whoami|hostname|uname\s+-a|ifconfig|ip\s+addr)\b',
     Severity.LOW, "reconnaissance",
     "System info gathering — benign alone but suspicious in combination")
rule(r'\bfind\s+/\s+.*-name\b.*\.(pem|key|crt|p12|pfx)',
     Severity.HIGH, "credential_access",
     "Searching filesystem for certificates/keys")


# ─── URL Extractor ───────────────────────────────────────────────────────────

URL_PATTERN = re.compile(r'https?://[^\s"\'`,;)\]}>]+', re.IGNORECASE)

def extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text for manual verification."""
    return URL_PATTERN.findall(text)


# ─── Scanner ─────────────────────────────────────────────────────────────────

SCANNABLE_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
    ".rb", ".pl", ".yaml", ".yml", ".json", ".toml", ".cfg",
    ".conf", ".ini", ".jsx", ".tsx", ".mjs", ".cjs", ".html",
    ".css", ".sql", ".r", ".go", ".rs", ".java", ".kt",
    ".swift", ".ps1", ".bat", ".cmd", ".lua", ".php",
}


def has_shebang(filepath: Path) -> bool:
    """Check if a file starts with a shebang (#!) line."""
    try:
        with open(filepath, "rb") as f:
            first_bytes = f.read(2)
            return first_bytes == b"#!"
    except Exception:
        return False


def is_text_file(filepath: Path) -> bool:
    """Heuristic check: is this file likely text (not binary)?"""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
            if b"\x00" in chunk:
                return False
            return True
    except Exception:
        return False


@dataclass
class ScanResult:
    skill_path: str
    files_scanned: int = 0
    files_flagged_unknown_ext: int = 0
    extracted_urls: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    @property
    def verdict(self) -> str:
        c = self.counts
        if c["CRITICAL"] > 0:
            return "FAIL — critical issues found"
        if c["HIGH"] > 0:
            return "WARN — high-severity issues require review"
        if c["MEDIUM"] > 0:
            return "CAUTION — medium issues found, verify intent"
        return "PASS — no significant issues detected"

    def to_dict(self):
        d = {
            "skill_path": self.skill_path,
            "verdict": self.verdict,
            "files_scanned": self.files_scanned,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
        if self.extracted_urls:
            d["extracted_urls"] = sorted(set(self.extracted_urls))
        return d


def scan_file(filepath: Path, findings: list[Finding], all_urls: list[str]):
    """Scan a single file against all rules, including two-line window for multiline rules."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return str(e)

    rel = str(filepath)
    lines = text.splitlines()

    # Extract URLs from entire file for the report
    file_urls = extract_urls(text)
    all_urls.extend(file_urls)

    # Single-line rules
    for line_num, line in enumerate(lines, start=1):
        for pattern, severity, category, description, is_multiline in RULES:
            if is_multiline:
                continue
            if pattern.search(line):
                snippet = line.strip()[:120]
                line_urls = extract_urls(line)
                findings.append(Finding(
                    severity=severity,
                    category=category,
                    message=description,
                    file=rel,
                    line=line_num,
                    snippet=snippet,
                    extracted_urls=line_urls,
                ))

    # Two-line sliding window for multiline rules (addresses review 2.1)
    for i in range(len(lines) - 1):
        combined = lines[i] + " " + lines[i + 1]
        for pattern, severity, category, description, is_multiline in RULES:
            if not is_multiline:
                continue
            if pattern.search(combined):
                snippet = (lines[i].strip() + " | " + lines[i + 1].strip())[:120]
                line_urls = extract_urls(combined)
                findings.append(Finding(
                    severity=severity,
                    category=category,
                    message=description + " (multi-line match)",
                    file=rel,
                    line=i + 1,
                    snippet=snippet,
                    extracted_urls=line_urls,
                ))

    return None


def should_scan(filepath: Path) -> tuple[bool, bool]:
    """Decide whether to scan a file. Returns (should_scan, is_unknown_ext).
    Scans by extension OR shebang presence. Flags unknown-extension text files.
    """
    ext = filepath.suffix.lower()

    # Always scan known extensions
    if ext in SCANNABLE_EXTENSIONS:
        return True, False

    # Scan files with shebangs regardless of extension (addresses review 2.3)
    if has_shebang(filepath):
        return True, True

    # For files with no extension or unknown extension, scan if they're text
    if ext == "" or ext not in SCANNABLE_EXTENSIONS:
        if is_text_file(filepath) and filepath.stat().st_size > 0:
            # Only flag/scan if it's not a trivially small file
            if filepath.stat().st_size > 50:
                return True, True

    return False, False


def structural_checks(skill_dir: Path, findings: list[Finding]):
    """Higher-level checks on skill structure and metadata."""
    skill_md = skill_dir / "SKILL.md"

    # 1. SKILL.md must exist
    if not skill_md.exists():
        findings.append(Finding(
            severity=Severity.HIGH,
            category="structure",
            message="Missing SKILL.md — every skill must have a SKILL.md file",
            file=str(skill_dir),
        ))
        return

    content = skill_md.read_text(encoding="utf-8", errors="replace")

    # 2. Check for YAML frontmatter
    if not content.startswith("---"):
        findings.append(Finding(
            severity=Severity.LOW,
            category="structure",
            message="SKILL.md lacks YAML frontmatter (---) — name and description should be declared",
            file=str(skill_md),
        ))
    else:
        fm_end = content.find("---", 3)
        if fm_end > 0:
            frontmatter = content[3:fm_end]
            if "name:" not in frontmatter:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category="structure",
                    message="Frontmatter missing 'name' field",
                    file=str(skill_md),
                ))
            if "description:" not in frontmatter:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category="structure",
                    message="Frontmatter missing 'description' field",
                    file=str(skill_md),
                ))

    # 3. Suspiciously large files
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.stat().st_size > 1_000_000:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="structure",
                message=f"Large file ({f.stat().st_size / 1_000_000:.1f} MB) — verify it's needed and not an embedded payload",
                file=str(f),
            ))

    # 4. Unexpected binary files (expanded list)
    binary_extensions = {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".com",
        ".msi", ".deb", ".rpm", ".apk", ".elf",
    }
    for f in skill_dir.rglob("*"):
        if f.suffix.lower() in binary_extensions:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="structure",
                message=f"Binary executable ({f.suffix}) in skill — binaries are difficult to audit and rarely needed",
                file=str(f),
            ))

    # 5. Hidden files / directories
    for f in skill_dir.rglob(".*"):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="structure",
            message="Hidden file/directory — may conceal malicious content",
            file=str(f),
        ))

    # 6. Files with no extension that contain executable code (addresses review 2.3)
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.suffix == "" and f.name != "SKILL.md" and f.name != "LICENSE":
            if has_shebang(f):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="structure",
                    message="Executable file with no extension (has shebang) — harder to audit, verify purpose",
                    file=str(f),
                ))


def scan_skill(skill_dir: Path) -> ScanResult:
    """Run the full scan on a skill directory."""
    result = ScanResult(skill_path=str(skill_dir))

    # Structural checks
    structural_checks(skill_dir, result.findings)

    # Scan files
    for filepath in sorted(skill_dir.rglob("*")):
        if not filepath.is_file():
            continue

        do_scan, is_unknown = should_scan(filepath)

        if is_unknown:
            result.files_flagged_unknown_ext += 1
            # Flag unknown-extension files that will be scanned
            result.findings.append(Finding(
                severity=Severity.LOW,
                category="structure",
                message=f"File with non-standard extension '{filepath.suffix or '(none)'}' — scanned due to shebang or text content",
                file=str(filepath),
            ))

        if do_scan:
            result.files_scanned += 1
            err = scan_file(filepath, result.findings, result.extracted_urls)
            if err:
                result.errors.append(f"{filepath}: {err}")

    # Sort findings: CRITICAL first
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                      Severity.LOW: 3, Severity.INFO: 4}
    result.findings.sort(key=lambda f: severity_order[f.severity])

    return result


# ─── Reporting ───────────────────────────────────────────────────────────────

COLORS = {
    "CRITICAL": "\033[1;91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[96m",
    "INFO":     "\033[90m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def print_report(result: ScanResult, use_color: bool = True):
    c = COLORS if use_color else {k: "" for k in COLORS}

    print()
    print(f"{c['BOLD']}{'=' * 70}{c['RESET']}")
    print(f"{c['BOLD']}  SKILL SECURITY AUDIT REPORT (v2){c['RESET']}")
    print(f"{c['BOLD']}{'=' * 70}{c['RESET']}")
    print(f"  Skill:          {result.skill_path}")
    print(f"  Files scanned:  {result.files_scanned}", end="")
    if result.files_flagged_unknown_ext:
        print(f" ({result.files_flagged_unknown_ext} non-standard extension)", end="")
    print()

    counts = result.counts
    verdict = result.verdict
    if "FAIL" in verdict:
        v_color = c["CRITICAL"]
    elif "WARN" in verdict:
        v_color = c["HIGH"]
    elif "CAUTION" in verdict:
        v_color = c["MEDIUM"]
    else:
        v_color = "\033[92m" if use_color else ""

    print(f"  Verdict:        {v_color}{verdict}{c['RESET']}")
    print()

    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    parts = []
    for lbl in labels:
        cnt = counts[lbl]
        if cnt > 0:
            parts.append(f"{c[lbl]}{cnt} {lbl}{c['RESET']}")
        else:
            parts.append(f"{c['DIM']}{cnt} {lbl}{c['RESET']}")
    print(f"  {' | '.join(parts)}")
    print(f"{c['BOLD']}{'-' * 70}{c['RESET']}")

    if not result.findings:
        print(f"\n  {c['BOLD']}No issues found.{c['RESET']}\n")
    else:
        categories: dict[str, list[Finding]] = {}
        for f in result.findings:
            categories.setdefault(f.category, []).append(f)

        for cat, findings in categories.items():
            print(f"\n  {c['BOLD']}[{cat.upper()}]{c['RESET']}")
            for f in findings:
                sev_c = c[f.severity.value]
                loc = f.file
                if f.line:
                    loc += f":{f.line}"
                print(f"    {sev_c}[{f.severity.value}]{c['RESET']} {f.message}")
                print(f"    {c['DIM']}|- {loc}{c['RESET']}")
                if f.snippet:
                    print(f"    {c['DIM']}   {f.snippet}{c['RESET']}")
                if f.extracted_urls:
                    for url in f.extracted_urls[:3]:
                        print(f"    {c['MEDIUM']}   URL: {url}{c['RESET']}")

    # Print extracted URLs summary
    unique_urls = sorted(set(result.extracted_urls))
    if unique_urls:
        print(f"\n  {c['BOLD']}[EXTRACTED URLS]{c['RESET']} — verify each destination is expected:")
        for url in unique_urls:
            print(f"    {c['MEDIUM']}{url}{c['RESET']}")

    if result.errors:
        print(f"\n  {c['BOLD']}[ERRORS]{c['RESET']}")
        for e in result.errors:
            print(f"    {c['HIGH']}{e}{c['RESET']}")

    print(f"\n{c['BOLD']}{'=' * 70}{c['RESET']}\n")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def find_skill_dirs(root: Path, recursive: bool) -> list[Path]:
    if (root / "SKILL.md").exists():
        return [root]

    if not recursive:
        print(f"ERROR: {root} has no SKILL.md. Use --recursive to scan subdirectories.",
              file=sys.stderr)
        sys.exit(1)

    dirs = []
    for p in sorted(root.rglob("SKILL.md")):
        dirs.append(p.parent)
    return dirs


def main():
    parser = argparse.ArgumentParser(
        description="Audit an agent skill directory for malicious behavior (v2).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("path", type=Path, help="Path to skill directory or parent directory")
    parser.add_argument("--recursive", "-r", action="store_true",
                        help="Scan all skills found under the given path")
    parser.add_argument("--output", "-o", type=Path, default=None,
                        help="Write JSON report to file")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--severity", "-s", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to display (default: LOW)")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"ERROR: Path {args.path} does not exist.", file=sys.stderr)
        sys.exit(1)

    skill_dirs = find_skill_dirs(args.path, args.recursive)
    if not skill_dirs:
        print(f"No skills found under {args.path}", file=sys.stderr)
        sys.exit(1)

    min_sev_order = {s.value: i for i, s in enumerate(Severity)}
    min_sev = min_sev_order[args.severity]

    all_results = []
    exit_code = 0

    for sd in skill_dirs:
        result = scan_skill(sd)

        result.findings = [
            f for f in result.findings
            if min_sev_order[f.severity.value] <= min_sev_order[args.severity]
               or min_sev_order[f.severity.value] <= min_sev
        ]

        print_report(result, use_color=not args.no_color)
        all_results.append(result)

        if result.counts["CRITICAL"] > 0 or result.counts["HIGH"] > 0:
            exit_code = 1

    if args.output:
        report = {
            "total_skills": len(all_results),
            "results": [r.to_dict() for r in all_results],
        }
        args.output.write_text(json.dumps(report, indent=2))
        print(f"JSON report written to {args.output}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
