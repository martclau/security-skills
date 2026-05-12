---
name: find-vulns
description: >
  Scan source code files for security vulnerabilities, rank them by severity,
  and produce a structured report with CWE IDs, root causes, proof-of-concept
  triggers, and suggested fixes. Use this skill whenever the user asks to
  "find vulnerabilities", "audit code for security", "do a security review",
  "check for buffer overflows", "look for bugs in this C code", "CTF challenge",
  "pen-test this source", or any variation of scanning source files for
  security issues — even if they don't use the word "vulnerability" explicitly.
  Also trigger when the user uploads a C/C++/Rust/Go/Python/JS file and asks
  for a "review" or "audit" in a security context.
---

# Vulnerability Scanner

Analyze source code for security vulnerabilities and produce a structured,
severity-ranked report.

## When to use

- User uploads or references a source file and asks for a security review
- User mentions CTF, vulnerability hunting, security audit, pen-test, or code hardening
- User asks about specific vulnerability classes (buffer overflows, integer overflows,
  use-after-free, format strings, injection, etc.) in the context of a real file

## Workflow

### 1. Identify the target

Determine which file(s) to scan. If the user uploaded files, find them in
`/mnt/user-data/uploads/`. If they reference a filename, locate it. If multiple
files are involved, scan each one individually and cross-reference shared
vulnerabilities (e.g., a library function misused by multiple callers).

### 2. Read and understand the code

Read the full source file. Before looking for bugs, build a mental model:
- What does this code do? (parser, network handler, crypto, etc.)
- What are the trust boundaries? (user input, network data, file I/O)
- Which functions handle untrusted data?

### 3. Hunt for vulnerabilities

Systematically check for these categories (not exhaustive — adapt to the language):

**Memory safety** (C/C++):
buffer overflows, heap overflows, stack overflows, use-after-free,
double-free, uninitialized memory, off-by-one errors

**Integer issues**:
integer overflow/underflow, sign confusion, truncation,
unsafe casts, unchecked arithmetic

**Input validation**:
format string bugs, injection (SQL, command, LDAP, XPath),
path traversal, null byte injection, TOCTOU race conditions

**Logic / design**:
missing authentication or authorization checks, insecure defaults,
hardcoded credentials, information leakage, missing error handling,
unchecked return values (especially malloc, read, write)

**Concurrency**:
race conditions, non-reentrant functions with static buffers,
missing locks, deadlocks, signal handler issues

**Language-specific** (Python, JS, Go, Rust, etc.):
deserialization attacks, prototype pollution, unsafe blocks,
regex DoS, timing side-channels

### 4. Rank by severity

Use this scale:
- **CRITICAL** — Remote code execution, arbitrary memory write, auth bypass
- **HIGH** — Denial of service, significant information leak, privilege escalation
- **MEDIUM** — Requires unusual input or specific conditions to trigger
- **LOW** — Theoretical, defense-in-depth issues, non-reentrant static buffers

### 5. Write the report

Produce a report with this structure for **each** vulnerability:

```
## [SEVERITY] #N — Short title

- **Type:** e.g., Buffer Overflow
- **CWE:** CWE-XXX
- **Function:** function_name (file:line)
- **Root cause:** Clear explanation of why the bug exists
- **Trigger:** How to reach/exploit it (PoC input if applicable)
- **Fix:** Concrete suggested remediation
```

End with a **Summary table** sorted by severity:

```
| # | Severity | CWE     | Function          | Issue (one-liner)          |
|---|----------|---------|-------------------|----------------------------|
| 1 | CRITICAL | CWE-787 | asn_read_oid:487  | Static buffer overflow     |
```

### 6. Save the report

- Write the report to the path requested by the user, or default to
  `vuln-report-<filename>.txt` in the working directory.
- If the user is in a chat context (Claude.ai), present the report inline
  and also save it as a downloadable file.

## Standalone CLI usage

This skill bundles a shell script for use with Claude Code CLI in headless
(non-interactive) mode. The script lives at `scripts/find-vulns.sh`.

```bash
# Basic usage
./find-vulns.sh <source-file> [output-file]

# Examples
./find-vulns.sh uasn1.c
./find-vulns.sh src/parser.c /tmp/vulns.txt
```

The script handles:
- Input validation and dependency checks (`claude` CLI, `jq`)
- Tool pre-approval (`--allowedTools "Read,Write,Edit"`) so the headless
  run doesn't stall on permission prompts
- Real-time streaming progress via `--output-format stream-json --verbose`
  piped through `jq`
- Post-run verification that the report file was actually created

Read `scripts/find-vulns.sh` if you need to see or adapt the CLI invocation.
