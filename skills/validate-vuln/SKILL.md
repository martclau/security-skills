---
name: validate-vuln
description: >
  Validate an inbound vulnerability report by verifying whether each finding
  is actually exploitable. Traces call graphs, checks trust boundaries,
  examines attacker reachability, and produces an honest exploitability
  assessment. Use this skill when the user says "validate this vuln report",
  "is this exploitable", "verify these findings", "triage this vulnerability
  report", "check if this bug is real", or provides a .vuln.md file for review.
---

# Vulnerability Report Validator

Critically assess an inbound vulnerability report to determine which findings
are actually exploitable versus theoretical, overstated, or false positives.

## When to use

- User receives a vulnerability report and wants to know what is real
- User provides a `*.vuln.md` file or vulnerability report for triage
- User asks "is this actually exploitable?", "validate these findings",
  "triage this report", or "which of these bugs matter?"

## Inputs

The report file is identified from the user's message. Common patterns:
- Explicit path: the user names a file directly
- Convention: `${FILE}.vuln.md` where `${FILE}` is the source file analyzed
- Upload: check `/mnt/user-data/uploads/` for recently added files

The report should reference specific source files, functions, and line numbers.
If it does not, note this as a quality gap in the assessment.

## Workflow

### 1. Read the vulnerability report

Read the full report. For each finding, extract:
- The claimed vulnerability type and severity
- The affected function and file/line
- The claimed root cause and trigger

### 2. Read the source code under analysis

Read every source file referenced by the report. Build a mental model of the
code before assessing individual findings. Understand:
- What the code does (parser, network handler, crypto, serializer, etc.)
- The trust boundaries (what data is attacker-controlled vs internal)
- The overall architecture and data flow

### 3. Verify each finding — the three-gate test

For each reported vulnerability, answer these three questions in order.
A finding must pass ALL three gates to be considered exploitable.

**Gate 1: Is the bug real?**
Read the exact lines cited. Confirm the code pattern described actually exists.
Check that the report has not misread types, misunderstood API contracts, or
confused compile-time vs runtime behavior. Compare against language specs,
library documentation, and header definitions.

- Reject if: the cited code does not exist, the types are different than
  claimed, the API guarantees behavior the report assumes is missing, or
  the pattern is idiomatic/correct usage.

**Gate 2: Is it reachable by an attacker?**
Trace the call graph from untrusted input to the vulnerable code. Determine:
- Who calls the affected function?
- What data reaches it, and is any of it attacker-controlled?
- Are there intervening checks that sanitize, validate, encrypt/HMAC-verify,
  or bound the data before it arrives?
- Does the vulnerable path require authentication, specific privileges, or
  possession of secrets (e.g., encryption keys)?

Use `Grep` and `Read` to follow the call chain. Do not assume reachability —
prove it by finding the actual call path from an entry point an attacker
controls (network input, file input, API parameter, environment variable).

- Reject if: no attacker-controlled data reaches the vulnerable code, or
  intervening security controls (HMAC, encryption, bounds checks, auth)
  prevent crafted input from arriving.

**Gate 3: Is the impact real?**
If the bug is real and reachable, assess actual impact:
- What does the attacker gain? (code execution, info leak, DoS, data
  corruption, privilege escalation, or nothing useful?)
- Are there mitigations that limit impact? (ASLR, stack canaries, sandboxing,
  allocator hardening, type constraints that limit the corruption range)
- For integer issues: does the truncated/overflowed value actually influence
  a security-relevant decision, buffer size, or memory operation?
- For missing bounds checks: what is the realistic maximum size, and does
  exceeding it lead to exploitable behavior or just a slightly large allocation?

- Reject if: the impact is purely theoretical, requires conditions that
  cannot arise in practice, or the "corruption" doesn't influence any
  security-relevant code path.

### 4. Classify each finding

Assign each finding one of these verdicts:

- **CONFIRMED EXPLOITABLE** — Bug is real, attacker-reachable, and has
  meaningful security impact. State the attack scenario.
- **CONFIRMED BUG, NOT EXPLOITABLE** — The code defect exists but cannot be
  reached by an attacker, or the impact is neutralized by other controls.
  Explain why. May still warrant a fix for code quality / defense-in-depth.
- **FALSE POSITIVE** — The reported issue is not actually a bug. The code
  is correct, the report misread the types/API, or the pattern is safe.
  Cite the specific evidence.
- **INSUFFICIENT EVIDENCE** — Cannot confirm or deny without access to
  additional code, configuration, or runtime context. State what is missing.

### 5. Assess report quality

After evaluating all findings, comment on the report's overall quality:
- Did it analyze call graphs and trust boundaries, or just pattern-match?
- Were severity ratings calibrated or inflated?
- Were there real issues the report missed? (If you spot something during
  your review, note it.)
- Did the report distinguish between attacker-reachable and internal-only
  code paths?

### 6. Write the validation report

Produce a structured output with this format:

```
# Vulnerability Report Validation
## Source report: <filename>
## Target code: <file(s) analyzed>

### Finding #N: <original title>
- **Original severity:** <what the report claimed>
- **Verdict:** CONFIRMED EXPLOITABLE | CONFIRMED BUG, NOT EXPLOITABLE |
  FALSE POSITIVE | INSUFFICIENT EVIDENCE
- **Adjusted severity:** <your assessment, or N/A if false positive>
- **Gate 1 (bug real?):** <yes/no + evidence>
- **Gate 2 (attacker-reachable?):** <yes/no + call graph evidence>
- **Gate 3 (impact real?):** <yes/no + impact analysis>
- **Rationale:** <concise explanation>

...repeat for each finding...

## Summary

| # | Original Severity | Verdict | Adjusted Severity | One-liner |
|---|-------------------|---------|-------------------|-----------|

## Report Quality Assessment
<paragraph on the strengths and weaknesses of the original report>
```

Save the validation report to `${REPORT_FILE%.vuln.md}.validation.md`, or
if the input file doesn't follow the `.vuln.md` convention, save to
`validation-<basename>.md` in the working directory.

## Key principles

- **Be honest, not adversarial.** The goal is accurate triage, not dunking
  on the reporter. Acknowledge real bugs even if they aren't exploitable.
- **Prove, don't assume.** Every reachability claim must be backed by a
  specific call chain you actually traced in the code.
- **Context matters.** A bug in a function only called with trusted internal
  data is fundamentally different from the same bug on a network parsing path.
- **Severity should reflect exploitability.** A type confusion that can never
  be triggered is not MEDIUM — it's a code quality note. Adjust accordingly.
- **Check for missed findings.** While validating, you may spot issues the
  original report missed. Include these as addenda.
