# Review Rubric & Report Format

The procedure for auditing an existing YARA rule (Mode B). Read this whenever
the user pastes a rule and asks for a review, audit, critique, or hardening.
Work the checks **in order** — house-rule violations are gating and reported
first.

## Contents

- [How to Review](#how-to-review)
- [Gate 1 — House Rules (hard fail)](#gate-1--house-rules-hard-fail)
- [Gate 2 — String Quality](#gate-2--string-quality)
- [Gate 3 — Condition & Performance](#gate-3--condition--performance)
- [Gate 4 — Style & Metadata Depth](#gate-4--style--metadata-depth)
- [Severity Scale](#severity-scale)
- [Report Format](#report-format)
- [Worked Review Example](#worked-review-example)

## How to Review

1. Parse the rule into meta / strings / condition.
2. Run Gates 1–4 below, collecting findings with the exact offending
   line/string and a concrete fix for each.
3. Severity-rank findings; house-rule failures are at least HIGH.
4. Emit the structured report (format below).
5. Unless the user asked for findings only, append a **corrected rule** that
   passes every gate. If the original used imports, rewrite that logic into raw
   byte checks and call out what changed (and anything genuinely unreplicable
   without a module).

## Gate 1 — House Rules (hard fail)

Any failure here means the rule is **not acceptable** regardless of how good
the detection logic is.

- [ ] **All six meta fields present, in order:** `author`, `date`,
      `description`, `hash`, `reference`, `version`. Missing or reordered → fail.
- [ ] `description` starts with "Detects" and states what + how.
- [ ] `date` is `YYYY-MM-DD`. `hash` is a real SHA256 of the matched sample
      (not an archive hash, not fabricated). `version` is set.
- [ ] Condition **opens with both** a header check (`uintXX(0) == <magic>`)
      **and** a filesize guard (`filesize < N`). Missing either → fail; this is
      the swap-file/disk-image FP defense.
- [ ] **Zero `import` statements.** Any `import "pe"`, `"elf"`, `"math"`,
      `"hash"`, `"dotnet"`, `"crx"`, `"dex"`, `"lnk"`, `"macho"`, `"magic"`,
      etc. → fail. All structural checks must use raw `uintXX()`.

For each failure, cite the line and give the fix: insert the missing field with
the correct contract, prepend the missing guard, or rewrite the import-based
check into bytes (see `conditions-and-performance.md` cookbook and the
no-modules table in SKILL.md).

## Gate 2 — String Quality

- [ ] No API names as primary indicators (`VirtualAlloc`, `WSASocket`, …).
- [ ] No common executables / generic paths / format specifiers.
- [ ] Every string used **alone** is ≥ 6 bytes with a meaningful 4-byte atom.
- [ ] No weak/repetitive atoms (`00 00 00 00`, `90 90 90 90`) without context.
- [ ] Strings categorized by confidence (`$x` specific, `$s` grouped, `$a`
      auxiliary); FP markers as `$fp`.
- [ ] `any of` is used only over individually-unique strings (else FP flood).
- [ ] Regexes anchored to a 4+ byte literal and fully bounded (`{0,30}`, never
      `.*` / unbounded `+`).
- [ ] `nocase` / `wide` justified by confirmed variation, not speculative.
- [ ] Hex blobs annotated and wrapped at 16 bytes/line.

## Gate 3 — Condition & Performance

- [ ] Short-circuit order: filesize/header → extra byte checks → string logic →
      `not any of ($fp*)`.
- [ ] Loops bounded by filesize; no unbounded `#a` iteration over large files.
- [ ] No in-rule hashing of regions (use the bytes directly).
- [ ] `or` alternatives parenthesized and indented; newline before each
      top-level `and`.
- [ ] No reliance on entropy/imphash (module-bound; out of scope here).

## Gate 4 — Style & Metadata Depth

- [ ] Name follows `{CATEGORY}_{PLATFORM}_{FAMILY}_{DETAIL}_{MonthYear}` with
      a uniqueness suffix.
- [ ] `description` within 60–400 chars, no URLs.
- [ ] `reference` is a stable public URL or `Internal Research`; not paywalled
      / ephemeral.
- [ ] Consistent 3- or 4-space indentation; string groups blank-line-separated.
- [ ] Optional fields (`score`, `tags`, `modified`) only appear **after** the
      six required fields.

## Severity Scale

- **CRITICAL** — Will FP-flood at scale (e.g., `any of` over `"http"`/`"fetch"`;
  no header+filesize guard so it fires on every pagefile/disk image).
- **HIGH** — Any House-Rule failure (missing meta field, an `import`, missing
  guard); unanchored/unbounded regex; API-name-only detection.
- **MEDIUM** — Speculative `nocase`/`wide`; sub-6-byte string used alone; weak
  atoms without context; condition not short-circuited.
- **LOW** — Naming/format deviations; missing-but-optional metadata; hex not
  wrapped/annotated.

## Report Format

Produce findings as a severity-ranked list, each entry concrete and
line-specific:

```
## YARA Rule Review: <rule name>

**Verdict:** <PASS | NEEDS WORK | REJECT>  —  one-line summary.

### Findings

#### [SEVERITY] #1 — <short title>
- **Location:** <line / string id / "condition">
- **Problem:** <why it's wrong, specifically>
- **Fix:** <concrete change to make>

#### [SEVERITY] #2 — ...

### Summary Table
| # | Severity | Gate | Issue (one-liner)                         | Fix (one-liner)              |
|---|----------|------|-------------------------------------------|------------------------------|
| 1 | HIGH     | 1    | Missing `version` and `hash` meta fields  | Add both per contract        |
| 2 | HIGH     | 1    | No header/filesize guard in condition     | Prepend MZ + filesize<5MB    |
| 3 | CRITICAL | 2    | `any of ($s*)` over API names             | Require unique $x + tighten  |
```

Then (unless findings-only was requested):

```
### Corrected Rule
<the rewritten rule that passes all four gates>

### What Changed
- <bullet per substantive change, especially any import→bytes rewrite and any
  capability that can't be replicated import-free>
```

## Worked Review Example

**Input rule (flawed):**

```yara
import "pe"
rule emotet
{
    meta:
        description = "emotet"
    strings:
        $a = "VirtualAlloc"
        $b = "http"
    condition:
        pe.is_pe and any of them
}
```

**Key findings you would report:**

- **[HIGH] Gate 1** — Only `description` present (and it doesn't start with
  "Detects"); missing `author`, `date`, `hash`, `reference`, `version`. *Fix:*
  add all six per contract.
- **[HIGH] Gate 1** — `import "pe"` and `pe.is_pe`. *Fix:* replace with
  `uint16(0) == 0x5A4D`; drop the import.
- **[HIGH] Gate 1** — No filesize guard. *Fix:* add `filesize < N` (sized to
  Emotet); together with the MZ check this stops pagefile/disk-image FPs.
- **[CRITICAL] Gate 2** — `any of` over `"VirtualAlloc"` and `"http"`: both are
  ubiquitous; this matches a huge share of all PEs and web-touching software.
  *Fix:* replace with Emotet-specific indicators (unique mutex, C2 URI
  pattern), categorize as `$x`/`$s`, require a real combination.
- **[LOW] Gate 4** — Name `emotet` doesn't follow the convention. *Fix:*
  `MAL_Win_Emotet_<detail>_<MonthYear>`.

**Corrected rule (shape):**

```yara
rule MAL_Win_Emotet_Loader_Jun26 {
    meta:
        author      = "A. Analyst"
        date         = "2026-06-02"
        description = "Detects Emotet loader via its unique mutex and C2 URI pattern"
        hash         = "TODO-sha256-of-confirmed-sample"   // BLOCKER: supply real SHA256 before deploy
        reference   = "Internal Research"
        version     = "1.0"
    strings:
        $x1 = "Global\\<unique-emotet-mutex>" ascii wide
        $s1 = "/whoami.php" ascii
        $s2 = /\/[a-z0-9]{6,12}\/gate\.php/ ascii
    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and (
            $x1
            or all of ($s*)
        )
}
```

Note in **What Changed** that `pe.is_pe` became `uint16(0) == 0x5A4D`, the
filesize guard was added, the placeholder `hash` is a deployment blocker, and
that no module-only capability (imphash/entropy) was needed here.
