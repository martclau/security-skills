---
name: yara-rule-authoring-review
description: >
  Author and review high-quality, import-free YARA detection rules that catch
  malware without drowning in false positives. Use whenever the user wants to
  write, create, review, audit, critique, harden, fix, or optimize a YARA rule
  or ruleset; convert IOCs, threat intel, hashes, or a malware analysis into a
  signature; debug false positives; or check a rule against a style guide.
  Trigger on mentions of YARA, YARA-X, "detection rule", "signature", "hunt
  rule", ".yar", ".yara", malware family detection, or any request that pastes
  a YARA rule and asks "is this good?", "review this", or "make this tighter".
  Trigger even when the user just pastes strings, hashes, or a sample
  description and asks for "a rule to detect this". Enforces a strict house
  style: six required meta fields (author, date, description, hash, reference,
  version), a mandatory file-header + filesize guard on every rule to avoid
  false positives on swap files and disk images, and NO module imports —
  detection uses raw uint8/uint16/uint32 checks only.
---

# YARA Rule Authoring & Review

Write detection rules that catch malware without drowning in false positives,
and review existing rules against a consistent, opinionated house style.

This skill synthesizes guidance from the Trail of Bits YARA-X authoring skill,
the Stairwell YARA best-practices guide, and the Neo23x0 (Florian Roth) YARA
Style Guide — then layers four **non-negotiable house rules** on top (see
below). Where the upstream sources disagree with the house rules, the house
rules win.

## House Rules (non-negotiable)

These four constraints apply to **every** rule this skill produces or approves.
They are stricter than the upstream guides on purpose. A rule that violates any
of them is not done.

1. **All six meta fields are required**, in this order: `author`, `date`,
   `description`, `hash`, `reference`, `version`. None may be omitted, even for
   hunting or internal rules. See [Required Metadata](#required-metadata) for
   the exact contract and what to do when a value is genuinely unknown.

2. **Every rule begins its condition with a header check AND a filesize
   guard.** This is the single highest-leverage false-positive defense. Without
   it, rules fire on swap files, hibernation files, memory dumps, raw disk
   images, and forensic captures — anywhere the target bytes happen to appear
   embedded in a much larger blob. The header check pins the match to a real
   file of the right type; the filesize ceiling rejects giant containers. See
   [The Mandatory Header + Filesize Guard](#the-mandatory-header--filesize-guard).

3. **No `import` statements. Ever.** No `pe`, `elf`, `macho`, `math`, `hash`,
   `dotnet`, `crx`, `dex`, `lnk`, `magic`, or any other module. All structural
   and magic-byte checks use raw `uint8()`, `uint16()`, `uint32()`,
   `uint8be()`, `uint16be()`, `uint32be()` reads at fixed offsets. This keeps
   rules portable across every YARA/YARA-X deployment and scanning backend
   (many of which disable or sandbox modules), removes module-version
   dependencies, and forces tighter, byte-level thinking. See
   [Working Without Modules](#working-without-modules) for import-free
   replacements for the most common module idioms — including how to do
   signed-binary and section checks without `pe`.

4. **Strings must be specific enough to survive a goodware corpus.** No API
   names, no common paths, no format specifiers, nothing under 6 bytes used
   alone. This is the core authoring discipline; the house rules above are
   guard rails around it, not a substitute for it.

## When to Use

- Writing a new YARA rule from samples, IOCs, hashes, or a threat report
- Reviewing or auditing an existing rule or ruleset for quality, FP risk, or
  style-guide conformance
- Tightening a rule that fires on goodware or on swap/dump/disk-image artifacts
- Converting strings, hex, or a malware description into a detection signature
- Migrating a legacy rule into this skill's import-free house style
- Preparing rules for production deployment with a consistent metadata contract

## When NOT to Use

- Static analysis requiring disassembly → use Ghidra/IDA workflows
- Dynamic/sandbox malware analysis → use sandbox skills
- Network detection (PCAP, flow) → use Suricata/Snort skills
- Memory forensics carving → use Volatility workflows
- Pure hash-blocklist detection → just ship a hash list; YARA is overkill

## The Two Modes

This skill operates in one of two modes. Decide which the user wants, then
follow the matching workflow.

### Mode A — Authoring (write a new rule)

Follow this loop. Detailed per-step guidance lives in the reference files; the
loop itself is below.

1. **Establish the target.** What family/tool/technique, and on what file type?
   "Detects ransomware" is a non-target. "Detects LockBit 3.0 config
   extraction" is a target. If the user is vague, ask one focused question
   (family? platform? what samples/IOCs do you have?) rather than guessing.

2. **Gather and triage indicators.** Collect candidate strings, hex sequences,
   and hashes from the user's samples, report, or IOC list. Check whether the
   sample is likely packed (high entropy, few readable strings) — if so, target
   the unpacked payload or the packer, not the packed layer. See
   `references/strings.md`.

3. **Select strings that survive goodware.** Apply the string decision tree.
   Prefer mutex names, C2 paths, PDB paths, config markers, stack strings.
   Reject API names, common executables, and anything < 6 bytes used alone.
   Categorize with the `$x` / `$s` / `$a` / `$fp` triad. See
   `references/strings.md`.

4. **Build the condition in short-circuit order.** Header check → filesize
   guard → cheap byte checks → string logic → FP filters. The header +
   filesize guard is mandatory (House Rule 2). See
   `references/conditions-and-performance.md`.

5. **Fill in all six meta fields.** No exceptions (House Rule 1). See
   [Required Metadata](#required-metadata).

6. **Lint, format, and self-review.** Run `yr check` and `yr fmt` if YARA-X is
   available. Then walk the [Quality Checklist](#quality-checklist) and the
   review rubric in `references/review-rubric.md` against your own rule.

7. **Validate against goodware before declaring done.** A rule untested against
   clean files is a draft, not a detection. State this to the user even if you
   can't run the corpus yourself, and tell them how (see
   `references/testing.md`).

Use the template at `assets/rule_template.yar` as the starting skeleton — it
already encodes the house rules.

### Mode B — Review (audit an existing rule)

When the user pastes a rule and asks for review/audit/critique/hardening:

1. **Parse the rule** into its parts (meta, strings, condition).
2. **Run the full review rubric** in `references/review-rubric.md`. It checks
   house-rule compliance first (all six meta fields, header+filesize guard, no
   imports), then string quality, condition order, FP risk, and style.
3. **Report findings as a structured list**, severity-ranked, each with the
   specific line/string at fault and a concrete fix — not vague advice. Use the
   report format in `references/review-rubric.md`.
4. **Offer a corrected version** of the rule that satisfies every house rule,
   unless the user only asked for findings. If the original used imports,
   rewrite the import-dependent logic into raw byte checks (House Rule 3) and
   call out exactly what changed and any capability that genuinely can't be
   replicated without a module.

## Required Metadata

Every rule MUST carry these six fields, in this order. This is stricter than
the upstream guides (which require only four) because consistent, complete
metadata is what makes a ruleset auditable and shareable at scale.

```yara
meta:
    author      = "Name / Handle / Org"          // who wrote it; full name or handle, no URLs
    date         = "2026-06-02"                    // YYYY-MM-DD, original creation date
    description = "Detects ..."                    // starts with "Detects", 60-400 chars, no URLs
    hash         = "<sha256 of the matched sample>" // SHA256 preferred; the file the rule matches
    reference   = "https://... or Internal Research" // public stable URL, or "Internal Research"
    version     = "1.0"                            // semantic-ish; bump on edits
```

**Field contracts:**

- **author** — Full name, handle, or org. Comma-separate multiple authors.
  Never a URL.
- **date** — `YYYY-MM-DD`. The *creation* date, not the publication or edit
  date. If you later edit the rule, bump `version` (and you may add an optional
  `modified` field); do not change `date`.
- **description** — Starts with the word "Detects". Aim for 60–400 characters.
  Say *what* it catches and *how* (e.g., "Detects FooLoader via its unique
  mutex and hardcoded C2 path"). No URLs in the description.
- **hash** — A SHA256 (preferred) of the actual sample the rule matches. Not
  the hash of an archive the sample came in. For memory-only rules, use the
  hash of the in-memory/unpacked form. If you have several, you may repeat the
  field or list them; at least one real hash is required.
- **reference** — A public, stable URL to the analysis/report, or the exact
  string `Internal Research` when the rule comes from your own work. Avoid
  paywalled or ephemeral links.
- **version** — Start at `1.0`. Bump it whenever the rule logic changes. This
  makes ruleset diffs and rollbacks legible.

**When a value is genuinely unknown:** do not silently drop the field — that
breaks House Rule 1 and downstream tooling that expects all six. Instead:

- No public report → `reference = "Internal Research"`.
- No sample hash in hand → tell the user the field is mandatory and ask them to
  supply the SHA256 of a confirmed sample; use a clearly-marked placeholder
  like `hash = "TODO-sha256-of-confirmed-sample"` and flag it as a blocker for
  deployment. Never invent a plausible-looking hash.
- Unknown author → ask. Attribution matters; don't fabricate it.

Optional fields you may add *after* the six (never instead of them): `modified`,
`score` (0–100, see `references/style-guide.md`), `tags`, `old_rule_name`,
`license`.

## The Mandatory Header + Filesize Guard

Every condition starts with both a header check and a filesize ceiling. This is
House Rule 2 and the highest-value FP defense in the whole skill.

**Why both, always:**

- **The header check** pins the match to a real file of the expected type at
  offset 0. Malware strings frequently appear *embedded* inside unrelated large
  blobs — pagefile.sys, hiberfil.sys, crash dumps, VM memory snapshots, raw
  `.dd`/`.E01` disk images, backup archives. Without a header anchor, your rule
  fires on the haystack, not the needle.
- **The filesize ceiling** rejects those giant containers outright and is
  nearly free to evaluate, so it belongs first for short-circuiting. Swap and
  hibernation files and disk images are enormous; a sane ceiling (sized to the
  real malware plus headroom) excludes them before any string scan runs.

Together they are the difference between a rule that flags an infected
workstation's pagefile a thousand times and one that flags the actual malware.

**Import-free header checks** (House Rule 3 — raw bytes only):

```yara
// Windows PE ("MZ")
uint16(0) == 0x5A4D

// ELF ("\x7fELF")
uint32(0) == 0x464C457F

// Mach-O (cover the slices you mean to; don't blanket all of them blindly)
//   0xFEEDFACE 32-bit, 0xFEEDFACF 64-bit, 0xCAFEBABE/0xBEBAFECA universal/fat
uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF
    or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA

// ZIP / Office OOXML / JAR / APK ("PK\x03\x04")
uint32(0) == 0x04034B50

// PDF ("%PDF")
uint32(0) == 0x46445025

// For PE specifically, you can also confirm the PE signature via the e_lfanew
// pointer without the pe module:
uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550   // "PE\0\0"
```

**Filesize guard** — pick a ceiling sized to the malware, not a round number
for its own sake. Use underscores (YARA-X) for readability:

```yara
filesize < 2MB              // a small loader
filesize < 10_000_000       // ~10 MB, a larger sample
```

**Canonical opening of every condition:**

```yara
condition:
    uint16(0) == 0x5A4D       // PE header — anchor to a real PE
    and filesize < 5MB        // reject swap files, dumps, disk images
    and ( /* string logic */ )
    and not any of ($fp*)
```

For file types with no reliable magic (loose JavaScript, many scripts), you
cannot anchor on a header. In that case **the filesize guard is still
mandatory**, and you must compensate for the missing header with an
extra-tight, structure-bearing anchor string (a distinctive token that only
appears in the target) plus a deliberately low filesize ceiling. Note this
explicitly in a comment so a reviewer understands why there is no magic check.

## Working Without Modules

House Rule 3 forbids all imports. Most module idioms have a raw-bytes
equivalent. Use these; if something truly cannot be done without a module, say
so plainly rather than importing.

| You might reach for… | Import-free replacement |
| --- | --- |
| `pe.is_pe` / `uint16(0)==0x5A4D` via module | `uint16(0) == 0x5A4D` (and optionally the `PE\0\0` check above) |
| `elf.type == elf.ET_EXEC` | `uint32(0) == 0x464C457F` plus an offset check on `e_type` (`uint16(16)`) if you need exec/dyn |
| `math.entropy(...)` for packed detection | You can't compute entropy without the module. Instead detect the *packer's* byte signatures, or target the unpacked payload's strings. Don't import `math`. |
| `hash.md5(...)` over a region | Don't hash in-rule (slow and import-bound). Put the exact bytes you'd have hashed directly as a hex string — faster and import-free (this is the Neo23x0 "String Matching FTW" tweak). |
| `pe.imphash()` clustering | Not replicable without the module. If imphash is the only signal you have, this skill isn't the right tool — note that to the user. Otherwise pivot to unique strings/section-name bytes. |
| `pe.number_of_signatures == 0` (skip signed files) | No import-free equivalent reads the Authenticode table cleanly. Reduce goodware FPs instead via (a) a tight filesize band, (b) more specific strings, and (c) optionally a `$fp*` string matching the legitimate vendor/signer name you keep colliding with. See FP guidance in `references/review-rubric.md`. |
| `pe` section name/size checks | Read section-name bytes at their file offset with `uintXX()` if you must, but prefer unique payload strings — section layouts drift across builds. |
| `crx` / `dex` / `lnk` structure parsing | Parse the few bytes you need with `uintXX()` at fixed offsets, or anchor on unique strings within the format. Accept that deep structural parsing is out of scope for an import-free rule. |

The cost of no-imports is real (no entropy, no imphash, no clean
signed-file filter). The payoff is portability and tighter byte-level rules.
When that trade genuinely blocks a detection, tell the user instead of quietly
importing a module.

## Rationalizations to Reject

When you catch yourself thinking one of these, stop.

| Rationalization | Correct response |
| --- | --- |
| "This rule is just for hunting, it can skip a meta field." | House Rule 1 has no hunting exemption. Fill all six. |
| "The filesize guard is obvious, I'll leave it off." | Then it fires on the victim's pagefile. Add it. |
| "I'll just import `pe` for one `is_pe` check." | `uint16(0)==0x5A4D` does it import-free. No imports. |
| "I need `math.entropy` to catch this packer." | Detect the packer's bytes or the unpacked payload. No `math` import. |
| "This generic string is unique enough." | Test against goodware. Your intuition is usually wrong. |
| "yarGen handed me these strings." | yarGen suggests; you validate every one by hand. |
| "It matches my 10 samples, ship it." | 10 samples ≠ production. Validate against a goodware corpus. |
| "One rule for all variants." | Causes FP floods. Target a specific family. |
| "I'll tighten it later if FPs show up." | FPs burn trust on day one. Write it tight now. |
| "The API name makes it malicious." | Legit software calls the same APIs. Need behavioral context. |
| "`any of them` is fine for these common strings." | Common + `any` = FP flood. `any of` is only for individually-unique strings. |
| "I'll leave the regex unanchored for flexibility." | Unanchored regex scans every byte of every file. Anchor to a 4+ byte literal or use hex. |
| "I'll add `nocase`/`wide` just in case." | Only with confirmed evidence the case/encoding varies. Both have real costs. |

## Quick Reference

### Naming Convention

```
{CATEGORY}_{PLATFORM}_{FAMILY}_{DETAIL}_{MonthYear}
```

Values run generic → specific, separated by `_`.

- **Categories:** `MAL_` (malware), `HKTL_` (hacktool), `WEBSHELL_`, `EXPL_`
  (exploit), `VULN_`, `SUSP_` (suspicious), `PUA_`, `GEN_` (generic).
- **Platforms:** `Win_`, `Lnx_`, `Mac_`, `Android_`, `Multi_`.
- **Examples:** `MAL_Win_Emotet_Loader_Jan26`,
  `SUSP_Lnx_Anomaly_HugeELF_Jun26`, `WEBSHELL_PHP_ChinaChopper_Mar26`.

Full conventions, tag vocabulary, and the score table live in
`references/style-guide.md`.

### String Selection (one-liner)

**Good:** mutex names, PDB paths, C2 paths/URIs, config markers, stack strings,
unique error messages. **Bad:** API names, common executables (`cmd.exe`),
format specifiers (`%s`), generic paths (`C:\Windows\`), anything < 6 bytes
used alone. Full decision tree: `references/strings.md`.

### Condition Order (short-circuit)

1. **Header check** — `uint16(0) == 0x5A4D` (mandatory)
2. **Filesize guard** — `filesize < 5MB` (mandatory; put first when you want
   the absolute cheapest check leading — both are near-instant, so lead with
   filesize and follow immediately with the header, or vice-versa, but include
   *both*)
3. **Cheap byte checks** — additional `uintXX()` offsets
4. **String logic** — `$x` / `$s` groupings
5. **FP filters** — `and not any of ($fp*)`

Details and indentation rules: `references/conditions-and-performance.md`.

### String Categorization Triad (+ FP)

- `$x*` — highly specific; one alone is strong evidence.
- `$s*` — grouped; meaningful only in combination.
- `$a*` — pre-selection/auxiliary; narrows file type, not a threat signal.
- `$fp*` — benign markers; if matched, suppress the rule.

## Quality Checklist

Before declaring any rule done (authoring) or approved (review):

**House rules (hard gate — fail any and the rule is not done):**
- [ ] All six meta fields present and in order: author, date, description,
      hash, reference, version
- [ ] `description` starts with "Detects" and explains what/how
- [ ] `date` is `YYYY-MM-DD`; `hash` is a real SHA256 (no fabricated value);
      `version` set
- [ ] Condition opens with a header check **and** a filesize guard
- [ ] Zero `import` statements; all structural checks use raw `uintXX()`

**Quality:**
- [ ] Name follows `{CATEGORY}_{PLATFORM}_{FAMILY}_{DETAIL}_{MonthYear}`
- [ ] Strings are unique (no API names, common paths, format strings)
- [ ] Every string used alone is ≥ 6 bytes with good atom potential
- [ ] Regexes are anchored to a 4+ byte literal and bounded (`{0,30}`, not `.*`)
- [ ] `nocase`/`wide` used only with confirmed evidence of variation
- [ ] Strings categorized via `$x`/`$s`/`$a`, FP markers via `$fp`
- [ ] Condition short-circuits: filesize/header → bytes → strings → FP filters

**Validation:**
- [ ] `yr check` passes with no errors (if YARA-X available)
- [ ] `yr fmt --check` passes (consistent formatting)
- [ ] Rule matches all intended samples
- [ ] Rule produces zero matches on a goodware corpus (or this is flagged as
      the outstanding pre-deployment step)

## Reference Documents

| Topic | Document |
| --- | --- |
| Naming, tags, metadata depth, score table | `references/style-guide.md` |
| String types, decision trees, triad, packing | `references/strings.md` |
| Condition order, atoms, regex anchoring, indentation | `references/conditions-and-performance.md` |
| Goodware validation & FP debugging workflow | `references/testing.md` |
| Full review rubric & structured report format | `references/review-rubric.md` |

## Assets

| File | Purpose |
| --- | --- |
| `assets/rule_template.yar` | Starting skeleton encoding all four house rules |

## Tooling Notes (YARA-X)

If YARA-X (`yr`) is available, use it — it powers VirusTotal's production
systems and gives precise error locations.

- `yr check rule.yar` — validate syntax with exact source locations
- `yr fmt -w rule.yar` — standardize formatting before sharing
- `yr scan -s rule.yar <path>` — scan and show which strings matched (key for
  FP debugging)

This skill's rules are import-free by design, so module-dump tooling
(`yr dump -m pe`) is intentionally not part of the workflow.
