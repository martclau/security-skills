# Style Guide: Naming, Tags, Metadata, Scoring

Conventions adapted from the Neo23x0 (Florian Roth) YARA Style Guide and the
Stairwell best-practices guide, constrained by this skill's house rules. Read
this when you need the full naming vocabulary, the score table, or the rules
for optional metadata.

## Contents

- [Rule Naming](#rule-naming)
- [Indentation & Layout](#indentation--layout)
- [Metadata — Full Reference](#metadata--full-reference)
- [Score Table](#score-table)
- [Tags](#tags)

## Rule Naming

The rule name is often the only thing a responder sees first. Encode the threat
type, classification, a descriptive identifier, and a period — values ordered
**generic → specific**, separated by underscores.

```
{CATEGORY}_{PLATFORM}_{FAMILY}_{DETAIL}_{MonthYear}
```

Not every slot is required, but more-generic slots should precede more-specific
ones. The `{MonthYear}` (or a trailing `_1`, `_2`) suffix lowers the chance two
analysts pick the same name.

### Category (most generic, first)

| Prefix | Meaning |
| --- | --- |
| `MAL_` | Malware |
| `HKTL_` | Hack tool |
| `WEBSHELL_` | Web shell |
| `EXPL_` | Exploit code / PoC / payload |
| `VULN_` | Vulnerability (e.g., vulnerable driver/library) |
| `SUSP_` | Suspicious / anomalous capability |
| `PUA_` | Possibly unwanted application |
| `GEN_` | Generic detection |

Useful intent/background qualifiers that can follow the category: `APT_`,
`CRIME_`, `RANSOM_`, `ANOMALY_`.

### Platform

`Win_`, `Lnx_`, `Mac_`, `Android_`, `Multi_`. (Architecture like `X64`/`ARM`
is usually omitted unless it matters.)

### Type / technology (optional middle slots)

Malware/file types: `RAT`, `Loader`, `Stealer`, `Crypter`, `Implant`, `DRV`
(driver). Technologies: `PS1`, `VBS`, `JS`, `BAT`, `NET`, `GO`, `Rust`, `PHP`,
`JSP`, `ASP`, `MalDoc`, `LNK`, `ZIP`, `RAR`. Modifiers: `OBFUSC`, `Encoded`,
`Unpacked`, `InMemory`. Packers: `UPX`, `Themida`, `NSIS`, `SFX`.

### Threat / actor identifiers

Family or actor names slot in as the specific identifier: `CobaltStrike`,
`PlugX`, `QakBot`, `Emotet`; `APT28`, `Lazarus`, `UNC4736`.

### Suffix for uniqueness (most specific, last)

`MonthYear` (`Jun26`, `Jan26`) or a number (`_1`, `_2`).

### Worked examples

- `MAL_Win_Emotet_Loader_Jan26` — Emotet loader (PE/Windows), Jan 2026.
- `MAL_CRIME_RANSOM_Lnx_Rust_Locker_May26` — Rust Linux ransomware locker.
- `WEBSHELL_PHP_ChinaChopper_Mar26` — PHP China Chopper web shell.
- `SUSP_Lnx_Anomaly_HugeELF_Jun26` — suspiciously large ELF.
- `HKTL_Win_Mimikatz_CredDump_Feb26` — Mimikatz credential dump tool.

## Indentation & Layout

Use consistent indentation (3 or 4 spaces) for every block. Group strings by
their `$x`/`$s`/`$a`/`$fp` category with a blank line between groups. In the
condition, place a newline before each top-level `and`, and indent `or` blocks
inside parentheses. (Concrete condition examples are in
`conditions-and-performance.md`.)

DO:

```yara
rule MAL_Win_Example_Loader_Jun26 {
    meta:
        author      = "A. Analyst"
        date         = "2026-06-02"
        description = "Detects Example loader via unique mutex and C2 URI"
        hash         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        reference   = "Internal Research"
        version     = "1.0"
    strings:
        $x1 = "Global\\ExampleLoaderMtx_v3" ascii wide

        $s1 = "/gate.php?id=" ascii
        $s2 = "loader_cfg_blob" ascii
    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and (
            $x1
            or all of ($s*)
        )
}
```

## Metadata — Full Reference

This skill **requires six** fields (see SKILL.md): `author`, `date`,
`description`, `hash`, `reference`, `version`. The upstream Neo23x0 guide
treats only the first four as mandatory and `hash`/`version` as optional — this
skill promotes them to required. Below is the full contract plus the optional
fields you may add **after** the six.

### Required (house rules)

- **author** — String. Full name or handle; comma-separate multiples. No URLs.
- **date** — String, `YYYY-MM-DD`. Original creation date only. Edits bump
  `version` (and may add `modified`); they do not change `date`.
- **description** — String, 60–400 chars, starts with "Detects". No URLs.
- **hash** — String. SHA256 (preferred) of the matched sample — not an archive
  hash; for memory-only rules, the in-memory form's hash. Repeat the field or
  list values for multiple samples. Never fabricate one.
- **reference** — String. Public, stable URL, or exactly `Internal Research`.
  Avoid paywalled/ephemeral links.
- **version** — String. Start `1.0`; bump on any logic change.

### Optional (only in addition to the six)

- **modified** — `YYYY-MM-DD` of the last edit.
- **score** — Integer 0–100; see the table below.
- **tags** — Comma-separated string of extra classifiers.
- **old_rule_name** — Previous name, so searches by the old name still hit.
- **license** — License under which the rule is released.

## Score Table

`score` (optional) blends severity (how bad the threat) and specificity (how
uniquely the rule pins it). Higher = prioritize the match.

| Range | Level | Examples |
| --- | --- | --- |
| 0–39 | Very low | Capabilities, packers (often combined to reach a higher total) |
| 40–59 | Noteworthy | Uncommon/malware-favored packers, PE header anomalies |
| 60–79 | Suspicious | Heuristics, obfuscation rules, generic detections |
| 80–100 | High | Direct, high-accuracy matches on malware / hack tools |

## Tags

Prefer encoding the main category in the rule **name**. Use rule-level tags
(`rule NAME : tag1 tag2`) or a `tags` meta field for secondary classifiers that
don't belong in the name — actor names, family names, attack types. Keep the
name concise; push the long tail into `tags`.
