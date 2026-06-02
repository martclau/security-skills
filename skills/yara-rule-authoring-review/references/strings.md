# Strings: Selection, Decision Trees, and Categorization

The single most important factor in a rule's quality and speed is string
choice. "You can't use well-formed conditions to make up for poorly chosen
strings." — Wesley Shields. Read this when selecting or reviewing strings.

## Contents

- [The Atom Principle](#the-atom-principle)
- [Is This String Good Enough?](#is-this-string-good-enough)
- [Good vs Bad Strings](#good-vs-bad-strings)
- [Hex vs Text vs Regex](#hex-vs-text-vs-regex)
- [The Categorization Triad](#the-categorization-triad-x--s--a)
- [False-Positive Markers](#false-positive-markers-fp)
- [all of vs any of](#all-of-vs-any-of)
- [Is the Sample Packed?](#is-the-sample-packed-check-first)
- [When Strings Fail](#when-strings-fail)
- [Platform String Hints](#platform-string-hints)

## The Atom Principle

YARA extracts short substrings (atoms, up to 4 bytes) from each string and
scans files for those atoms first; only where an atom hits does it verify the
full pattern. Consequences:

- Strings under 4 bytes — and weak/ repetitive atoms like `00 00 00 00` or
  `90 90 90 90` — force slow verification on far too many files.
- **Stairwell's stricter floor: treat 6 bytes as the practical minimum** for a
  string used on its own. `"FNoC"` looks unique but collides inside base64
  blobs; `"FNoC3haB"` does not.
- A regex with no fixed literal substring has **no atom** and is evaluated at
  every offset of every file — a performance catastrophe. Always give a regex a
  concrete anchor (see below).

## Is This String Good Enough?

```
Is this string good enough?
├─ Under ~6 bytes (used alone)?        → NO. Find a longer one or combine.
├─ Repeated/low-entropy bytes (0000, 9090)? → NO. Add surrounding context.
├─ An API name (VirtualAlloc, CreateRemoteThread)? → NO. Use hex of the call site + a unique marker.
├─ Appears in Windows/macOS/Linux system files? → NO. Too generic.
├─ A common path (C:\Windows\, /usr/bin, cmd.exe)? → NO. Find a malware-specific path.
├─ Unique to this family?              → YES. Use it (likely an $x).
└─ Shared with other malware too?      → MAYBE. Combine with a family-specific marker ($s group).
```

## Good vs Bad Strings

**Gold/Silver/Bronze (use these):**
- **Mutex names** — gold. Often globally unique to a family.
- **C2 paths / URIs / webhook URLs** — silver.
- **PDB paths** — strong; developer-specific.
- **Config markers / magic blob headers** — strong.
- **Stack strings** (recovered via FLOSS) — almost always unique.
- **Unique error/log messages** — bronze, but useful in `$s` groups.

**Reject (FP magnets):**
- API names (`VirtualAlloc`, `WSASocket`) — legit software uses them too.
- Common executables (`cmd.exe`, `powershell.exe`).
- Format specifiers (`%s`, `%d`, `%08x`).
- Generic paths (`C:\Windows\`, `/tmp/`).
- Library boilerplate that ships in benign binaries.
- JS-specific traps: `require`, `fetch`, `axios`, `Buffer`, `crypto`,
  `process.env` alone — need a specific env-var name or exfil destination.

## Hex vs Text vs Regex

```
What string type?
├─ Exact ASCII/Unicode text?           → TEXT: $s = "MutexName" ascii wide
├─ Specific byte sequence?             → HEX:  $h = { 4D 5A 90 00 }
├─ Byte sequence with variation?       → HEX + wildcards: { 4D 5A ?? ?? 50 45 }
├─ Structured pattern (URL, path)?     → BOUNDED, ANCHORED REGEX: /gate\/[a-z0-9]{8,16}\.php/
└─ Unknown encoding (XOR/base64)?      → TEXT + modifier: $s = "config" xor(0x01-0xFF)
```

**Readability conventions:**
- Prefer readable text over hex when the bytes are printable ASCII. Use hex
  only for control characters or true byte sequences.
- Annotate hex blobs with an ASCII comment and wrap at 16 bytes per line so
  reviewers can gauge length without scrolling.

```yara
/* )));\nIEX( */
$h = { 29 29 29 3b 0a 49 45 58 28 0a }
```

## The Categorization Triad ($x / $s / $a)

Group strings by confidence so the condition can express graduated
requirements:

1. **`$x*` — Highly specific.** Unique to the target; one match alone is strong
   evidence. (e.g., a bespoke mutex, a hardcoded attacker handle.)
2. **`$s*` — Grouped.** Not unique individually, but a cluster is telling.
   Require several together (`all of ($s*)`, `3 of ($s*)`).
3. **`$a*` — Auxiliary / pre-selection.** Common tokens that only narrow file
   type/format (e.g., `"Go build"`). Never a threat signal on their own; they
   shrink the search space.

This lets a condition say "any one killer string, OR the full benign-looking
cluster":

```yara
condition:
    uint16(0) == 0x5A4D
    and filesize < 20MB
    and $a1
    and (
        1 of ($x*)
        or all of ($s*)
    )
```

## False-Positive Markers ($fp)

Strings that indicate a benign file. If an `$fp*` matches, the rule must not
fire. This is the import-free way to carve out a vendor you keep colliding with
(a substitute for `pe.number_of_signatures == 0`, which needs the `pe` module).

```yara
strings:
    $s1 = "main.inject" ascii
    $s2 = "main.loadPayload" ascii
    $fp1 = "Copyright by LegitSoftCorp" ascii wide
condition:
    uint16(0) == 0x5A4D
    and filesize < 20MB
    and all of ($s*)
    and not any of ($fp*)
```

## all of vs any of

```
Require all, or allow any?
├─ Each string individually unique to malware? → any of ($x*)  (each alone is suspicious)
├─ Strings common but the combination is telling? → all of ($s*)  (require the full pattern)
├─ Mixed confidence?               → all of ($core_*) and any of ($variant_*)
└─ Seeing false positives?         → tighten: any → all, add more required strings.
```

**Production lesson:** `any of ($net_*)` where the set was `"fetch"`,
`"axios"`, `"http"` matched nearly every web app. Requiring credential-path AND
network-call AND exfil-destination together eliminated the FPs. `any of` is
only safe when each member is individually unique.

## Is the Sample Packed? (Check First)

```
Is the sample packed?
├─ Very few readable strings, or strings look like noise? → Likely packed.
├─ Known packer (UPX/MPRESS/custom) signature present?    → Target the packer OR the unpacked payload.
└─ Readable, meaningful strings present?                  → Proceed with string-based detection.
```

(Entropy is the classic packed-sample tell, but computing it in-rule needs the
`math` module, which House Rule 3 forbids. Judge packing from string readability
and packer signatures instead, or unpack first and write the rule against the
payload.) **Don't write rules against packed layers** — the packing changes,
the payload doesn't.

## When Strings Fail

If extraction yields only API names and generic paths:

```
String extraction failed — now what?
├─ Consistent structural anomaly?  → Target section-name bytes / sizes via uintXX() at fixed offsets.
├─ Distinctive metadata?           → Target version-info / resource bytes.
├─ Recoverable stack strings?      → Run FLOSS; stack strings are usually unique.
└─ Genuinely nothing unique?       → This sample may not be detectable with an import-free YARA rule.
                                      Say so rather than shipping a weak rule.
```

Note: imphash clustering and entropy gating — common fallbacks elsewhere — rely
on the `pe`/`math` modules and are out of scope here (House Rule 3). If one of
those is the *only* viable signal, tell the user this skill isn't the right fit
for that particular sample.

## Platform String Hints

| Platform | Header (import-free) | Good strings |
| --- | --- | --- |
| Windows PE | `uint16(0)==0x5A4D` | Mutex names, PDB paths, config markers |
| ELF (Linux) | `uint32(0)==0x464C457F` | Unique argv/usage banners, persistence paths |
| Mach-O | `uint32(0)==0xFEEDFACF` (+ fat variants) | Keylogger artifacts, LaunchAgent paths, keychain calls in context |
| Office OOXML / ZIP | `uint32(0)==0x04034B50` | Auto-exec macro markers, encoded payload blobs |
| PDF | `uint32(0)==0x46445025` | `/JavaScript`, `/Launch` with a unique payload token |
| Loose JS (no magic) | *none possible* — use tight filesize + unique token | Obfuscator signatures (`_0x`), specific C2 domains/webhooks, eval+decode chains |

macOS good indicators (used **in context**, never alone): keylogger
(`CGEventTapCreate`, `kCGEventKeyDown`), persistence
(`~/Library/LaunchAgents`, `/Library/LaunchDaemons`), credential theft
(`security find-generic-password`, `keychain`).
