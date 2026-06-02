# Conditions & Performance

How to order and structure conditions for correctness, false-positive
resistance, and speed. Read this when building or reviewing a condition block.

## Contents

- [Short-Circuit Order](#short-circuit-order)
- [The Mandatory Opening](#the-mandatory-opening)
- [Condition Layout & Indentation](#condition-layout--indentation)
- [Regex Anchoring](#regex-anchoring)
- [Loop Discipline](#loop-discipline)
- [Modifier Discipline](#modifier-discipline)
- [Filesize Bands for FP Control](#filesize-bands-for-fp-control)
- [Import-Free Header Cookbook](#import-free-header-cookbook)

## Short-Circuit Order

YARA evaluates conditions left to right and stops at the first failure. Put the
cheapest, most-restrictive checks first so expensive work rarely runs.

1. **filesize guard** — `filesize < 5MB`. Near-instant; rejects swap files,
   dumps, and disk images before anything else. (House Rule 2)
2. **header check** — `uint16(0) == 0x5A4D`. Near-instant; anchors to a real
   file of the right type. (House Rule 2)
3. **additional byte checks** — other `uintXX()` offsets you rely on.
4. **string logic** — `$x`/`$s` groupings (atom matching already happened in
   the scan phase; this is the boolean combination).
5. **FP filters** — `and not any of ($fp*)`.

Both filesize and header are mandatory and both are cheap, so either can lead;
the rule is to include **both** before any string logic.

## The Mandatory Opening

Every condition opens like this (House Rule 2):

```yara
condition:
    uint16(0) == 0x5A4D       // header: anchor to a real PE
    and filesize < 5MB        // guard: reject swap/dump/disk-image blobs
    and ( /* string logic */ )
    and not any of ($fp*)
```

Why it matters: malware byte-sequences routinely appear *embedded* inside huge
artifacts — `pagefile.sys`, `hiberfil.sys`, crash/memory dumps, raw `.dd`/`.E01`
disk images, backups. Without the header anchor and size ceiling, the rule
flags the container, producing a flood of useless hits on a single infected or
imaged host. With them, it flags the actual file.

If the target file type has no reliable magic (loose JS, some scripts): the
filesize guard is **still required**, and you must compensate with an extra
tight, structure-bearing anchor string plus a low filesize ceiling. Leave a
comment explaining the missing header check.

## Condition Layout & Indentation

- Newline before each top-level `and` — proven to improve readability.
- Wrap `or` alternatives in parentheses and indent them as a block.
- Group magic-byte alternatives in their own parenthesized block.

```yara
condition:
    (
        uint16(0) == 0x5A4D       // MZ
        or uint32(0) == 0x464C457F // ELF
    )
    and filesize < 300KB
    and (
        1 of ($x*)
        or (
            2 of ($s*)
            and 3 of them
        )
    )
    and not any of ($fp*)
```

## Regex Anchoring

A regex without a fixed 4+ byte literal substring has no atom and runs at every
file offset — catastrophic. Always anchor to a distinctive literal, and bound
all quantifiers.

```yara
// BAD — no atom, unbounded; scans every byte of every file
$r = /https?:\/\/.*/

// GOOD — anchored to a literal, bounded length
$r = /mshta\.exe https?:\/\/[a-z0-9]{8,16}\.onion/
```

Stairwell's framing: in `/somethinghere[0-9]{5,43}/`, `somethinghere` is
extracted as the atom; the regex engine only runs where that atom hit. No
literal anchor → the engine runs everywhere. If you can't anchor, use a hex
pattern with wildcards instead.

Bound every quantifier: `{0,30}` not `*`, `{1,100}` not `+`.

## Loop Discipline

Bound every loop with filesize, and never iterate an unbounded match count over
a large file.

```yara
// Bound the count and the file size together
filesize < 100KB and for all i in (1..#a) : ( @a[i] < 0x400 )
```

An unbounded `#a` can reach thousands in a large file, causing exponential
slowdown.

**Don't loop-and-hash PE regions.** A pattern like
`for any s in pe.sections : (hash.md5(s.raw_data_offset, 0x100) == "...")`
needs the `pe` and `hash` modules (forbidden here) *and* is slower than
necessary. Put the exact bytes you'd hash directly as a hex string — faster and
import-free (the Neo23x0 "String Matching FTW" tweak):

```yara
strings:
    $first256 = { 55 8B EC 83 EC ... }   // the bytes you'd otherwise MD5
condition:
    uint16(0) == 0x5A4D and filesize < 2MB and $first256 at <offset>
```

## Modifier Discipline

- **`nocase`** generates exponentially more atom variations and causes FPs on
  short strings (camel-cased `KeRnEl32.dLl` is unique; `nocase` makes it match
  the ubiquitous `kernel32.dll`). Use only with confirmed case variation.
- **`wide`** doubles string matching cost. Use only when you've confirmed the
  string appears UTF-16 in samples (combine `ascii wide` only when both occur).
- **`xor`** — for XOR-encoded strings; bound the key range when you can
  (`xor(0x01-0xFF)`).
- **`base64`** (YARA-X) — only on strings of 3+ characters.

"If you don't have a clear reason for using those modifiers, don't do it."

## Filesize Bands for FP Control

Because House Rule 3 forbids `pe.number_of_signatures` (the usual "skip signed
software" filter), lean harder on filesize and specificity to manage the
goodware haystack. When a rule matches too many legitimate files, split it into
filesize bands so each variant covers a narrower slice and is easier to triage:

```yara
// one rule per band: <1MB, 1–2MB, 2–3MB, ...
filesize > 1MB and filesize < 2MB
```

Combined with more-specific strings and a `$fp*` vendor marker, this is the
import-free FP-reduction toolkit.

## Import-Free Header Cookbook

All header checks use raw byte reads (House Rule 3). Offsets are little-endian
unless `be` is noted.

```yara
// Windows PE ("MZ"), and optional confirmation of the "PE\0\0" signature
uint16(0) == 0x5A4D
uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550

// ELF ("\x7fELF")
uint32(0) == 0x464C457F
// big-endian view of the same magic
uint32be(0) == 0x7F454C46

// Mach-O slices
uint32(0) == 0xFEEDFACE     // 32-bit
uint32(0) == 0xFEEDFACF     // 64-bit
uint32(0) == 0xCAFEBABE     // universal/fat
uint32(0) == 0xBEBAFECA     // fat, byte-swapped

// ZIP / OOXML / JAR / APK ("PK\x03\x04")
uint32(0) == 0x04034B50

// PDF ("%PDF")
uint32(0) == 0x46445025

// RAR ("Rar!") — note the exclusion idiom, useful in negative checks
uint32be(0) == 0x52617221   // == "Rar!"; use != to exclude RAR
```

Exclusion works too: if you know the target is **not** a PE, `uint16(0) !=
0x5A4D` shrinks the haystack.
