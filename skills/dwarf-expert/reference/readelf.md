# Parsing ELF and DWARF With readelf (and eu-readelf, objdump)

`readelf` parses and dumps ELF structure and can decode DWARF sections. Prefer `dwarfdump`/`llvm-dwarfdump` for deep DWARF work (DIE-tree browsing, name/address search, verification), but `readelf` is excellent for a quick look at ELF structure, listing which `.debug_*` sections exist, and dumping individual DWARF sections — and it's almost always installed.

## ELF orientation
- `readelf -h <file>` — ELF header (class 32/64-bit, type, machine, entry point).
- `readelf -S <file>` — section headers. `readelf -S <file> | grep -i debug` lists the DWARF sections present.
- `readelf -l <file>` — program headers / segments.
- `readelf -s <file>` — symbol table (`.symtab`/`.dynsym`); distinct from DWARF, but useful context.
- `readelf -x <section> <file>` / `-p <section> <file>` — hex / string dump of a named section.
- `readelf -n <file>` — notes (e.g. build-id, used by debuginfod and `.gnu_debuglink`).

## Dumping DWARF
`readelf` decodes DWARF via `-w`/`--debug-dump`:
- `readelf --debug-dump=<section> <file>` — dump a specific DWARF section. Common values:
  - `info` — the `.debug_info` DIE tree.
  - `abbrev` — abbreviation tables.
  - `decodedline` — the decoded line-number table (address↔line rows); `rawline` for the raw program + header.
  - `loc` — location lists (`.debug_loc` / `.debug_loclists`).
  - `Ranges` — range lists (`.debug_ranges` / `.debug_rnglists`).
  - `frames` / `frames-interp` — call-frame info (`.debug_frame` / `.eh_frame`); `-interp` shows the interpreted unwind table.
  - `aranges`, `pubnames`, `pubtypes`, `str`, `addr`, `str-offsets`, `gdb_index`, `macro`.
  - With no argument, `-w` dumps all DWARF sections.
- `readelf --debug-dump=info --dwarf-depth=N <file>` — do not display DIEs at depth ≥ N (limit tree depth).
- `readelf --debug-dump=info --dwarf-start=N <file>` — begin display at the DIE at offset N.
- `readelf` also accepts `=follow-links`/`=no-follow-links` to control whether it follows `.gnu_debugaltlink`/debuglink to separate debug files.

Examples:
```bash
readelf -S app | grep debug                      # what DWARF is present
readelf --debug-dump=info app | head -60         # peek at the CU/DIE tree
readelf --debug-dump=info --dwarf-depth=1 app    # just CU-level DIEs
readelf --debug-dump=decodedline app             # address ↔ source line table
readelf --debug-dump=abbrev app                  # abbreviation tables
```

## eu-readelf (elfutils)
elfutils ships `eu-readelf`, an alternative with similar flags and sometimes clearer DWARF output:
- `eu-readelf -w <file>` — dump all DWARF sections.
- `eu-readelf --debug-dump=<section> <file>` — dump a specific section (similar section names to GNU readelf).
On some distros `eu-readelf` decodes newer DWARF5 constructs more completely than an older GNU `readelf`; if one tool shows `Unknown` for a form/section, try the other (or `llvm-dwarfdump`).

## objdump
`objdump` can also dump DWARF and is handy when correlating debug info with disassembly:
- `objdump -h <file>` — section headers (like `readelf -S`).
- `objdump --dwarf=<section> <file>` — dump a DWARF section (same section keywords as readelf, e.g. `--dwarf=info`, `--dwarf=decodedline`).
- `objdump -d -l <file>` — disassemble (`-d`) with source line numbers interleaved (`-l`, which reads `.debug_line`). Useful for seeing how addresses map back to source.
- `objdump -S <file>` — disassemble with **source code** interleaved (needs the source available and debug info).

## Choosing readelf vs dwarfdump
- Quick "what's in this ELF / which debug sections exist / dump one section" → `readelf` (or `objdump`).
- "Browse/search the DIE tree, look up by name or address, show parents/children, verify integrity" → `dwarfdump`/`llvm-dwarfdump` (see `dwarfdump.md`).
- Newer DWARF5 features render most reliably in recent `llvm-dwarfdump`; fall back to it if `readelf` shows unknown tags/forms.
