---
name: dwarf-expert
description: Provides deep expertise for analyzing, parsing, creating, and reasoning about DWARF debug information and the DWARF standard (v3, v4, v5). Use this skill whenever DWARF is involved in any way — answering questions about the DWARF format/standard, inspecting or extracting DWARF from a binary (.debug_info, .debug_line, .debug_abbrev, and other debug sections), decoding DIEs / tags / attributes / forms, working with dwarfdump, llvm-dwarfdump, readelf, eu-readelf, or objdump on debug data, verifying DWARF integrity, mapping addresses to source lines or functions, interpreting DWARF expressions and location/range lists, dealing with split DWARF (.dwo/.dwp), or writing/modifying/reviewing code that parses DWARF (libdwarf, pyelftools, gimli, debug/dwarf, LibObjectFile). Trigger even when the user does not say "DWARF" explicitly but is clearly working with compiled debug info, symbol/line tables, or debugger-format data.
allowed-tools: Read Bash Grep Glob WebSearch
---

# DWARF Expert

This skill provides technical knowledge and expertise about the DWARF debugging information format (versions 3, 4, and 5) and how to work with DWARF data in practice. It covers answering questions about the standard, explaining and giving examples of DWARF features, parsing and inspecting DWARF in real binaries, verifying integrity, and writing/modifying/reviewing code that interacts with DWARF.

DWARF is the dominant debug-info format for ELF (Linux/BSD), and is also used inside Mach-O (via separate `.dSYM` bundles), PE/COFF, and WebAssembly. The format is the same across containers even though the tooling to extract it differs.

## When to Use This Skill
- Understanding, parsing, or extracting DWARF debug information from compiled binaries
- Answering questions about the DWARF standard (v3, v4, v5) — sections, DIEs, tags, attributes, forms, encodings
- Decoding what a specific `DW_TAG_*`, `DW_AT_*`, `DW_FORM_*`, `DW_OP_*`, or `DW_LNE_*` means
- Mapping a machine address to its source file/line/function, or vice versa
- Interpreting DWARF expressions, location lists, and range lists
- Working with split DWARF (`-gsplit-dwarf`, `.dwo` files, `.dwp` packages) or DWARF supplementary files
- Using `dwarfdump`, `llvm-dwarfdump`, `readelf`, `eu-readelf`, or `objdump` to inspect debug info
- Verifying DWARF integrity with `llvm-dwarfdump --verify` or comparing debug-info quality across builds
- Writing, modifying, or reviewing code that parses DWARF (libdwarf, pyelftools, gimli, Go `debug/dwarf`, LibObjectFile)

## When NOT to Use This Skill
- **DWARF v1/v2**: Expertise targets versions 3–5. v1/v2 are obsolete and structurally different (e.g. v2 used `.debug_pubnames`/`.debug_loc`/`.debug_ranges` rather than the v5 `.debug_names`/`.debug_loclists`/`.debug_rnglists`); flag the version gap rather than guessing.
- **General ELF work with no debug info**: For symbol tables, segments, relocations, or hardening that don't touch `.debug_*`, use a general ELF approach or an ELF-specific skill.
- **Live/runtime debugging**: To actually run, breakpoint, or inspect a process, use `gdb`/`lldb`. DWARF is the static data those tools consume, not the debugger itself.
- **Reverse engineering of stripped binaries**: Use Ghidra/IDA/radare2 unless the specific task is analyzing DWARF sections that are present.
- **Compiler codegen bugs**: Wrong DWARF emitted by GCC/Clang is a toolchain issue. This skill helps *diagnose* malformed DWARF but does not fix compilers.

# Core Mental Model (read first)
Before diving into tools, hold this model in mind — most confusion about DWARF dissolves once it is clear:

- DWARF describes a program as a tree of **Debugging Information Entries (DIEs)**. Each DIE has a **tag** (`DW_TAG_*`, what it is — a function, variable, type, …) and a list of **attributes** (`DW_AT_*`, e.g. its name, type, address range), each attribute encoded with a **form** (`DW_FORM_*`, how the value's bytes are stored).
- DIEs live in **`.debug_info`**, grouped into **compilation units (CUs)**. To save space, the actual DIE bytes in `.debug_info` don't repeat their structure; they reference an **abbreviation** in **`.debug_abbrev`** that declares the tag, the children flag, and the (attribute, form) list. **You almost always parse `.debug_abbrev` first, then `.debug_info`.**
- Other sections hold specialized data: line tables (`.debug_line`), strings (`.debug_str`), address-to-source acceleration, location/range lists, call-frame info (`.debug_frame`/`.eh_frame`), and so on.

For the full data model (CU header layout, the abbrev↔info relationship, common tags/attributes/forms, and how values are decoded), read `{baseDir}/reference/data-model.md`. For the complete section catalog including all v5 additions, read `{baseDir}/reference/sections.md`.

# Authoritative Sources
DWARF has many edge cases and version-specific behaviors. Do not rely on memory for specific constants, attribute applicability, or v5 semantics — verify against:

1. **Official DWARF standard (dwarfstd.org)**: The DWARF5 PDF is the ground truth. Web-search specific sections, e.g. `DWARF5 DW_AT_high_pc site:dwarfstd.org` or `DWARF5 DW_TAG_subprogram attributes`. Also useful: the **DWARF5 errata** page (`dwarfstd.org/errata-dwarf5.html`) for clarifications/corrections.
2. **LLVM's reference implementation** (`llvm/lib/DebugInfo/DWARF/`): reliable, actively maintained code. Key files: `DWARFDie.cpp` (DIE/attribute access), `DWARFUnit.cpp` (CU parsing), `DWARFDebugLine.cpp` (line programs), `DWARFExpression.cpp` (expressions), `DWARFVerifier.cpp` (validation logic).
3. **libdwarf** (`github.com/davea42/libdwarf-code`): the C reference implementation behind `dwarfdump`; its documentation describes data structures in detail.
4. **pyelftools** (`github.com/eliben/pyelftools`): readable Python implementation with an `examples/` directory that doubles as executable documentation.

When you state a specific fact about the standard (a constant value, which version introduced a feature, whether an attribute is permitted on a tag), cite which source confirms it. If unsure, say so and verify rather than guessing.

# Inspecting DWARF in a Binary
First identify what you have and which tools exist, then pick the lightest tool for the job. See the decision guide below.

## Quick orientation
```bash
file <binary>                          # ELF? Mach-O? PE? stripped?
readelf -S <binary> | grep debug       # which .debug_* sections are present
dwarfdump --version                    # is `dwarfdump` libdwarf or LLVM? (options differ)
llvm-dwarfdump --debug-info <binary> | head   # peek at the CU/DIE tree
```
If there are no `.debug_*` sections, the binary may be stripped, or (on macOS) the DWARF may live in a separate `.dSYM` bundle, or debug info may be in a separate `.debug`/`.dwo` file or fetched via debuginfod.

## Tools
- **`dwarfdump` / `llvm-dwarfdump`** — the primary DWARF tools. Best for dumping the DIE tree, searching DIEs by name/address, showing parents/children, and verifying. Read `{baseDir}/reference/dwarfdump.md`.
- **`readelf` / `eu-readelf` / `objdump`** — good for general ELF structure and section dumps; usable for DWARF but less ergonomic than dwarfdump. Read `{baseDir}/reference/readelf.md`.

## Verification & quality metrics
Validate DWARF integrity and compare debug-info quality across builds/optimization levels:
```bash
llvm-dwarfdump --verify <binary>                      # structural validation
llvm-dwarfdump --verify --error-display=full <binary> # detailed errors + summary
llvm-dwarfdump --verify --verify-json=errors.json <binary>  # machine-readable (CI)
llvm-dwarfdump --statistics <binary>                  # single-line JSON quality metrics
```
Common patterns: verify before distributing; use `--statistics` to catch debug-info regressions between compiler versions or `-O` levels; identify malformed DWARF that breaks debuggers; validate the output of DWARF-producing tools against known-good binaries.

# Working With Code
For writing, modifying, or reviewing code that parses or emits DWARF — including library choice (libdwarf, pyelftools, gimli, Go `debug/dwarf`, LibObjectFile) and runnable pyelftools examples — read `{baseDir}/reference/coding.md`.

# Line Programs, Expressions, and Lists
For address↔line mapping (the `.debug_line` state machine), DWARF expressions/location descriptions (`DW_OP_*`), and location/range lists (including the v5 `.debug_loclists`/`.debug_rnglists`), read `{baseDir}/reference/line-and-expressions.md`.

# Version Differences & Split DWARF
For what changed across v3→v4→v5 (new sections, replaced sections, indexed forms, the v5 unit-header `unit_type` byte) and how split DWARF (`.dwo`/`.dwp`) and supplementary files work, read `{baseDir}/reference/dwarf5-changes.md`. Always confirm the DWARF version first (`llvm-dwarfdump --debug-info <binary> | grep version`, or the CU header's `version` field) — semantics and section names differ by version, and a single binary can mix CUs of different versions.

# Choosing Your Approach
```
┌─ Question about the DWARF standard / what a DW_* constant means?
│   └─ Use the data-model + sections references; verify specifics on dwarfstd.org / LLVM source
├─ Need to know what sections exist or what one section is for?
│   └─ {baseDir}/reference/sections.md
├─ Need the data model (DIEs, abbrev↔info, tags/attributes/forms)?
│   └─ {baseDir}/reference/data-model.md
├─ Need to verify DWARF integrity or compare build quality?
│   └─ llvm-dwarfdump --verify / --statistics (see Verification above)
├─ Need a quick section dump or general ELF info?
│   └─ {baseDir}/reference/readelf.md
├─ Need to browse/search the DIE tree, or look up a DIE by name/address?
│   └─ {baseDir}/reference/dwarfdump.md
├─ Need address↔line mapping, DWARF expressions, or location/range lists?
│   └─ {baseDir}/reference/line-and-expressions.md
├─ Working across DWARF versions, or with .dwo/.dwp split DWARF?
│   └─ {baseDir}/reference/dwarf5-changes.md
└─ Writing/modifying/reviewing code that handles DWARF?
    └─ {baseDir}/reference/coding.md
```
