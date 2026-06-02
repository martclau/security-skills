# DWARF Section Catalog

DWARF data is split across multiple sections (in ELF these are `.debug_*` sections; in Mach-O `.dSYM` bundles and other containers the names and prefixes differ, but the roles are identical). This catalog covers what each section holds and which DWARF version introduced or replaced it. Confirm version-specific details against dwarfstd.org when precision matters.

## Core sections (present in most DWARF)
| Section | Role |
|---------|------|
| `.debug_info` | The main DIE tree: compilation units and their debugging information entries. The heart of DWARF. |
| `.debug_abbrev` | Abbreviation tables that define the tag, children flag, and (attribute, form) layout for the terse DIEs in `.debug_info`. Must be read to interpret `.debug_info`. |
| `.debug_line` | The line-number program: a bytecode for a state machine that produces the address↔(file, line, column) mapping. |
| `.debug_str` | String table; many `DW_AT_*` string values are offsets (`DW_FORM_strp`) into here. |
| `.debug_frame` | Call Frame Information (CFI) for stack unwinding (how to restore registers / find the return address at any PC). |

## Acceleration / lookup sections
| Section | Role | Version notes |
|---------|------|---------------|
| `.debug_aranges` | Maps address ranges to the CU that describes them (fast CU lookup by address). | v2+ |
| `.debug_pubnames` | Name→DIE index for globals/functions. | v2–v4; **deprecated in v5** (replaced by `.debug_names`) |
| `.debug_pubtypes` | Name→DIE index for types. | v3–v4; **deprecated in v5** (replaced by `.debug_names`) |
| `.debug_names` | **New in DWARF5.** Unified, more capable name index (functions, types, namespaces) replacing pubnames/pubtypes. | v5 |

## DWARF5 additions (new sections)
DWARF5 introduced several sections, largely to make debug info smaller and to eliminate relocations (important for split DWARF and link-time size):

| Section | Role |
|---------|------|
| `.debug_addr` | Pool of target addresses, indexed by `DW_FORM_addrx*`. Lets `.debug_info` store small indices instead of relocatable addresses. Indexed relative to `DW_AT_addr_base`. |
| `.debug_str_offsets` | Offset table for indexed strings (`DW_FORM_strx*`), indexed relative to `DW_AT_str_offsets_base`; entries point into `.debug_str`. |
| `.debug_line_str` | String table specifically for the line-number program's file/directory names (`DW_FORM_line_strp`). Keeps line-table strings separate from `.debug_str`. |
| `.debug_loclists` | **Replaces** `.debug_loc`. Location lists in a more compact, relocation-free encoding; referenced by `DW_FORM_sec_offset` or indexed by `DW_FORM_loclistx` (relative to `DW_AT_loclists_base`). |
| `.debug_rnglists` | **Replaces** `.debug_ranges`. Range lists, likewise more compact; referenced by `DW_FORM_sec_offset` or indexed by `DW_FORM_rnglistx` (relative to `DW_AT_rnglists_base`). |

## Sections replaced or deprecated in DWARF5
- `.debug_loc` → **`.debug_loclists`** (v5). A v5 producer emits `.debug_loclists`; a v4 binary uses `.debug_loc`. The same `DW_AT_location` offset means different sections depending on the CU's version.
- `.debug_ranges` → **`.debug_rnglists`** (v5).
- `.debug_pubnames` / `.debug_pubtypes` → **`.debug_names`** (v5).
- `.debug_macinfo` → **`.debug_macro`** (introduced DWARF5, also available as a GNU extension earlier) for macro information.

## Type units
| Section | Role | Version notes |
|---------|------|---------------|
| `.debug_types` | Separate type units to deduplicate large type descriptions across CUs. | Introduced in **v4**; in **v5** type units were folded back into `.debug_info` (distinguished by the unit header's `unit_type` = `DW_UT_type`). So a v4 binary may have `.debug_types`; a v5 binary generally will not. |

## Split DWARF (`-gsplit-dwarf`) sections
With split DWARF, most debug info is moved out of the main object into `.dwo` files / `.dwp` packages to speed up linking. The main binary keeps a small **skeleton** unit; the bulk lives in `.dwo`-suffixed sections:
- In the `.dwo`/`.dwp`: `.debug_info.dwo`, `.debug_abbrev.dwo`, `.debug_line.dwo`, `.debug_str.dwo`, `.debug_str_offsets.dwo`, `.debug_loclists.dwo`, `.debug_rnglists.dwo`, etc.
- In the main binary's skeleton: `.debug_addr` (the address pool stays with the linked binary), plus `DW_AT_dwo_name`/`DW_AT_GNU_dwo_name` and `DW_AT_dwo_id` linking skeleton to `.dwo`.
- `.debug_cu_index` / `.debug_tu_index` appear in `.dwp` packages to index the bundled CUs/TUs.
See `dwarf5-changes.md` for how skeleton/split units fit together.

## Unwinding sections (related but ABI-defined)
- `.eh_frame` / `.eh_frame_hdr` — exception-handling unwind info. Uses the DWARF CFI encoding but is defined by the platform ABI (LSB) rather than the DWARF standard, and is typically present even in otherwise-stripped binaries. Closely related to `.debug_frame`; tools like `readelf --debug-dump=frames` and `llvm-dwarfdump --eh-frame` decode it.

## Tips for listing sections
```bash
readelf -S <binary> | grep -i debug      # ELF section headers
llvm-dwarfdump --show-sections <binary>   # (when available)
objdump -h <binary> | grep debug
```
Absence of `.debug_info` means there is no DWARF in this file directly — check for a stripped binary, a separate debug file (`.debug`, debuglink, or debuginfod), or (macOS) a `.dSYM` bundle.
