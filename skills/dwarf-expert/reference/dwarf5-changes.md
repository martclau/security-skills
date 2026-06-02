# DWARF Version Differences and Split DWARF

DWARF semantics, section names, and encodings change between versions, and a single binary can contain CUs of different versions (the linker concatenates `.debug_info` from objects built with different `-gdwarf-N` flags). **Always determine the version per CU before interpreting its data.** Verify specifics against dwarfstd.org and the DWARF5 errata page.

## Determining the version
```bash
llvm-dwarfdump --debug-info <binary> | grep -m1 version   # e.g. "version = 0x0005"
readelf --debug-dump=info <binary> | grep -m1 Version
```
Or read the 2-byte `version` field at the start of each CU header (see `data-model.md`).

## v3 → v4 (highlights)
- **`.debug_types`** introduced: separate type units to deduplicate large type info across CUs (folded back into `.debug_info` in v5).
- **`DW_AT_high_pc` as a constant**: v4 allowed `DW_AT_high_pc` to be a *constant offset* from `DW_AT_low_pc` (form class `constant`), not only an absolute address. This is the origin of the high_pc form-class check that all robust parsers need (see `data-model.md`).
- New/clarified attributes for the line table and other areas; refined location/frame semantics.

## v4 → v5 (the big one)
DWARF5 is an upward-compatible extension of v4 but changes a lot. Key changes (per dwarfstd.org):

**Header change.** The CU header gains a `unit_type` byte after `version`, and `address_size` moves before `debug_abbrev_offset`. Unit types include `DW_UT_compile`, `DW_UT_partial`, `DW_UT_type`, `DW_UT_skeleton`, `DW_UT_split_compile`, `DW_UT_split_type`. (See `data-model.md` for the exact field order — getting this wrong is a common v5 parsing bug.)

**New sections / replacements** (details in `sections.md`):
- `.debug_loc` → **`.debug_loclists`**; `.debug_ranges` → **`.debug_rnglists`** — more compact, relocation-free.
- `.debug_pubnames`/`.debug_pubtypes` → **`.debug_names`** — unified accelerator.
- New `.debug_addr`, `.debug_str_offsets`, `.debug_line_str`.
- `.debug_macinfo` → **`.debug_macro`**.
- `.debug_types` units merged into `.debug_info` (as `DW_UT_type` units).

**Indexed forms (compactness + no relocations).** New forms store small indices resolved through base attributes on the CU root DIE:
- `DW_FORM_strx*` → index into `.debug_str_offsets` (base: `DW_AT_str_offsets_base`).
- `DW_FORM_addrx*` → index into `.debug_addr` (base: `DW_AT_addr_base`).
- `DW_FORM_loclistx` → index into `.debug_loclists` (base: `DW_AT_loclists_base`).
- `DW_FORM_rnglistx` → index into `.debug_rnglists` (base: `DW_AT_rnglists_base`).
- `DW_FORM_line_strp` → offset into `.debug_line_str`.
- `DW_FORM_implicit_const` → value stored in the abbrev declaration itself.

  Parser note: resolve the `*_base` attributes on the root DIE **before** decoding indexed attributes. A common approach (used in real GDB patches) is a two-pass read: first handle attributes that establish the bases, then the indexed attributes that depend on them. Watch for GNU-prefixed pre-standard variants in transitional binaries (`DW_AT_GNU_addr_base`, `DW_AT_GNU_ranges_base`, `DW_FORM_GNU_*`).

**Line-number program changes.** The v5 line program header restructures file and directory entries: directory and file name tables become *form-described* (entry-format descriptors + counts), file indexing becomes **0-based** (file 0 is the primary source file), and names can use `.debug_line_str`. This differs from the v≤4 layout where file indices were 1-based and the tables were simple NUL-terminated lists. (See `line-and-expressions.md`.)

**New DIEs / attributes.** Call-site description (`DW_TAG_call_site`, `DW_TAG_call_site_parameter`, related attributes and `DW_OP_*`) for tail calls/tail recursion; `DW_AT_noreturn`; improvements for C++ (auto return type, deleted/defaulted special members) and Fortran (assumed/dynamic-rank arrays, coarrays); typed-value DWARF expression operators.

## DWARF5 errata
The DWARF5 standard has an official errata/clarifications page (`dwarfstd.org/errata-dwarf5.html`). Notable clarifications include `.dwo` offset handling for indexed forms, the rule that 32-bit and 64-bit DWARF formats must not be intermixed within a single unit, and loclists/rnglists offset sizing. When a v5 detail seems ambiguous or a tool disagrees with the PDF, check the errata.

## Split DWARF (`-gsplit-dwarf`, Fission)
Split DWARF moves the bulk of debug info out of object files to make linking faster and binaries smaller; debuggers/tools fetch the detail on demand.

- The linked binary keeps a **skeleton unit** (`DW_UT_skeleton`, root `DW_TAG_skeleton_unit`) with just enough to locate the full info: `DW_AT_dwo_name` (or `DW_AT_GNU_dwo_name`), `DW_AT_dwo_id`, `DW_AT_comp_dir`, and ranges/addr bases.
- The full DIE tree lives in a companion **`.dwo`** file in `.debug_*.dwo` sections (e.g. `.debug_info.dwo`, `.debug_abbrev.dwo`, `.debug_str.dwo`, `.debug_str_offsets.dwo`, `.debug_line.dwo`, `.debug_loclists.dwo`, `.debug_rnglists.dwo`). The matching unit there is a `DW_UT_split_compile` unit.
- The **address pool (`.debug_addr`) stays in the linked binary** (addresses aren't known until link), so split units use `DW_FORM_addrx*` to reference it.
- Multiple `.dwo` files can be bundled into a single **`.dwp`** package (via `dwp` or `llvm-dwp`) containing `.debug_cu_index`/`.debug_tu_index` to index the bundled units.

Tool usage:
```bash
llvm-dwarfdump <binary>.dwo            # dump the split unit's full info
llvm-dwarfdump --debug-info <binary>   # the skeleton in the main binary
```
When analyzing split DWARF, you typically need *both* the skeleton (for addresses/bases) and the `.dwo`/`.dwp` (for the DIEs). If a `.dwo` is missing, tools can only show the skeleton.

## Supplementary object files
DWARF supports a supplementary file mechanism (and the related GNU `DW_FORM_GNU_ref_alt` / `.gnu_debugaltlink`, used by `dwz`) where common debug info is factored into a shared supplementary object and referenced from multiple binaries. References then point into the *local* `.debug_info` for ordinary refs and into the supplementary file for the alternate-reference forms. If a binary has been processed by `dwz`, expect these cross-file references.
