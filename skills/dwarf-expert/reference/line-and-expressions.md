# Line Programs, DWARF Expressions, and Lists

This reference covers three closely related areas that go beyond the static DIE tree: the line-number program (address↔source mapping), DWARF expressions (how values/locations are computed), and location/range lists. Verify specific opcode semantics against dwarfstd.org or LLVM's `DWARFDebugLine.cpp` / `DWARFExpression.cpp`.

## The line-number program (`.debug_line`)
`.debug_line` does not store a literal table. It stores a **bytecode program** for a finite state machine; running ("interpreting") that program *emits rows* of a logical matrix mapping machine addresses to (file, line, column, plus flags like `is_stmt`, `end_sequence`, `prologue_end`). This compression is why you can't just read the mapping out directly — a tool or library must run the state machine.

Key state-machine registers: `address`, `file`, `line`, `column`, `is_stmt`, `basic_block`, `end_sequence`, `prologue_end`, `epilogue_begin`, `op_index` (for VLIW). Special opcodes advance `address` and `line` together compactly; standard opcodes (`DW_LNS_*`) and extended opcodes (`DW_LNE_*`, e.g. `DW_LNE_set_address`, `DW_LNE_end_sequence`) handle the rest.

**Version difference (v5):** the line-program *header* changed significantly in DWARF5. Directory and file tables are described by entry-format descriptors (so they can carry MD5 hashes, sizes, etc.), file/dir names may live in `.debug_line_str`, and **file indices are 0-based** (entry 0 is the primary source file). In v≤4, file indices are **1-based** and the dir/file tables are simple lists. Off-by-one file-index bugs almost always trace to this change — branch on the line program's version.

**Inspecting the line table:**
```bash
llvm-dwarfdump --debug-line <binary>            # decoded line table (rows)
readelf --debug-dump=decodedline <binary>       # decoded rows
readelf --debug-dump=rawline <binary>           # raw program + header (for debugging the encoding)
```

**Mapping an address to a source line / function (pyelftools):**
```python
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class

def addr_to_line(path, address):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return None
        dwarf = elf.get_dwarf_info()
        for CU in dwarf.iter_CUs():
            lp = dwarf.line_program_for_CU(CU)
            if lp is None:
                continue
            prev = None
            for entry in lp.get_entries():
                st = entry.state
                if st is None:
                    continue
                if not st.end_sequence:
                    if prev and prev.address <= address < st.address:
                        # resolve file name via the line program's file_entry table
                        return prev.line, prev.file
                prev = st
    return None
```
For function lookup, iterate DIEs for `DW_TAG_subprogram`, read `DW_AT_low_pc`, and compute the end from `DW_AT_high_pc` honoring its form class:
```python
high = die.attributes['DW_AT_high_pc']
if describe_form_class(high.form) == 'address':
    high_pc = high.value
else:  # 'constant' → offset from low_pc
    high_pc = die.attributes['DW_AT_low_pc'].value + high.value
```
Caveat: a single `[low_pc, high_pc)` interval ignores functions with non-contiguous ranges (`DW_AT_ranges`); handle those for correctness.

## DWARF expressions (`DW_OP_*`)
A DWARF expression is a small stack-machine program that computes either a **value** or a **location** (where something lives). It appears in `DW_AT_location`, `DW_AT_frame_base`, `DW_AT_data_member_location`, and many other attributes, encoded as `DW_FORM_exprloc` (a counted block) or referenced from a location list.

Operation families:
- **Literals / constants:** `DW_OP_lit0..31`, `DW_OP_const*`, `DW_OP_addr` (a relocatable address), `DW_OP_addrx` (v5 index into `.debug_addr`).
- **Registers:** `DW_OP_reg0..31` / `DW_OP_regx` (the value is *in* the register), vs `DW_OP_breg0..31` / `DW_OP_bregx` (register + offset → an address).
- **Stack / arithmetic / logic:** `DW_OP_dup`, `DW_OP_drop`, `DW_OP_plus`, `DW_OP_minus`, `DW_OP_and`, `DW_OP_shl`, `DW_OP_deref`, etc.
- **Frame-relative:** `DW_OP_fbreg` (offset from the frame base established by `DW_AT_frame_base`) — the most common way local variables are located.
- **Composite / pieces:** `DW_OP_piece`, `DW_OP_bit_piece` describe values split across multiple locations (e.g. a struct partly in registers, partly in memory).
- **Implicit values:** `DW_OP_stack_value` (the computed value *is* the value, with no storage location), `DW_OP_implicit_value`.
- **Typed operations (v5):** operators that put typed values on the stack (`DW_OP_const_type`, `DW_OP_regval_type`, `DW_OP_convert`, …).
- **Call-site (v5):** `DW_OP_entry_value` (a.k.a. earlier GNU `DW_OP_GNU_entry_value`) recovers a value as it was on function entry — used with `DW_TAG_call_site`.

To decode by hand, dump with `--verbose`/raw output and walk opcodes; or let a library evaluate. In pyelftools, `elftools.dwarf.dwarf_expr.DWARFExprParser` parses an expression block into a list of operations.

## Location lists and range lists
When a variable's location or an entity's address range varies over the PC (e.g. a variable that lives in different registers across its scope, or a function with discontiguous code), DWARF uses **lists** rather than a single expression/interval:

- **Location lists** — `DW_AT_location` references a location list: a sequence of `[pc_start, pc_end) → DWARF expression` entries.
  - DWARF ≤4: in `.debug_loc`, referenced by a section offset.
  - DWARF 5: in **`.debug_loclists`**, referenced by `DW_FORM_sec_offset` or indexed by `DW_FORM_loclistx` (relative to `DW_AT_loclists_base`). v5 entries use compact `DW_LLE_*` encodings (`DW_LLE_offset_pair`, `DW_LLE_base_address`, `DW_LLE_start_length`, …).
- **Range lists** — `DW_AT_ranges` references a range list describing non-contiguous address ranges.
  - DWARF ≤4: `.debug_ranges`, list of address pairs (with a base-address mechanism).
  - DWARF 5: **`.debug_rnglists`** with `DW_RLE_*` encodings (`DW_RLE_offset_pair`, `DW_RLE_base_address`, `DW_RLE_start_length`, `DW_RLE_startx_length`, …), referenced by offset or `DW_FORM_rnglistx` (relative to `DW_AT_rnglists_base`).

Practical consequence: the *same* offset value in `DW_AT_location`/`DW_AT_ranges` resolves against a *different section* depending on the CU's DWARF version. Determine the version first; for v5 indexed forms, resolve the relevant `*_base` before indexing.

**Inspecting:**
```bash
llvm-dwarfdump --debug-loclists <binary>   # v5 location lists
llvm-dwarfdump --debug-rnglists <binary>   # v5 range lists
readelf --debug-dump=loc <binary>          # .debug_loc / .debug_loclists
readelf --debug-dump=Ranges <binary>       # .debug_ranges / .debug_rnglists
```

## Call Frame Information (CFI)
`.debug_frame` (and the ABI-defined `.eh_frame`) describe, for each PC, how to unwind: where the canonical frame address (CFA) is and how to recover saved registers and the return address. The encoding is a set of CFI instructions (a compact program per address range, organized into CIEs and FDEs). Decode with `llvm-dwarfdump --debug-frame` / `--eh-frame` or `readelf --debug-dump=frames`. This is what makes backtraces possible in optimized code without frame pointers.
