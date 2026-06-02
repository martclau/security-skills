# The DWARF Data Model

This reference explains how DWARF represents a program. Understanding this structure is the difference between mechanically running tools and actually reasoning about DWARF. Verify specific constant values and version-specific applicability against the DWARF5 standard (dwarfstd.org) or LLVM/libdwarf source — this file gives the model and the most common constants, not an exhaustive enumeration.

## Contents
- [Debugging Information Entries (DIEs)](#debugging-information-entries-dies)
- [Compilation units and the CU header](#compilation-units-and-the-cu-header)
- [Abbreviations: how `.debug_abbrev` and `.debug_info` relate](#abbreviations-how-debug_abbrev-and-debug_info-relate)
- [Tags (`DW_TAG_*`)](#tags-dw_tag_)
- [Attributes (`DW_AT_*`)](#attributes-dw_at_)
- [Forms (`DW_FORM_*`)](#forms-dw_form_)
- [How a DIE is decoded, end to end](#how-a-die-is-decoded-end-to-end)
- [Special DIE relationships](#special-die-relationships-you-must-handle)
- [Common encodings: LEB128](#common-encodings-leb128)

## Debugging Information Entries (DIEs)
A DWARF description of a program is a tree of **DIEs**. Each DIE:
- has a **tag** (`DW_TAG_*`) saying what kind of entity it describes (a compile unit, function, variable, base type, struct, etc.);
- carries a set of **attributes** (`DW_AT_*`) that fill in the details (its name, its type, its address range, its declaration file/line, …), each stored using a particular **form** (`DW_FORM_*`) that dictates the byte encoding of the value;
- may **own children** (e.g. a `DW_TAG_subprogram` owns `DW_TAG_formal_parameter` and `DW_TAG_variable` children) and has **siblings**.

The tree is serialized via a "has children" flag plus a null entry (a DIE with abbreviation code 0) that terminates a sibling chain. The first DIE of a CU is the **root DIE** — typically `DW_TAG_compile_unit` (or `DW_TAG_partial_unit` / `DW_TAG_skeleton_unit` in split DWARF) — and everything else descends from it.

## Compilation units and the CU header
`.debug_info` is a concatenation of **compilation units**. Each CU begins with a header, then the DIE tree.

CU header fields (DWARF5, 32-bit DWARF format):
| Field | Size | Meaning |
|-------|------|---------|
| `unit_length` | 4 bytes (or `0xffffffff` then 8 bytes for 64-bit DWARF) | length of the unit, not counting this field |
| `version` | 2 bytes | DWARF version (3, 4, 5, …) |
| `unit_type` | 1 byte | **DWARF5 only** — e.g. `DW_UT_compile`, `DW_UT_partial`, `DW_UT_skeleton`, `DW_UT_split_compile`, `DW_UT_type` |
| `address_size` | 1 byte | target pointer size (4 or 8) |
| `debug_abbrev_offset` | 4/8 bytes | offset into `.debug_abbrev` for this unit's abbrev table |

**Important ordering change:** in DWARF ≤4 the header is `unit_length, version, debug_abbrev_offset, address_size` (no `unit_type` byte, and `address_size` comes last). DWARF5 inserts `unit_type` after `version` and moves `address_size` before the abbrev offset. Type units and split units have additional header fields. Always branch on `version` when parsing headers.

The 32-bit vs 64-bit DWARF format (distinct from the target's address size) is selected by the initial length: a 32-bit unit has a `unit_length < 0xfffffff0`; the escape value `0xffffffff` introduces a 64-bit unit whose real length follows as 8 bytes. The two formats must not be mixed within a single CU.

## Abbreviations: how `.debug_abbrev` and `.debug_info` relate
To avoid repeating structural metadata for every DIE, the bytes in `.debug_info` are terse: each DIE starts with an unsigned LEB128 **abbreviation code**, followed only by the raw attribute *values*. The *meaning* of those values — the tag, whether the DIE has children, and the ordered list of (attribute, form) pairs — lives in **`.debug_abbrev`**.

An abbreviation declaration in `.debug_abbrev` contains:
1. the abbreviation **code** (ULEB128, unique within that abbrev table; code 0 marks the end of the table);
2. the **tag** (ULEB128);
3. a **has-children** byte (`DW_CHILDREN_yes`/`DW_CHILDREN_no`);
4. a series of **(attribute, form)** pairs, each a ULEB128 attribute code + ULEB128 form code, terminated by a `(0, 0)` pair.
   - DWARF5 adds `DW_FORM_implicit_const`, whose constant value is stored in the abbrev declaration itself (a third SLEB128 operand) rather than in `.debug_info`.

**Consequence for parsing:** you cannot interpret `.debug_info` without first reading the relevant abbrev table (located via the CU header's `debug_abbrev_offset`). The standard workflow is: read CU header → load its abbrev table → for each DIE, read its abbrev code → look up the declaration → read each attribute value according to its form. Tools like `dwarfdump --print-abbrev` (or `readelf --debug-dump=abbrev`) dump the abbrev tables directly.

## Tags (`DW_TAG_*`)
Tags name the kind of entity. The most frequently encountered:

| Tag | Describes |
|-----|-----------|
| `DW_TAG_compile_unit` | a full compilation unit (root DIE) |
| `DW_TAG_partial_unit` / `DW_TAG_skeleton_unit` | partial/skeleton CU (imported units; split DWARF) |
| `DW_TAG_subprogram` | a function or method (may be a definition or just a declaration) |
| `DW_TAG_inlined_subroutine` | an inlined instance of a function |
| `DW_TAG_formal_parameter` | a function parameter |
| `DW_TAG_variable` | a variable (global, local, or static) |
| `DW_TAG_base_type` | a primitive type (int, float, char, …) |
| `DW_TAG_pointer_type`, `DW_TAG_array_type`, `DW_TAG_const_type`, `DW_TAG_typedef`, `DW_TAG_volatile_type` | type modifiers/constructors |
| `DW_TAG_structure_type`, `DW_TAG_union_type`, `DW_TAG_class_type`, `DW_TAG_enumeration_type` | aggregate/enum types |
| `DW_TAG_member` | a member of a struct/union/class |
| `DW_TAG_subrange_type` | array bounds (child of `DW_TAG_array_type`) |
| `DW_TAG_lexical_block` | a `{ }` scope |
| `DW_TAG_namespace` | a C++ namespace |
| `DW_TAG_call_site` / `DW_TAG_call_site_parameter` | **DWARF5** call-site (incl. tail-call) info |

## Attributes (`DW_AT_*`)
Attributes carry the details of a DIE. High-frequency ones:

| Attribute | Typical meaning |
|-----------|-----------------|
| `DW_AT_name` | the entity's name |
| `DW_AT_type` | reference to the DIE describing this entity's type |
| `DW_AT_low_pc` | starting address (function/block) |
| `DW_AT_high_pc` | end address **or** size — see the form note below |
| `DW_AT_ranges` | reference to a range list (non-contiguous address ranges) |
| `DW_AT_location` | where a variable lives (a DWARF expression or location-list reference) |
| `DW_AT_decl_file`, `DW_AT_decl_line`, `DW_AT_decl_column` | source position of the declaration |
| `DW_AT_external` | flag: visible outside its CU |
| `DW_AT_declaration` | flag: this is a declaration, not a definition |
| `DW_AT_specification` | reference from a definition DIE back to its declaration DIE |
| `DW_AT_abstract_origin` | reference from an inlined/concrete instance to the abstract DIE it instantiates |
| `DW_AT_frame_base` | how to compute the frame base for a subprogram |
| `DW_AT_comp_dir`, `DW_AT_producer` | compilation directory; producer (compiler) string |
| `DW_AT_data_member_location` | offset of a member within its containing aggregate |
| `DW_AT_byte_size`, `DW_AT_bit_size`, `DW_AT_data_bit_offset` | sizes/bit layout |

**The `DW_AT_high_pc` gotcha (very common source of bugs):** since DWARF4, `DW_AT_high_pc` may be encoded either as an **address** (form class `address`) — in which case it is the actual end address — or as a **constant** (form class `constant`) — in which case it is an *offset* and the real end address is `DW_AT_low_pc + DW_AT_high_pc`. You must check the form class to interpret it. In pyelftools: `describe_form_class(attr.form)` returns `'address'` or `'constant'`.

## Forms (`DW_FORM_*`)
The form tells you how an attribute's value bytes are encoded and how to interpret them. Forms group into **classes** (address, constant, string, reference, flag, block, exprloc, loclistsptr, etc.). Common forms:

| Form | Encoding / meaning |
|------|--------------------|
| `DW_FORM_addr` | a target-address-sized value |
| `DW_FORM_data1/2/4/8`, `DW_FORM_sdata`, `DW_FORM_udata` | constants (fixed-size or LEB128) |
| `DW_FORM_string` | inline NUL-terminated string |
| `DW_FORM_strp` | offset into `.debug_str` |
| `DW_FORM_line_strp` | **DWARF5** offset into `.debug_line_str` |
| `DW_FORM_strx` / `strx1..4` | **DWARF5** index into `.debug_str_offsets` (needs `DW_AT_str_offsets_base`) |
| `DW_FORM_ref1/2/4/8`, `DW_FORM_ref_udata` | reference to another DIE, relative to the CU start |
| `DW_FORM_ref_addr` | reference to a DIE by absolute `.debug_info` offset (can cross CUs) |
| `DW_FORM_addrx` / `addrx1..4` | **DWARF5** index into `.debug_addr` (needs `DW_AT_addr_base`) |
| `DW_FORM_sec_offset` | a 4-byte (32-bit DWARF) / 8-byte (64-bit) section offset (line, loclists, rnglists, …) |
| `DW_FORM_exprloc` | a counted DWARF expression block |
| `DW_FORM_flag`, `DW_FORM_flag_present` | boolean (`flag_present` carries no value bytes — its presence means true) |
| `DW_FORM_loclistx` / `DW_FORM_rnglistx` | **DWARF5** index into `.debug_loclists` / `.debug_rnglists` |
| `DW_FORM_implicit_const` | **DWARF5** value stored in the abbrev declaration, not in `.debug_info` |

**Indexed forms and their base attributes (DWARF5):** the `strx`, `addrx`, `loclistx`, `rnglistx` forms store small *indices*, not values. Resolving them requires the corresponding base attribute on the (skeleton or full) CU root DIE: `DW_AT_str_offsets_base`, `DW_AT_addr_base`, `DW_AT_loclists_base`, `DW_AT_rnglists_base`. This indirection is what makes v5 compact and relocation-free, and it is a frequent cause of parser bugs when the base is not resolved before the indexed attributes. (See `dwarf5-changes.md`.)

## How a DIE is decoded, end to end
1. From the CU header, note `version`, `address_size`, and `debug_abbrev_offset`.
2. Load the abbrev table at that offset.
3. At the current `.debug_info` position, read a ULEB128 abbreviation code.
   - Code 0 → this is a null DIE; it terminates the current sibling chain (pop a level).
4. Look up the abbrev declaration: get the tag, the has-children flag, and the ordered (attribute, form) list.
5. For each (attribute, form): read/interpret the value per the form's encoding (resolving `strp`/`strx` to strings, `addrx` to addresses, references to DIE offsets, etc.).
6. If the declaration says has-children, the following DIEs are this DIE's children until a null DIE closes the level.

## Special DIE relationships you must handle
Robust DWARF code accounts for these — they are where naive parsers go wrong (and are worth flagging in code review):
- **Declaration vs definition** (`DW_AT_declaration`, `DW_AT_specification`): a function/variable may appear as a declaration in one place and a definition elsewhere; the definition points back via `DW_AT_specification`. Attributes (like `DW_AT_name`) may live only on the declaration.
- **Abstract instances and inlining** (`DW_AT_abstract_origin`): inlined and concrete out-of-line instances reference an abstract DIE that holds shared attributes; you often must follow `DW_AT_abstract_origin` to recover the name/type.
- **Cross-CU and cross-file references** (`DW_FORM_ref_addr`, supplementary objects): a reference may target a DIE in another CU or another object file.
- **Non-contiguous ranges** (`DW_AT_ranges`): a function/block may not be a single `[low_pc, high_pc)` interval; it can be a range list. Don't assume contiguity.
- **Missing attributes**: most attributes are optional. Always handle absence; don't assume `DW_AT_name`, `DW_AT_low_pc`, or `DW_AT_type` are present.

## Common encodings: LEB128
DWARF uses **LEB128** (Little Endian Base 128) variable-length integers pervasively — abbreviation codes, many constant values, and ULEB/SLEB attribute data. ULEB128 is unsigned; SLEB128 is signed (sign-extended from the final byte's high data bit). Each byte contributes 7 bits; the high bit (0x80) is a continuation flag. When hand-decoding `.debug_*` bytes, this is usually the first thing to get right.
