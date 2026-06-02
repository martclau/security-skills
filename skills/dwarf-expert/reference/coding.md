# Writing, Modifying, or Reviewing Code That Interacts With DWARF

You may be asked to write, modify, or review code that handles, parses, or emits DWARF. Use your DWARF expertise here, but not on unrelated code in the same project.

## General guidelines
- **Rely on authoritative sources** for ground truth about sections, DIEs, attributes, forms, and encodings: the DWARF5 standard (dwarfstd.org) and LLVM/libdwarf source. Don't hardcode constants from memory without checking.
- **Account for the awkward parts of the model** (these are where parsers break — see `data-model.md`): the `DW_AT_high_pc` address-vs-constant form-class check; optional/missing attributes; declaration vs definition (`DW_AT_specification`); abstract origins/inlining (`DW_AT_abstract_origin`); non-contiguous ranges (`DW_AT_ranges`); cross-CU/cross-file references; and, for DWARF5, resolving the `*_base` attributes before decoding indexed forms (`strx`/`addrx`/`loclistx`/`rnglistx`).
- **Branch on version.** Header layout, line-program header, and the location/range sections all differ by version. A single binary can mix CU versions.

## Writing code
- **Prefer Python for scripting.** For filtering/searching/one-off analysis, Python with `pyelftools` is usually the fastest path unless another language is specified.
- **Leverage existing libraries** rather than hand-rolling a parser (see the table below); only parse bytes by hand when the task is specifically about the wire format or no suitable library exists.
- **Refer to library documentation** (in-code and online) as needed; pyelftools' `examples/` directory is effectively executable documentation.

## Modifying code
- **Follow existing style**, naming, and formatting.
- **Group related changes** and separate unrelated ones into distinct steps.
- **Describe each change's purpose** to the user.
- **Flag large/complex changes before making them** — e.g. broad changes to support a new tag/attribute, or anything touching the version-branching logic.

## Reviewing code
- **Only suggest changes; don't modify** the code under review.
- **Probe the edge cases above**: missing attributes, declaration/specification DIEs, abstract origins, indexed-form base resolution, high_pc form class, non-contiguous ranges, 32- vs 64-bit DWARF, and version-specific section/header handling. These are the most common real defects in DWARF code.

## Common DWARF libraries
Prefer these when writing new code (pick the one matching the language):
| Library | Language | URL | Notes |
|---------|----------|-----|-------|
| `libdwarf` | C/C++ | https://github.com/davea42/libdwarf-code | Lower-level interface; the engine behind `dwarfdump`. |
| `pyelftools` | Python | https://github.com/eliben/pyelftools | Pure-Python; also parses ELF generally. Great `examples/`. |
| `gimli` | Rust | https://github.com/gimli-rs/gimli | Performance-focused; typically paired with the `object` crate to open files. |
| `debug/dwarf` | Go | https://pkg.go.dev/debug/dwarf | Standard library; pair with `debug/elf`/`debug/macho`/`debug/pe`. |
| `LibObjectFile` | .NET | https://github.com/xoofx/LibObjectFile | Also handles ELF/PE-COFF object files generally. |
| LLVM `DebugInfo/DWARF` | C++ | (LLVM source) | The reference implementation; usable as a library and as the canonical behavior to match. |

## Worked pyelftools examples
These follow the patterns in pyelftools' own `examples/`. The entry point is always `ELFFile(...).get_dwarf_info()`.

**Walk the DIE tree of every CU:**
```python
from elftools.elf.elffile import ELFFile

with open(path, 'rb') as f:
    elf = ELFFile(f)
    if not elf.has_dwarf_info():
        raise SystemExit('no DWARF info')
    dwarf = elf.get_dwarf_info()
    for CU in dwarf.iter_CUs():
        print(f'CU at {CU.cu_offset:#x}, version {CU["version"]}, len {CU["unit_length"]}')
        top = CU.get_top_DIE()            # root DIE (DW_TAG_compile_unit)
        for die in CU.iter_DIEs():        # depth-first over the CU
            if die.is_null():
                continue                  # null DIE terminates a sibling chain
            name = die.attributes.get('DW_AT_name')
            print(f'  {die.tag} @ {die.offset:#x}'
                  + (f' name={name.value.decode()}' if name else ''))
```

**Find DIEs by name (exhaustive):**
```python
def find_dies_by_name(dwarf, target):
    hits = []
    for CU in dwarf.iter_CUs():
        for die in CU.iter_DIEs():
            if die.is_null():
                continue
            nm = die.attributes.get('DW_AT_name')
            if nm and nm.value.decode('utf-8', 'replace') == target:
                hits.append(die)
    return hits
```

**Resolve a DIE's type by following `DW_AT_type`:**
```python
def type_die_of(die, CU):
    t = die.attributes.get('DW_AT_type')
    if t is None:
        return None
    # DW_FORM_ref* are offsets relative to the CU; get_DIE_from_refaddr handles it.
    return CU.get_DIE_from_refaddr(t.value + CU.cu_offset)
```
(Be careful: `DW_FORM_ref_addr` is an absolute `.debug_info` offset and may cross CUs; the CU-relative refs add `cu_offset`. Check `t.form` if both can occur.)

**Decode an address to function/file/line:** see the address-mapping example in `line-and-expressions.md`, which also shows the required `DW_AT_high_pc` form-class handling via `describe_form_class`.

**Parse a DWARF expression block:**
```python
from elftools.dwarf.dwarf_expr import DWARFExprParser
parser = DWARFExprParser(CU.structs)
loc = die.attributes['DW_AT_location']
if loc.form == 'DW_FORM_exprloc':
    for op in parser.parse_expr(loc.value):
        print(op.op_name, op.args)
# If DW_AT_location is a loclist reference instead, resolve it via the
# location-lists section (see line-and-expressions.md).
```

When pyelftools' high-level helpers don't expose something, `CU.structs` gives the version-aware Construct definitions for low-level parsing, and `elftools.dwarf.descriptions` (`describe_form_class`, `describe_attr_value`, etc.) helps interpret raw values.
