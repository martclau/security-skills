# Parsing DWARF With dwarfdump / llvm-dwarfdump

`dwarfdump` parses and dumps DWARF information: dump individual sections, display DIE trees (parents and children), search DIEs by name or address, and verify well-formedness. It is the primary tool for DWARF-specific inspection and is more capable for this than `readelf`.

## Two implementations — check which you have
Two utilities both commonly named `dwarfdump` exist, with overlapping but **different** command-line options:
- **libdwarf's** `dwarfdump`
- **LLVM's** `llvm-dwarfdump`

The bare command `dwarfdump` may be either, depending on the system. Run `dwarfdump --version` first to find out. The options below are for **LLVM's** implementation unless noted; if the system has libdwarf's `dwarfdump`, consult `dwarfdump --help`, as flag names differ (e.g. libdwarf uses short flags like `-i`, `-l`, `-a`). On macOS, `dwarfdump` is Apple's libdwarf-derived tool.

## Commonly used options (LLVM)
- `dwarfdump --version` — identify the implementation/version.
- `dwarfdump --help` — list options.
- `dwarfdump --all` — dump all DWARF sections.
- `dwarfdump --<debug_section>` — dump one section, e.g. `--debug-info`, `--debug-abbrev`, `--debug-line`, `--debug-addr`, `--debug-names`, `--debug-loclists`, `--debug-rnglists`. Repeatable to dump several.
- `dwarfdump --show-children [--recurse-depth=<n>]` — when printing selected DIEs, also show their children (optionally depth-limited). Use for functions and aggregate types, whose children hold parameters, locals, and members.
- `dwarfdump --show-parents [--parent-recurse-depth=<n>]` — show a DIE's parents; use when the enclosing scope (namespace, class, CU) matters.
- `dwarfdump --show-form` — print the `DW_FORM_*` of each attribute. Use when the encoding matters (e.g. diagnosing the `DW_AT_high_pc` address-vs-constant question, or indexed forms).
- `dwarfdump --verbose` — print low-level encoding details; useful for debugging the bytes.
- `dwarfdump --find=<pattern>` — fast lookup of an exact name via the accelerator tables (`.debug_names`/pubnames). Not exhaustive; if it finds nothing, fall back to `--name`.
- `dwarfdump --name <pattern> [--ignore-case] [--regex]` — exhaustive search over all DIEs for a name match; `--regex` enables pattern search. Slower but complete; use when `--find` misses or you need patterns.
- `dwarfdump --lookup=<address>` — find the DIE at a specific address. Use when you have an address (e.g. from another DIE's reference) and want the corresponding DIE.

## Verification options (llvm-dwarfdump)
- `llvm-dwarfdump --verify <binary>` — validate structure: CU chains, DIE relationships, address ranges, references.
- `llvm-dwarfdump --verify --error-display=<mode>` — control detail: `quiet`, `summary`, `details`, `full`.
- `llvm-dwarfdump --verify --verify-json=<path>` — JSON error summary (good for CI).
- `llvm-dwarfdump --verify --quiet` — no stdout; rely on exit code (0 = valid).
- `llvm-dwarfdump --statistics <binary>` — single-line JSON of debug-info quality metrics; compare across builds/optimization levels to catch regressions.

## Searching for DIEs
Often you must locate specific DIEs (and their children/parents). Escalate through three tiers:

### 1. Simple search
Exact name or exact address → `--find`, `--name`, or `--lookup` directly.

### 2. Complex search via filtering
For criteria the built-in search can't express (e.g. "all formal parameters whose type is `float *`"), dump and filter with text tools:
| Step | Description | Example |
|------|-------------|---------|
| Initial filter | Dump and grep for a distinguishing token. | `dwarfdump <file> \| grep "float \*"` |
| Get DIE address | Print preceding context to capture the DIE's offset/address line. | `dwarfdump <file> \| grep -B 5 "float \*"` |
| Refine | Add filters to narrow to the desired tag. | `dwarfdump <file> \| grep -B 5 "float \*" \| grep "DW_TAG_formal_parameter"` |
| Uniform output | For each matching address, re-dump consistently. | `dwarfdump --lookup=<address> [--show-children] [--show-parents]` |

### 3. Scripted search
When filtering is too brittle or the criteria are genuinely structural (e.g. multiple exact attribute-value constraints, following `DW_AT_type`/`DW_AT_specification` references), write a Python script with `pyelftools` (see `coding.md`). Reserve this for cases where the text-filtering approach fails or becomes unwieldy.

## Tips
- Combine `--name`/`--find` with `--show-children`/`--show-parents` to get a DIE *in context* in one command.
- Use `--show-form` whenever an attribute's interpretation depends on its form (high_pc, indexed v5 forms, strings via strp/strx).
- For very large binaries, prefer `--find` (accelerator-backed) over `--name` (exhaustive) as a first pass.
