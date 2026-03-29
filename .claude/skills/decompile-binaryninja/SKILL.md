---
name: decompile-binaryninja
description: Decompile a binary with Binary Ninja headless mode. Extracts HLIL pseudocode for every function into <binary>.dec/<funcname>@<ADDR>.c files. Invoke manually with /decompile-binaryninja <binary>.
argument-hint: <binary_path>
disable-model-invocation: true
allowed-tools: Bash(python3 *), Bash(rm -rf *), Bash(file *), Bash(ls *)
---

Decompile `$ARGUMENTS` using Binary Ninja headless mode via the bundled `scripts/decompile.py` script at `${CLAUDE_SKILL_DIR}/scripts/decompile.py`.

This skill is the Binary Ninja equivalent of [haruspex](https://github.com/0xdea/haruspex) and the IDA Pro `decompile-idapro` skill. It uses Binary Ninja's HLIL (High Level IL) — the same decompiler layer exposed under "Pseudo C" view in the UI — to extract pseudocode for every function.

## Binary Ninja installation

```
~/Downloads/binaryninja/
```

The `binaryninja` Python package lives at `<BN_DIR>/python/`. The script adds this to `sys.path` automatically. Override the default install path with the `BN_DIR` environment variable if needed.

**License requirement:** Headless mode requires Binary Ninja **Commercial** or above. Personal edition does not support headless operation.

## Steps

1. **Validate** the binary path `$ARGUMENTS` exists and is a file.

2. **Check for an existing output directory** at `$ARGUMENTS.dec`. If it exists and is non-empty, remove it first — the script refuses to overwrite:
   ```bash
   rm -rf "$ARGUMENTS.dec"
   ```

3. **Run the decompiler** using the system Python with the BN package on the path:
   ```bash
   PYTHONPATH=~/Downloads/binaryninja/python python3 "${CLAUDE_SKILL_DIR}/scripts/decompile.py" "$ARGUMENTS" 2>/dev/null
   ```
   Or using BN's bundled Python interpreter (avoids any PYTHONPATH setup):
   ```bash
   ~/Downloads/binaryninja/bnpython3 "${CLAUDE_SKILL_DIR}/scripts/decompile.py" "$ARGUMENTS" 2>/dev/null
   ```

4. **Report** the summary line emitted by the script, e.g.:
   ```
   [+] Decompiled 312 functions into `/path/to/binary.dec`
   ```

## What the script does

- Adds `~/Downloads/binaryninja/python` to `sys.path` automatically.
- Opens the binary with `binaryninja.load(path)` using a context manager (prevents memory leaks).
- Calls `bv.update_analysis_and_wait()` to ensure full analysis before decompiling.
- Suppresses BN's info-level log output via `log_to_stderr(LogLevel.WarningLog)`.
- Iterates `bv.functions`, decompiles each via `func.hlil`, and writes pseudocode to `<binary>.dec/<funcname>@<ADDRESS>.c`.
- Functions with no HLIL (e.g. unresolved imports, data functions) are silently skipped.
- Output filename format matches haruspex: `<sanitized_name>@<HEX_ADDR>.c`.

## IL layers in Binary Ninja

Binary Ninja exposes multiple analysis layers. This script uses **HLIL**, the highest level:

| Layer | API | Description |
|---|---|---|
| Disassembly | `func.instructions` | Raw assembly |
| LLIL | `func.llil` | Lifted IL — architecture-normalized |
| MLIL | `func.mlil` | Variables and types introduced |
| **HLIL** | **`func.hlil`** | **C-like pseudocode (used here)** |
| Pseudo C | Linear view `"Pseudo C"` | Rendered C output (UI representation) |

## Key API reference

```python
from binaryninja import load

with load(binary_path) as bv:
    bv.update_analysis_and_wait()

    print(bv.arch.name)       # architecture
    print(bv.platform.name)   # platform
    print(bv.view_type)       # file type

    for func in bv.functions:
        print(func.name)              # function name
        print(hex(func.start))        # start address
        print(func.return_type)       # return type
        print(func.parameter_vars)    # parameters

        hlil = func.hlil              # HighLevelILFunction or None
        if hlil:
            for inst in hlil.instructions:
                print(inst)           # C-like pseudocode line
```

## Reference

- Binary Ninja cookbook: <https://docs.binary.ninja/dev/cookbook.html>
- Headless automation examples: <https://www.mintlify.com/Vector35/binaryninja-api/examples/headless-automation>
- Bundled Python examples: `~/Downloads/binaryninja/examples/python/`
- Rust reference implementation (haruspex): <https://github.com/0xdea/haruspex>
- IDA Pro equivalent skill: `decompile-idapro` (in the same skills directory)
