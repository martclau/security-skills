---
name: decompile-binaryninja
description: Decompile a binary with Binary Ninja headless mode. Extracts Pseudo C for every function into <binary>.bn.dec/<funcname>@<ADDR>.c files. Invoke manually with /decompile-binaryninja <binary>.
argument-hint: <binary_path>
disable-model-invocation: true
allowed-tools: Bash(python3 *), Bash(rm -rf *), Bash(file *), Bash(ls *)
---

Decompile `$ARGUMENTS` using Binary Ninja headless mode via the bundled `scripts/decompile.py` script at `${CLAUDE_SKILL_DIR}/scripts/decompile.py`.

This skill is the Binary Ninja equivalent of [haruspex](https://github.com/0xdea/haruspex) and the IDA Pro `decompile-idapro` skill. It renders each function as **Pseudo C** (Binary Ninja's C-like decompiler output, the same as the UI "Pseudo C" view), falling back to raw HLIL where a Pseudo C representation is unavailable.

## Binary Ninja installation

```
~/Downloads/binaryninja/
```

The `binaryninja` Python package lives at `<BN_DIR>/python/`. The script adds this to `sys.path` automatically. Override the default install path with the `BN_DIR` environment variable if needed.

**License requirement:** Headless mode requires Binary Ninja **Commercial** or above. Personal edition does not support headless operation.

## Steps

1. **Validate** the binary path `$ARGUMENTS` exists and is a file.

2. **Check for an existing output directory** at `$ARGUMENTS.bn.dec`. If it exists and is non-empty, remove it first — the script refuses to overwrite:
   ```bash
   rm -rf "$ARGUMENTS.bn.dec"
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
   [+] Decompiled 312 functions into `/path/to/binary.bn.dec`
   ```

## What the script does

- **Detects UPX packing** (any `UPXn` PE section name, or the `UPX!` magic) and, when
  `upx` is available, transparently runs `upx -d` on a **throwaway copy** *before*
  analysis — otherwise a packed binary decompiles to only its handful of unpacking-stub
  functions instead of the real code. The original sample is **never modified** (it is
  copied to a temp dir first), and the `.bn.dec` output directory stays keyed to the
  original path. This is static decompression — the sample is **not executed**. It
  degrades gracefully (warns and analyzes the packed stub) when `upx` is missing or the
  UPX header is tampered/unsupported. Set `DECOMPILE_NO_UNPACK=1` to skip unpacking.
  `upx` is looked up on `PATH` then `~/.local/bin`, `/usr/local/bin`, `/usr/bin`; only
  UPX is handled automatically (other packers/protectors are not). Shared behavior with
  the `decompile-idapro` skill.
- Adds `~/Downloads/binaryninja/python` to `sys.path` automatically.
- Opens the binary with `binaryninja.load(path, options=...)` using a context manager (prevents memory leaks).
- **Enables the function signature matcher on every run** (`analysis.signatureMatcher.autorun`) so C-runtime library functions get real names instead of `sub_*` — see "Library-function naming" below.
- Calls `bv.update_analysis_and_wait()` to ensure full analysis before decompiling.
- Suppresses BN's info-level log output via `log_to_stderr(LogLevel.WarningLog)`.
- Iterates `bv.functions` and renders each to **Pseudo C** via a single-function linear view (`LinearViewObject.single_function_language_representation`, walked with a `LinearViewCursor`), falling back to a single-function HLIL view; writes the result to `<binary>.bn.dec/<funcname>@<ADDRESS>.c`. Rendering uses `DisassemblySettings` with `ShowAddress=False` (no address gutter) and `WaitForIL=True` (deterministic output).
- Functions with no decompilable body (e.g. unresolved imports, data functions) are silently skipped.
- Output filename format matches haruspex: `<sanitized_name>@<HEX_ADDR>.c`.
- Prepends a short comment header to each `.c` (function name + address, `thunk`/`lib`/`imported` flags, and caller/callee counts). The prototype is already the first line of the Pseudo C, so it is not repeated.
- Writes an **`index.json` manifest** into the output directory: top-level `meta` (tool, BN version, binary path, sha256, size, arch, file type, function count, whether UPX was auto-unpacked) plus one entry per emitted function (`name`, `address`, `file`, `lines`, `is_thunk`, `is_lib`, `is_imported`, `n_callers`, `n_callees`) — so downstream tools/agents can navigate the output without globbing. Same schema as the `decompile-idapro` skill.

## Library-function naming

Library functions are named automatically — no flag needed (unlike the `decompile-idapro`
counterpart, which must opt into FLIRT):

- **WARP** (Binary Ninja's current signature system) is a bundled core plugin shipping
  signature libraries (`msvcrt`, `libc6`, `libstdc++`, `libgcc`, …) and runs as part of the
  default **"full"** analysis (BN's default `analysis.mode`). This is the primary, modern
  naming path and needs no configuration.
- The script *additionally* sets `analysis.signatureMatcher.autorun = True` on every load.
  This legacy signature matcher is **deprecated in BN in favor of WARP**, but still applies
  the bundled CRT signature libraries and can name functions WARP misses, so it is kept on
  as belt-and-suspenders. (BN's `analysis.mode` already defaults to `"full"`, so the script
  does not set it.)
- **Go** binaries are named from BN's built-in `.gopclntab` symbol recovery, which runs
  regardless of the above (BN ships no Go-specific signature library).
- **Rust** binaries: BN demangles Rust symbols and renders *Pseudo Rust* (the bundled
  `liblang_pseudorust` plugin), so symbol-bearing Rust reads cleanly. But BN ships **no Rust
  signature library** (WARP bundles only `libc6`/`libgcc`/`libstdc++`/`msvcrt`), so on a
  **stripped** Rust binary the std/runtime/crate functions stay `sub_*` unless you add a Rust
  WARP/signature library yourself. This is the one spot where the `decompile-idapro`
  counterpart does more out of the box: IDA ships bundled Rust FLIRT signatures
  (`sig/rust/<triple>/`) that the skill applies automatically.

All of this is purely static — nothing is executed — and composes with the UPX auto-unpack
(e.g. a packed binary unpacks, then gets analyzed and named).

## IL layers in Binary Ninja

Binary Ninja exposes multiple analysis layers. This script renders **Pseudo C** (the top layer), with **HLIL** as the fallback:

| Layer | API | Description |
|---|---|---|
| Disassembly | `func.instructions` | Raw assembly |
| LLIL | `func.llil` | Lifted IL — architecture-normalized |
| MLIL | `func.mlil` | Variables and types introduced |
| HLIL | `func.hlil` | C-like pseudocode (fallback used here) |
| **Pseudo C** | **`LinearViewObject.single_function_language_representation`** | **Rendered C output, UI "Pseudo C" view (used here)** |

## Key API reference

```python
from binaryninja import load
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption
from binaryninja.lineardisassembly import LinearViewObject, LinearViewCursor

with load(binary_path) as bv:
    bv.update_analysis_and_wait()

    print(bv.arch.name)       # architecture
    print(bv.platform.name)   # platform
    print(bv.view_type)       # file type

    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowAddress, False)
    settings.set_option(DisassemblyOption.WaitForIL, True)

    for func in bv.functions:
        print(func.name, hex(func.start))    # name + start address

        # Render Pseudo C for this function (HLIL fallback via single_function_hlil):
        obj = LinearViewObject.single_function_language_representation(func, settings)
        cur = LinearViewCursor(obj); cur.seek_to_begin()
        while True:
            for line in cur.lines:
                print(line)               # rendered Pseudo C line
            if not cur.next():
                break
```

## Reference

- Binary Ninja cookbook: <https://docs.binary.ninja/dev/cookbook.html>
- Headless automation examples: <https://www.mintlify.com/Vector35/binaryninja-api/examples/headless-automation>
- Bundled Python examples: `~/Downloads/binaryninja/examples/python/`
- Rust reference implementation (haruspex): <https://github.com/0xdea/haruspex>
- IDA Pro equivalent skill: `decompile-idapro` (in the same skills directory)
