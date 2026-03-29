---
name: decompile-idapro
description: Decompile a binary with IDA Pro headless mode. Extracts pseudocode for every non-thunk function into <binary>.dec/<funcname>@<ADDR>.c files. Invoke manually with /decompile-idapro <binary>.
argument-hint: <binary_path>
disable-model-invocation: true
allowed-tools: Bash(python3 *), Bash(rm -rf *), Bash(file *), Bash(ls *)
---

Decompile `$ARGUMENTS` using IDA Pro 9.3 via the `idapro` Python library (headless idalib).

This skill is the Python equivalent of [haruspex](https://github.com/0xdea/haruspex) — a Rust tool that uses idalib to extract Hex-Rays pseudocode for every non-thunk function in a binary. The bundled `scripts/decompile.py` uses the same logic.

## IDA Pro installation

```
~/.local/share/applications/IDA Professional 9.3/
```

The `idapro` Python package lives at `<IDADIR>/idalib/python/` and is automatically added to `sys.path` by `decompile.py`. The install dir is registered in `~/.idapro/ida-config.json` so no `IDADIR` env var is needed.

## Steps

1. **Validate** the binary path `$ARGUMENTS` exists and is a file.

2. **Check for an existing output directory** at `$ARGUMENTS.dec`. If it exists and is non-empty, remove it first — the script refuses to overwrite (matching haruspex):
   ```bash
   rm -rf "$ARGUMENTS.dec"
   ```

3. **Run the decompiler**, suppressing IDA Pro's verbose console output on stderr:
   ```bash
   python3 "${CLAUDE_SKILL_DIR}/scripts/decompile.py" "$ARGUMENTS" 2>/dev/null
   ```

4. **Report** the summary line emitted by the script, e.g.:
   ```
   [+] Decompiled 5718 functions into `/path/to/binary.dec`
   ```

## What the script does

- Removes stale IDA sidecar files (`.id0`, `.id1`, `.id2`, `.nam`, `.til`) before opening — a previous interrupted run leaves these behind and causes `open_database` to return error code 4 (corrupted DB).
- Opens the binary with `idapro.open_database(path, run_auto_analysis=True)` and waits for full auto-analysis.
- Explicitly loads the architecture-appropriate Hex-Rays decompiler plugin (e.g. `hexx64` for x86-64) via `idaapi.load_plugin()` — plugins are not auto-loaded in headless/idalib mode; this must be called before `ida_hexrays.init_hexrays_plugin()`.
- Iterates all functions, skips thunks (`FUNC_THUNK`), decompiles the rest, and writes pseudocode to `<binary>.dec/<funcname>@<ADDRESS>.c`.
- Treats license errors as fatal; all other decompiler errors are skipped silently.
- Closes the database without saving (`idapro.close_database(save=False)`).

## IDA 9.x API notes

- `get_inf_structure()` was removed in IDA 9.x; use `idaapi.inf_get_procname()`, `idaapi.inf_get_cc_id()`, `idaapi.inf_get_filetype()` instead.
- Gepetto plugin (`~/.idapro/plugins/gepetto/`) fails to load in headless mode (Qt not available) — harmless, noisy on stderr, suppressed by `2>/dev/null`.

## Decompiler plugin map

| Processor (`inf_get_procname`) | Plugin |
|---|---|
| `metapc` (x86 / x86-64) | `hexx64` |
| `arm` / `armb` | `hexarm` |
| `mips` / `mipsr` / `mipsb` | `hexmips` |
| `ppc` | `hexppc` |
| `riscv` | `hexrv` |
| `v850` | `hexv850` |
| `arc` | `hexarc` |

If the processor name is unrecognised, the script attempts to load all plugins and lets `init_hexrays_plugin()` succeed on the right one.

## Reference

- Rust reference implementation: [haruspex](https://github.com/0xdea/haruspex) (`haruspex/` in this repo)
- IDA Pro idalib Python example: `~/.local/share/applications/IDA Professional 9.3/idalib/examples/idacli.py`
- Blog post: [4 Powerful Applications of IDALib](https://hex-rays.com/blog/4-powerful-applications-of-idalib-headless-ida-in-action)
- Binary Ninja equivalent skill: `decompile-binaryninja` (in the same skills directory)
