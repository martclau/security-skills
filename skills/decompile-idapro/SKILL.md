---
name: decompile-idapro
description: Decompile a binary with IDA Pro headless mode. Extracts pseudocode for every non-thunk function into <binary>.ida.dec/<funcname>@<ADDR>.c files. Invoke manually with /decompile-idapro <binary>.
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

1. **Validate** the binary path `$ARGUMENTS` exists and is a file. `$ARGUMENTS` is the binary path only — the `--aggressive` flag below is appended by this procedure, it is not part of `$ARGUMENTS`.

2. **Check for an existing output directory** at `$ARGUMENTS.ida.dec`. If it exists and is non-empty, remove it first — the script refuses to overwrite (matching haruspex):
   ```bash
   rm -rf "$ARGUMENTS.ida.dec"
   ```

3. **Run the decompiler**, suppressing IDA Pro's verbose console output on stderr:
   ```bash
   python3 "${CLAUDE_SKILL_DIR}/scripts/decompile.py" "$ARGUMENTS" 2>/dev/null
   ```
   If the user asked for the higher-recall pass, append `--aggressive` (or set
   `DECOMPILE_AGGRESSIVE=1`) — see "Default vs. aggressive mode" below:
   ```bash
   python3 "${CLAUDE_SKILL_DIR}/scripts/decompile.py" "$ARGUMENTS" --aggressive 2>/dev/null
   ```

4. **Report** the summary line emitted by the script, e.g.:
   ```
   [+] Decompiled 5718 functions into `/path/to/binary.ida.dec`
   ```

## What the script does

- **Detects UPX packing** (any `UPXn` PE section name, or the `UPX!` magic) and, when
  `upx` is available, transparently runs `upx -d` on a **throwaway copy** *before*
  analysis — otherwise a packed binary decompiles to only its handful of unpacking-stub
  functions instead of the real code. The original sample is **never modified** (it is
  copied to a temp dir first), and the `.ida.dec` output directory stays keyed to the
  original path. This is static decompression — the sample is **not executed**. It
  degrades gracefully (prints a warning and analyzes the packed stub) when `upx` is
  missing or the UPX header is tampered/unsupported. Set `DECOMPILE_NO_UNPACK=1` to skip
  unpacking entirely. See "Optional dependency: UPX" below.
- Removes stale IDA sidecar files (`.id0`, `.id1`, `.id2`, `.nam`, `.til`) before opening — a previous interrupted run leaves these behind and causes `open_database` to return error code 4 (corrupted DB).
- Opens the binary with `idapro.open_database(path, run_auto_analysis=True)` and waits for full auto-analysis.
- Explicitly loads the architecture-appropriate Hex-Rays decompiler plugin (e.g. `hexx64` for x86-64) via `idaapi.load_plugin()` — plugins are not auto-loaded in headless/idalib mode; this must be called before `ida_hexrays.init_hexrays_plugin()`.
- **Applies FLIRT library signatures on every run**, scoped to the *detected* compiler
  family (plus the Go stdlib for Go binaries) so matched library functions get real
  names/prototypes instead of `sub_*`. See "Default vs. aggressive mode" below.
- Iterates all functions, skips thunks (`FUNC_THUNK`) — unless `--aggressive` is set — decompiles the rest, and writes pseudocode to `<binary>.ida.dec/<funcname>@<ADDRESS>.c`.
- Prepends a short comment header to each `.c` (function name + address, `thunk`/`lib` flags, and caller/callee counts). The function prototype is already the first line of the pseudocode, so it is not repeated.
- Writes an **`index.json` manifest** into the output directory: top-level `meta` (tool, IDA version, binary path, sha256, size, arch, file type, function count, whether UPX was auto-unpacked) plus one entry per emitted function (`name`, `address`, `file`, `lines`, `is_thunk`, `is_lib`, `is_imported`, `n_callers`, `n_callees`) — so downstream tools/agents can navigate the output without globbing. Same schema as the `decompile-binaryninja` skill (`is_imported` is always `false` here — IDA exposes no direct per-function import flag; use `is_thunk`/`is_lib`).
- Treats license errors as fatal; all other decompiler errors are skipped silently.
- Closes the database without saving (`idapro.close_database(save=False)`).

## Default vs. aggressive mode (`--aggressive` / `-a` / `DECOMPILE_AGGRESSIVE=1`)

**Default (every run): scoped FLIRT signatures.** FLIRT application is cheap and high-value,
so it always runs — but scoped to the toolchain IDA detected:

- The compiler family is read from `inf_get_cc_id()` / `inf_get_filetype()` and mapped to
  the C-runtime signatures shipped with IDA (`vc*`/`msvc*` for MSVC, `gcc*` — plus
  `mingw*`/`cygwin*` on PE — for GNU, `bc*` for Borland, …). If the compiler can't be
  identified, it falls back to the broad CRT set so detection failure never costs names.
- **Go** binaries (auto-detected via `Go build ID` / `.gopclntab` / `go.buildinfo` /
  `runtime.main`) additionally get the Go-stdlib signatures (`go_std_abi0`,
  `go_std_abiinternal`), so functions are named `runtime.*` / `net/http.*` / `main.*`.
- Scoping (rather than firing every compiler family) avoids spurious cross-compiler
  matches. FLIRT needs a pattern+CRC hit, so a queued-but-unmatched signature costs
  analysis time, not false names.

**`--aggressive` adds two higher-cost steps** (trades speed/precision for recall):

1. **Max analysis flags + full re-plan** — sets every `AF_*`/`AF2_*` flag and re-plans the
   whole image so IDA chases more code into functions. On well-formed PEs this is marginal;
   it matters for obfuscated / position-independent / sparsely-referenced code, but on
   ordinary binaries it can also turn data into spurious `sub_*` and is slower. FLIRT is
   applied *after* the re-plan so signatures also land on newly-discovered code.
2. **Include thunks** — does not skip `FUNC_THUNK` functions (default skips them, matching
   haruspex; their pseudocode is trivial trampoline code).

Everything here is purely static — nothing is executed. Combine freely with the UPX
auto-unpack (e.g. a packed Go binary unpacks, then gets Go FLIRT applied).

## Optional dependency: UPX

The auto-unpack step (above) shells out to the standard `upx` binary. It is looked up on
`PATH` and then at `~/.local/bin/upx`, `/usr/local/bin/upx`, `/usr/bin/upx`. If absent,
packed binaries still decompile — you just get the unpacking stub. To install the
official static build:

```bash
ver=4.2.4
curl -fsSL -o /tmp/upx.tar.xz \
  "https://github.com/upx/upx/releases/download/v${ver}/upx-${ver}-amd64_linux.tar.xz"
tar -C /tmp -xf /tmp/upx.tar.xz
install -m755 /tmp/upx-${ver}-amd64_linux/upx ~/.local/bin/upx
```

`upx -d` only reverses the (lossless, reversible) UPX compression; it does not run the
target. UPX is the only packer handled automatically — other packers/protectors (ASPack,
Themida, custom crypters) are not, and a few functions from such a binary is the signal
to unpack it by other means first.

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
