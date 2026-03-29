#!/usr/bin/env python3
"""
decompile.py - Headless full decompiler using IDA Pro 9.x idalib Python bindings

Mirrors haruspex (https://github.com/0xdea/haruspex): extracts pseudocode for
every non-thunk function and writes each to a separate .c file under <binary>.dec/

Usage:
    python3 decompile.py <binary_file>

Requirements:
    - IDA Pro 9.x with a valid Hex-Rays decompiler license
    - idapro Python package on PYTHONPATH  (ships with IDA under idalib/python/)
    - IDADIR env var OR ~/.idapro/ida-config.json pointing at the IDA install dir

Quick setup (if IDADIR is not already in the environment):
    export IDADIR="$HOME/.local/share/applications/IDA Professional 9.3"
    export PYTHONPATH="$IDADIR/idalib/python"
    python3 decompile.py /path/to/binary
"""

import os
import re
import sys

# ---------------------------------------------------------------------------
# Bootstrap: add the idapro package to sys.path if PYTHONPATH is not set.
# The idapro package lives in <IDADIR>/idalib/python/
# ---------------------------------------------------------------------------
_IDA_DEFAULT = os.path.expanduser(
    "~/.local/share/applications/IDA Professional 9.3"
)
_IDADIR = os.environ.get("IDADIR", _IDA_DEFAULT)
_IDALIB_PYTHON = os.path.join(_IDADIR, "idalib", "python")

if _IDALIB_PYTHON not in sys.path:
    sys.path.insert(0, _IDALIB_PYTHON)

import idapro          # loads libidalib.so and initialises the IDA kernel
import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idautils
import idc

# Decompiler plugin name for each IDA processor family
_PROC_TO_DECOMPILER = {
    "metapc": "hexx64",   # x86 / x86-64
    "arm":    "hexarm",   # ARM / AArch64
    "armb":   "hexarm",
    "mips":   "hexmips",
    "mipsr":  "hexmips",
    "mipsb":  "hexmips",
    "ppc":    "hexppc",
    "riscv":  "hexrv",
    "v850":   "hexv850",
    "arc":    "hexarc",
}


# ---------------------------------------------------------------------------
# Constants (match haruspex exactly)
# ---------------------------------------------------------------------------
MAX_FILENAME_LEN = 64
_RESERVED_RE = re.compile(r'[./:<>"\\|?*]')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sanitize_name(name: str) -> str:
    return _RESERVED_RE.sub("_", name)[:MAX_FILENAME_LEN]


def output_path(dirpath: str, func_name: str, start_ea: int) -> str:
    safe = sanitize_name(func_name) if func_name else "[no_name]"
    return os.path.join(dirpath, f"{safe}@{start_ea:X}.c")


def decompile_to_file(cfunc, filepath: str) -> None:
    lines = [
        ida_lines.tag_remove(line.line)
        for line in cfunc.get_pseudocode()
    ]
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(f"Usage: {sys.argv[0]} <binary_file>", file=sys.stderr)
        return 1

    binary_path = os.path.abspath(sys.argv[1])

    if not os.path.isfile(binary_path):
        print(f"[!] File not found: {binary_path}", file=sys.stderr)
        return 1

    # Remove any stale IDA database files that would cause "corrupted DB" errors
    for ext in (".id0", ".id1", ".id2", ".nam", ".til"):
        stale = binary_path + ext
        if os.path.exists(stale):
            os.remove(stale)

    # Open binary and run auto-analysis (equivalent to IDB::open in haruspex)
    print(f"[*] Analyzing binary file `{binary_path}`")
    idapro.open_database(binary_path, run_auto_analysis=True)
    print("[+] Successfully analyzed binary file")
    print()

    # Print binary metadata (IDA 9.x uses inf_get_* functions)
    import idaapi
    proc_name = idaapi.inf_get_procname()
    print(f"[-] Processor: {proc_name}")
    print(f"[-] Compiler:  {idaapi.inf_get_cc_id()}")
    print(f"[-] File type: {idaapi.inf_get_filetype()}")
    print()

    # Load the architecture-appropriate Hex-Rays decompiler plugin and initialise it.
    # The plugin must be explicitly loaded in headless/idalib mode.
    plugin_name = _PROC_TO_DECOMPILER.get(proc_name.lower())
    if plugin_name:
        idaapi.load_plugin(plugin_name)
    else:
        # Unknown architecture: try all known decompiler plugins
        for p in _PROC_TO_DECOMPILER.values():
            idaapi.load_plugin(p)

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available", file=sys.stderr)
        idapro.close_database(save=False)
        return 1

    # Prepare output directory: <binary>.dec/
    dirpath = binary_path + ".dec"
    print(f"[*] Preparing output directory `{dirpath}`")
    if os.path.isdir(dirpath):
        try:
            os.rmdir(dirpath)          # only succeeds if empty
        except OSError:
            print(
                f"[!] Output directory `{dirpath}` already exists and is not empty",
                file=sys.stderr,
            )
            idapro.close_database(save=False)
            return 1
    os.makedirs(dirpath)
    print("[+] Output directory is ready")
    print()

    # Decompile all non-thunk functions
    print("[*] Extracting pseudocode of functions...")
    print()
    decompiled_count = 0

    for start_ea in idautils.Functions():
        func = ida_funcs.get_func(start_ea)
        if func is None:
            continue

        # Skip thunk functions (mirrors FunctionFlags::THUNK in haruspex)
        if func.flags & ida_funcs.FUNC_THUNK:
            continue

        func_name = idc.get_func_name(start_ea) or "[no name]"
        out_path = output_path(dirpath, func_name, start_ea)

        try:
            cfunc = ida_hexrays.decompile(start_ea)
            if cfunc is None:
                continue
            decompile_to_file(cfunc, out_path)
            print(f"{func_name} -> `{out_path}`")
            decompiled_count += 1

        except ida_hexrays.DecompilationFailure as exc:
            if "license" in str(exc).lower():
                print(f"[!] Decompiler license error: {exc}", file=sys.stderr)
                idapro.close_database(save=False)
                return 1
            continue  # other decompiler errors are non-fatal

        except Exception as exc:
            print(f"[!] Unexpected error decompiling {func_name}: {exc}", file=sys.stderr)
            continue

    # Clean up and report
    if decompiled_count == 0:
        try:
            os.rmdir(dirpath)
        except OSError:
            pass
        print("[!] No functions were decompiled, check your input file", file=sys.stderr)
        idapro.close_database(save=False)
        return 1

    print()
    print(f"[+] Decompiled {decompiled_count} functions into `{dirpath}`")
    print(f"[+] Done processing binary file `{binary_path}`")

    idapro.close_database(save=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
