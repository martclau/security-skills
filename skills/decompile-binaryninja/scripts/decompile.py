#!/usr/bin/env python3
"""
decompile.py - Headless Binary Ninja full decompiler script

Extracts HLIL pseudocode for every function in a binary and writes each to a
separate .c file under <binary>.dec/, mirroring the output layout of haruspex
(https://github.com/0xdea/haruspex) and decompile.py (IDA Pro equivalent).

Usage:
    PYTHONPATH=~/Downloads/binaryninja/python python3 decompile.py <binary>
  or (using BN's bundled interpreter):
    ~/Downloads/binaryninja/bnpython3 decompile.py <binary>

Requirements:
    - Binary Ninja Commercial / Ultimate (headless requires Commercial or above)
    - Binary Ninja installed at ~/Downloads/binaryninja/ (default; override with BN_DIR)
"""

import os
import re
import sys

# ---------------------------------------------------------------------------
# Bootstrap: add the binaryninja Python package to sys.path if needed.
# Override the default install path with the BN_DIR environment variable.
# ---------------------------------------------------------------------------
_BN_DIR = os.environ.get("BN_DIR", os.path.expanduser("~/Downloads/binaryninja"))
_BN_PYTHON = os.path.join(_BN_DIR, "python")
if _BN_PYTHON not in sys.path:
    sys.path.insert(0, _BN_PYTHON)

from binaryninja import load, LogLevel
from binaryninja.log import log_to_stderr

# Suppress BN's info-level log noise; only show warnings and above
log_to_stderr(LogLevel.WarningLog)

# ---------------------------------------------------------------------------
# Constants (match haruspex / decompile.py naming conventions)
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


def function_signature(func) -> str:
    """Build a C-style function signature string from BN's type information."""
    try:
        ret = str(func.return_type) if func.return_type else "void"
        params = ", ".join(
            f"{p.type} {p.name}" if p.name else str(p.type)
            for p in func.parameter_vars
        )
        return f"{ret} {func.name}({params})"
    except Exception:
        return f"/* {func.name} */"


def decompile_to_file(func, filepath: str) -> bool:
    """
    Write HLIL pseudocode for *func* to *filepath*.
    Returns True on success, False if the function has no HLIL.
    """
    hlil = func.hlil
    if hlil is None:
        return False

    lines = [function_signature(func), "{"]
    for inst in hlil.instructions:
        lines.append(f"    {inst}")
    lines.append("}")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return True


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

    print(f"[*] Analyzing binary file `{binary_path}`")

    with load(binary_path) as bv:
        if bv is None:
            print(f"[!] Failed to load binary: {binary_path}", file=sys.stderr)
            return 1

        # Ensure full analysis has completed
        bv.update_analysis_and_wait()
        print("[+] Successfully analyzed binary file")
        print()

        arch_name = bv.arch.name if bv.arch else "unknown"
        plat_name = bv.platform.name if bv.platform else "unknown"
        print(f"[-] Architecture: {arch_name}")
        print(f"[-] Platform:     {plat_name}")
        print(f"[-] File type:    {bv.view_type}")
        print()

        # Prepare output directory: <binary>.dec/
        dirpath = binary_path + ".dec"
        print(f"[*] Preparing output directory `{dirpath}`")
        if os.path.isdir(dirpath):
            try:
                os.rmdir(dirpath)   # succeeds only if empty
            except OSError:
                print(
                    f"[!] Output directory `{dirpath}` already exists and is not empty",
                    file=sys.stderr,
                )
                return 1
        os.makedirs(dirpath)
        print("[+] Output directory is ready")
        print()

        print("[*] Extracting pseudocode of functions...")
        print()
        decompiled_count = 0

        for func in bv.functions:
            func_name = func.name or "[no name]"
            out_path = output_path(dirpath, func_name, func.start)

            try:
                if decompile_to_file(func, out_path):
                    print(f"{func_name} -> `{out_path}`")
                    decompiled_count += 1
            except Exception as exc:
                print(f"[!] Error decompiling {func_name}: {exc}", file=sys.stderr)
                continue

        if decompiled_count == 0:
            try:
                os.rmdir(dirpath)
            except OSError:
                pass
            print("[!] No functions were decompiled, check your input file", file=sys.stderr)
            return 1

        print()
        print(f"[+] Decompiled {decompiled_count} functions into `{dirpath}`")
        print(f"[+] Done processing binary file `{binary_path}`")

    return 0


if __name__ == "__main__":
    sys.exit(main())
