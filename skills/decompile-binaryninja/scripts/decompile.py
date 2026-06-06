#!/usr/bin/env python3
"""
decompile.py - Headless Binary Ninja full decompiler script

Extracts HLIL pseudocode for every function in a binary and writes each to a
separate .c file under <binary>.bn.dec/, mirroring the output layout of haruspex
(https://github.com/0xdea/haruspex) and decompile.py (IDA Pro equivalent).

Usage:
    PYTHONPATH=~/Downloads/binaryninja/python python3 decompile.py <binary>
  or (using BN's bundled interpreter):
    ~/Downloads/binaryninja/bnpython3 decompile.py <binary>

Requirements:
    - Binary Ninja Commercial / Ultimate (headless requires Commercial or above)
    - Binary Ninja installed at ~/Downloads/binaryninja/ (default; override with BN_DIR)
"""

import atexit
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Bootstrap: add the binaryninja Python package to sys.path if needed.
# Override the default install path with the BN_DIR environment variable.
# ---------------------------------------------------------------------------
_BN_DIR = os.environ.get("BN_DIR", os.path.expanduser("~/Downloads/binaryninja"))
_BN_PYTHON = os.path.join(_BN_DIR, "python")
if _BN_PYTHON not in sys.path:
    sys.path.insert(0, _BN_PYTHON)

from binaryninja import load, LogLevel, core_version
from binaryninja.log import log_to_stderr
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, SymbolType, InstructionTextTokenType
from binaryninja.lineardisassembly import LinearViewObject, LinearViewCursor

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


def _line_text(line) -> str:
    """Render one linear-view line to text, dropping BN's tag-indicator tokens
    (TagToken renders as emoji glyphs like 🌐/❓/🚫 — UI annotations, not code).
    Indentation (a separate token type) is preserved."""
    return "".join(
        t.text for t in line.contents.tokens
        if t.type != InstructionTextTokenType.TagToken
    )


def _render_linear(obj) -> list:
    """Walk a LinearViewObject and return its rendered text lines (in order)."""
    cur = LinearViewCursor(obj)
    cur.seek_to_begin()
    out = []
    while True:
        out += [_line_text(line) for line in cur.lines]
        if not cur.next():
            break
    return out


def render_function(func, settings) -> "list | None":
    """Render *func* to pseudocode lines. Prefer true Pseudo C (BN's 'Pseudo C'
    language representation — real C syntax with correct nesting/types, matching
    the UI Pseudo C view); fall back to HLIL. Returns None if the function has no
    decompilable body (e.g. unresolved imports, data functions)."""
    for factory in (LinearViewObject.single_function_language_representation,
                    LinearViewObject.single_function_hlil):   # HLIL fallback
        try:
            lines = _render_linear(factory(func, settings))
            if lines:
                return lines
        except Exception:
            continue
    return None


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def func_flags(func) -> dict:
    """Best-effort {is_thunk, is_lib, is_imported} for a BN function."""
    out = {"is_thunk": False, "is_lib": False, "is_imported": False}
    try:
        out["is_thunk"] = bool(func.is_thunk)
    except Exception:
        pass
    try:
        st = func.symbol.type if func.symbol else None
        out["is_imported"] = st == SymbolType.ImportedFunctionSymbol
        out["is_lib"] = st == SymbolType.LibraryFunctionSymbol
    except Exception:
        pass
    return out


def function_header(func, name: str, flags: dict, n_callers: int, n_callees: int) -> list:
    """Compact comment block prepended to each .c (the prototype is already the
    first line of the Pseudo C body, so it is not repeated here)."""
    tags = [k[3:] for k in ("is_thunk", "is_lib", "is_imported") if flags.get(k)]
    tag = f"  [{', '.join(tags)}]" if tags else ""
    return [
        f"// {name} @ {func.start:#x}{tag}",
        f"// callers: {n_callers}   callees: {n_callees}",
        "",
    ]


def write_manifest(dirpath: str, meta: dict, functions: list) -> None:
    """Write an index.json describing the run and every emitted function."""
    try:
        with open(os.path.join(dirpath, "index.json"), "w", encoding="utf-8") as fh:
            json.dump({"meta": meta, "functions": functions}, fh, indent=2)
    except Exception as exc:
        print(f"[!] could not write index.json: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# UPX handling
# ---------------------------------------------------------------------------
# A UPX-packed binary only carries the unpacking *stub* as on-disk code; the
# real program is compressed (the `UPXn` sections, with the inflate-target
# section empty on disk). Decompiling it yields a handful of stub functions.
# `upx -d` reverses the compression statically (it does NOT execute the file),
# so we transparently unpack to a throwaway copy and analyze that instead. The
# original sample is never modified.

def is_upx_packed(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    if data[:2] != b"MZ":
        return b"UPX!" in data[:8192]            # non-PE (e.g. ELF) UPX
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return b"UPX!" in data[:8192]
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        opt = struct.unpack_from("<H", data, pe + 20)[0]
        sect = pe + 24 + opt
        for i in range(nsec):
            name = data[sect + i * 40: sect + i * 40 + 8].rstrip(b"\0")
            if name.upper().startswith(b"UPX"):
                return True
    except Exception:
        pass
    return b"UPX!" in data[:8192]


def _find_upx() -> "str | None":
    found = shutil.which("upx")
    if found:
        return found
    for cand in (os.path.expanduser("~/.local/bin/upx"),
                 "/usr/local/bin/upx", "/usr/bin/upx"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def maybe_unpack(path: str) -> str:
    """If `path` is UPX-packed and `upx` is available, decompress a temp copy
    and return its path (registering cleanup); otherwise return `path`
    unchanged. Failures degrade gracefully to analyzing the packed file."""
    if os.environ.get("DECOMPILE_NO_UNPACK"):
        return path
    if not is_upx_packed(path):
        return path

    print("[*] UPX-packed binary detected (UPX section/magic present)")
    upx = _find_upx()
    if not upx:
        print("[!] `upx` not found on PATH or ~/.local/bin — decompiling the packed "
              "stub only. Install upx to recover the real code.", file=sys.stderr)
        return path

    tmpdir = tempfile.mkdtemp(prefix="decompile_upx_")
    atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
    tmpbin = os.path.join(tmpdir, os.path.basename(path) + ".unpacked")
    shutil.copy2(path, tmpbin)

    print(f"[*] Unpacking with `{upx} -d` (static decompression — not executed)")
    try:
        res = subprocess.run([upx, "-d", tmpbin],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as exc:
        print(f"[!] upx invocation failed: {exc} — using the packed file",
              file=sys.stderr)
        return path
    if res.returncode != 0:
        print("[!] `upx -d` failed (tampered/unsupported header?) — decompiling the "
              "packed stub only:", file=sys.stderr)
        sys.stderr.write(res.stdout.decode("utf-8", "replace"))
        return path

    print(f"[+] Unpacked OK ({os.path.getsize(path)} -> {os.path.getsize(tmpbin)} bytes); "
          "analyzing the unpacked image")
    return tmpbin


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Args: <binary_file>. (A bare -a/--aggressive is accepted as a deprecated
    # no-op: the signature matcher now runs on every decompile, see below.)
    positional = []
    for arg in sys.argv[1:]:
        if arg in ("-h", "--help"):
            positional = []
            break
        if arg in ("-a", "--aggressive"):
            continue   # deprecated no-op; signature matcher always runs now
        positional.append(arg)
    if len(positional) != 1:
        print(f"Usage: {sys.argv[0]} <binary_file>", file=sys.stderr)
        return 1

    binary_path = os.path.abspath(positional[0])

    if not os.path.isfile(binary_path):
        print(f"[!] File not found: {binary_path}", file=sys.stderr)
        return 1

    # Transparently UPX-unpack to a throwaway copy if needed (original untouched).
    # BN loads `analysis_path`; the .bn.dec output dir stays keyed to the original.
    analysis_path = maybe_unpack(binary_path)

    # The function signature matcher names library functions (msvcrt/ucrt/...). It
    # is deprecated in BN in favor of WARP — which already runs as part of the
    # default "full" analysis — but it still adds names, so we keep it enabled on
    # every run as belt-and-suspenders. (`analysis.mode "full"` is already the
    # default, so it is not set here.) Static analysis only; nothing is executed.
    load_options = {"analysis.signatureMatcher.autorun": True}

    print(f"[*] Analyzing binary file `{binary_path}`")

    with load(analysis_path, options=load_options) as bv:
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

        # Prepare output directory: <binary>.bn.dec/
        dirpath = binary_path + ".bn.dec"
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

        # Render settings: no address gutter, and WaitForIL for deterministic output.
        settings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowAddress, False)
        settings.set_option(DisassemblyOption.WaitForIL, True)

        decompiled_count = 0
        manifest = []          # one entry per emitted function, written to index.json

        for func in bv.functions:
            func_name = func.name or "[no name]"
            out_path = output_path(dirpath, func_name, func.start)

            try:
                lines = render_function(func, settings)
                if not lines:
                    continue
                flags = func_flags(func)
                try:
                    n_callers, n_callees = len(func.callers), len(func.callees)
                except Exception:
                    n_callers = n_callees = 0
                header = function_header(func, func_name, flags, n_callers, n_callees)
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(header + lines) + "\n")
                print(f"{func_name} -> `{out_path}`")
                decompiled_count += 1
                manifest.append({
                    "name": func_name,
                    "address": f"{func.start:#x}",
                    "file": os.path.basename(out_path),
                    "lines": len(lines),
                    "is_thunk": flags["is_thunk"],
                    "is_lib": flags["is_lib"],
                    "is_imported": flags["is_imported"],
                    "n_callers": n_callers,
                    "n_callees": n_callees,
                })
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

        try:
            tool_version = core_version()
        except Exception:
            tool_version = "unknown"
        write_manifest(dirpath, {
            "tool": "binary-ninja",
            "tool_version": tool_version,
            "binary": binary_path,
            "sha256": sha256_file(binary_path),
            "size": os.path.getsize(binary_path),
            "arch": arch_name,
            "file_type": str(bv.view_type),
            "function_count": decompiled_count,
            "upx_unpacked": analysis_path != binary_path,
        }, manifest)

        print()
        print(f"[+] Decompiled {decompiled_count} functions into `{dirpath}`")
        print(f"[+] Wrote manifest `{os.path.join(dirpath, 'index.json')}`")
        print(f"[+] Done processing binary file `{binary_path}`")

    return 0


if __name__ == "__main__":
    sys.exit(main())
