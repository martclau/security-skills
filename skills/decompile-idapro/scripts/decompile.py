#!/usr/bin/env python3
"""
decompile.py - Headless full decompiler using IDA Pro 9.x idalib Python bindings

Mirrors haruspex (https://github.com/0xdea/haruspex): extracts pseudocode for
every non-thunk function and writes each to a separate .c file under <binary>.ida.dec/

Usage:
    python3 decompile.py <binary_file> [--aggressive|-a]

Requirements:
    - IDA Pro 9.x with a valid Hex-Rays decompiler license
    - idapro Python package on PYTHONPATH  (ships with IDA under idalib/python/)
    - IDADIR env var OR ~/.idapro/ida-config.json pointing at the IDA install dir

Quick setup (if IDADIR is not already in the environment):
    export IDADIR="$HOME/.local/share/applications/IDA Professional 9.3"
    export PYTHONPATH="$IDADIR/idalib/python"
    python3 decompile.py /path/to/binary
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
import ida_ida
import ida_kernwin
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


def render_pseudocode(cfunc) -> list:
    """Hex-Rays pseudocode as plain-text lines (color tags stripped)."""
    return [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def caller_eas(func_ea: int) -> set:
    """Start EAs of functions with a (non-flow) code reference to func_ea."""
    eas = set()
    try:
        for ref in idautils.CodeRefsTo(func_ea, 0):     # 0 = exclude ordinary flow
            f = ida_funcs.get_func(ref)
            if f:
                eas.add(f.start_ea)
    except Exception:
        pass
    return eas


def callee_eas(func) -> set:
    """Start EAs of other functions referenced (call/jump) from within func."""
    eas = set()
    try:
        for head in idautils.FuncItems(func.start_ea):
            for ref in idautils.CodeRefsFrom(head, 0):   # 0 = exclude ordinary flow
                f = ida_funcs.get_func(ref)
                if f and f.start_ea != func.start_ea:
                    eas.add(f.start_ea)
    except Exception:
        pass
    return eas


def function_header(func, name: str, n_callers: int, n_callees: int) -> list:
    """Compact comment block prepended to each .c (the prototype is already in
    the pseudocode body, so it is not repeated here)."""
    tags = []
    if func.flags & ida_funcs.FUNC_THUNK:
        tags.append("thunk")
    if func.flags & ida_funcs.FUNC_LIB:
        tags.append("lib")
    tag = f"  [{', '.join(tags)}]" if tags else ""
    return [
        f"// {name} @ {func.start_ea:#x}{tag}",
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
# FLIRT signatures (applied on every run) + aggressive analysis (opt-in)
# ---------------------------------------------------------------------------
# FLIRT library-signature application is cheap and high-value: matched library
# functions get real names/prototypes instead of `sub_*`. A queued-but-unmatched
# signature only costs analysis time (FLIRT needs a pattern+CRC hit) — it never
# produces false names — so we apply generously but in two tiers:
#
#   Tier 1 (every run, cheap): the compiler/format signatures shipped under the
#     ARCH-APPROPRIATE <IDADIR>/sig/<proc>/ dir (sig/pc for x86, sig/arm for ARM,
#     ...), plus the Go-stdlib and Rust-std signatures for those runtimes.
#   Tier 2 (--aggressive only, expensive): all Rust versions, the statically-
#     linked distro package sigs (sig/linux/{debian,ubuntu}), and the Windows
#     VS-channel CRT/MFC/ATL/SDK sigs (sig/windows/vs-channels).
#
# Bare-name application (plan_to_apply_idasgn("vc32rtf")) resolves ARCH-SCOPED
# under sig/<current-proc>/, so Tier-1 compiler sigs are applied by name. The
# off-path dirs (sig/rust/<triple>, sig/golang/stdlibs, sig/linux, sig/windows)
# are NOT on that search path and must be applied by ABSOLUTE path.
#
# Aggressive mode (--aggressive / -a / DECOMPILE_AGGRESSIVE=1) also maxes the
# analysis flags and re-plans the whole image (recall up, precision down, slower)
# and stops skipping thunks. None of this executes the target — all static.

def _is_go(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    return any(m in data for m in
               (b"Go build ID", b"go.buildinfo", b".gopclntab", b"runtime.main"))


def _is_rust(path: str) -> bool:
    """Detect a Rust binary from compiler-embedded path/runtime markers."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    return any(m in data for m in
               (b"/rustc/", b"library/std", b"cargo/registry",
                b"rust_begin_unwind", b"RUST_BACKTRACE"))


def set_aggressive_analysis() -> None:
    """Enable every analysis flag so IDA chases more code into functions."""
    try:
        ida_ida.inf_set_af(0xFFFFFFFF)
        if hasattr(ida_ida, "inf_set_af2"):
            ida_ida.inf_set_af2(0xFFFFFFFF)
    except Exception as exc:
        print(f"[!] could not set aggressive analysis flags: {exc}", file=sys.stderr)


# FLIRT sig name-prefixes shipped under <IDADIR>/sig/pc/, keyed by compiler.
_BROAD_CRT = ("vc", "msvc", "gcc", "mingw", "cygwin")

# Processor name -> sig/<subdir> that ships its signatures (dirs present in IDA 9.x).
# Only "pc" is compiler-prefixed; the other dirs are tiny and format-named
# (elf/pe/mfc/android_arm/...), so we apply them whole. This map is best-effort —
# the exact inf_get_procname() strings for some families (mips*/sh*/h8/68k) are not
# all verified; _sig_subdir_for_proc() also tries a same-named sig/<proc> dir before
# falling back to "pc", so a missing alias degrades to "no arch sigs", never a crash.
_PROC_TO_SIGDIR = {
    "metapc": "pc",
    "arm": "arm", "armb": "arm",
    "mips": "mips", "mipsl": "mips", "mipsr": "mips", "mipsb": "mips", "mipsrl": "mips",
    "68000": "mc68k", "68k": "mc68k",
    "sh3": "sh3", "sh4": "sh3",
    "h8": "h8", "h8500": "h8",
    "tms320c6": "tms320c6",
}


def _sig_subdir_for_proc(proc: str) -> str:
    p = proc.lower()
    if p in _PROC_TO_SIGDIR:
        return _PROC_TO_SIGDIR[p]
    if os.path.isdir(os.path.join(_IDADIR, "sig", p)):   # procname == dir name
        return p
    return "pc"


def choose_flirt_prefixes() -> tuple:
    """Pick FLIRT sig name-prefixes scoped to the detected compiler/toolchain
    (sig/pc only — the non-pc arch dirs are not compiler-prefixed). Unknown
    compiler -> broad CRT fallback, so detection failure never loses names.
    Call after the database is open (inf_* are valid then)."""
    try:
        comp = ida_ida.inf_get_cc_id()
        is_pe = ida_ida.inf_get_filetype() == ida_ida.f_PE
    except Exception:
        return _BROAD_CRT
    if comp == idc.COMP_MS:
        return ("vc", "msvc")
    if comp == idc.COMP_GNU:
        # MinGW/Cygwin are GNU-on-PE; include them only for PE targets.
        return ("gcc", "mingw", "cygwin") if is_pe else ("gcc",)
    if comp == idc.COMP_BC:
        return ("bc",)
    if comp == idc.COMP_WATCOM:
        return ("ow", "wat")
    return _BROAD_CRT          # COMP_UNK / anything else


def _queue_by_name(names) -> int:
    """Queue bare-name signatures (resolution is arch-scoped to sig/<proc>/).
    Returns how many actually queued; auto_wait() applies them."""
    queued = 0
    for n in names:
        try:
            if ida_funcs.plan_to_apply_idasgn(n):    # returns # modules; 0 == not found
                queued += 1
        except Exception:
            pass
    return queued


def _queue_by_path(paths) -> int:
    """Queue signatures by ABSOLUTE path (for dirs off the sig/<proc> search
    path: rust/<triple>, golang/stdlibs, linux/*, windows/vs-channels)."""
    queued = 0
    for p in paths:
        try:
            if ida_funcs.plan_to_apply_idasgn(p):
                queued += 1
        except Exception:
            pass
    return queued


def apply_compiler_signatures(sigdir: str) -> tuple:
    """Tier 1: compiler/format sigs from sig/<sigdir>, applied by bare name. For
    'pc' scope to the detected compiler family (155 sigs); for the small non-pc
    arch dirs (format-named, <10 sigs) apply them all. Returns (queued, label)."""
    base = os.path.join(_IDADIR, "sig", sigdir)
    try:
        sigs = sorted(f[:-4] for f in os.listdir(base) if f.endswith(".sig"))
    except OSError as exc:
        print(f"[!] could not list FLIRT sigs at {base}: {exc}", file=sys.stderr)
        return 0, ""
    if sigdir == "pc":
        prefixes = choose_flirt_prefixes()
        names = [s for s in sigs if s.lower().startswith(tuple(prefixes))]
        scope = "/".join(prefixes)
    else:
        names = sigs                       # tiny, format-named -> apply all
        scope = ",".join(sigs)
    q = _queue_by_name(names)
    # Gate the label on q, not names: bare names are resolved arch-scoped, so a
    # pc-fallback proc whose names don't resolve queues nothing — don't claim it did.
    return q, (f"{sigdir}: {scope}" if q else "")


def apply_go_signatures(sigdir: str, is64: bool) -> tuple:
    """Tier 1: Go stdlib sigs. x86 ships go_std_* under sig/pc (bare name OK);
    ARM/ARM64 have golang_std_{arm,arm64}_* under sig/golang/stdlibs (abs path)."""
    if sigdir == "pc":
        q = _queue_by_name(["go_std_abi0", "go_std_abiinternal"])
        return q, ("go: pc" if q else "")
    if sigdir == "arm":
        tok = "arm64" if is64 else "arm"
        gdir = os.path.join(_IDADIR, "sig", "golang", "stdlibs")
        try:
            paths = [os.path.join(gdir, f) for f in os.listdir(gdir)
                     if f.startswith(f"golang_std_{tok}_") and f.endswith(".sig")]
        except OSError:
            paths = []
        q = _queue_by_path(paths)
        return q, (f"go: {tok}" if q else "")
    return 0, ""               # no Go sigs shipped for other arches


def _rust_triple(proc: str, is64: bool, filetype) -> str:
    """Best-effort map IDA's arch + file type to a rustc target-triple dir name
    under sig/rust/ (e.g. 'aarch64-apple-darwin'). '' when undeterminable."""
    if proc.startswith("metapc"):
        arch = "x86_64" if is64 else "i686"
    elif proc.startswith("arm"):
        arch = "aarch64" if is64 else "armv7"
    else:
        arch = ""
    os_tok = {ida_ida.f_MACHO: "apple-darwin",
              ida_ida.f_PE: "pc-windows-msvc",
              ida_ida.f_ELF: "unknown-linux-gnu"}.get(filetype, "")
    return f"{arch}-{os_tok}" if arch and os_tok else ""


def _rust_dir(triple: str) -> str:
    """Resolve sig/rust/<triple>/, with a substring fallback (e.g. musl/eabihf
    variants of the same arch+OS). '' when nothing matches."""
    sig_rust = os.path.join(_IDADIR, "sig", "rust")
    if not triple or not os.path.isdir(sig_rust):
        return ""
    exact = os.path.join(sig_rust, triple)
    if os.path.isdir(exact):
        return exact
    arch, _, os_part = triple.partition("-")
    for d in sorted(os.listdir(sig_rust)):
        if d.startswith(arch) and os_part and os_part in d:
            return os.path.join(sig_rust, d)
    return ""


def _rust_ver(fname: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", fname)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def apply_rust_signatures(triple: str, all_versions: bool = False) -> tuple:
    """Rust std sigs under sig/rust/<triple>/ — off the sig/<proc> search path,
    so applied by ABSOLUTE path. Default: the newest per-version rust_*.sig (one
    version usually matches a given binary; wrong versions just CRC-miss). With
    all_versions (--aggressive) queue every version. The shipped
    rust_bundle_<triple> is .metadata-only (no .sig), so it is intentionally
    skipped. Returns (queued, label)."""
    tdir = _rust_dir(triple)
    if not tdir:
        return 0, ""
    sigs = sorted((f for f in os.listdir(tdir) if f.endswith(".sig")), key=_rust_ver)
    if not sigs:
        return 0, ""
    chosen = sigs if all_versions else [sigs[-1]]
    q = _queue_by_path([os.path.join(tdir, f) for f in chosen])
    dn = os.path.basename(tdir)
    if all_versions:
        label = f"rust: {dn}/all-versions ({len(chosen)})"
    else:
        label = f"rust: {dn}/{chosen[0][:-4]} (newest)"
    return q, (label if q else "")


def _distro_arch_token(proc: str, is64: bool) -> str:
    """Map proc/bitness to the distro package-arch suffix used by
    sig/linux/{debian,ubuntu}/*-<arch>.sig (best-effort)."""
    if proc.startswith("metapc"):
        return "amd64" if is64 else "i386"
    if proc.startswith("arm"):
        return "arm64" if is64 else "armhf"
    if proc.startswith("mips"):
        return "mips64el" if is64 else "mipsel"
    return ""


def apply_distro_signatures(proc: str, is64: bool) -> tuple:
    """Tier 2 (ELF only): statically-linked distro package sigs under
    sig/linux/{debian,ubuntu}/*-<arch>.sig (abs path). Hundreds of -dev package
    sigs; most CRC-miss (time, not false names)."""
    tok = _distro_arch_token(proc, is64)
    if not tok:
        return 0, ""
    paths = []
    for distro in ("debian", "ubuntu"):
        d = os.path.join(_IDADIR, "sig", "linux", distro)
        try:
            paths += [os.path.join(d, f) for f in os.listdir(d)
                      if f.endswith(f"-{tok}.sig")]
        except OSError:
            pass
    q = _queue_by_path(paths)
    return q, (f"distro: debian/ubuntu {tok} ({q}/{len(paths)})" if paths else "")


def apply_vschannel_signatures() -> tuple:
    """Tier 2 (PE only): modern MSVC CRT/MFC/ATL + Windows SDK sigs under
    sig/windows/vs-channels/** (abs path)."""
    root = os.path.join(_IDADIR, "sig", "windows", "vs-channels")
    paths = []
    for dp, _dirs, fns in os.walk(root):
        paths += [os.path.join(dp, f) for f in fns if f.endswith(".sig")]
    q = _queue_by_path(paths)
    return q, (f"vs-channels ({q}/{len(paths)})" if paths else "")


def plan_signatures(proc: str, filetype, is64: bool,
                    analysis_path: str, aggressive: bool) -> list:
    """Queue all applicable FLIRT signatures (Tier 1 always; Tier 2 when
    aggressive). The caller's single auto_wait() applies them. Returns the list
    of human-readable group labels for the console and the manifest."""
    sigdir = _sig_subdir_for_proc(proc)
    labels = []

    def add(res):
        _q, lab = res
        if lab:
            labels.append(lab)

    add(apply_compiler_signatures(sigdir))
    if _is_go(analysis_path):
        add(apply_go_signatures(sigdir, is64))
    if _is_rust(analysis_path):
        add(apply_rust_signatures(_rust_triple(proc, is64, filetype),
                                  all_versions=aggressive))
    if aggressive:
        if filetype == ida_ida.f_ELF:
            add(apply_distro_signatures(proc, is64))
        if filetype == ida_ida.f_PE:
            add(apply_vschannel_signatures())
    return labels


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Args: <binary_file> [--aggressive|-a]. Aggressive can also be set via the
    # DECOMPILE_AGGRESSIVE env var. Default applies scoped FLIRT signatures and
    # skips thunks; aggressive adds max analysis flags + full re-plan and includes
    # thunks.
    aggressive = bool(os.environ.get("DECOMPILE_AGGRESSIVE"))
    positional = []
    for arg in sys.argv[1:]:
        if arg in ("-h", "--help"):
            positional = []
            break
        if arg in ("-a", "--aggressive"):
            aggressive = True
        else:
            positional.append(arg)
    if len(positional) != 1:
        print(f"Usage: {sys.argv[0]} <binary_file> [--aggressive|-a]", file=sys.stderr)
        return 1

    binary_path = os.path.abspath(positional[0])

    if not os.path.isfile(binary_path):
        print(f"[!] File not found: {binary_path}", file=sys.stderr)
        return 1

    # Transparently UPX-unpack to a throwaway copy if needed (original untouched).
    # IDA opens `analysis_path`; the .ida.dec output dir stays keyed to the original.
    analysis_path = maybe_unpack(binary_path)

    # Remove any stale IDA database files that would cause "corrupted DB" errors
    for ext in (".id0", ".id1", ".id2", ".nam", ".til"):
        stale = analysis_path + ext
        if os.path.exists(stale):
            os.remove(stale)

    # Open binary and run auto-analysis (equivalent to IDB::open in haruspex)
    print(f"[*] Analyzing binary file `{binary_path}`")
    idapro.open_database(analysis_path, run_auto_analysis=True)
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

    # FLIRT signatures are applied on EVERY run (Tier 1), arch-correct. Aggressive
    # mode first maxes the analysis flags and re-plans the whole image (so signatures
    # also land on newly-discovered code), adds the expensive Tier-2 signature sets,
    # and later stops skipping thunks.
    if aggressive:
        print("[*] Aggressive mode: max analysis flags + full re-plan + include thunks")
        set_aggressive_analysis()
        ida_auto.plan_and_wait(idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea())

    try:
        is64 = bool(idaapi.inf_is_64bit())
    except Exception:
        is64 = False
    filetype = idaapi.inf_get_filetype()
    sig_labels = plan_signatures(proc_name, filetype, is64, analysis_path, aggressive)
    ida_auto.auto_wait()      # apply queued signatures (cheap when not re-planning)
    if sig_labels:
        print("[*] Applied FLIRT signatures:")
        for lab in sig_labels:
            print(f"      - {lab}")
    else:
        print("[*] No FLIRT signatures applied")
    print()

    # Prepare output directory: <binary>.ida.dec/
    dirpath = binary_path + ".ida.dec"
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

    # Decompile functions (thunks skipped by default; included in aggressive mode)
    print("[*] Extracting pseudocode of functions...")
    print()
    decompiled_count = 0
    manifest = []          # one entry per emitted function, written to index.json

    for start_ea in idautils.Functions():
        func = ida_funcs.get_func(start_ea)
        if func is None:
            continue

        # Skip thunk functions (mirrors FunctionFlags::THUNK in haruspex),
        # unless aggressive mode asked to include them.
        if func.flags & ida_funcs.FUNC_THUNK and not aggressive:
            continue

        func_name = idc.get_func_name(start_ea) or "[no name]"
        out_path = output_path(dirpath, func_name, start_ea)

        try:
            cfunc = ida_hexrays.decompile(start_ea)
            if cfunc is None:
                continue
            body = render_pseudocode(cfunc)
            callers, callees = caller_eas(start_ea), callee_eas(func)
            header = function_header(func, func_name, len(callers), len(callees))
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(header + body) + "\n")
            print(f"{func_name} -> `{out_path}`")
            decompiled_count += 1
            manifest.append({
                "name": func_name,
                "address": f"{start_ea:#x}",
                "file": os.path.basename(out_path),
                "lines": len(body),
                "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
                "is_lib": bool(func.flags & ida_funcs.FUNC_LIB),
                "is_imported": False,   # IDA has no direct import flag here
                "n_callers": len(callers),
                "n_callees": len(callees),
            })

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

    try:
        tool_version = ida_kernwin.get_kernel_version()
    except Exception:
        tool_version = "unknown"
    write_manifest(dirpath, {
        "tool": "ida-pro",
        "tool_version": tool_version,
        "binary": binary_path,
        "sha256": sha256_file(binary_path),
        "size": os.path.getsize(binary_path),
        "arch": proc_name,
        "file_type": int(filetype),
        "function_count": decompiled_count,
        "upx_unpacked": analysis_path != binary_path,
        "signatures": sig_labels,
    }, manifest)

    print()
    print(f"[+] Decompiled {decompiled_count} functions into `{dirpath}`")
    print(f"[+] Wrote manifest `{os.path.join(dirpath, 'index.json')}`")
    print(f"[+] Done processing binary file `{binary_path}`")

    idapro.close_database(save=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
