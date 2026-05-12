#!/usr/bin/env python3
"""
binary_analyzer.py -- Static binary security analysis tool.

Modes:
  --entropy     Compute per-section Shannon entropy (ELF/PE).
  --checksec    Check ELF security mitigations (fallback when checksec is not installed).
  --pe-security Check PE security mitigations.
  --heuristics  Scan strings and binary for behavioral indicators.
  --vt-hash     Look up a SHA-256 hash on VirusTotal (requires VT_API_KEY env var).

Usage:
  python3 binary_analyzer.py --entropy /path/to/binary
  python3 binary_analyzer.py --checksec /path/to/binary
  python3 binary_analyzer.py --heuristics /path/to/binary [--strings /path/to/strings.txt]
  python3 binary_analyzer.py --vt-hash <sha256> [--no-color] [-o report.json]
"""

import argparse
import json
import math
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

USE_COLOR = True

def _c(code: str, text: str) -> str:
    if not USE_COLOR:
        return text
    codes = {"red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
             "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"}
    return f"{codes.get(code, '')}{text}{codes['reset']}"


def severity_color(sev: str) -> str:
    return {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
            "LOW": "cyan", "INFO": "green"}.get(sev, "reset")


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def entropy_label(e: float) -> str:
    if e < 1.0:
        return "very low (sparse / padding)"
    if e < 3.5:
        return "low (plain text or data)"
    if e < 6.5:
        return "medium (compiled code)"
    if e < 7.2:
        return "high (compressed / mixed)"
    return "VERY HIGH -- possible packing or encryption"


def elf_sections(path: str) -> list[dict]:
    """Return ELF sections via readelf."""
    sections = []
    try:
        out = subprocess.check_output(
            ["readelf", "-S", "--wide", path], stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sections

    # Parse readelf -S output lines like:
    # [ 1] .text  PROGBITS  addr  off  size  ...
    pattern = re.compile(
        r'\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)'
    )
    for line in out.splitlines():
        m = pattern.search(line)
        if m:
            name, offset, size = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
            if size > 0:
                sections.append({"name": name, "offset": offset, "size": size})
    return sections


def compute_entropy(binary_path: str) -> list[dict]:
    results = []
    raw = Path(binary_path).read_bytes()

    # Try ELF sections
    sections = elf_sections(binary_path)
    if sections:
        for sec in sections:
            chunk = raw[sec["offset"]: sec["offset"] + sec["size"]]
            e = shannon_entropy(chunk)
            results.append({
                "section": sec["name"],
                "offset": hex(sec["offset"]),
                "size": sec["size"],
                "entropy": round(e, 3),
                "label": entropy_label(e),
            })
    else:
        # Fallback: whole-file entropy
        e = shannon_entropy(raw)
        results.append({
            "section": "(whole file)",
            "offset": "0x0",
            "size": len(raw),
            "entropy": round(e, 3),
            "label": entropy_label(e),
        })

    return results


def print_entropy(results: list[dict]) -> None:
    print(_c("bold", "\n=== Entropy Analysis ==="))
    print(f"{'Section':<20} {'Size':>10}  {'Entropy':>8}  Label")
    print("-" * 70)
    for r in results:
        high = r["entropy"] >= 7.2
        color = "red" if high else ("yellow" if r["entropy"] >= 6.5 else "green")
        print(
            f"{r['section']:<20} {r['size']:>10}  "
            f"{_c(color, '{:>8.3f}'.format(r['entropy']))}  {r['label']}"
        )


# ---------------------------------------------------------------------------
# ELF checksec (manual fallback)
# ---------------------------------------------------------------------------

ELF_MAGIC = b'\x7fELF'

def is_elf(data: bytes) -> bool:
    return data[:4] == ELF_MAGIC


def elf_checksec(binary_path: str) -> dict:
    raw = Path(binary_path).read_bytes()
    if not is_elf(raw):
        return {"error": "Not an ELF binary"}

    results = {}

    # --- NX / stack non-executable ---
    # GNU_STACK segment with flags not including execute (bit 0)
    try:
        out = subprocess.check_output(
            ["readelf", "-l", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        nx = True
        for line in out.splitlines():
            if "GNU_STACK" in line:
                # flags field is last token; 'E' means executable
                nx = "E" not in line.split()[-1]
                break
        results["NX"] = {"enabled": nx, "severity": "HIGH" if not nx else "INFO"}
    except Exception:
        results["NX"] = {"enabled": None, "severity": "INFO"}

    # --- PIE ---
    try:
        out = subprocess.check_output(
            ["readelf", "-h", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        pie = "DYN" in out  # ET_DYN means PIE or shared lib
        results["PIE"] = {"enabled": pie, "severity": "MEDIUM" if not pie else "INFO"}
    except Exception:
        results["PIE"] = {"enabled": None, "severity": "INFO"}

    # --- Stack canary ---
    try:
        out = subprocess.check_output(
            ["readelf", "--dyn-syms", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        canary = "__stack_chk_fail" in out
        results["StackCanary"] = {"enabled": canary, "severity": "MEDIUM" if not canary else "INFO"}
    except Exception:
        results["StackCanary"] = {"enabled": None, "severity": "INFO"}

    # --- RELRO ---
    try:
        out = subprocess.check_output(
            ["readelf", "-l", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        if "GNU_RELRO" in out:
            # Full RELRO: also check for BIND_NOW in dynamic section
            dyn_out = subprocess.check_output(
                ["readelf", "-d", binary_path], stderr=subprocess.DEVNULL, text=True
            )
            full = "BIND_NOW" in dyn_out or "FLAGS" in dyn_out and "BIND_NOW" in dyn_out
            results["RELRO"] = {
                "enabled": "full" if full else "partial",
                "severity": "INFO" if full else "LOW",
            }
        else:
            results["RELRO"] = {"enabled": False, "severity": "MEDIUM"}
    except Exception:
        results["RELRO"] = {"enabled": None, "severity": "INFO"}

    # --- FORTIFY ---
    try:
        out = subprocess.check_output(
            ["readelf", "--dyn-syms", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        fortify = "_chk@" in out or "__sprintf_chk" in out or "__memcpy_chk" in out
        results["FORTIFY"] = {"enabled": fortify, "severity": "LOW" if not fortify else "INFO"}
    except Exception:
        results["FORTIFY"] = {"enabled": None, "severity": "INFO"}

    # --- RPATH / RUNPATH ---
    try:
        out = subprocess.check_output(
            ["readelf", "-d", binary_path], stderr=subprocess.DEVNULL, text=True
        )
        rpath_lines = [l for l in out.splitlines() if "(RPATH)" in l or "(RUNPATH)" in l]
        if rpath_lines:
            paths = [l.split("Library")[-1].strip() if "Library" in l else l for l in rpath_lines]
            risky = any("$ORIGIN" not in p and p.strip() not in ("", "[]") for p in paths)
            results["RPATH"] = {
                "enabled": True,
                "value": rpath_lines,
                "severity": "MEDIUM" if risky else "LOW",
            }
        else:
            results["RPATH"] = {"enabled": False, "severity": "INFO"}
    except Exception:
        results["RPATH"] = {"enabled": None, "severity": "INFO"}

    return results


def print_checksec(results: dict) -> None:
    if "error" in results:
        print(_c("yellow", results["error"]))
        return
    print(_c("bold", "\n=== ELF Security Features ==="))
    label_map = {
        "NX": "NX (no-exec stack)",
        "PIE": "PIE (position independent)",
        "StackCanary": "Stack canary",
        "RELRO": "RELRO",
        "FORTIFY": "FORTIFY_SOURCE",
        "RPATH": "RPATH / RUNPATH",
    }
    for key, label in label_map.items():
        if key not in results:
            continue
        r = results[key]
        val = r.get("enabled")
        sev = r.get("severity", "INFO")
        color = severity_color(sev)
        if key == "RPATH":
            status = "present" if val else "absent (good)"
        elif isinstance(val, str):
            status = val
        elif val is True:
            status = "enabled"
        elif val is False:
            status = "disabled"
        else:
            status = "unknown"
        print(f"  {label:<30} {_c(color, status):>20}  [{sev}]")


# ---------------------------------------------------------------------------
# PE security features
# ---------------------------------------------------------------------------

PE_DLLCHARACTERISTICS = {
    0x0020: ("HIGH_ENTROPY_VA", "64-bit ASLR with high entropy VA"),
    0x0040: ("DYNAMIC_BASE", "ASLR enabled"),
    0x0080: ("FORCE_INTEGRITY", "Code integrity checks"),
    0x0100: ("NX_COMPAT", "NX/DEP compatible"),
    0x0200: ("NO_ISOLATION", "No isolation (BAD)"),
    0x0400: ("NO_SEH", "No structured exception handling (BAD)"),
    0x0800: ("NO_BIND", "Do not bind"),
    0x1000: ("APP_CONTAINER", "App container isolation"),
    0x2000: ("WDM_DRIVER", "WDM driver"),
    0x4000: ("GUARD_CF", "Control Flow Guard"),
    0x8000: ("TERMINAL_SERVER_AWARE", "Terminal Server Aware"),
}

def pe_security(binary_path: str) -> dict:
    raw = Path(binary_path).read_bytes()
    results = {}

    # PE signature offset at 0x3C
    if len(raw) < 0x40:
        return {"error": "File too small to be a PE"}
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe_offset:pe_offset+4] != b"PE\x00\x00":
        return {"error": "PE signature not found"}

    # COFF header
    machine = struct.unpack_from("<H", raw, pe_offset + 4)[0]
    results["machine"] = hex(machine)

    # Optional header
    opt_offset = pe_offset + 24
    magic = struct.unpack_from("<H", raw, opt_offset)[0]
    is_pe32_plus = magic == 0x20B

    dll_char_offset = opt_offset + (70 if not is_pe32_plus else 78)
    if dll_char_offset + 2 > len(raw):
        return {"error": "Cannot read DllCharacteristics"}
    dll_chars = struct.unpack_from("<H", raw, dll_char_offset)[0]
    results["DllCharacteristics"] = hex(dll_chars)
    results["features"] = {}

    good_flags = {0x0020, 0x0040, 0x0080, 0x0100, 0x1000, 0x4000}
    bad_flags  = {0x0200, 0x0400}

    for flag, (name, desc) in PE_DLLCHARACTERISTICS.items():
        present = bool(dll_chars & flag)
        if flag in bad_flags:
            sev = "HIGH" if present else "INFO"
        elif flag in good_flags:
            sev = "INFO" if present else "MEDIUM"
        else:
            sev = "INFO"
        results["features"][name] = {"present": present, "description": desc, "severity": sev}

    return results


def print_pe_security(results: dict) -> None:
    if "error" in results:
        print(_c("yellow", results["error"]))
        return
    print(_c("bold", "\n=== PE Security Features ==="))
    print(f"  Machine: {results.get('machine')}  DllCharacteristics: {results.get('DllCharacteristics')}")
    for name, info in results.get("features", {}).items():
        sev = info["severity"]
        color = severity_color(sev)
        status = "present" if info["present"] else "absent"
        print(f"  {name:<25} {_c(color, status):>10}  {info['description']}  [{sev}]")


# ---------------------------------------------------------------------------
# Heuristic / behavioral indicator scan
# ---------------------------------------------------------------------------

HEURISTIC_RULES = [
    # (category, severity, regex_pattern, description)
    ("c2_communication",    "HIGH",   r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",        "Hardcoded IP-based URL"),
    ("c2_communication",    "HIGH",   r"\.onion",                                               "Tor hidden service reference"),
    ("c2_communication",    "MEDIUM", r"(beacon|heartbeat|checkin|check-in|c2|command.and.control)", "C2 terminology"),
    ("c2_communication",    "MEDIUM", r"User-Agent:.*[Mm]ozilla",                               "Hardcoded HTTP User-Agent (mimicry)"),
    ("persistence",         "HIGH",   r"(crontab|/etc/cron\.|rc\.local|\.bashrc|\.profile)",   "Shell persistence path"),
    ("persistence",         "HIGH",   r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Registry Run key (persistence)"),
    ("persistence",         "HIGH",   r"CreateService|StartService",                            "Windows service creation"),
    ("persistence",         "MEDIUM", r"systemctl\s+enable|/etc/systemd/system",                "Systemd service installation"),
    ("anti_analysis",       "HIGH",   r"(IsDebuggerPresent|CheckRemoteDebuggerPresent)",        "Debugger detection API"),
    ("anti_analysis",       "HIGH",   r"ptrace\s*\(\s*PTRACE_TRACEME",                          "ptrace anti-debug (Linux)"),
    ("anti_analysis",       "MEDIUM", r"(VirtualBox|VMware|QEMU|Hyper-V|KVM|sandbox)",         "Sandbox/VM detection string"),
    ("anti_analysis",       "MEDIUM", r"(SleepEx|NtDelayExecution|sleep\s*\(\s*[3-9]\d{3})",   "Long sleep delay (evasion)"),
    ("privilege_escalation","HIGH",   r"sudo\s+-[nsSk]",                                        "sudo privilege escalation attempt"),
    ("privilege_escalation","HIGH",   r"(chmod\s+[46]7[57]|chmod\s+\+s)",                      "SUID/SGID bit setting"),
    ("privilege_escalation","MEDIUM", r"(OpenProcessToken|AdjustTokenPrivileges)",               "Windows token privilege manipulation"),
    ("credential_access",   "HIGH",   r"/etc/shadow",                                           "Shadow password file access"),
    ("credential_access",   "HIGH",   r"(SAM|SYSTEM|SECURITY)\x00",                            "Windows credential hive reference"),
    ("credential_access",   "HIGH",   r"(lsass\.exe|MiniDumpWriteDump)",                        "LSASS / credential dumping"),
    ("credential_access",   "MEDIUM", r"(\.ssh/id_rsa|\.ssh/id_ed25519|known_hosts)",           "SSH private key path"),
    ("credential_access",   "MEDIUM", r"(AKIA[0-9A-Z]{16})",                                   "AWS access key pattern"),
    ("lateral_movement",    "HIGH",   r"(PsExec|wmic\s+/node|schtasks\s+/create\s+/s)",        "Remote execution utility"),
    ("lateral_movement",    "MEDIUM", r"(445|\\\\.*\\IPC\$|SMB)",                              "SMB lateral movement indicator"),
    ("defense_evasion",     "HIGH",   r"(rm\s+-rf?\s+\$0|self.delete|DeleteFileA.*argv\[0\])", "Self-deletion"),
    ("defense_evasion",     "HIGH",   r"(wevtutil\s+cl|ClearEventLog|auditd\s+stop)",           "Log clearing"),
    ("defense_evasion",     "MEDIUM", r"(UPX!|MPRESS|Themida|VMProtect|ASPack)",               "Packer signature"),
    ("injection",           "HIGH",   r"(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)","Classic process injection APIs"),
    ("injection",           "HIGH",   r"(NtUnmapViewOfSection|ZwUnmapViewOfSection)",           "Process hollowing API"),
    ("injection",           "MEDIUM", r"(LoadLibraryA|GetProcAddress)",                         "Dynamic API resolution (shellcode pattern)"),
    ("destructive",         "HIGH",   r"(dd\s+if=/dev/zero|dd\s+if=/dev/random).*/dev/(sd|nvme|hd)", "Raw disk wipe"),
    ("destructive",         "HIGH",   r"(shred|wipe)\s+(-[zurf]+\s+)?/",                       "Secure file deletion on root paths"),
    ("destructive",         "HIGH",   r"(CryptEncrypt|CryptGenKey).*(\.doc|\.xls|\.jpg|\.pdf)", "Ransomware-like encryption pattern"),
    ("network",             "MEDIUM", r"(SOCK_RAW|socket\s*\(\s*AF_PACKET)",                   "Raw socket usage"),
    ("network",             "MEDIUM", r"(tcpdump|pcap_open_live|PcapOpenLive)",                 "Packet capture"),
    ("exfiltration",        "HIGH",   r"(curl|wget).*(--upload-file|-T|-d @)",                 "File upload via curl/wget"),
    ("exfiltration",        "HIGH",   r"(ftp|sftp|scp).+password",                             "Cleartext credential in FTP/SCP command"),
]


def run_heuristics(binary_path: str, strings_path: str | None = None) -> list[dict]:
    findings = []

    # Build corpus: binary content as text (lossy) + strings file if provided
    raw = Path(binary_path).read_bytes()
    corpus_bytes = raw

    corpus_text_parts = []
    try:
        corpus_text_parts.append(raw.decode("latin-1", errors="replace"))
    except Exception:
        pass

    if strings_path:
        try:
            corpus_text_parts.append(Path(strings_path).read_text(errors="replace"))
        except Exception:
            pass

    corpus_text = "\n".join(corpus_text_parts)

    for category, severity, pattern, description in HEURISTIC_RULES:
        matches = re.findall(pattern, corpus_text, re.IGNORECASE)
        if matches:
            # Deduplicate and cap
            unique = list(dict.fromkeys(str(m) for m in matches))[:5]
            findings.append({
                "category": category,
                "severity": severity,
                "description": description,
                "pattern": pattern,
                "matches": unique,
            })

    return findings


def print_heuristics(findings: list[dict]) -> None:
    print(_c("bold", "\n=== Behavioral Indicators ==="))
    if not findings:
        print(_c("green", "  No suspicious patterns found."))
        return

    by_category: dict[str, list] = {}
    for f in findings:
        by_category.setdefault(f["category"], []).append(f)

    for cat, items in sorted(by_category.items()):
        print(f"\n  [{cat.upper().replace('_', ' ')}]")
        for item in sorted(items, key=lambda x: x["severity"]):
            color = severity_color(item["severity"])
            print(f"    {_c(color, item['severity']):<12} {item['description']}")
            for m in item["matches"]:
                print(f"               match: {m[:100]}")


# ---------------------------------------------------------------------------
# VirusTotal hash lookup
# ---------------------------------------------------------------------------

def vt_hash_lookup(sha256: str) -> dict:
    import urllib.request
    import urllib.error

    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        return {"error": "VT_API_KEY environment variable not set"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found", "message": "Hash not found in VirusTotal database"}
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = {
        "sha256": sha256,
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "total_engines": sum(stats.values()),
        "names": attrs.get("names", [])[:5],
        "type": attrs.get("type_description", ""),
        "first_seen": attrs.get("first_submission_date", ""),
        "popular_threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
    }

    # Top detections
    detections = {}
    for engine, result in attrs.get("last_analysis_results", {}).items():
        if result.get("category") in ("malicious", "suspicious"):
            detections[engine] = result.get("result", "")
    results["detections"] = dict(list(detections.items())[:10])

    return results


def print_vt(result: dict) -> None:
    print(_c("bold", "\n=== VirusTotal Hash Lookup ==="))
    if "error" in result:
        print(_c("yellow", f"  Error: {result['error']}"))
        return
    if result.get("status") == "not_found":
        print(_c("green", "  Hash not found in VirusTotal (novel or private sample)"))
        return

    mal = result["malicious"]
    sus = result["suspicious"]
    total = result["total_engines"]
    color = "red" if mal > 0 else ("yellow" if sus > 0 else "green")
    print(f"  Detections: {_c(color, f'{mal} malicious, {sus} suspicious')} / {total} engines")
    if result.get("popular_threat_label"):
        print(f"  Threat label: {_c('red', result['popular_threat_label'])}")
    if result.get("names"):
        print(f"  Known names: {', '.join(result['names'])}")
    if result.get("type"):
        print(f"  File type: {result['type']}")
    if result.get("detections"):
        print("  Top detections:")
        for engine, label in result["detections"].items():
            print(f"    {engine:<25} {label}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global USE_COLOR

    parser = argparse.ArgumentParser(description="Binary security analysis tool")
    parser.add_argument("target", nargs="?", help="Path to binary file")
    parser.add_argument("--entropy",     action="store_true", help="Entropy analysis")
    parser.add_argument("--checksec",    action="store_true", help="ELF security features")
    parser.add_argument("--pe-security", action="store_true", help="PE security features")
    parser.add_argument("--heuristics",  action="store_true", help="Behavioral indicators scan")
    parser.add_argument("--strings",     help="Path to pre-extracted strings file")
    parser.add_argument("--vt-hash",     metavar="SHA256",    help="VirusTotal hash lookup")
    parser.add_argument("--no-color",    action="store_true", help="Disable ANSI colour")
    parser.add_argument("-o",            metavar="FILE",      help="Write JSON output to file")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    output: dict = {}

    # VirusTotal hash lookup (no binary needed)
    if args.vt_hash:
        result = vt_hash_lookup(args.vt_hash)
        print_vt(result)
        output["vt"] = result

    # Binary-dependent modes
    if args.entropy or args.checksec or args.pe_security or args.heuristics:
        if not args.target:
            print("Error: a target binary path is required for this mode", file=sys.stderr)
            sys.exit(1)
        if not Path(args.target).exists():
            print(f"Error: {args.target!r} does not exist", file=sys.stderr)
            sys.exit(1)

    if args.entropy and args.target:
        results = compute_entropy(args.target)
        print_entropy(results)
        output["entropy"] = results

    if args.checksec and args.target:
        results = elf_checksec(args.target)
        print_checksec(results)
        output["checksec"] = results

    if args.pe_security and args.target:
        results = pe_security(args.target)
        print_pe_security(results)
        output["pe_security"] = results

    if args.heuristics and args.target:
        findings = run_heuristics(args.target, args.strings)
        print_heuristics(findings)
        output["heuristics"] = findings

    if not any([args.entropy, args.checksec, args.pe_security, args.heuristics, args.vt_hash]):
        parser.print_help()
        sys.exit(0)

    if args.o and output:
        Path(args.o).write_text(json.dumps(output, indent=2, default=str))
        print(f"\nJSON report written to: {args.o}")


if __name__ == "__main__":
    main()
