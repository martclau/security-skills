#!/usr/bin/env python3
"""
VirusTotal Script Scanner — Uploads scripts from a skill directory to VirusTotal
and retrieves malware analysis results.

Usage:
    python vt_scan.py <skill-path> --api-key <key>                # scan all scripts
    python vt_scan.py <skill-path> --api-key <key> -o results.json # JSON output
    python vt_scan.py <skill-path> --api-key <key> --poll-timeout 120

Requires a free VirusTotal API key: https://www.virustotal.com/gui/join-us
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

VT_API_BASE = "https://www.virustotal.com/api/v3"

SCRIPT_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".rb", ".pl",
    ".php", ".lua", ".ps1", ".bat", ".cmd", ".mjs", ".cjs",
    ".jsx", ".tsx", ".go", ".rs", ".java", ".kt", ".swift", ".r",
}

MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB (VT free tier limit)


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class EngineResult:
    engine: str
    detected: bool
    category: str
    result: Optional[str] = None


@dataclass
class FileScanResult:
    file: str
    sha256: str
    size_bytes: int
    status: str  # "clean", "malicious", "suspicious", "undetected", "error", "skipped"
    detections: int = 0
    total_engines: int = 0
    detection_names: list = field(default_factory=list)
    engine_results: list = field(default_factory=list)
    vt_link: str = ""
    error: str = ""

    def to_dict(self):
        d = asdict(self)
        return d


@dataclass
class ScanSummary:
    skill_path: str
    total_scripts: int = 0
    scanned: int = 0
    skipped: int = 0
    clean: int = 0
    malicious: int = 0
    suspicious: int = 0
    errors: int = 0
    results: list = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.malicious > 0:
            return "MALICIOUS — VirusTotal engines flagged one or more scripts"
        if self.suspicious > 0:
            return "SUSPICIOUS — some scripts received low-confidence detections"
        if self.errors > 0 and self.clean == 0:
            return "INCONCLUSIVE — all uploads failed, could not complete scan"
        return "CLEAN — no scripts flagged by VirusTotal engines"

    def to_dict(self):
        d = asdict(self)
        d["verdict"] = self.verdict
        return d


# ── VirusTotal API helpers ───────────────────────────────────────────────────

def vt_request(method: str, url: str, api_key: str,
               data: bytes = None, headers: dict = None,
               content_type: str = None) -> dict:
    """Make an API request to VirusTotal. Returns parsed JSON."""
    # Restrict to HTTPS only (addresses Bandit B310 — prevents file:// scheme abuse)
    if not url.startswith("https://"):
        raise RuntimeError(f"Refusing non-HTTPS URL: {url}")

    hdrs = {"x-apikey": api_key, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if content_type:
        hdrs["Content-Type"] = content_type

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        raise RuntimeError(f"VT API {e.code}: {body[:300]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"VT API connection error: {e.reason}") from e


def upload_file(filepath: Path, api_key: str) -> str:
    """Upload a file to VirusTotal. Returns the analysis ID."""
    boundary = "----VTBoundary" + secrets.token_hex(12)

    file_content = filepath.read_bytes()
    filename = filepath.name

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_content + f"\r\n--{boundary}--\r\n".encode()

    result = vt_request(
        "POST",
        f"{VT_API_BASE}/files",
        api_key,
        data=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    return result["data"]["id"]


def check_hash_first(sha256: str, api_key: str) -> Optional[dict]:
    """Check if VT already has a report for this hash. Returns None if not found."""
    try:
        result = vt_request("GET", f"{VT_API_BASE}/files/{sha256}", api_key)
        return result
    except RuntimeError as e:
        if "404" in str(e):
            return None
        raise


def poll_analysis(analysis_id: str, api_key: str,
                  timeout: int = 300, interval: int = 15) -> dict:
    """Poll VirusTotal until the analysis completes or timeout is reached."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = vt_request("GET", f"{VT_API_BASE}/analyses/{analysis_id}", api_key)
        status = result.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return result
        time.sleep(interval)
    raise TimeoutError(f"Analysis {analysis_id} did not complete within {timeout}s")


def parse_analysis(analysis: dict) -> tuple[int, int, str, list[str], list[EngineResult]]:
    """Parse a VT analysis response into structured results.
    Returns (detections, total, status, detection_names, engine_results).
    """
    attrs = analysis.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {})

    # Analysis endpoint structure
    results_dict = attrs.get("results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    detections = malicious + suspicious
    detection_names = []
    engine_results = []

    for engine_name, engine_data in results_dict.items():
        cat = engine_data.get("category", "undetected")
        detected = cat in ("malicious", "suspicious")
        res_name = engine_data.get("result")
        engine_results.append(EngineResult(
            engine=engine_name,
            detected=detected,
            category=cat,
            result=res_name,
        ))
        if detected and res_name:
            detection_names.append(f"{engine_name}: {res_name}")

    if malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "suspicious"
    else:
        status = "clean"

    return detections, total, status, detection_names, engine_results


def parse_file_report(report: dict) -> tuple[int, int, str, list[str], list[EngineResult]]:
    """Parse a VT file report (from hash lookup) into structured results."""
    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results_dict = attrs.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    detections = malicious + suspicious
    detection_names = []
    engine_results = []

    for engine_name, engine_data in results_dict.items():
        cat = engine_data.get("category", "undetected")
        detected = cat in ("malicious", "suspicious")
        res_name = engine_data.get("result")
        engine_results.append(EngineResult(
            engine=engine_name,
            detected=detected,
            category=cat,
            result=res_name,
        ))
        if detected and res_name:
            detection_names.append(f"{engine_name}: {res_name}")

    if malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "suspicious"
    else:
        status = "clean"

    return detections, total, status, detection_names, engine_results


# ── Main scanning logic ─────────────────────────────────────────────────────

def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_script(filepath: Path, api_key: str, poll_timeout: int) -> FileScanResult:
    """Scan a single script file via VirusTotal."""
    rel = str(filepath)
    size = filepath.stat().st_size
    sha256 = compute_sha256(filepath)

    result = FileScanResult(file=rel, sha256=sha256, size_bytes=size, status="clean")

    if size > MAX_FILE_SIZE:
        result.status = "skipped"
        result.error = f"File too large ({size / 1_000_000:.1f} MB, limit {MAX_FILE_SIZE // 1_000_000} MB)"
        return result

    if size == 0:
        result.status = "skipped"
        result.error = "Empty file"
        return result

    try:
        # Check if VT already has a report for this file hash
        print(f"  Checking hash {sha256[:16]}... ", end="", flush=True)
        existing = check_hash_first(sha256, api_key)

        if existing:
            print("found existing report")
            detections, total, status, names, engines = parse_file_report(existing)
            vt_id = existing.get("data", {}).get("id", sha256)
        else:
            # Upload the file
            print("uploading... ", end="", flush=True)
            analysis_id = upload_file(filepath, api_key)
            print(f"polling for results... ", end="", flush=True)
            analysis = poll_analysis(analysis_id, api_key, timeout=poll_timeout)
            print("done")
            detections, total, status, names, engines = parse_analysis(analysis)
            vt_id = sha256

        result.detections = detections
        result.total_engines = total
        result.status = status
        result.detection_names = names
        result.engine_results = [asdict(e) for e in engines]
        result.vt_link = f"https://www.virustotal.com/gui/file/{sha256}"

    except TimeoutError:
        print("timed out")
        result.status = "error"
        result.error = f"Analysis timed out after {poll_timeout}s"
    except RuntimeError as e:
        print(f"error: {e}")
        result.status = "error"
        result.error = str(e)
    except Exception as e:
        print(f"unexpected error: {e}")
        result.status = "error"
        result.error = str(e)

    return result


def find_scripts(skill_dir: Path) -> list[Path]:
    """Find all script files in the skill directory."""
    scripts = []
    for filepath in sorted(skill_dir.rglob("*")):
        if filepath.is_file() and filepath.suffix.lower() in SCRIPT_EXTENSIONS:
            scripts.append(filepath)
    return scripts


def scan_skill_scripts(skill_dir: Path, api_key: str,
                       poll_timeout: int = 300) -> ScanSummary:
    """Scan all scripts in a skill directory via VirusTotal."""
    summary = ScanSummary(skill_path=str(skill_dir))

    scripts = find_scripts(skill_dir)
    summary.total_scripts = len(scripts)

    if not scripts:
        print("  No script files found in skill directory.")
        return summary

    print(f"  Found {len(scripts)} script(s) to scan.\n")

    for i, script in enumerate(scripts, 1):
        print(f"  [{i}/{len(scripts)}] {script.name}")
        result = scan_script(script, api_key, poll_timeout)
        summary.results.append(result.to_dict())

        if result.status == "clean":
            summary.clean += 1
            summary.scanned += 1
        elif result.status == "malicious":
            summary.malicious += 1
            summary.scanned += 1
        elif result.status == "suspicious":
            summary.suspicious += 1
            summary.scanned += 1
        elif result.status == "skipped":
            summary.skipped += 1
        else:
            summary.errors += 1

        # Rate limit: VT free tier allows 4 requests/min. We use ~2 per file
        # (hash check + possible upload), so wait between files.
        if i < len(scripts):
            print("  (waiting 15s for rate limit...)")
            time.sleep(15)

    return summary


# ── Terminal reporting ───────────────────────────────────────────────────────

COLORS = {
    "RED":   "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW":"\033[93m",
    "CYAN":  "\033[96m",
    "GRAY":  "\033[90m",
    "BOLD":  "\033[1m",
    "DIM":   "\033[2m",
    "RESET": "\033[0m",
}


def print_report(summary: ScanSummary, use_color: bool = True):
    c = COLORS if use_color else {k: "" for k in COLORS}

    print()
    print(f"{c['BOLD']}{'=' * 70}{c['RESET']}")
    print(f"{c['BOLD']}  VIRUSTOTAL SCAN REPORT{c['RESET']}")
    print(f"{c['BOLD']}{'=' * 70}{c['RESET']}")
    print(f"  Skill:     {summary.skill_path}")
    print(f"  Scripts:   {summary.total_scripts} found, {summary.scanned} scanned, {summary.skipped} skipped")

    verdict = summary.verdict
    if "MALICIOUS" in verdict:
        v_color = c["RED"]
    elif "SUSPICIOUS" in verdict:
        v_color = c["YELLOW"]
    elif "INCONCLUSIVE" in verdict:
        v_color = c["GRAY"]
    else:
        v_color = c["GREEN"]

    print(f"  Verdict:   {v_color}{verdict}{c['RESET']}")
    print(f"{c['BOLD']}{'-' * 70}{c['RESET']}")

    for r in summary.results:
        status = r["status"]
        fname = Path(r["file"]).name

        if status == "malicious":
            s_color = c["RED"]
            icon = "!!"
        elif status == "suspicious":
            s_color = c["YELLOW"]
            icon = "??"
        elif status == "clean":
            s_color = c["GREEN"]
            icon = "ok"
        elif status == "skipped":
            s_color = c["GRAY"]
            icon = "--"
        else:
            s_color = c["YELLOW"]
            icon = "xx"

        det_str = ""
        if r["total_engines"] > 0:
            det_str = f" ({r['detections']}/{r['total_engines']} engines)"

        print(f"  {s_color}[{icon}]{c['RESET']} {fname} — {status}{det_str}")

        if r.get("vt_link"):
            print(f"       {c['DIM']}{r['vt_link']}{c['RESET']}")
        if r.get("error"):
            print(f"       {c['YELLOW']}{r['error']}{c['RESET']}")
        if r.get("detection_names"):
            for dn in r["detection_names"][:5]:
                print(f"       {c['RED']}{dn}{c['RESET']}")
            if len(r["detection_names"]) > 5:
                print(f"       {c['DIM']}... and {len(r['detection_names']) - 5} more{c['RESET']}")

    print(f"\n{c['BOLD']}{'=' * 70}{c['RESET']}\n")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Upload skill scripts to VirusTotal and analyze results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("path", type=Path, help="Path to the skill directory")
    parser.add_argument("--api-key", default=None,
                        help="VirusTotal API key. Can also be set via VT_API_KEY env var. "
                             "(free tier: https://www.virustotal.com/gui/join-us)")
    parser.add_argument("--output", "-o", type=Path, default=None,
                        help="Write JSON report to file")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--poll-timeout", type=int, default=300,
                        help="Max seconds to wait for each analysis (default: 300)")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"ERROR: Path {args.path} does not exist.", file=sys.stderr)
        sys.exit(1)

    # Prefer env var over CLI arg to avoid key in shell history / process listing
    api_key = os.environ.get("VT_API_KEY") or args.api_key
    if not api_key or len(api_key) < 20:
        print("ERROR: A valid VirusTotal API key is required.", file=sys.stderr)
        print("Set via: export VT_API_KEY='your-key-here'", file=sys.stderr)
        print("Or pass: --api-key 'your-key-here'", file=sys.stderr)
        print("Get a free key at: https://www.virustotal.com/gui/join-us", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Scanning scripts in: {args.path}\n")
    summary = scan_skill_scripts(args.path, api_key, args.poll_timeout)

    print_report(summary, use_color=not args.no_color)

    if args.output:
        args.output.write_text(json.dumps(summary.to_dict(), indent=2))
        print(f"JSON report written to {args.output}")

    if summary.malicious > 0:
        sys.exit(2)
    elif summary.suspicious > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
