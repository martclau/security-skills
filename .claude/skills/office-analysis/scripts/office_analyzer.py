#!/usr/bin/env python3
"""
office_analyzer.py — Helper script for the office-analysis Claude Code skill.

Modes:
  --triage           Run format identification and oleid-style triage
  --check-equation   Detect Equation Editor OLE objects (CVE-2017-11882)
  --check-rels       Scan OOXML .rels files for external URL references
  --check-rtf-template  Detect RTF remote template references
  --deobfuscate      Extract IOCs from VBA source via common obfuscation patterns
  --iocs             Aggregate IOCs from multiple analysis outputs
  --vt-hash          Look up a SHA-256 hash on VirusTotal
  --entropy          Compute per-stream entropy for OLE files

Outputs JSON by default; use --no-json for plain text.
Requires: oletools (oleid, olevba, oledump), python-magic
Optional: requests (for VT lookup), zipfile (stdlib)
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional dependency handling
# ---------------------------------------------------------------------------

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Equation Editor CLSID bytes (little-endian in OLE stream)
EQUATION_CLSID = b'\x02\xce\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'

# Magic bytes
MAGIC_OLE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
MAGIC_ZIP = b'PK\x03\x04'
MAGIC_RTF = b'{\\rtf'

# OOXML relationship types that may reference external resources
EXTERNAL_REL_TYPES = [
    'attachedTemplate',
    'externalLink',
    'externalLinkPath',
    'hyperlink',
    'image',
    'frame',
    'oleObject',
    'subDocument',
]

# Suspicious VBA API calls by category
VBA_SUSPICIOUS_APIS = {
    'execution': [
        'Shell', 'WScript.Shell', 'CreateObject', 'GetObject',
        'CallByName', 'Application.Run', 'MacroOptions',
    ],
    'download': [
        'URLDownloadToFile', 'URLDownloadToFileA', 'WinHttpRequest',
        'XMLHTTP', 'ServerXMLHTTP', 'InternetExplorer.Application',
        'wget', 'curl', 'BitsAdmin',
    ],
    'process_spawn': [
        'powershell', 'cmd.exe', 'cmd /c', 'wscript', 'cscript',
        'mshta', 'rundll32', 'regsvr32', 'certutil', 'wmic',
    ],
    'persistence': [
        'RegWrite', 'RegCreateKey', 'RegSetValue',
        'HKLM', 'HKCU', 'CurrentVersion\\Run',
        'Startup', 'schtasks', 'at.exe',
    ],
    'file_ops': [
        'Open.*For Output', 'Open.*For Binary',
        'FileCopy', 'Kill ', 'MkDir',
        'Environ("TEMP")', 'Environ("APPDATA")',
    ],
    'encoding': [
        'Base64', 'Chr(', 'Asc(', 'ChrW(',
        'StrReverse', 'String(', 'Space(',
        'Replace(', 'Join(', 'Split(',
    ],
    'injection': [
        'VirtualAlloc', 'WriteProcessMemory', 'CreateThread',
        'RtlMoveMemory', 'CallWindowProc', 'EnumWindows',
    ],
    'anti_analysis': [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'GetTickCount', 'QueryPerformanceCounter',
        'VirtualBox', 'VMware', 'VBOX', 'Sandboxie',
    ],
}

# IOC regex patterns
IOC_PATTERNS = {
    'url': re.compile(
        r'https?://[^\s\'"<>\x00-\x1f]{8,}',
        re.IGNORECASE,
    ),
    'unc_path': re.compile(
        r'\\\\[a-z0-9._-]{2,}\\[^\s\'"<>]{2,}',
        re.IGNORECASE,
    ),
    'ip_port': re.compile(
        r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        r'(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}'
        r'(?::\d{2,5})?\b',
    ),
    'temp_path': re.compile(
        r'(?:%TEMP%|%APPDATA%|%LOCALAPPDATA%|C:\\Users\\[^\\]+\\AppData|'
        r'C:\\Windows\\Temp|/tmp/|/dev/shm/)[^\s\'"<>\x00-\x1f]{2,}',
        re.IGNORECASE,
    ),
    'registry_run': re.compile(
        r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)'
        r'[\\][^\s\'"<>\x00-\x1f]{5,}',
        re.IGNORECASE,
    ),
    'base64_blob': re.compile(
        r'(?:[A-Za-z0-9+/]{40,}={0,2})',
    ),
    'powershell_encoded': re.compile(
        r'(?:-enc(?:odedcommand)?|-e\s+)[A-Za-z0-9+/=]{20,}',
        re.IGNORECASE,
    ),
}


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(path: str) -> dict:
    """Detect true file format from magic bytes."""
    result = {'path': path, 'format': 'unknown', 'extension': Path(path).suffix.lower()}
    with open(path, 'rb') as f:
        header = f.read(16)

    if header[:8] == MAGIC_OLE:
        result['format'] = 'OLE2'
        result['format_detail'] = 'Microsoft Compound Binary File (OLE2)'
    elif header[:4] == MAGIC_ZIP:
        result['format'] = 'OOXML'
        result['format_detail'] = 'Office Open XML (ZIP-based)'
        # Disambiguate subtypes from content types
        try:
            with zipfile.ZipFile(path) as z:
                if '[Content_Types].xml' in z.namelist():
                    ct = z.read('[Content_Types].xml').decode('utf-8', errors='replace')
                    if 'wordprocessingml' in ct:
                        result['format_subtype'] = 'Word'
                    elif 'spreadsheetml' in ct:
                        result['format_subtype'] = 'Excel'
                    elif 'presentationml' in ct:
                        result['format_subtype'] = 'PowerPoint'
        except Exception:
            pass
    elif header[:5] == MAGIC_RTF or header[:6] == b'{\\rtf1':
        result['format'] = 'RTF'
        result['format_detail'] = 'Rich Text Format'
    elif header[:2] == b'\x50\x4b' and b'mimetypeapplication/vnd' in header:
        result['format'] = 'OOXML'
    else:
        result['format'] = 'unknown'
        result['format_detail'] = f'magic: {header[:8].hex()}'

    ext_map = {
        '.doc': 'OLE2', '.dot': 'OLE2', '.xls': 'OLE2', '.xlt': 'OLE2',
        '.ppt': 'OLE2', '.pot': 'OLE2',
        '.docx': 'OOXML', '.docm': 'OOXML', '.dotx': 'OOXML', '.dotm': 'OOXML',
        '.xlsx': 'OOXML', '.xlsm': 'OOXML', '.xltx': 'OOXML', '.xltm': 'OOXML',
        '.xlsb': 'OOXML', '.pptx': 'OOXML', '.pptm': 'OOXML',
        '.rtf': 'RTF',
    }
    expected = ext_map.get(result['extension'])
    result['extension_matches_format'] = (expected == result['format']) if expected else None

    return result


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

def triage(path: str) -> dict:
    """High-level triage: format, hashes, basic risk indicators."""
    report = {'file': path, 'indicators': [], 'warnings': []}

    # Hashes
    data = open(path, 'rb').read()
    report['md5'] = hashlib.md5(data).hexdigest()
    report['sha256'] = hashlib.sha256(data).hexdigest()
    report['size_bytes'] = len(data)

    # Format
    fmt = detect_format(path)
    report['format'] = fmt

    if fmt.get('extension_matches_format') is False:
        report['warnings'].append(
            f"Extension '{fmt['extension']}' does not match detected format '{fmt['format']}' — possible disguise"
        )

    # OLE2 triage
    if fmt['format'] == 'OLE2' and HAS_OLEFILE:
        _triage_ole(path, data, report)

    # OOXML triage
    elif fmt['format'] == 'OOXML':
        _triage_ooxml(path, report)

    # RTF triage
    elif fmt['format'] == 'RTF':
        _triage_rtf(data, report)

    return report


def _triage_ole(path, data, report):
    try:
        ole = olefile.OleFileIO(path)
    except Exception as e:
        report['warnings'].append(f'olefile parse error: {e}')
        return

    streams = ole.listdir()
    report['ole_streams'] = ['/'.join(s) for s in streams]

    # VBA detection
    vba_streams = [s for s in streams if 'VBA' in [x.upper() for x in s]]
    report['vba_present'] = len(vba_streams) > 0
    if report['vba_present']:
        report['indicators'].append('VBA macros detected in OLE streams')

    # Equation Editor
    for stream in streams:
        try:
            content = ole.openstream(stream).read()
            if EQUATION_CLSID in content:
                report['indicators'].append(
                    'Equation Editor object (CLSID 0002CE02) detected — potential CVE-2017-11882 vessel'
                )
                break
        except Exception:
            pass

    # SRP streams (VBA stomping indicator)
    srp_streams = [s for s in streams if any('SRP' in x.upper() for x in s)]
    if srp_streams:
        report['indicators'].append(
            f'SRP streams found ({len(srp_streams)}) — possible VBA stomping; p-code may differ from visible source'
        )

    # Embedded OLE objects
    if ole.exists('ObjectPool'):
        report['indicators'].append('ObjectPool storage present — embedded OLE objects detected')

    ole.close()


def _triage_ooxml(path, report):
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        report['warnings'].append(f'ZIP parse error: {e}')
        return

    names = zf.namelist()
    report['ooxml_parts'] = names

    # vbaProject.bin
    vba_parts = [n for n in names if 'vbaProject' in n or n.endswith('.bin')]
    if vba_parts:
        report['vba_present'] = True
        report['indicators'].append(
            f'Macro-enabled document: vbaProject.bin found ({", ".join(vba_parts)})'
        )

    # Content types with unexpected entries
    if '[Content_Types].xml' in names:
        ct = zf.read('[Content_Types].xml').decode('utf-8', errors='replace')
        unexpected = [t for t in ['application/x-msdownload', 'text/html', 'application/x-shockwave-flash']
                      if t in ct]
        for t in unexpected:
            report['indicators'].append(f'Unexpected content type in [Content_Types].xml: {t}')

    # .rels files with external URLs
    rels_files = [n for n in names if n.endswith('.rels')]
    for rels in rels_files:
        content = zf.read(rels).decode('utf-8', errors='replace')
        if 'http://' in content or 'https://' in content:
            urls = IOC_PATTERNS['url'].findall(content)
            for url in urls:
                report['indicators'].append(
                    f'External URL in {rels}: {url} — possible template injection'
                )

    # Embedded PE/executables in embeddings
    embed_dirs = [n for n in names if '/embeddings/' in n or '/media/' in n]
    for part in embed_dirs:
        try:
            data = zf.read(part)
            if data[:2] == b'MZ':
                report['indicators'].append(f'PE executable embedded in {part}')
            elif data[:8] == MAGIC_OLE:
                report['indicators'].append(f'OLE object embedded in {part}')
        except Exception:
            pass

    zf.close()


def _triage_rtf(data: bytes, report):
    text = data.decode('latin-1', errors='replace')

    # Remote template
    template_pattern = re.compile(r'\\template\s+(https?://[^\s\\}]+)', re.IGNORECASE)
    matches = template_pattern.findall(text)
    for url in matches:
        report['indicators'].append(
            f'RTF remote template reference: {url} — loads on open (CVE-2017-0199 pattern)'
        )

    # OLE object blocks
    obj_count = text.count(r'\object')
    if obj_count > 0:
        report['indicators'].append(f'{obj_count} \\object block(s) found in RTF — embedded OLE objects')

    # objdata size (large = likely shellcode or payload)
    objdata_matches = re.findall(r'\\objdata\s+([0-9a-fA-F\s]{20,})', text)
    for od in objdata_matches:
        hex_bytes = re.sub(r'\s', '', od)
        if len(hex_bytes) > 400:
            report['indicators'].append(
                f'Large \\objdata block found ({len(hex_bytes)//2} bytes) — possible shellcode or embedded payload'
            )

    # Nested ZIP in RTF (embedded OOXML)
    pk_matches = [m.start() for m in re.finditer(r'504b0304', text, re.IGNORECASE)]
    if pk_matches:
        report['indicators'].append(
            f'ZIP magic bytes (504b0304) found in RTF hex data — embedded OOXML document'
        )

    # URLs in RTF body
    urls = IOC_PATTERNS['url'].findall(text)
    if urls:
        for url in urls[:10]:  # cap at 10 to avoid noise
            report['indicators'].append(f'URL found in RTF body: {url}')


# ---------------------------------------------------------------------------
# Equation Editor check (dedicated mode)
# ---------------------------------------------------------------------------

def check_equation(path: str) -> dict:
    """Scan OLE file for Equation Editor CLSID and surrounding bytes."""
    result = {'path': path, 'equation_editor_found': False, 'findings': []}
    if not HAS_OLEFILE:
        result['error'] = 'olefile not installed (pip install olefile)'
        return result

    data = open(path, 'rb').read()
    offset = 0
    while True:
        idx = data.find(EQUATION_CLSID, offset)
        if idx == -1:
            break
        result['equation_editor_found'] = True
        # Grab 32 bytes after CLSID as potential shellcode preview
        context = data[idx:idx + 48].hex()
        result['findings'].append({
            'offset': hex(idx),
            'clsid_hex': EQUATION_CLSID.hex(),
            'context_bytes': context,
            'note': 'Equation Editor CLSID detected — inspect surrounding bytes for CVE-2017-11882 shellcode pattern',
        })
        offset = idx + 16

    return result


# ---------------------------------------------------------------------------
# OOXML .rels checker
# ---------------------------------------------------------------------------

def check_rels(extracted_dir: str) -> dict:
    """Scan all .rels files in an extracted OOXML directory for external references."""
    result = {'directory': extracted_dir, 'findings': []}
    rels_files = list(Path(extracted_dir).rglob('*.rels'))

    for rels_path in rels_files:
        try:
            content = rels_path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue

        # Parse Relationship elements
        rel_pattern = re.compile(
            r'<Relationship\s[^>]*Type="([^"]*)"[^>]*Target="([^"]*)"[^>]*/?>',
            re.IGNORECASE,
        )
        for m in rel_pattern.finditer(content):
            rel_type = m.group(1)
            target = m.group(2)

            if target.startswith('http://') or target.startswith('https://') or target.startswith('\\\\'):
                # Extract short relationship type name
                short_type = rel_type.split('/')[-1] if '/' in rel_type else rel_type
                severity = 'HIGH' if short_type == 'attachedTemplate' else 'MEDIUM'
                result['findings'].append({
                    'file': str(rels_path.relative_to(extracted_dir)),
                    'relationship_type': short_type,
                    'full_type': rel_type,
                    'target': target,
                    'severity': severity,
                    'note': (
                        'Template injection: document will fetch and execute remote template on open'
                        if short_type == 'attachedTemplate'
                        else f'External {short_type} reference'
                    ),
                })

    return result


# ---------------------------------------------------------------------------
# RTF remote template checker
# ---------------------------------------------------------------------------

def check_rtf_template(path: str) -> dict:
    """Check RTF file for \\*\\template control word pointing to external URL."""
    result = {'path': path, 'remote_template_found': False, 'findings': []}
    data = open(path, 'rb').read()
    text = data.decode('latin-1', errors='replace')

    # Standard template reference
    for pattern in [
        re.compile(r'\\\*\\template\s+(https?://[^\s\\}]+)', re.IGNORECASE),
        re.compile(r'\\template\s+(https?://[^\s\\}]+)', re.IGNORECASE),
        re.compile(r'\\\*\\template\s+(\\\\[^\s\\}]+)', re.IGNORECASE),
    ]:
        for m in pattern.finditer(text):
            result['remote_template_found'] = True
            result['findings'].append({
                'offset': hex(m.start()),
                'url': m.group(1),
                'pattern': pattern.pattern,
                'severity': 'HIGH',
                'note': 'RTF \\*\\template points to external resource — document will fetch it on open (CVE-2017-0199 family)',
            })

    return result


# ---------------------------------------------------------------------------
# IOC extraction / deobfuscation
# ---------------------------------------------------------------------------

def deobfuscate_vba(vba_source_path: str) -> dict:
    """Extract IOCs from VBA source via common obfuscation patterns."""
    result = {'source_file': vba_source_path, 'iocs': [], 'suspicious_apis': {}, 'warnings': []}
    try:
        text = open(vba_source_path, encoding='utf-8', errors='replace').read()
    except Exception as e:
        result['error'] = str(e)
        return result

    # Scan for suspicious API calls
    for category, apis in VBA_SUSPICIOUS_APIS.items():
        hits = []
        for api in apis:
            if re.search(re.escape(api), text, re.IGNORECASE):
                hits.append(api)
        if hits:
            result['suspicious_apis'][category] = hits

    # Extract IOCs via regex
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        for m in matches:
            if ioc_type == 'base64_blob':
                # Only keep blobs that decode cleanly and contain useful strings
                try:
                    decoded = base64.b64decode(m + '==').decode('utf-8', errors='ignore')
                    if any(kw in decoded.lower() for kw in ['http', 'cmd', 'powershell', 'shell', '.exe', '.dll']):
                        result['iocs'].append({'type': 'base64_decoded', 'raw': m[:40] + '...', 'decoded_preview': decoded[:120]})
                except Exception:
                    pass
            else:
                result['iocs'].append({'type': ioc_type, 'value': m})

    # Auto-execution triggers
    autoexec_triggers = [
        'AutoOpen', 'AutoClose', 'Auto_Open', 'Auto_Close',
        'Document_Open', 'Document_Close', 'Workbook_Open',
        'Workbook_BeforeClose', 'Workbook_Activate',
        'DocumentOpen', 'WindowActivate',
    ]
    found_triggers = [t for t in autoexec_triggers if re.search(r'\b' + re.escape(t) + r'\b', text, re.IGNORECASE)]
    if found_triggers:
        result['autoexec_triggers'] = found_triggers

    # Chr() concatenation pattern (common obfuscation)
    chr_pattern = re.compile(r'Chr\(\s*(\d+)\s*\)', re.IGNORECASE)
    chr_chars = chr_pattern.findall(text)
    if len(chr_chars) > 5:
        try:
            decoded_str = ''.join(chr(int(c)) for c in chr_chars)
            result['iocs'].append({
                'type': 'chr_concatenation',
                'char_count': len(chr_chars),
                'decoded_preview': decoded_str[:200],
            })
        except Exception:
            pass

    # Deduplicate IOCs
    seen = set()
    deduped = []
    for ioc in result['iocs']:
        key = json.dumps(ioc, sort_keys=True)
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)
    result['iocs'] = deduped

    return result


def aggregate_iocs(target_path: str, vba_source: str = None, vipermonkey: str = None) -> dict:
    """Aggregate IOCs from multiple analysis outputs."""
    result = {'target': target_path, 'iocs': []}

    # From raw file triage
    triage_result = triage(target_path)
    for indicator in triage_result.get('indicators', []):
        url_matches = IOC_PATTERNS['url'].findall(indicator)
        for url in url_matches:
            result['iocs'].append({'source': 'triage', 'type': 'url', 'value': url})

    # From VBA source
    if vba_source and os.path.exists(vba_source):
        deob = deobfuscate_vba(vba_source)
        for ioc in deob.get('iocs', []):
            ioc['source'] = 'vba_source'
            result['iocs'].append(ioc)

    # From ViperMonkey output
    if vipermonkey and os.path.exists(vipermonkey):
        vm_text = open(vipermonkey, encoding='utf-8', errors='replace').read()
        for ioc_type, pattern in IOC_PATTERNS.items():
            for m in pattern.findall(vm_text):
                result['iocs'].append({'source': 'vipermonkey', 'type': ioc_type, 'value': m})

    # Deduplicate
    seen = set()
    deduped = []
    for ioc in result['iocs']:
        key = json.dumps(ioc, sort_keys=True)
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)
    result['iocs'] = deduped
    result['total_iocs'] = len(deduped)
    return result


# ---------------------------------------------------------------------------
# VirusTotal hash lookup
# ---------------------------------------------------------------------------

def vt_hash_lookup(sha256: str) -> dict:
    """Look up a SHA-256 hash on VirusTotal (requires VT_API_KEY env var)."""
    api_key = os.environ.get('VT_API_KEY')
    if not api_key:
        return {'error': 'VT_API_KEY environment variable not set. Never paste API keys in chat.'}
    if not HAS_REQUESTS:
        return {'error': 'requests library not installed (pip install requests)'}

    url = f'https://www.virustotal.com/api/v3/files/{sha256}'
    headers = {'x-apikey': api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 404:
            return {'hash': sha256, 'found': False, 'note': 'Hash not found in VirusTotal — novel or modified sample'}
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        names = attrs.get('names', [])[:5]
        return {
            'hash': sha256,
            'found': True,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'total_engines': sum(stats.values()),
            'known_names': names,
            'first_submission': attrs.get('first_submission_date'),
            'last_analysis_date': attrs.get('last_analysis_date'),
            'verdict': (
                'MALICIOUS' if stats.get('malicious', 0) >= 5
                else 'SUSPICIOUS' if stats.get('malicious', 0) >= 1 or stats.get('suspicious', 0) >= 3
                else 'CLEAN'
            ),
        }
    except Exception as e:
        return {'error': str(e)}


# ---------------------------------------------------------------------------
# Entropy (per-stream for OLE files)
# ---------------------------------------------------------------------------

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def stream_entropy(path: str) -> dict:
    """Compute entropy for each OLE stream."""
    result = {'path': path, 'streams': []}
    if not HAS_OLEFILE:
        result['error'] = 'olefile not installed (pip install olefile)'
        return result
    try:
        ole = olefile.OleFileIO(path)
    except Exception as e:
        result['error'] = str(e)
        return result

    for stream in ole.listdir(streams=True, storages=False):
        try:
            data = ole.openstream(stream).read()
            entropy = compute_entropy(data)
            result['streams'].append({
                'name': '/'.join(stream),
                'size_bytes': len(data),
                'entropy': round(entropy, 3),
                'high_entropy': entropy > 7.0,
            })
        except Exception:
            pass

    ole.close()
    result['streams'].sort(key=lambda x: x['entropy'], reverse=True)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Office document security analysis helper for the office-analysis Claude Code skill',
    )
    parser.add_argument('target', nargs='?', help='Path to the Office document or VBA source file')
    parser.add_argument('--triage', action='store_true', help='Run triage on the document')
    parser.add_argument('--check-equation', action='store_true', help='Check for Equation Editor OLE objects')
    parser.add_argument('--check-rels', action='store_true', help='Scan extracted OOXML directory for external .rels refs')
    parser.add_argument('--check-rtf-template', action='store_true', help='Check RTF for remote template reference')
    parser.add_argument('--deobfuscate', action='store_true', help='Extract IOCs from VBA source file')
    parser.add_argument('--iocs', action='store_true', help='Aggregate IOCs from multiple sources')
    parser.add_argument('--vba-source', help='Path to extracted VBA source (for --iocs)')
    parser.add_argument('--vipermonkey', help='Path to ViperMonkey output file (for --iocs)')
    parser.add_argument('--entropy', action='store_true', help='Compute per-stream entropy (OLE files)')
    parser.add_argument('--vt-hash', metavar='SHA256', help='VirusTotal hash lookup')
    parser.add_argument('-o', '--output', help='Write JSON output to file')
    parser.add_argument('--no-json', action='store_true', help='Print human-readable output instead of JSON')
    args = parser.parse_args()

    result = None

    if args.vt_hash:
        result = vt_hash_lookup(args.vt_hash)
    elif not args.target:
        parser.print_help()
        sys.exit(1)
    elif args.triage:
        result = triage(args.target)
    elif args.check_equation:
        result = check_equation(args.target)
    elif args.check_rels:
        result = check_rels(args.target)
    elif args.check_rtf_template:
        result = check_rtf_template(args.target)
    elif args.deobfuscate:
        result = deobfuscate_vba(args.target)
    elif args.iocs:
        result = aggregate_iocs(args.target, vba_source=args.vba_source, vipermonkey=args.vipermonkey)
    elif args.entropy:
        result = stream_entropy(args.target)
    else:
        parser.print_help()
        sys.exit(1)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f'Results written to {args.output}', file=sys.stderr)
    elif args.no_json:
        if isinstance(result, dict):
            for k, v in result.items():
                print(f'{k}: {v}')
        else:
            print(result)
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
