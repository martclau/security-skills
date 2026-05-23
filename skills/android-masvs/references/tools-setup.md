# Tools setup

`unpack_apk.sh` uses several tools. None is strictly required (the script
degrades gracefully), but you'll get much better coverage with all of them
installed. This file lists what's needed and how to install in the typical
sandbox environments where this skill runs.

## Recommended set

| Tool | What it gives you | Install method |
|---|---|---|
| `python3` + `androguard` | Manifest parsing, components, signing, ARSC strings — works without Java | `pip install --break-system-packages androguard` |
| `apktool` | Smali decoding, decoded resources, original AndroidManifest | OS package, or download JAR from https://github.com/iBotPeaches/Apktool/releases |
| `jadx` | Java/Kotlin decompilation from DEX (grep-friendly) | OS package, or download from https://github.com/skylot/jadx/releases |
| `aapt2` (or `aapt`) | Manifest dump fallback when apktool isn't available | `apt install aapt2` |
| `apksigner` | Signing scheme verification (v1/v2/v3/v4) and cert fingerprints | `apt install apksigner` |
| `unzip` | Raw APK contents | usually preinstalled |
| `ripgrep` (`rg`) | Faster recursive search | `apt install ripgrep` |
| `checksec` (`checksec.sh`) | Binary hardening overview for native libs | `apt install checksec`, or fall back to `readelf` |
| `keytool` | Cert printing if `apksigner` isn't available | comes with OpenJDK |
| `dex2jar` | Last-resort DEX→JAR if jadx is missing | `apt install dex2jar` |

## Installing in a Claude sandbox (Ubuntu)

The egress proxy in this environment allows `pypi.org`, `github.com`, and
the Ubuntu apt mirrors. So:

```bash
# Python-only path (lightest, always works)
pip install --break-system-packages androguard

# Plus apt-installable tools (most useful additions)
sudo apt-get update -qq
sudo apt-get install -y -qq apktool aapt2 apksigner ripgrep openjdk-21-jre-headless dex2jar checksec

# jadx is not in apt — download a release JAR
mkdir -p /opt/jadx && cd /opt/jadx
JADX_URL="https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip"
curl -sL "$JADX_URL" -o jadx.zip && unzip -q jadx.zip && rm jadx.zip
ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
```

(Adjust the jadx version to whatever's current — check
https://github.com/skylot/jadx/releases.)

## Minimal path (no Java available)

If you can't install Java tools, you can still produce a useful assessment:

1. `pip install --break-system-packages androguard` — gives you manifest,
   permissions, components, signing, package info, and full ARSC string
   table.
2. `unzip` the APK to read `assets/`, `lib/`, `META-INF/`, resources.arsc.
3. For DEX inspection without decompiling to Java, use `androguard`'s
   `DalvikVMFormat` — string constants, class names, method signatures
   are all available, and you can grep them.

```python
# Quick DEX string dump with androguard
from androguard.misc import AnalyzeAPK
a, d, dx = AnalyzeAPK("app.apk")
for dex in d:
    for s in dex.get_strings():
        print(s)
```

Note that without smali or decompiled Java, you'll miss control-flow
context. You can still catch most CRITICAL/HIGH findings (hardcoded keys,
weak crypto algorithm strings, exported components), but MEDIUM findings
that depend on *how* an API is called need real decompilation.

## What the script does when tools are missing

`unpack_apk.sh` logs warnings (`[unpack][WARN] ...`) for each missing tool
but continues. Inspect `meta/` after running — anything not populated
indicates a missing tool. Decide whether to install the missing tool or
proceed with reduced coverage.

## Networked sandboxes vs offline ones

If the sandbox has no internet access, none of the install commands work.
In that case:
- Tell the user up front what coverage is reduced.
- Focus on what you can do: manifest analysis (Python stdlib can parse
  binary AXML with a small helper), resources.arsc inspection,
  string-extraction from DEX bytes, and grep on `META-INF/` plaintext.
- Defer Java-level findings to "out of scope (tooling unavailable)".
