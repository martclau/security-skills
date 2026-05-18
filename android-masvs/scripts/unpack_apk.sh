#!/usr/bin/env bash
# unpack_apk.sh — Decode an APK and emit a stable working layout.
#
# Usage: unpack_apk.sh <apk> <workdir>
#
# Produces (under <workdir>):
#   decoded/    apktool output (manifest+res+smali). If apktool is missing,
#               only AndroidManifest.xml decoded via aapt2/androguard.
#   java/       jadx decompiled sources (if jadx is installed)
#   unpacked/   raw unzip of the APK (always produced)
#   meta/       manifest.xml, permissions.txt, components.txt, signing.txt,
#               strings.txt, apk-info.txt, libs.txt
#   findings.md  empty report skeleton
#
# The script is intentionally tolerant: missing tools produce warnings, not
# failures, so partial analysis can still proceed.

set -u
APK="${1:-}"
WORKDIR="${2:-}"

if [[ -z "$APK" || -z "$WORKDIR" ]]; then
  echo "Usage: $0 <apk> <workdir>" >&2
  exit 2
fi

if [[ ! -f "$APK" ]]; then
  echo "ERROR: APK not found: $APK" >&2
  exit 2
fi

mkdir -p "$WORKDIR"/{decoded,java,unpacked,meta}
WORKDIR_ABS="$(cd "$WORKDIR" && pwd)"
APK_ABS="$(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")"

note() { echo "[unpack] $*"; }
warn() { echo "[unpack][WARN] $*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# 1. Raw unzip — always works, gives us classes.dex, resources.arsc, lib/, etc.
note "Unzipping APK..."
unzip -q -o "$APK_ABS" -d "$WORKDIR_ABS/unpacked" || warn "unzip failed (corrupt apk?)"

# 2. apktool decode — manifest + resources + smali
if have apktool; then
  note "Running apktool d ..."
  apktool d -f -o "$WORKDIR_ABS/decoded" "$APK_ABS" >"$WORKDIR_ABS/meta/apktool.log" 2>&1 \
    || warn "apktool failed; see meta/apktool.log"
else
  warn "apktool not installed; smali decoding skipped. See references/tools-setup.md"
fi

# 3. Pretty manifest
if [[ -f "$WORKDIR_ABS/decoded/AndroidManifest.xml" ]]; then
  cp "$WORKDIR_ABS/decoded/AndroidManifest.xml" "$WORKDIR_ABS/meta/manifest.xml"
elif have aapt2; then
  note "Using aapt2 to dump manifest (binary form decoded)..."
  aapt2 dump xmltree "$APK_ABS" --file AndroidManifest.xml \
    >"$WORKDIR_ABS/meta/manifest.xml" 2>/dev/null \
    || warn "aapt2 manifest dump failed"
elif have aapt; then
  aapt dump xmltree "$APK_ABS" AndroidManifest.xml \
    >"$WORKDIR_ABS/meta/manifest.xml" 2>/dev/null \
    || warn "aapt manifest dump failed"
elif have python3 && python3 -c 'import androguard' 2>/dev/null; then
  note "Using androguard to dump manifest..."
  python3 - <<PY >"$WORKDIR_ABS/meta/manifest.xml" 2>/dev/null || warn "androguard manifest dump failed"
from androguard.core.bytecodes.apk import APK
import sys
a = APK("$APK_ABS")
sys.stdout.write(a.get_android_manifest_axml().get_xml().decode("utf-8", "replace"))
PY
else
  warn "No tool available to decode AndroidManifest.xml"
fi

# 4. Inventory: permissions, components, package info, libs
PYINV="$WORKDIR_ABS/meta/_inv.py"
cat >"$PYINV" <<'PY'
import sys, os, json, re

apk_path = sys.argv[1]
meta_dir = sys.argv[2]

def write(name, text):
    with open(os.path.join(meta_dir, name), "w") as f:
        f.write(text)

try:
    from androguard.core.bytecodes.apk import APK
    a = APK(apk_path)
    info = []
    info.append(f"package         : {a.get_package()}")
    info.append(f"versionName     : {a.get_androidversion_name()}")
    info.append(f"versionCode     : {a.get_androidversion_code()}")
    info.append(f"minSdkVersion   : {a.get_min_sdk_version()}")
    info.append(f"targetSdkVersion: {a.get_target_sdk_version()}")
    info.append(f"appName         : {a.get_app_name()}")
    info.append(f"mainActivity    : {a.get_main_activity()}")
    write("apk-info.txt", "\n".join(info) + "\n")

    write("permissions.txt", "\n".join(sorted(a.get_permissions())) + "\n")

    comps = []
    for kind, getter in (("activity", a.get_activities),
                         ("service",  a.get_services),
                         ("receiver", a.get_receivers),
                         ("provider", a.get_providers)):
        for c in getter():
            exported = a.get_element(kind, "exported", c)
            comps.append(f"{kind}\t{c}\texported={exported}")
    write("components.txt", "\n".join(comps) + "\n")

    libs = []
    for f in a.get_files():
        if f.startswith("lib/") and f.endswith(".so"):
            libs.append(f)
    write("libs.txt", "\n".join(sorted(libs)) + "\n")

    # Strings: dump app's resource strings
    try:
        rs = a.get_android_resources()
        out = []
        for pkg in rs.get_packages_names():
            for locale in rs.get_locales(pkg):
                for sid, sname, sval in rs.get_resolved_strings_id(pkg).items() if False else []:
                    pass
        # Simple fallback: dump all string resources
        out = []
        for pkg in rs.get_packages_names():
            for sid in rs.get_res_id_by_key(pkg, "string", "") if False else []:
                pass
        # Use lower-level approach
        for pkg in rs.get_packages_names():
            try:
                for res_id, res_name in rs.get_id(pkg).items() if False else []:
                    pass
            except Exception:
                pass
        # Cleanest: iterate ARSC string pool via get_strings_resources
        try:
            xml = rs.get_strings_resources()
            write("strings.txt", xml.decode("utf-8", "replace"))
        except Exception:
            write("strings.txt", "")
    except Exception as e:
        write("strings.txt", f"# strings extraction failed: {e}\n")

except Exception as e:
    write("apk-info.txt", f"# androguard not available or failed: {e}\n# Fall back to aapt/apktool output.\n")
PY

if have python3 && python3 -c 'import androguard' 2>/dev/null; then
  python3 "$PYINV" "$APK_ABS" "$WORKDIR_ABS/meta" || warn "androguard inventory failed"
else
  # Fallback inventory using grep on the apktool manifest
  if [[ -f "$WORKDIR_ABS/meta/manifest.xml" ]]; then
    grep -oE 'android:name="[^"]+"' "$WORKDIR_ABS/meta/manifest.xml" \
      | grep -E '\.permission\.|android.permission' \
      | sed 's/.*"\(.*\)"/\1/' | sort -u >"$WORKDIR_ABS/meta/permissions.txt" 2>/dev/null || true
    grep -nE '<(activity|service|receiver|provider)\b' "$WORKDIR_ABS/meta/manifest.xml" \
      >"$WORKDIR_ABS/meta/components.txt" 2>/dev/null || true
  fi
  ls "$WORKDIR_ABS/unpacked/lib/" 2>/dev/null | xargs -I{} ls "$WORKDIR_ABS/unpacked/lib/{}" 2>/dev/null \
    >"$WORKDIR_ABS/meta/libs.txt" 2>/dev/null || true
  echo "# androguard not installed; partial inventory. Install with: pip install --break-system-packages androguard" \
    >"$WORKDIR_ABS/meta/apk-info.txt"
fi

# 5. Signing info
if have apksigner; then
  note "Running apksigner verify..."
  apksigner verify --verbose --print-certs "$APK_ABS" \
    >"$WORKDIR_ABS/meta/signing.txt" 2>&1 || true
elif have keytool && [[ -f "$WORKDIR_ABS/unpacked/META-INF/CERT.RSA" ]]; then
  keytool -printcert -file "$WORKDIR_ABS/unpacked/META-INF/CERT.RSA" \
    >"$WORKDIR_ABS/meta/signing.txt" 2>&1 || true
else
  echo "# apksigner/keytool not available — install android-sdk-build-tools or OpenJDK" \
    >"$WORKDIR_ABS/meta/signing.txt"
fi

# 6. jadx — Java decompilation (optional, may take time on large APKs)
if have jadx; then
  note "Running jadx (this may take a minute)..."
  jadx --no-res -d "$WORKDIR_ABS/java" "$APK_ABS" >"$WORKDIR_ABS/meta/jadx.log" 2>&1 \
    || warn "jadx returned non-zero; partial output may still be usable"
else
  warn "jadx not installed; will rely on apktool smali. Install jadx for Java decompilation."
fi

# 7. Report skeleton
cat >"$WORKDIR_ABS/findings.md" <<'MD'
# MASVS Assessment — <App name> (<package>)

**Version:**
**Min/Target/Compile SDK:**
**Signing:**
**Assessed against:** OWASP MASVS v2.0
**Analysis type:** Static only (dynamic checks listed separately)

## App overview
<fill in: what the app does, tech stack, threat picture>

## Summary
| # | Severity | MASVS | MASWE | Finding |
|---|----------|-------|-------|---------|

## Findings (detail)

## Passed checks

## Out-of-scope / requires dynamic analysis

## Methodology
MD

note "Done. Workspace: $WORKDIR_ABS"
echo
echo "Next steps (Phase 3 onwards):"
echo "  - Read meta/manifest.xml, meta/permissions.txt, meta/components.txt"
echo "  - Open references/masvs-*.md and run the listed checks against:"
echo "      smali  -> $WORKDIR_ABS/decoded/smali*/"
echo "      java   -> $WORKDIR_ABS/java/sources/"
echo "      res    -> $WORKDIR_ABS/decoded/res/"
echo "  - Fill in $WORKDIR_ABS/findings.md"
