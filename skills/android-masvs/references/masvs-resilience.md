# MASVS-RESILIENCE — Resilience against reverse engineering and tampering

Controls:
- **MASVS-RESILIENCE-1**: The app validates the integrity of the platform.
- **MASVS-RESILIENCE-2**: The app implements anti-tampering mechanisms.
- **MASVS-RESILIENCE-3**: The app implements anti-static-analysis mechanisms.
- **MASVS-RESILIENCE-4**: The app implements anti-dynamic-analysis techniques.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-XXXX/`

## Scoping note

RESILIENCE is the only MASVS category that's **conditional**. It applies
when the app needs to resist a malicious end-user (banking, DRM, gaming,
exam-proctoring, etc.). For low-risk apps (a public-info reader, an open-
source utility), most RESILIENCE findings should be downgraded to INFO.

Decide once, up front, whether RESILIENCE applies to this app. State the
decision in the report's "App overview".

## Checks (when RESILIENCE applies)

### R1 — Debuggable flag

**MASWE:** MASWE-0067 (Debuggable Flag Not Disabled)
**MASTG:** MASTG-TEST-0039, MASTG-TEST-0226

In `meta/manifest.xml`, on `<application>`:
- `android:debuggable="true"` in a release APK is CRITICAL — anyone with
  ADB can attach a debugger, dump memory, hook methods.
- Missing or `="false"` is correct.

```bash
grep -nE 'android:debuggable' "$WORK/meta/manifest.xml"
```

### R2 — APK signing scheme

**MASWE:** MASWE-0104 (App Integrity Not Verified)
**MASTG:** MASTG-TEST-0038, MASTG-TEST-0224, MASTG-TEST-0225

Read `meta/signing.txt`:

- Should be signed with v2+ (v2/v3/v4). v1-only (JAR signing) is vulnerable
  to Janus (CVE-2017-13156) on older Android versions.
- Key algorithm: RSA-2048+ or EC P-256.
- For Play distribution, v3 (key rotation) and v4 (incremental APK) are
  nice-to-haves.

Findings:
- v1-only signed → MEDIUM.
- RSA < 2048 → MEDIUM.

### R3 — ProGuard / R8 (code obfuscation)

**MASWE:** MASWE-0089 (Code Obfuscation Not Implemented)
**MASTG:** MASTG-TEST-0051

Heuristics:
- Classes named `a.a`, `b.b.c` in smali → obfuscated.
- Original-style names (`com.example.app.UserManager`, `LoginActivity`) in
  most classes → not obfuscated.
- `mapping.txt` referenced or shipped → ProGuard/R8 was used (mapping in the
  APK is unusual; usually only on the developer side).

```bash
ls "$WORK/decoded/smali"*/com/ 2>/dev/null | head -20
# Count single-char class names as a quick proxy
find "$WORK/decoded/smali"* -name '*.smali' 2>/dev/null | awk -F/ '{print $NF}' | grep -cE '^[a-z]\.smali$'
```

For RESILIENCE-required apps, missing obfuscation is MEDIUM.

### R4 — Native code stripping

**MASWE:** MASWE-0093 (Debugging Symbols Not Removed)
**MASTG:** MASTG-TEST-0040, MASTG-TEST-0288

```bash
for lib in $(find "$WORK/unpacked/lib/" -name '*.so'); do
  echo "=== $lib ==="
  file "$lib"
  readelf -S "$lib" 2>/dev/null | grep -E '\.symtab|\.debug'
done
```

Hits on `.debug*` sections or `.symtab` (vs only `.dynsym`) mean debug info
wasn't stripped. LOW-MEDIUM finding.

### R5 — Debug-only code shipping in release

**MASWE:** MASWE-0094 (Non-Production Resources Not Removed), MASWE-0095 (Code That Disables Security Controls Not Removed)
**MASTG:** MASTG-TEST-0041

```bash
rg -nE 'BuildConfig\.DEBUG|BuildConfig\.BUILD_TYPE|isDebuggable|TODO|FIXME|DELETE|TEST_ONLY' "$WORK/java/" 2>/dev/null | head -40
rg -nE 'webContentsDebugging|setWebContentsDebuggingEnabled\(true\)' "$WORK/java/" 2>/dev/null
```

Branches gated on `BuildConfig.DEBUG` are fine as long as they're stripped
by R8 at release. To verify, check whether the decompiled output still
contains the debug branches — if you see `if (false)` blocks or
`StrictMode` setup, R8 may not be aggressive enough or the build wasn't a
release.

### R6 — Root detection

**MASWE:** MASWE-0097 (Root/Jailbreak Detection Not Implemented)
**MASTG:** MASTG-TEST-0045, MASTG-TEST-0324, MASTG-TEST-0325

Patterns:
- Checking for `su` binary in `/system/bin/`, `/system/xbin/`, `/sbin/`, etc.
- Looking for known root apps: `com.topjohnwu.magisk`, `eu.chainfire.supersu`,
  `com.koushikdutta.rommanager`.
- `RootBeer` library (`com.scottyab.rootbeer`).
- Google Play Integrity API (`PlayIntegrity.requestIntegrityToken`).

```bash
rg -niE 'rootbeer|RootBeer|com\.topjohnwu\.magisk|chainfire\.supersu|/system/bin/su|isDeviceRooted|PlayIntegrity|IntegrityManager' "$WORK/java/" 2>/dev/null
```

Play Integrity API is the modern, server-verifiable approach. Local root
checks are easily bypassed (Frida hooks the methods) — note this in the
report.

### R7 — Emulator detection

**MASWE:** MASWE-0099 (Emulator Detection Not Implemented)
**MASTG:** MASTG-TEST-0049

```bash
rg -niE 'Build\.FINGERPRINT|generic|sdk_gphone|sdk_google|goldfish|ranchu|emulator|genymotion|/dev/qemu_pipe' "$WORK/java/" 2>/dev/null
```

### R8 — Anti-debugging / Frida detection

**MASWE:** MASWE-0101 (Debugger Detection Not Implemented), MASWE-0102 (Dynamic Analysis Tools Detection Not Implemented)
**MASTG:** MASTG-TEST-0046, MASTG-TEST-0048

Patterns:
- `Debug.isDebuggerConnected()` — Java-level check.
- `ptrace(PTRACE_TRACEME, ...)` in JNI — native debugger detection.
- Scanning `/proc/self/maps` for `frida-agent`, `gum-js-loop`, etc.
- Checking `/proc/self/status` for `TracerPid`.

```bash
rg -niE 'isDebuggerConnected|TracerPid|frida|gum-js|/proc/self/maps' "$WORK/java/" "$WORK/decoded/smali*/" 2>/dev/null
```

### R9 — App integrity / signature pinning

**MASWE:** MASWE-0104 (App Integrity Not Verified), MASWE-0106 (Official Store Verification Not Implemented)
**MASTG:** MASTG-TEST-0047

The app should verify it hasn't been resigned (repackaged with a different
key). Patterns:
- `PackageManager.getPackageInfo(..., GET_SIGNATURES)` followed by a hash
  comparison.
- Play Integrity API verdict checking.
- Checking installer source (`getInstallerPackageName`) for
  `com.android.vending` (Play Store).

```bash
rg -nE 'getPackageInfo|GET_SIGNATURES|GET_SIGNING_CERTIFICATES|getInstallerPackageName|getInstallSourceInfo' "$WORK/java/" 2>/dev/null
```

### R10 — Reverse-engineering note

Static analysis can only tell you whether RESILIENCE *mechanisms* are
*present in the code*. It cannot tell you whether they're *effective*.
A `RootBeer` check that any Frida user can hook past in five seconds still
"passes" static analysis. Always note in the report that effectiveness
requires dynamic testing.

## When RESILIENCE does NOT apply

If the threat model doesn't include a hostile end-user (e.g. an OSS app
where users would just patch out the checks anyway, or a utility with no
secrets to protect), say so plainly in the report. Mention you reviewed
RESILIENCE controls and marked them N/A — don't generate a long list of
LOW findings the user will dismiss.

## Passed checks worth noting

- `android:debuggable` not set or `false`
- Signed v2+ with RSA-2048 / EC P-256
- ProGuard/R8 enabled with obfuscation
- Native libs stripped
- Play Integrity API integration
- Multiple, layered anti-tamper signals (not a single grep-able call)
