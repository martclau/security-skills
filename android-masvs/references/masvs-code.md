# MASVS-CODE — Security best practices for data processing

Controls:
- **MASVS-CODE-1**: The app requires an up-to-date platform version.
- **MASVS-CODE-2**: The app has a mechanism for enforcing app updates.
- **MASVS-CODE-3**: The app only uses software components without known vulnerabilities.
- **MASVS-CODE-4**: The app validates and sanitizes all untrusted inputs.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-XXXX/`

## Checks

### K1 — Outdated platform targets

**MASWE:** MASWE-0077 (Running on a recent Platform Version Not Ensured), MASWE-0078 (Latest Platform Version Not Targeted)
**MASTG:** MASTG-TEST-0245

Read `meta/apk-info.txt`:

- `minSdkVersion`: lower → wider device support but exposed to older OS bugs
  and old crypto/network defaults. `minSdk < 21` (Android 5) is rarely
  justifiable now. `minSdk < 24` misses important platform security
  improvements (NSC, default cleartext rules).
- `targetSdkVersion`: This is the security-relevant one. As of 2026, Google
  Play requires `targetSdk` to be the current platform minus one. `targetSdk`
  two or more versions behind is a finding (MEDIUM) — the app opts out of
  recent platform hardening.

### K2 — Update enforcement

**MASWE:** MASWE-0075 (Enforced Updating Not Implemented)
**MASTG:** MASTG-TEST-0036

Banking / finance / messaging apps should refuse to operate on outdated
versions. Look for use of the Play Core Library
(`com.google.android.play:app-update`):

```bash
rg -nE 'AppUpdateManager|InAppUpdate|requestUpdateFlow' "$WORK/java/" 2>/dev/null
```

Absence is INFO-MEDIUM depending on app sensitivity.

### K3 — Dependencies with known vulnerabilities

**MASWE:** MASWE-0076 (Dependencies with Known Vulnerabilities)
**MASTG:** MASTG-TEST-0272, MASTG-TEST-0274

Identify shipped libraries:

```bash
# JARs / classes paths in smali
ls "$WORK/decoded/smali"*/ 2>/dev/null | head -30
ls "$WORK/decoded/smali"*/com/ 2>/dev/null | head -50
ls "$WORK/decoded/smali"*/org/ 2>/dev/null | head -50

# Native libraries
cat "$WORK/meta/libs.txt"

# Look for version strings or build metadata
find "$WORK/unpacked/" -name 'META-INF' -type d
ls "$WORK/unpacked/META-INF/" 2>/dev/null
find "$WORK/unpacked/" -name '*.version' -o -name 'pom.xml' -o -name 'pom.properties' 2>/dev/null | head -20
```

Common high-risk indicators:
- OpenSSL native lib older than the current LTS — check `lib/*/libcrypto.so`
  with `strings | grep -i "openssl"`.
- Old Bouncy Castle (`org/bouncycastle/` smali) < 1.70.
- Old OkHttp / Retrofit / Glide / Picasso — check for CVE-listed versions.
- Old WebKit-derived components shipped in cross-platform apps.
- React Native / Cordova / Capacitor with outdated runtimes.

If you can extract a version string (e.g. from string resources or build
config), search the web for the most current CVEs against that library
version. Note in the report when you couldn't determine a version.

For each identified library, list:
- Name
- Version (if known) or "unknown"
- Whether known CVEs apply

### K4 — SQL injection in `ContentProvider` queries / app DB

**MASWE:** MASWE-0086 (SQL Injection)
**MASTG:** MASTG-TEST-0339, MASTG-TEST-0025

```bash
rg -nE 'rawQuery\(|execSQL\(|query\(.*null,.*null' "$WORK/java/" 2>/dev/null
```

For each hit, look at the first argument — if a string is built with `+`
concatenation from user input, that's SQL injection. Safe pattern uses `?`
placeholders.

```java
// BAD
db.rawQuery("SELECT * FROM users WHERE name='" + name + "'", null);
// GOOD
db.rawQuery("SELECT * FROM users WHERE name=?", new String[]{name});
```

### K5 — Unsafe deserialization

**MASWE:** MASWE-0088 (Insecure Object Deserialization)
**MASTG:** MASTG-TEST-0034, MASTG-TEST-0337

```bash
rg -nE 'ObjectInputStream|readObject|Parcel(?!able).*readSerializable|XStream|SnakeYaml|Yaml\.load|JsonReader' "$WORK/java/" 2>/dev/null
```

- `ObjectInputStream.readObject()` on attacker-controlled bytes — HIGH/CRITICAL
  (Java deserialization gadgets).
- `Bundle.getParcelable(key)` without specifying the expected class on
  `targetSdk >= 33` — Android requires the typed overload now to prevent
  type-confusion. The old untyped overload throws a warning/exception.
- `SnakeYaml`'s default `Yaml().load(...)` is dangerous (use `SafeConstructor`).

### K6 — Dynamic code loading

**MASWE:** MASWE-0085 (Unsafe Dynamic Code Loading)

```bash
rg -nE 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|System\.load(Library)?\(' "$WORK/java/" 2>/dev/null
```

`DexClassLoader` loading code from the network or external storage is HIGH —
allows post-install code injection that bypasses Play review.
`System.loadLibrary("name")` for app-bundled native libs is fine; loading
a path-controlled file is not.

### K7 — Unsafe input handling

**MASWE:** MASWE-0079 (Unsafe Handling of Data from the Network), MASWE-0081 (Unsafe Handling Of Data From External Interfaces), MASWE-0083 (Unsafe Handling of Data From The User Interface), MASWE-0084 (Unsafe Handling of Data from IPC), MASWE-0087 (Insecure Parsing and Escaping)

Broad category. Specific things to grep:

- **XML parsing** with external entities enabled: `DocumentBuilderFactory`,
  `SAXParserFactory`, `XmlPullParser` — Android's defaults are usually safe
  but custom configs may enable DOCTYPE. Search for `setFeature` calls
  setting `disallow-doctype-decl` to false.
- **Command exec**: `Runtime.getRuntime().exec(...)` with concatenated user
  input — command injection.
- **File path concatenation**: `new File(baseDir, userInput)` without
  canonicalisation — path traversal.

```bash
rg -nE 'Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder|new File\([^,]+\,\s*[a-z]' "$WORK/java/" 2>/dev/null
```

### K8 — Native library hardening

**MASWE:** MASWE-0116 (Compiler-Provided Security Features Not Used)
**MASTG:** MASTG-TEST-0044, MASTG-TEST-0222, MASTG-TEST-0223, MASTG-TEST-0288

For each `.so` in `meta/libs.txt`, check:

```bash
for lib in $(find "$WORK/unpacked/lib/" -name '*.so'); do
  echo "=== $lib ==="
  if command -v checksec >/dev/null; then
    checksec --file="$lib" 2>/dev/null
  else
    readelf -d "$lib" 2>/dev/null | grep -E 'BIND_NOW|NX|FORTIFY'
    readelf -h "$lib" 2>/dev/null | grep -E 'Type'
    readelf -l "$lib" 2>/dev/null | grep -E 'GNU_STACK|GNU_RELRO'
  fi
done
```

Findings (per lib):
- Missing **PIE** (Position Independent Executable) → ASLR doesn't apply. On
  shared libraries (`.so`), this means missing `DF_PIE` flag. Most modern
  Android `.so` are PIC by default but check `Type:` from `readelf -h` —
  `DYN` is good, `EXEC` is bad.
- Missing **NX** (`GNU_STACK` segment with `RWE` permissions) — stack is
  executable.
- Missing **RELRO** (no `GNU_RELRO` segment) — GOT is writable.
- Missing **Stack Canaries** — search the binary for `__stack_chk_fail`
  symbol; absent means `-fstack-protector` wasn't used.
- Missing **FORTIFY_SOURCE** — strings like `__memcpy_chk`, `__strcpy_chk`
  should be present.

These are LOW-MEDIUM findings individually, MEDIUM-HIGH if the lib parses
network data.

## Passed checks worth noting

- `targetSdk` is current
- `minSdk >= 24`
- Parameterised SQL throughout
- Native libraries have PIE / NX / RELRO / canaries
- Dependencies pinned and recent (call out the SBOM if one exists)
- Uses `Bundle.getParcelable(key, ClassName.class)` typed overload
