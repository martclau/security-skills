---
name: android-masvs
description: >
  Assess an Android application against the OWASP Mobile Application Security
  Verification Standard (MASVS v2.0) and produce a structured security report
  with MASVS / MASWE / MASTG references, severity ratings, and remediation
  guidance. Use this skill whenever the user asks to "audit an APK", "review
  an Android app for security", "run MASVS checks", "MAS assessment", "OWASP
  mobile audit", "check an Android app for vulnerabilities", "look at this
  AndroidManifest", or any variation involving security analysis of an
  Android app, APK, AAB, or Android source tree — even if they don't say
  "MASVS" explicitly. Also trigger when the user uploads a `.apk`, `.aab`,
  `.xapk`, or Android project and asks for a "security review", "audit",
  "hardening review", or "pen-test".
allowed-tools: Bash(bash *), Bash(apktool *), Bash(jadx *), Bash(aapt2 *), Bash(apksigner *), Bash(unzip *), Bash(rg *), Bash(grep *), Bash(file *), Bash(ls *), Bash(readelf *)
---

# Android MASVS Assessment

Statically assess an Android application against OWASP MASVS v2.0 and produce a
findings report tied to MASVS controls, MASWE weaknesses, and MASTG test IDs.

## Scope and limits

This skill performs **static** analysis: decoded manifest, resources, smali,
decompiled Java/Kotlin, native libraries' metadata, certificates, configs.
Dynamic checks (Frida, traffic interception on a live device, runtime
instrumentation) are out of scope for automated runs — note them in the report
as items the user should verify on a real device.

If the user explicitly asks for dynamic analysis or behavioural testing, tell
them what the skill covers and offer to draft a manual test plan instead of
faking dynamic findings.

## Workflow

Work through these phases in order. Don't skip ahead — later phases assume
the earlier ones produced the expected files.

### Phase 1 — Identify the target

Find the artifact to assess. Check, in order:
1. A path the user mentioned explicitly
2. The current working directory
3. In claude.ai contexts, `/mnt/user-data/uploads/` for `.apk`, `.aab`,
   `.xapk`, or `.zip` of a project

If you get an `.aab` (Android App Bundle), the user usually wants the same
checks — note it in the report and process it the same way (it's a zip, just
with a different top-level layout). For `.xapk` (a zipped APK + OBB), unzip
and assess the inner `.apk`.

If nothing is provided, ask the user where the file is — don't invent a
target.

### Phase 2 — Unpack and inventory

Run the unpack script:

```bash
bash "${CLAUDE_SKILL_DIR}/scripts/unpack_apk.sh" <path/to/app.apk> <workdir>
```

This decodes the APK with `apktool` (or falls back to `unzip` + `aapt2` if
apktool isn't installed), runs `jadx` for Java decompilation when available,
and produces:

```
<workdir>/
├── decoded/                 apktool output (manifest, res/, smali/, original/)
├── java/                    jadx-decompiled sources (if jadx installed)
├── unpacked/                raw unzip (always present)
├── meta/
│   ├── manifest.xml         pretty-printed AndroidManifest.xml
│   ├── permissions.txt      list of <uses-permission> entries
│   ├── components.txt       activities / services / receivers / providers + exported flags
│   ├── signing.txt          apksigner verification output + cert SHA-256
│   ├── strings.txt          aapt2 dumped string resources
│   ├── apk-info.txt         package, versionCode/Name, min/target/compileSdk
│   └── libs.txt             native libraries by ABI
└── findings.md              report skeleton you will fill in
```

If `unpack_apk.sh` reports missing tools, read `references/tools-setup.md`
for installation instructions in this sandbox.

### Phase 3 — Build the threat picture

Before running individual MASVS checks, skim the manifest and decompiled
sources for **context**. Spend a few minutes on this; it changes how you
weight later findings:

- **What does the app do?** Banking / payments / health / messaging / utility?
  Sensitivity of the data drives severity scoring.
- **Trust boundaries:** What network endpoints does it talk to? What IPC
  surfaces does it expose (exported components, deep links, content
  providers)? What permissions does it request?
- **Tech stack:** Native (Kotlin/Java only), Flutter, React Native, Xamarin,
  Cordova, Unity? Each has different storage / network conventions.
  Cross-platform apps need framework-specific checks too (e.g., a Flutter app
  ships an AOT snapshot in `libapp.so`; React Native ships JS bundles).

Write a 3–5 line "App overview" at the top of `findings.md` before going
deeper.

### Phase 4 — Run checks per MASVS category

Go through each of the eight MASVS categories. For each one, read the
matching reference file in `references/` — it contains the concrete patterns,
file locations, and MASWE/MASTG IDs to cite.

| Category | Reference file | Quick summary of what to check |
|---|---|---|
| MASVS-STORAGE | `references/masvs-storage.md` | Sensitive data in SharedPreferences, SQLite, external storage, logs, backups, screenshots |
| MASVS-CRYPTO | `references/masvs-crypto.md` | Weak algorithms (DES, RC4, MD5, SHA-1), ECB mode, hardcoded keys, predictable IVs, `Random` vs `SecureRandom` |
| MASVS-AUTH | `references/masvs-auth.md` | Biometric API misuse, hardcoded API keys, JWT handling, WebView credentials |
| MASVS-NETWORK | `references/masvs-network.md` | Cleartext traffic, weak TLS, certificate pinning, hostname verification, WebView `onReceivedSslError` |
| MASVS-PLATFORM | `references/masvs-platform.md` | Exported components, deep links, `WebView.addJavascriptInterface`, `setAllowFileAccess`, tapjacking |
| MASVS-CODE | `references/masvs-code.md` | minSdk/targetSdk, SQL injection, deserialization, `DexClassLoader`, dependencies with known CVEs |
| MASVS-RESILIENCE | `references/masvs-resilience.md` | Debuggable flag, ProGuard/R8, root detection, anti-debug, integrity checks, signing scheme version |
| MASVS-PRIVACY | `references/masvs-privacy.md` | Dangerous permissions, trackers/SDKs, identifiers (IMEI, ad ID), data-collection declarations |

Don't read every reference upfront — open the one you're currently working on,
finish that category's checks, then move to the next. This keeps context
manageable.

For each check, the reference file tells you the search command, what a hit
looks like, and the MASWE/MASTG IDs to cite. Run the commands against the
workdir. When you find something, add an entry to the findings table (format
below). When a check passes cleanly, note it briefly under "Passed checks" at
the bottom of the report — auditors care about coverage, not just failures.

### Phase 5 — Write the report

Use this exact structure for `findings.md`:

```markdown
# MASVS Assessment — <App name> (<package>)

**Version:** <versionName> (<versionCode>)
**Min/Target/Compile SDK:** <values>
**Signing:** <v1/v2/v3/v4>, key alg <RSA-2048/ECDSA-P256/...>, SHA-256 <fingerprint>
**Assessed against:** OWASP MASVS v2.0
**Analysis type:** Static only (dynamic checks listed separately)

## App overview
<3–5 lines: what the app does, tech stack, threat picture>

## Summary
| # | Severity | MASVS | MASWE | Finding |
|---|----------|-------|-------|---------|
| 1 | HIGH     | MASVS-NETWORK-1 | MASWE-0050 | Cleartext traffic permitted for `api.example.com` |
| ... |

## Findings (detail)

### [SEVERITY] #N — Short title
- **MASVS control:** MASVS-CATEGORY-N
- **MASWE:** MASWE-XXXX (link)
- **MASTG test:** MASTG-TEST-XXXX (link)
- **Evidence:** file:line or manifest excerpt (quoted)
- **Why it matters:** one or two sentences on the real-world impact
- **Remediation:** concrete change (API to use, config flag, code snippet)

(repeat for every finding)

## Passed checks
Brief bulleted list of MASVS controls that were checked and passed cleanly.

## Out-of-scope / requires dynamic analysis
Bulleted list of things that can't be confirmed without runtime testing
(e.g., "verify root-detection actually blocks app startup on a rooted device",
"confirm certificate pinning rejects a Burp Suite MITM").

## Methodology
- Tools used (apktool x.y.z, jadx x.y.z, androguard x.y.z, ...)
- Files inspected
- Commands run (briefly)
```

### Phase 6 — Save and present

Write `findings.md` to the workdir and give the user its path (in claude.ai
contexts, write to `/mnt/user-data/outputs/` and present it with the
`present_files` tool). If the report is long, also drop a short summary in
chat — the table of findings — so the user can see the headline without
opening the file.

## Severity scale

Use this scale consistently:

- **CRITICAL** — Trivially exploitable, leads to account takeover, RCE,
  or compromise of all user data. (Example: hardcoded prod API key with admin
  scope; exported activity launching arbitrary intents with system privileges.)
- **HIGH** — Significant impact but requires some condition (network-level
  attacker, malicious app installed, specific user action). (Example:
  cleartext traffic to backend; missing cert pinning on banking app.)
- **MEDIUM** — Real issue, but exploit chain is non-trivial or impact is
  bounded. (Example: backup not excluding sensitive prefs; debuggable on
  release for testing builds only.)
- **LOW** — Defence-in-depth, hardening recommendation, or low-impact
  hygiene issue. (Example: missing ProGuard, no root detection on a non-
  sensitive app, target SDK one version behind.)
- **INFO** — Observation worth noting but not a vulnerability (e.g. uses
  `BiometricPrompt` correctly — passed; or "uses SQLCipher 4.5.0, no known
  CVEs at time of assessment").

When scaling severity, weight the **data sensitivity** of the app. A
hardcoded analytics key in a calculator app is LOW; the same pattern in a
banking app may be HIGH.

## Reading patterns

When grepping smali or decompiled Java, prefer ripgrep when available
(`rg -nF '<pattern>' <dir>`) — it's faster and respects `.gitignore`. Fall
back to `grep -rnF` otherwise.

When inspecting the manifest, work from `meta/manifest.xml` (pretty-printed),
not `decoded/AndroidManifest.xml` directly — apktool output is already plain
XML but the pretty-printed version is easier to scan.

For native libraries (`lib/<abi>/*.so`), use `file`, `readelf -d`, and
`checksec` (if installed) to assess binary hardening — see the CODE reference
for the specific flags to check.

## Citing standards

Every finding must cite at least one of:
- A MASVS control ID (e.g. `MASVS-STORAGE-1`)
- A MASWE weakness ID (e.g. `MASWE-0050`)
- A MASTG test ID (e.g. `MASTG-TEST-0235`)

Prefer MASWE for the *what* (the weakness class) and MASTG for the *how*
(the specific test that surfaced it). Link to the canonical OWASP MAS URL
when including IDs in the report; the references files list the URL pattern.

## When the input isn't an APK

If the user gives you Android source code (a Gradle project, not a built
artifact), skip Phase 2 and adapt:
- Read `build.gradle` / `build.gradle.kts` for SDK levels, dependencies,
  signing config, ProGuard settings.
- Read `src/main/AndroidManifest.xml` directly.
- Grep `src/` for the same patterns the references describe.

Manifest behaviour and code patterns are the same; the file paths differ.
You can still produce a full MASVS report from source.
