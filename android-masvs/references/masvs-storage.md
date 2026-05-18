# MASVS-STORAGE — Secure storage of sensitive data on the device

Controls:
- **MASVS-STORAGE-1**: The app securely stores sensitive data.
- **MASVS-STORAGE-2**: The app prevents leakage of sensitive data.

Canonical URL pattern for citing in the report:
- Control: `https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/`
- MASWE: `https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-XXXX/`

## Before you start

"Sensitive data" in MASVS terms includes auth tokens, session IDs, encryption
keys, PII, payment data, health data, credentials, and any cached server data
that's protected behind login. Don't flag every string write — flag writes of
data that should not leave the secure boundary.

## Checks

### S1 — SharedPreferences holding sensitive data

**MASWE:** MASWE-0006 (Sensitive Data Stored Unencrypted in Private Storage Locations)
**MASTG:** MASTG-TEST-0287

Look for plaintext `SharedPreferences` storing tokens, passwords, PII. The
preferred secure alternative is `EncryptedSharedPreferences` (Jetpack
Security) or DataStore + Android KeyStore.

```bash
# In decompiled Java
rg -n --no-heading 'getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences' "$WORK/java/" 2>/dev/null

# In smali
rg -n --no-heading 'getSharedPreferences|EncryptedSharedPreferences' "$WORK/decoded/smali*/" 2>/dev/null
```

Then inspect the keys being written. A hit on `EncryptedSharedPreferences` is
*good* (defence-in-depth) — note it under passed checks. A hit on raw
`SharedPreferences.Editor.putString(...)` for keys like `token`, `password`,
`auth`, `jwt`, `session`, `api_key` is a finding.

### S2 — Files written to external storage

**MASWE:** MASWE-0007 (Sensitive Data Stored Unencrypted in Shared Storage)
**MASTG:** MASTG-TEST-0200, MASTG-TEST-0202

`getExternalStorageDirectory`, `getExternalFilesDir`, `MediaStore.*`, or use of
`WRITE_EXTERNAL_STORAGE` / `READ_EXTERNAL_STORAGE`. With scoped storage
(Android 11+), the legacy variants are less common but still appear.

```bash
rg -n --no-heading 'getExternalStorageDirectory|getExternalFilesDir|MediaStore\.|Environment\.getExternalStorage' "$WORK/java/" 2>/dev/null
```

Cross-reference with `meta/permissions.txt` — if the app holds
`WRITE_EXTERNAL_STORAGE` and writes sensitive blobs there, it's a finding.

### S3 — SQLite without encryption

**MASWE:** MASWE-0006
**MASTG:** MASTG-TEST-0304

Plain `SQLiteOpenHelper` / Room with no encryption. Look for SQLCipher
(`net.sqlcipher`) as the secure alternative. Note: encryption is only required
if the DB stores sensitive data — a cache of public content doesn't need it.

```bash
rg -n --no-heading 'SQLiteOpenHelper|RoomDatabase|net\.sqlcipher' "$WORK/java/" 2>/dev/null
```

### S4 — Logcat leaks of sensitive data

**MASWE:** MASWE-0001 (Insertion of Sensitive Data into Logs)
**MASTG:** MASTG-TEST-0003, MASTG-TEST-0203, MASTG-TEST-0231

Production builds calling `Log.d`, `Log.v`, `Log.i` with tokens / auth headers
/ PII. `Log.e` with stack traces is fine unless it embeds secrets.

```bash
rg -nF --no-heading 'Log.d(' "$WORK/java/" 2>/dev/null | grep -iE 'token|password|secret|jwt|auth|user|email|phone|ssn' | head -50
rg -n  --no-heading 'System\.out\.print' "$WORK/java/" 2>/dev/null | head -20
```

Also check for Timber, Logger, Logback, SLF4J — same issue.

### S5 — Backup configuration

**MASWE:** MASWE-0003 (Backup Unencrypted), MASWE-0004 (Sensitive Data Not Excluded From Backup)
**MASTG:** MASTG-TEST-0009, MASTG-TEST-0216, MASTG-TEST-0262

Inspect `meta/manifest.xml`:

- `android:allowBackup="true"` (the default) + no `android:fullBackupContent` or
  `android:dataExtractionRules` → backups will scoop up everything, including
  sensitive prefs. Either set `allowBackup="false"` or supply an
  exclusion ruleset.
- If `android:fullBackupContent="@xml/backup_rules"` is set, read
  `decoded/res/xml/backup_rules.xml` and confirm sensitive paths are
  `<exclude>`d.
- For `targetSdk >= 31`, the modern attribute is `android:dataExtractionRules`
  pointing at an XML with `<cloud-backup>` and `<device-transfer>` sections.

### S6 — Hardcoded secrets in resources / assets / smali

**MASWE:** MASWE-0005 (API Keys Hardcoded in the App Package), MASWE-0013 (Hardcoded Cryptographic Keys)
**MASTG:** MASTG-TEST-0212

```bash
# Strings.xml + values resources
rg -niE 'api[_-]?key|secret|token|password|aws_|firebase|bearer' "$WORK/decoded/res/values*/" 2>/dev/null

# Assets directory (configs, JSON, .properties)
find "$WORK/unpacked/assets/" -type f 2>/dev/null | head -50

# Smali constants
rg -nE 'const-string [vp][0-9]+, "(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9A-Za-z]{36})"' "$WORK/decoded/smali*/" 2>/dev/null
```

High-confidence regex hits (`AIza...` Google API key, `AKIA...` AWS key,
`sk_live_...` Stripe key, `ghp_...` GitHub PAT, JWTs starting `eyJ`) are
findings. Lower-confidence string matches need a glance before reporting.

### S7 — Sensitive data in screenshots and the recents view

**MASWE:** MASWE-0055 (Sensitive Data Leaked via Screenshots or Screen Recordings)
**MASTG:** MASTG-TEST-0010, MASTG-TEST-0291

Sensitive screens (payment entry, biometric prompt, secrets viewer) should
set `FLAG_SECURE`:

```bash
rg -n --no-heading 'FLAG_SECURE|setFlags.*8192|setRecentsScreenshotEnabled' "$WORK/java/" 2>/dev/null
```

If the app handles financial/health data and *no* activity sets
`FLAG_SECURE`, that's a MEDIUM finding (recents thumbnails and screenshots
can leak the most recent screen).

### S8 — Keyboard cache leak on sensitive inputs

**MASWE:** MASWE-0118 (Sensitive Data Not Removed After Use) and related
**MASTG:** MASTG-TEST-0006, MASTG-TEST-0258, MASTG-TEST-0316

Sensitive `EditText` inputs (passwords, card numbers, OTPs) should use
`inputType="textPassword"` or
`textNoSuggestions|textVisiblePassword`, and Compose `KeyboardOptions(
autoCorrect = false, keyboardType = KeyboardType.NumberPassword)`.

```bash
rg -n --no-heading 'inputType|KeyboardType\.' "$WORK/decoded/res/layout/" "$WORK/java/" 2>/dev/null | head -30
```

A `EditText` named or hinted as `password`/`card`/`cvv`/`otp` without a
no-suggestions input type is a finding.

### S9 — Cleartext config and secrets in `META-INF` / `assets`

Skim `unpacked/assets/` and `unpacked/META-INF/` for `*.json`, `*.properties`,
`*.xml`, `*.txt` that may contain API endpoints, keys, or service
credentials shipped with the app.

```bash
find "$WORK/unpacked/assets/" -type f \( -name '*.json' -o -name '*.properties' -o -name '*.xml' -o -name '*.txt' \) -exec grep -lEi 'key|secret|token|password|endpoint' {} + 2>/dev/null
```

## What to put in the report

For each hit:
- File:line evidence (quote the literal line, but truncate secrets to first
  4 chars + `…` — don't paste full secrets into the report).
- Cite the MASWE + MASTG ID as listed above.
- Suggest the concrete fix: `EncryptedSharedPreferences`, exclude from backup
  via `<exclude>` rule, `FLAG_SECURE`, etc.

## What to mention in "Passed checks"

- App uses `EncryptedSharedPreferences` or `MasterKey` from `androidx.security`
- App uses SQLCipher or Room with a `SupportFactory` for SQLCipher
- `allowBackup="false"` or restrictive `dataExtractionRules`
- Sensitive activities set `FLAG_SECURE`
- Password fields use `textPassword` input type
