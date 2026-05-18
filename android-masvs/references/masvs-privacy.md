# MASVS-PRIVACY — Privacy

Controls:
- **MASVS-PRIVACY-1**: The app minimizes access to sensitive data and resources.
- **MASVS-PRIVACY-2**: The app prevents identification of the user.
- **MASVS-PRIVACY-3**: The app is transparent about data collection and usage.
- **MASVS-PRIVACY-4**: The app offers user controls for data processing.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-PRIVACY/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-XXXX/`

## Scoping note

Privacy is partly a legal / policy question (privacy policy, consent flows,
GDPR/CCPA compliance) that goes beyond what static analysis can verify.
Restrict the report to what's observable in the binary; flag policy items
as items the user should confirm.

## Checks

### Pr1 — Excessive / dangerous permissions

**MASWE:** MASWE-0117 (Inadequate Permission Management)
**MASTG:** MASTG-TEST-0254, MASTG-TEST-0255

Read `meta/permissions.txt`. Flag dangerous permissions (Google's
classification) that don't have an obvious justification given what the
app does. Common over-asks:

- `READ_CONTACTS` / `WRITE_CONTACTS` for an app with no contacts feature
- `ACCESS_FINE_LOCATION` for an app with no location feature
- `READ_PHONE_STATE` (often used to get IMEI / identifiers — see Pr3)
- `READ_EXTERNAL_STORAGE` on Android 13+ (replaced by media-type permissions)
- `RECORD_AUDIO` / `CAMERA` for apps with no obvious use
- `QUERY_ALL_PACKAGES` (visibility of installed apps; abused for fingerprinting)
- `SYSTEM_ALERT_WINDOW` (overlay; abused for tapjacking / phishing)
- `REQUEST_INSTALL_PACKAGES` (lets the app install other APKs)
- `ACCESSIBILITY_SERVICE` (very powerful; should be rare)

Cross-reference the app's stated functionality (App overview phase) — a
note-taking app requesting `RECORD_AUDIO` for "voice notes" is fine; the
same permission with no audio UI is a finding.

### Pr2 — Permission rationale missing

**MASWE:** MASWE-0117
**MASTG:** MASTG-TEST-0256

For dangerous permissions, the app should call
`shouldShowRequestPermissionRationale` and explain *why* before the system
dialog appears. Absence is INFO/LOW (UX issue with privacy implications).

```bash
rg -nE 'shouldShowRequestPermissionRationale|requestPermissions' "$WORK/java/" 2>/dev/null
```

### Pr3 — Tracking / unique identifiers

**MASWE:** MASWE-0110 (Use of Unique Identifiers for User Tracking)
**MASTG:** MASTG-TEST-0318, MASTG-TEST-0319

Hardware identifiers that survive uninstall (or even factory reset) are
privacy-hostile. Google's guidance: use the Advertising ID for advertising,
`Settings.Secure.ANDROID_ID` for non-resettable per-app identifier, and a
random installation UUID for analytics.

```bash
rg -nE 'getDeviceId|getImei|getMeid|getSubscriberId|getSerial|Build\.SERIAL|MAC_ADDRESS|getMacAddress|WifiInfo\.getMacAddress|AdvertisingIdClient|ANDROID_ID' "$WORK/java/" 2>/dev/null
```

Findings:
- `getDeviceId()` / `getImei()` (deprecated, restricted on Android 10+, but
  still seen) — MEDIUM.
- Reading MAC addresses (`getMacAddress` returns `02:00:00:00:00:00` on
  Android 6+, but pre-6 leak persists) — LOW.
- `Build.SERIAL` for non-system apps — restricted but worth noting.
- Advertising ID combined with PII without user opt-out — MEDIUM.

### Pr4 — Third-party SDKs / trackers

**MASWE:** MASWE-0108 (Sensitive Data in Network Traffic), MASWE-0111 (Inadequate Privacy Policy)
**MASTG:** MASTG-TEST-0206 (dynamic; note as out-of-scope)

Inventory shipped SDKs:

```bash
# Common analytics / ad / tracking packages
ls "$WORK/decoded/smali"*/com/google/ "$WORK/decoded/smali"*/com/facebook/ \
   "$WORK/decoded/smali"*/com/amplitude/ "$WORK/decoded/smali"*/com/mixpanel/ \
   "$WORK/decoded/smali"*/com/appsflyer/ "$WORK/decoded/smali"*/com/adjust/ \
   "$WORK/decoded/smali"*/io/branch/ "$WORK/decoded/smali"*/com/segment/ \
   "$WORK/decoded/smali"*/com/onesignal/ "$WORK/decoded/smali"*/io/sentry/ \
   "$WORK/decoded/smali"*/com/microsoft/clarity/ 2>/dev/null
```

Notable: AppsFlyer, Adjust, Branch, Mixpanel, Amplitude, Segment, Facebook
SDK, Google Firebase Analytics, OneSignal, Microsoft Clarity, Sentry,
Crashlytics, Singular, Kochava, Tenjin.

For each: name it in the report. The user's privacy policy / data
collection declarations need to disclose each one. Note this is a
*disclosure* check — the SDK itself is not a vulnerability.

The Exodus Privacy database (https://reports.exodus-privacy.eu.org/) is a
useful reference but its checks are exactly the kind of pattern matching
done here.

### Pr5 — Network sends of PII at app start

**MASWE:** MASWE-0108

Without dynamic analysis you can't see the actual payloads, but you can
spot patterns where the app collects identifiers early. Look at
`Application.onCreate` / first activity `onCreate` for analytics init
calls — list which ones initialize at startup vs after consent.

If you find an "init" call that runs before any consent UI is presented
to the user, that's a MEDIUM finding for GDPR-adjacent jurisdictions
(no lawful basis prior to consent).

### Pr6 — Consent UI present?

**MASWE:** MASWE-0115 (Inadequate or Ambiguous User Consent Mechanisms)

If the app uses tracking SDKs and you find no string resources mentioning
"consent", "privacy", "cookies", "accept", "decline", "tracking" — likely
no consent flow.

```bash
rg -niE 'consent|cookies|privacy|tracking' "$WORK/decoded/res/values*/strings.xml" 2>/dev/null | head -30
```

Absence is a finding when tracking SDKs are present.

### Pr7 — Background location

If `ACCESS_BACKGROUND_LOCATION` is granted, the user expects a clear use
case (navigation, geofencing, run tracking). Note this as a high-sensitivity
permission whose justification belongs in the privacy policy. Android 11+
enforces a separate prompt, which is good — but apps still ask.

### Pr8 — Clipboard / pasteboard access

Apps reading clipboard on `onResume` can scrape what the user copied from
another app. Android 12+ shows a toast when the clipboard is read, which
discourages this — but the pattern is still common.

```bash
rg -nE 'ClipboardManager|getPrimaryClip|getText\(\)' "$WORK/java/" 2>/dev/null | head -20
```

## Privacy policy / Play Console items

Note these but mark "out of scope for static analysis — verify on Play
listing":

- Data Safety section accurate (matches the SDKs and permissions found).
- Privacy policy URL working and reflects the actual data handling.
- Account / data deletion path provided.

## Passed checks worth noting

- Minimal permission set, all justified by visible features
- Uses Advertising ID instead of hardware identifiers
- Consent gate before tracker initialisation
- App ID / install UUID rather than persistent hardware ID for analytics
- `tools:dataExtractionRules` and backup rules excluding sensitive paths
