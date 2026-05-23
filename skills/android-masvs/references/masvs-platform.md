# MASVS-PLATFORM — Secure interaction with the mobile platform

Controls:
- **MASVS-PLATFORM-1**: The app uses IPC mechanisms securely.
- **MASVS-PLATFORM-2**: The app uses WebViews securely.
- **MASVS-PLATFORM-3**: The app uses the user interface securely.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-XXXX/`

This category produces the most findings on most apps — exported components
and WebView misuse are everywhere. Work through it methodically.

## Checks

### P1 — Exported components without permission gating

**MASWE:** MASWE-0062 (Insecure Services), MASWE-0063 (Insecure Broadcast Receivers), MASWE-0064 (Insecure Content Providers), MASWE-0066 (Insecure Intents)
**MASTG:** MASTG-TEST-0029, MASTG-TEST-0030

For each entry in `meta/components.txt`, check:

- **Exported flag**: `android:exported="true"` (or implicit `true` because the
  component has an `<intent-filter>` and `targetSdk < 31`). Since Android 12
  (target 31), `exported` must be set explicitly when intent filters exist.
- **Permission**: Does it have `android:permission="..."`?
- **Permission protection level**: If yes, look up the permission in
  `decoded/AndroidManifest.xml` `<permission>` declarations or the
  Android docs. `signature` or `signatureOrSystem` are good; `normal` or
  `dangerous` mean any app can hold them.

For each exported component without proper protection, check what it does
(look in smali/java for the class):

- **Activities** that perform sensitive actions on receipt of an intent (delete
  data, change settings, share user data) — finding.
- **Services** that accept user-controllable extras and perform actions —
  finding.
- **Broadcast receivers** for `android.intent.action.BOOT_COMPLETED` etc. are
  usually fine; receivers for custom in-app actions need permission gating.
- **Content providers** with `exported="true"` and no `readPermission` /
  `writePermission` — definitely a finding. Check for SQL injection (see
  CODE §K7 / MASWE-0086) and path traversal in `openFile`.

### P2 — Implicit intents leaking data

**MASWE:** MASWE-0066 (Insecure Intents)
**MASTG:** MASTG-TEST-0026

Sending sensitive data via an implicit intent (no component name) means any
matching app receives it.

```bash
rg -nE 'new Intent\("[^"]+"\)|Intent\.ACTION_(SEND|VIEW|SENDTO)|setAction\(' "$WORK/java/" 2>/dev/null | head -40
```

For each implicit intent, check whether the `putExtra` payload is sensitive.

### P3 — PendingIntent mutability

**MASWE:** MASWE-0066
**MASTG:** MASTG-TEST-0030

`PendingIntent.getActivity(ctx, 0, intent, 0)` without `FLAG_IMMUTABLE` on
Android 12+ now requires it explicitly. Mutable `PendingIntent` with an
implicit underlying intent allows a malicious app to modify the intent.

```bash
rg -nE 'PendingIntent\.get|FLAG_(IM)?MUTABLE|FLAG_UPDATE_CURRENT' "$WORK/java/" 2>/dev/null
```

Findings:
- `FLAG_MUTABLE` + implicit base intent — HIGH.
- No flag specified on `targetSdk >= 31` — won't run; if it does, app has a
  workaround that may indicate other compat hacks.

### P4 — Deep link / App link hijack

**MASWE:** MASWE-0058 (Insecure Deep Links)
**MASTG:** MASTG-TEST-0028

Inspect activities with `<intent-filter>` containing
`android:scheme` and `BROWSABLE` category:

- **Custom schemes** (`myapp://...`) can be claimed by other apps — anything
  passed through them is attacker-controllable.
- **HTTP/HTTPS schemes** with `android:autoVerify="true"` need a matching
  `assetlinks.json` at the host's `/.well-known/` to be considered verified
  App Links; without it, the system shows a chooser.

Then check the receiving activity's `onCreate` / `onNewIntent` for:
- Loading the intent's `data` URI into a `WebView` (combine with §P6 below).
- Using path / query params as filenames, SQL fragments, or class names.
- Granting capabilities based on link parameters.

### P5 — Tapjacking

**MASWE:** MASWE-0056 (Tapjacking Attacks)
**MASTG:** MASTG-TEST-0035, MASTG-TEST-0340

Sensitive screens (auth prompts, confirmation dialogs, payment) should set
`android:filterTouchesWhenObscured="true"` on the View, or call
`View.setFilterTouchesWhenObscured(true)`. Compose: check for similar
guards in confirmation dialogs.

```bash
rg -nE 'filterTouchesWhenObscured|setFilterTouchesWhenObscured' "$WORK/decoded/res/layout/" "$WORK/java/" 2>/dev/null
```

Missing = MEDIUM finding for sensitive apps.

### P6 — WebView JavaScript bridge

**MASWE:** MASWE-0068 (JavaScript Bridges in WebViews)
**MASTG:** MASTG-TEST-0033, MASTG-TEST-0334

`addJavascriptInterface(obj, "name")` exposes Java methods to JavaScript.
On `targetSdk < 17` this allowed reflection (CVE-2012-6636). On modern
targets, only `@JavascriptInterface`-annotated methods are exposed — but the
exposed methods themselves can still be dangerous.

```bash
rg -nE 'addJavascriptInterface|@JavascriptInterface' "$WORK/java/" 2>/dev/null
```

For each interface:
- What URLs is JS loaded from? If from `http://` or a third-party CDN, the
  interface is reachable by an MITM or by anyone controlling that source.
- What methods are exposed? Methods that touch the filesystem, run shell,
  or perform privileged actions are findings.

### P7 — WebView settings

**MASWE:** MASWE-0069 (WebViews Allows Access to Local Resources), MASWE-0070 (JavaScript Loaded from Untrusted Sources), MASWE-0074 (Web Content Debugging Enabled)
**MASTG:** MASTG-TEST-0031, MASTG-TEST-0032, MASTG-TEST-0227, MASTG-TEST-0250, MASTG-TEST-0252

Inspect each WebView's `WebSettings`:

```bash
rg -nE 'setJavaScriptEnabled|setAllowFileAccess|setAllowContentAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setMixedContentMode|setWebContentsDebuggingEnabled' "$WORK/java/" 2>/dev/null
```

Findings:
- `setJavaScriptEnabled(true)` + loads remote untrusted content — XSS surface
  (MEDIUM-HIGH depending on what the JS bridge or cookies expose).
- `setAllowFileAccessFromFileURLs(true)` / `setAllowUniversalAccessFromFileURLs(true)` — HIGH (cross-origin file reads).
- `setAllowContentAccess(true)` default-true on old versions — allows
  reading `content://` URIs that may include other apps' providers.
- `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` — MEDIUM (mixed HTTP in
  HTTPS page).
- `setWebContentsDebuggingEnabled(true)` in production — MEDIUM
  (Chrome DevTools can attach if the device is connected via ADB).

### P8 — WebView URL loading from intents

**MASWE:** MASWE-0071 (WebViews Loading Content from Untrusted Sources)

```bash
rg -nE 'webView\.loadUrl\(|webView\.loadData\(' "$WORK/java/" 2>/dev/null
```

If the loaded URL comes from `getIntent().getData()` or another intent extra
without validation, a malicious deep link can load arbitrary content into the
WebView, escalating any of P6/P7 issues.

### P9 — Screenshot / screen-recording controls in sensitive UI

See `masvs-storage.md` §S7 (FLAG_SECURE). Cross-reference under MASVS-PLATFORM
as well since the platform mechanism is the same.

### P10 — Notifications leaking sensitive content

**MASWE:** MASWE-0054 (Sensitive Data Leaked via Notifications)
**MASTG:** MASTG-TEST-0315

Notifications shown on the lock screen with full content (auth codes, message
previews) leak even with the device locked. `setVisibility(VISIBILITY_PRIVATE)`
or `VISIBILITY_SECRET` hides content on the lock screen.

```bash
rg -nE 'NotificationCompat\.Builder|setVisibility|VISIBILITY_(PRIVATE|PUBLIC|SECRET)' "$WORK/java/" 2>/dev/null
```

If the app sends OTPs / message previews and uses `VISIBILITY_PUBLIC` (the
default), that's a MEDIUM finding for sensitive apps.

## Passed checks worth noting

- Exported components properly gated by signature-level permissions
- All `PendingIntent` uses `FLAG_IMMUTABLE`
- `addJavascriptInterface` only called for known trusted local content
- `setWebContentsDebuggingEnabled` is guarded by `BuildConfig.DEBUG`
- Deep links use `autoVerify="true"` with a valid assetlinks.json
- Sensitive views set `filterTouchesWhenObscured="true"`
