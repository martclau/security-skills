# MASVS-AUTH — Authentication and authorization

Controls:
- **MASVS-AUTH-1**: The app uses secure authentication and authorization
  protocols and follows the relevant best practices.
- **MASVS-AUTH-2**: The local session is terminated when the user logs out.
- **MASVS-AUTH-3**: A second factor of authentication exists at the remote
  endpoint and the 2FA requirement is consistently enforced.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-XXXX/`

## Important caveat

Many AUTH controls depend on **server-side** behaviour and cannot be fully
verified statically from the client. Be explicit in the report about what you
verified (client implementation) vs what you assumed/inferred (server
behaviour). Flag server-side claims as "requires confirmation".

## Checks

### A1 — Hardcoded API keys / OAuth client secrets

**MASWE:** MASWE-0005 (API Keys Hardcoded in the App Package)
**MASTG:** MASTG-TEST-0212

OAuth client *secrets* in a mobile app are intrinsically broken (PKCE replaces
them). API keys broadly scoped server-side are equally bad. Public, scoped
keys (e.g. Firebase config, Google Maps key restricted to app signature) are
usually OK.

See `masvs-storage.md` §S6 for the patterns. When you find an API key, judge:
- What does it grant? (broad admin = HIGH; restricted = INFO)
- Does the backend rely on it for auth? (yes = finding)

### A2 — Biometric authentication misuse

**MASWE:** MASWE-0044 (Biometric Authentication Can Be Bypassed), MASWE-0046 (Crypto Keys Not Invalidated on New Biometric Enrollment)
**MASTG:** MASTG-TEST-0018, MASTG-TEST-0327, MASTG-TEST-0328

Biometric on Android is done right when:
- Uses `BiometricPrompt` (not deprecated `FingerprintManager`).
- The biometric gates *use of a KeyStore key* (cryptographic binding), not
  just a boolean callback. Look for `BiometricPrompt.CryptoObject` plus a key
  with `setUserAuthenticationRequired(true)`.
- The key has `setInvalidatedByBiometricEnrollment(true)` so enrolling a new
  fingerprint invalidates the key (otherwise attacker enrolls their finger
  and uses the existing key).
- `BiometricManager.Authenticators.BIOMETRIC_STRONG` is required (not
  `BIOMETRIC_WEAK`).

```bash
rg -nE 'BiometricPrompt|FingerprintManager|setUserAuthenticationRequired|setInvalidatedByBiometricEnrollment|BIOMETRIC_(STRONG|WEAK)|CryptoObject' "$WORK/java/" 2>/dev/null
```

Findings (in order of severity):
- `FingerprintManager` (deprecated; supports weak biometrics) — MEDIUM/HIGH.
- `BiometricPrompt` without `CryptoObject` (event-bound only — the result is
  a simple yes/no that can be hooked at runtime) — MEDIUM for non-sensitive
  apps, HIGH for banking/payments.
- `setUserAuthenticationRequired(true)` without
  `setInvalidatedByBiometricEnrollment(true)` — MEDIUM (enrollment-bypass).
- Allowing `BIOMETRIC_WEAK` (e.g. face unlock on some devices) for sensitive
  operations — MEDIUM.

### A3 — Authentication material stored insecurely

**MASWE:** MASWE-0036 (Authentication Material Stored Unencrypted on the Device)

Refresh tokens, session IDs, OAuth refresh tokens, PINs. Should be in
`EncryptedSharedPreferences` or, better, in an `AndroidKeyStore`-protected
container. Cross-reference with `masvs-storage.md` §S1.

### A4 — Auth material sent over cleartext

**MASWE:** MASWE-0037 (Authentication Material Sent over Insecure Connections)

If any auth endpoint is in cleartext HTTP — covered in
`masvs-network.md` §N1. Cite both MASVS-AUTH and MASVS-NETWORK.

### A5 — Insecure JWT handling

**MASWE:** MASWE-0038 (Authentication Tokens Not Validated)

Findings:
- Decoding a JWT and trusting fields without verifying the signature.
- Accepting `alg: none` JWTs.
- Storing JWTs in plain `SharedPreferences` (see §A3).

```bash
rg -nF 'eyJ' "$WORK/java/" 2>/dev/null  # JWT literals
rg -nE 'JWT|JsonWebToken|jwt\.io|jjwt|Jwts\.parser' "$WORK/java/" 2>/dev/null
```

For "decode without verify", look at uses of `JWT.decode(...)` from
`com.auth0:java-jwt` — `decode` doesn't verify, `require(...).build().verify`
does.

### A6 — WebView credential handling

**MASWE:** MASWE-0040 (Insecure Authentication in WebViews)

Apps that load OAuth flows in `WebView` (rather than Custom Tabs /
`AppAuth`) can intercept credentials via `WebViewClient.shouldInterceptRequest`
or JS bridges. Modern best practice: use `androidx.browser.customtabs`
(Chrome Custom Tabs) or the AppAuth library, not an in-app WebView.

```bash
rg -nE 'WebView|CustomTabsIntent|AppAuth|AuthorizationService' "$WORK/java/" 2>/dev/null | head -40
```

If you see auth URLs (Google, Facebook, Microsoft OAuth endpoints) loaded
into a WebView, that's a finding.

### A7 — Locally enforced authorization

**MASWE:** MASWE-0041 / MASWE-0042 (Authentication/Authorization Enforced Only Locally)

Pure client-side checks like `if (user.isAdmin) showAdminScreen()` without a
corresponding server-side enforcement enable trivial bypass. You can rarely
prove this is the *only* check from static analysis alone — but if you spot
"admin mode" toggles, hidden screens unlocked by a local flag, or feature
flags shipped in the APK, flag them as MEDIUM with the caveat that the
server side should be verified.

```bash
rg -niE 'isAdmin|isPremium|isPaid|isPro|debugMode|adminMode' "$WORK/java/" 2>/dev/null | head -40
```

### A8 — PIN/passcode storage

**MASWE:** MASWE-0043 (App Custom PIN Not Bound to Platform KeyStore)

App PINs should be checked by unlocking a KeyStore key (so the PIN itself
is never compared in cleartext on-device). If you see a PIN compared against
a stored hash with `MessageDigest`, that's a finding — the right design is
`KeyGenParameterSpec` + PIN as KDF input.

```bash
rg -nE 'enterPin|enter_pin|setPin|checkPin' "$WORK/java/" 2>/dev/null
```

## Passed checks worth noting

- `BiometricPrompt` with `CryptoObject` and `BIOMETRIC_STRONG`
- Keys with `setUserAuthenticationRequired(true)` +
  `setInvalidatedByBiometricEnrollment(true)`
- OAuth flows in Chrome Custom Tabs or AppAuth library
- Refresh tokens stored in `EncryptedSharedPreferences` / KeyStore
