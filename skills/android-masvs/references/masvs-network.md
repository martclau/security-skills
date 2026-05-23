# MASVS-NETWORK — Secure network communication

Controls:
- **MASVS-NETWORK-1**: The app secures all network traffic according to the
  current best practices.
- **MASVS-NETWORK-2**: The app performs identity pinning for all remote endpoints
  under the developer's control.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-XXXX/`

## Checks

### N1 — Cleartext traffic allowed

**MASWE:** MASWE-0050 (Cleartext Traffic)
**MASTG:** MASTG-TEST-0233, MASTG-TEST-0235, MASTG-TEST-0237

Inspect, in order:

1. **Manifest**: `android:usesCleartextTraffic` on `<application>`.
   - Missing + `targetSdk >= 28` → defaults to `false` (good).
   - `usesCleartextTraffic="true"` → all HTTP allowed (finding).

2. **Network Security Config** (referenced by
   `android:networkSecurityConfig="@xml/network_security_config"`):
   - Read `decoded/res/xml/network_security_config.xml`.
   - `<base-config cleartextTrafficPermitted="true">` → all traffic plain
     HTTP allowed (HIGH finding).
   - Per-domain `<domain-config cleartextTrafficPermitted="true">` → cleartext
     allowed for specific hosts (MEDIUM-HIGH depending on host).
   - `<debug-overrides>` allowing user-installed CAs is fine **as long as
     it's `<debug-overrides>`**; if the same config appears under
     `<base-config>`, that's a finding (see N4).

3. **Hardcoded HTTP URLs** in code:

   ```bash
   rg -nE 'http://[^"'\'']+' "$WORK/decoded/res/values*/" "$WORK/java/" "$WORK/decoded/smali*/" 2>/dev/null | grep -vE 'http://schemas\.android\.com|http://www\.w3\.org|http://xmlns\.|localhost|127\.0\.0\.1' | head -50
   ```

   Filter out schema URLs (`schemas.android.com`, `xmlns`) — those aren't
   network endpoints.

### N2 — TLS configured insecurely

**MASWE:** MASWE-0052 (Insecure Certificate Validation)
**MASTG:** MASTG-TEST-0020, MASTG-TEST-0217, MASTG-TEST-0282

The worst pattern: custom `X509TrustManager` whose `checkServerTrusted` is
empty or always returns.

```bash
rg -nE 'X509TrustManager|HostnameVerifier|TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER|SSLContext\.getInstance' "$WORK/java/" 2>/dev/null
```

Patterns to flag:
- `new X509TrustManager() { public void checkServerTrusted(...) { } }` (empty body) — CRITICAL.
- `new HostnameVerifier() { return true; }` — CRITICAL.
- `org.apache.http.conn.ssl.AllowAllHostnameVerifier` or `ALLOW_ALL_HOSTNAME_VERIFIER` — CRITICAL.
- `SSLContext.getInstance("SSL")` / `"SSLv3"` / `"TLSv1"` / `"TLSv1.1"` — MEDIUM-HIGH (deprecated protocols).
- `SSLContext.getInstance("Default")` is fine — uses platform default.

### N3 — Missing certificate pinning

**MASWE:** MASWE-0047 (Insecure Identity Pinning)
**MASTG:** MASTG-TEST-0022, MASTG-TEST-0242, MASTG-TEST-0244

Pinning isn't strictly required by MASVS-NETWORK-1, but **is** required by
MASVS-NETWORK-2 for endpoints under the developer's control. For
financial / health / messaging apps, missing pinning is typically MEDIUM.

How pinning is normally done:
- **Network Security Config**: `<pin-set>` element with one or more `<pin
  digest="SHA-256">...</pin>` entries inside a `<domain-config>`.
- **OkHttp**: `CertificatePinner.Builder().add(host, "sha256/...")`.
- **TrustKit**: configuration via `<trustkit-config>`.

```bash
rg -nE 'CertificatePinner|pin-set|trustkit-config|pin digest' "$WORK/java/" "$WORK/decoded/res/xml/" 2>/dev/null
```

If absent for sensitive apps, that's a finding under MASVS-NETWORK-2.

If `<pin-set>` is present, check `expiration` attribute — expired pins are a
separate finding (MASTG-TEST-0243). Also check for `<trust-anchors>` allowing
user CAs which would defeat pinning.

### N4 — Trust in user-installed CAs

**MASWE:** MASWE-0052
**MASTG:** MASTG-TEST-0285, MASTG-TEST-0286

```xml
<!-- Bad if it's in <base-config>, fine in <debug-overrides> -->
<base-config>
  <trust-anchors>
    <certificates src="user"/>
  </trust-anchors>
</base-config>
```

Allows MITM via any user-installed CA (Burp, corporate proxy, malicious).

Also: apps with `targetSdk <= 23` trust user CAs by default (no NSC
required). If `targetSdk <= 23` and no NSC overrides it, that's a finding
(MEDIUM).

### N5 — WebView SSL error handling

**MASWE:** MASWE-0052
**MASTG:** MASTG-TEST-0284

`onReceivedSslError(view, handler, error) { handler.proceed(); }` overrides
the SSL warning and accepts any cert — CRITICAL when paired with auth
flows in the WebView.

```bash
rg -nE 'onReceivedSslError|SslErrorHandler' "$WORK/java/" "$WORK/decoded/smali*/" 2>/dev/null
```

Look at the body. `handler.cancel()` is correct; `handler.proceed()` is the
bug.

### N6 — Hostname verification disabled

**MASWE:** MASWE-0052
**MASTG:** MASTG-TEST-0234, MASTG-TEST-0283

Apache HttpClient (deprecated but still used): `SSLSocketFactory` with
`ALLOW_ALL_HOSTNAME_VERIFIER`. OkHttp: custom `hostnameVerifier { _, _ -> true }`.
Java: `HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true)`.

```bash
rg -nE 'setHostnameVerifier|setDefaultHostnameVerifier|hostnameVerifier' "$WORK/java/" 2>/dev/null
```

### N7 — Use of low-level socket APIs

**MASWE:** MASWE-0048 (Insecure Machine-to-Machine Communication), MASWE-0049 (Proven Networking APIs Not used)
**MASTG:** MASTG-TEST-0239

Direct `Socket` or `DatagramSocket` for protocols that should be TLS:

```bash
rg -nE 'new Socket\(|new DatagramSocket\(|new ServerSocket\(' "$WORK/java/" 2>/dev/null
```

Each hit needs inspection — if the protocol is HTTP-over-Socket, that's
cleartext.

## Where the network config lives

After `apktool` decode, the XML lives at:
- `decoded/AndroidManifest.xml` (look for `networkSecurityConfig` attribute).
- `decoded/res/xml/<name>.xml` (the referenced file).

Pretty-print it and walk through the rules. A safe NSC looks like:

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">...</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

## Passed checks worth noting

- `usesCleartextTraffic="false"` (explicit or via targetSdk≥28 default)
- NSC with `cleartextTrafficPermitted="false"` base-config
- Certificate pinning for backend domains
- No custom `TrustManager` / `HostnameVerifier`
- WebView `onReceivedSslError` calls `handler.cancel()`
