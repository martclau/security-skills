# MASVS-CRYPTO — Cryptographic functionality

Controls:
- **MASVS-CRYPTO-1**: Cryptography used to protect sensitive data follows industry best practices.
- **MASVS-CRYPTO-2**: Cryptographic key material is managed securely.

URL pattern:
- MASWE: `https://mas.owasp.org/MASWE/MASVS-CRYPTO/MASWE-XXXX/`
- MASTG: `https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-XXXX/`

## Checks

### C1 — Broken or weak algorithms

**MASWE:** MASWE-0019 (Risky Cryptography Implementations), MASWE-0021 (Improper Hashing)
**MASTG:** MASTG-TEST-0221 (broken symmetric), MASTG-TEST-0014

Hits to flag:
- Symmetric: `DES`, `3DES`/`DESede`, `RC4`, `RC2`, `Blowfish` (in modern apps)
- Hash for security: `MD5`, `MD4`, `SHA-1`, `SHA-0`
  - MD5/SHA-1 for non-security purposes (checksums of public data) is fine —
    don't flag unless context shows it's used for auth/signing/integrity.
- Asymmetric: `RSA` with key size < 2048; `DSA` < 2048; any ECDSA on a
  non-NIST curve unless explicitly justified.

```bash
rg -nE '"(DES|DESede|RC4|RC2|MD5|MD4|SHA-?1)"|Cipher\.getInstance\("DES' "$WORK/java/" "$WORK/decoded/smali*/" 2>/dev/null
rg -nE 'MessageDigest\.getInstance\("(MD5|SHA-?1)"\)' "$WORK/java/" "$WORK/decoded/smali*/" 2>/dev/null
```

### C2 — ECB mode for symmetric encryption

**MASWE:** MASWE-0020 (Improper Encryption)
**MASTG:** MASTG-TEST-0232

ECB is deterministic and leaks patterns. Any `Cipher.getInstance("AES/ECB/*")`
or `getInstance("AES")` (defaults to ECB on Android) is a finding.

```bash
rg -nE 'Cipher\.getInstance\("AES("|/ECB|/[A-Z]+/ECB)' "$WORK/java/" "$WORK/decoded/smali*/" 2>/dev/null
rg -nF 'AES/ECB/' "$WORK/decoded/smali*/" 2>/dev/null
```

The bare string `"AES"` (no mode specified) is also a finding — Android
defaults to ECB. Recommend `AES/GCM/NoPadding` (preferred) or
`AES/CBC/PKCS7Padding` with a random IV.

### C3 — Predictable IVs

**MASWE:** MASWE-0022 (Predictable Initialization Vectors)
**MASTG:** MASTG-TEST-0309

Common bugs:
- All-zero IV: `new IvParameterSpec(new byte[16])`
- Reused IV across encryptions
- IV derived from password/userId/timestamp

```bash
rg -n 'IvParameterSpec' "$WORK/java/" 2>/dev/null
rg -nE 'new byte\[(16|12|8)\]\s*[,)]' "$WORK/java/" 2>/dev/null | grep -i iv
```

Then verify the IV's source — random per encryption (good) or static (bad).

### C4 — Insecure RNG

**MASWE:** MASWE-0027 (Improper Random Number Generation)
**MASTG:** MASTG-TEST-0016, MASTG-TEST-0204, MASTG-TEST-0205

`java.util.Random`, `Math.random()`, `currentTimeMillis()` used to seed key
material, IVs, tokens, or session IDs are findings. `SecureRandom` is
required.

```bash
rg -nE 'new Random\(|Math\.random\(|System\.currentTimeMillis\(\)' "$WORK/java/" 2>/dev/null
```

Cross-reference: a `new Random()` next to cipher setup, key generation, or
token creation is a clear finding. `new Random()` for UI shuffling or animation
delays is fine.

### C5 — Hardcoded crypto keys

**MASWE:** MASWE-0013 (Hardcoded Cryptographic Keys in Use)
**MASTG:** MASTG-TEST-0212

```bash
rg -nE 'SecretKeySpec\(.*"[A-Za-z0-9+/=]{16,}"' "$WORK/java/" 2>/dev/null
rg -nE 'const-string [vp][0-9]+, "[A-Fa-f0-9]{32,64}"' "$WORK/decoded/smali*/" 2>/dev/null | head -50
```

Look for:
- 16/24/32-byte ASCII/hex string literals passed to `SecretKeySpec` or
  `IvParameterSpec`.
- Base64 blobs of suspicious length stored in resources or assets and used
  as key material.

### C6 — Key storage outside Android KeyStore

**MASWE:** MASWE-0014 (Cryptographic Keys Not Properly Protected at Rest), MASWE-0015 (Deprecated Android KeyStore Implementations)
**MASTG:** MASTG-KNOW-0043 (background)

The right place to store crypto keys is the Android KeyStore
(`AndroidKeyStore` provider). Bouncy Castle KeyStore, file-based keystores,
or in-memory + persisted byte arrays are findings.

```bash
rg -nE 'KeyStore\.getInstance\("(AndroidKeyStore|BKS|BouncyCastle|PKCS12)"\)' "$WORK/java/" 2>/dev/null
rg -nE 'KeyGenerator\.getInstance|KeyPairGenerator\.getInstance' "$WORK/java/" 2>/dev/null
```

`AndroidKeyStore` is the only acceptable answer for protecting keys at rest.
Bonus to look for: `setUserAuthenticationRequired(true)` for high-value keys
(binds use to biometric / PIN).

### C7 — RSA without OAEP padding / PKCS1v1.5 padding

**MASWE:** MASWE-0023 (Risky Padding)

```bash
rg -nE 'Cipher\.getInstance\("RSA/[^"]*PKCS1Padding"\)' "$WORK/java/" 2>/dev/null
```

`RSA/ECB/PKCS1Padding` is vulnerable to padding-oracle attacks in
encryption use. Use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.

### C8 — Unauthenticated encryption

**MASWE:** MASWE-0024 (Improper Use of MAC)
**MASTG:** MASTG-TEST-0013, MASTG-TEST-0015

`AES/CBC/PKCS7Padding` without an HMAC is malleable. Either use authenticated
modes (`AES/GCM/NoPadding`) or apply Encrypt-then-MAC.

When you see `AES/CBC/*` in a context that handles authentication tokens or
integrity-sensitive payloads (not just storage at rest), look for a paired
HMAC over the ciphertext. If absent — finding.

## What to put in "Passed checks"

- Uses `AndroidKeyStore` for key storage
- `AES/GCM/NoPadding` with random IVs from `SecureRandom`
- RSA-2048+ with OAEP padding
- HMAC-SHA-256 for integrity
- `setUserAuthenticationRequired(true)` on keys gating sensitive ops
- `KeyGenParameterSpec` with appropriate purposes (not reusing a signing key for encryption)
