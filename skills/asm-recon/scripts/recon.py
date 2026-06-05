#!/usr/bin/env python3
"""
asm-recon — Attack-surface monitoring collector.

Collects PASSIVE (third-party datasets) and NO-IMPACT ACTIVE (single
client-like requests to the target) signals about a set of owned domains,
then emits two artifacts:

  1. <outdir>/<YYYY-MM-DD>.json   — structured longitudinal state (diffable)
  2. <outdir>/REPORT.md           — human-readable report, leading with the
                                     diff against the most recent prior JSON

Hard boundaries (see SKILL.md):
  * NO port scanning, NO login/auth attempts, NO directory/DNS brute-force,
    NO vulnerability probing, NO fuzzing.
  * Subdomains are discovered ONLY from public data (certificate
    transparency) and then resolved. They are never brute-forced.
  * AXFR (zone transfer) IS attempted against the domain's own nameservers —
    this is a configuration audit. A successful transfer is a finding.
  * Secrets are stored as a redacted fingerprint only, never in plaintext.

This script degrades gracefully: every collector is wrapped so a failure in
one source (network, missing dependency, rate limit) never aborts the run.
Sources that could not be reached are recorded under scan.source_status.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

# Bundled, pure-stdlib DNS client (scripts/dnsmini.py) — no pip packages
# required. Kept import-guarded so a packaging mishap degrades gracefully
# (DNS records, AXFR audit and ASN enrichment are skipped, exactly as the
# old optional-dnspython path behaved) rather than aborting the run.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import dnsmini
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

UTC = dt.timezone.utc
SCHEMA_VERSION = "1.0"
HTTP_TIMEOUT = 12
USER_AGENT = "asm-recon/1.0 (attack-surface-monitoring; owned-assets-only)"


def now_iso():
    return dt.datetime.now(UTC).isoformat()


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _http_get(url, timeout=HTTP_TIMEOUT, max_bytes=200_000):
    """Single GET. Returns (status, headers_dict, body_bytes, final_url)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read(max_bytes)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, headers, body, resp.geturl()


def redact_fingerprint(secret_value):
    """Turn a secret into a non-reversible fingerprint for safe storage."""
    h = hashlib.sha256(secret_value.encode("utf-8", "ignore")).hexdigest()
    return {"sha256_prefix": h[:16], "length": len(secret_value)}


# --------------------------------------------------------------------------- #
# Collectors — each returns data and never raises past its own boundary
# --------------------------------------------------------------------------- #

def collect_rdap_domain(domain, status):
    """Passive: registrar / registrant / dates / nameservers via RDAP."""
    out = {
        "registrar": None, "created": None, "expires": None,
        "nameservers": [], "whois_registrant": None,
        "source": "rdap.org", "collected_at": now_iso(), "method": "passive",
    }
    try:
        url = f"https://rdap.org/domain/{domain}"
        code, _, body, _ = _http_get(url)
        data = json.loads(body)
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                out["created"] = ev.get("eventDate")
            if ev.get("eventAction") == "expiration":
                out["expires"] = ev.get("eventDate")
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                out["registrar"] = _vcard_fn(vcard)
            if "registrant" in roles:
                out["whois_registrant"] = _vcard_fn(ent.get("vcardArray", []))
        out["nameservers"] = sorted(
            ns.get("ldhName", "").lower()
            for ns in data.get("nameservers", []) if ns.get("ldhName")
        )
        status["rdap"] = "ok"
    except Exception as e:
        status["rdap"] = f"error: {type(e).__name__}"
    return out


def _vcard_fn(vcard_array):
    """Pull the 'fn' (formatted name) value out of an RDAP jCard."""
    try:
        for item in vcard_array[1]:
            if item[0] == "fn":
                return item[3]
    except Exception:
        pass
    return None


def collect_crtsh_subdomains(domain, status):
    """Passive: subdomains from certificate transparency (crt.sh)."""
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        code, _, body, _ = _http_get(url, max_bytes=5_000_000)
        # crt.sh returns concatenated JSON objects in some modes; this mode
        # returns a proper array.
        for row in json.loads(body):
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and " " not in name:
                    found.add(name)
        status["crtsh"] = "ok"
    except Exception as e:
        status["crtsh"] = f"error: {type(e).__name__}"
    return found


def collect_certspotter_subdomains(domain, status):
    """
    Passive: subdomains from certificate transparency (SSLMate CertSpotter).

    Serves as a fallback for crt.sh, which is frequently slow or unreachable.
    The unauthenticated endpoint returns one page (newest issuances) and is
    rate-limited; that is plenty as a backstop. Set CERTSPOTTER_TOKEN in the
    environment to authenticate and lift the per-IP limits.
    """
    found = set()
    try:
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               f"&include_subdomains=true&expand=dns_names")
        headers = {"User-Agent": USER_AGENT}
        token = os.environ.get("CERTSPOTTER_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            body = resp.read(5_000_000)
        # The response is a JSON array of issuances; each has a dns_names list.
        # include_subdomains pulls in certs whose SANs cover sibling domains on
        # other TLDs, so the endswith filter below is what keeps us in-scope.
        for row in json.loads(body):
            for name in row.get("dns_names", []):
                name = str(name).strip().lower().lstrip("*.")
                if name.endswith(domain) and " " not in name:
                    found.add(name)
        status["certspotter"] = "ok"
    except Exception as e:
        status["certspotter"] = f"error: {type(e).__name__}"
    return found


def resolve_host(fqdn):
    """No-impact active: resolve A/AAAA/CNAME for one host."""
    rec = {"a": [], "aaaa": [], "cname": None,
           "dangling_cname": False, "resolves": False}
    if not HAVE_DNS:
        return rec
    for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
        try:
            rec[key] = sorted(dnsmini.query(fqdn, rtype))
        except Exception:
            pass
    try:
        cname = dnsmini.query(fqdn, "CNAME")
        if cname:
            rec["cname"] = cname[0].rstrip(".").lower()
    except Exception:
        pass
    rec["resolves"] = bool(rec["a"] or rec["aaaa"])
    # Dangling CNAME heuristic: a CNAME exists but the target does not resolve.
    # dnsmini.query returns [] for NXDOMAIN/NODATA and raises only on transport
    # failure — both mean the target is not usable, so both flag dangling.
    if rec["cname"] and not rec["resolves"]:
        try:
            if not dnsmini.query(rec["cname"], "A"):
                rec["dangling_cname"] = True
        except Exception:
            rec["dangling_cname"] = True
    return rec


def collect_zone_records(domain, status):
    """No-impact active: MX/NS/TXT/CAA/SOA + SPF/DMARC/DKIM derivation."""
    out = {"mx": [], "ns": [], "txt": [], "caa": [],
           "spf": None, "dmarc": None, "dkim_selectors": [],
           "collected_at": now_iso(), "method": "active-noimpact"}
    if not HAVE_DNS:
        status["dns_records"] = "skipped: bundled DNS module unavailable"
        return out
    try:
        out["mx"] = sorted(f"{pref} {exch.rstrip('.')}"
                           for pref, exch in dnsmini.query(domain, "MX"))
    except Exception:
        pass
    try:
        out["ns"] = sorted(n.rstrip(".").lower()
                           for n in dnsmini.query(domain, "NS"))
    except Exception:
        pass
    try:
        txts = list(dnsmini.query(domain, "TXT"))
        out["txt"] = sorted(txts)
        for t in txts:
            if t.lower().startswith("v=spf1"):
                out["spf"] = t
    except Exception:
        pass
    try:
        out["caa"] = sorted(f'{flags} {tag} "{val}"'
                            for flags, tag, val in dnsmini.query(domain, "CAA"))
    except Exception:
        pass
    try:
        for t in dnsmini.query(f"_dmarc.{domain}", "TXT"):
            if "v=DMARC1" in t:
                out["dmarc"] = t
    except Exception:
        pass
    # Probe a few extremely common DKIM selectors (published-record lookups,
    # not brute force — this is a tiny fixed list of well-known selectors).
    for sel in ("default", "google", "selector1", "selector2", "k1", "mail"):
        try:
            if dnsmini.query(f"{sel}._domainkey.{domain}", "TXT"):
                out["dkim_selectors"].append(sel)
        except Exception:
            pass
    status["dns_records"] = "ok"
    return out


def attempt_zone_transfer(domain, nameservers, status):
    """
    No-impact active CONFIG AUDIT: attempt AXFR against each authoritative
    nameserver. Should fail. A success is a misconfiguration finding.
    Returns (result_block, leaked_records_set).
    """
    block = {"nameservers_tested": [], "results": {},
             "collected_at": now_iso(), "method": "active-noimpact"}
    leaked = set()
    if not HAVE_DNS:
        status["axfr"] = "skipped: bundled DNS module unavailable"
        return block, leaked
    if not nameservers:
        status["axfr"] = "skipped: no nameservers known"
        return block, leaked
    any_allowed = False
    for ns in nameservers:
        block["nameservers_tested"].append(ns)
        try:
            ns_ip = socket.gethostbyname(ns)
        except Exception:
            block["results"][ns] = {"axfr_allowed": None,
                                    "records_returned": 0,
                                    "note": "ns did not resolve"}
            continue
        # Fast pre-check: AXFR uses TCP/53. Confirm the port is reachable with
        # a short connect timeout so a filtered/dropped port fails in seconds
        # rather than stalling on a silently-dropped TCP handshake.
        try:
            probe = socket.create_connection((ns_ip, 53), timeout=5)
            probe.close()
        except Exception as e:
            block["results"][ns] = {"axfr_allowed": False,
                                    "records_returned": 0,
                                    "note": f"tcp/53 unreachable: "
                                            f"{type(e).__name__}"}
            continue
        try:
            # dnsmini.axfr returns absolute, lowercased, de-duplicated owner
            # names (no trailing dot) — no relativization needed.
            names = dnsmini.axfr(ns_ip, domain, timeout=10)
            block["results"][ns] = {"axfr_allowed": True,
                                    "records_returned": len(names)}
            any_allowed = True
            for fq in names:
                if fq.endswith(domain) and fq != domain:
                    leaked.add(fq)
        except Exception:
            block["results"][ns] = {"axfr_allowed": False,
                                    "records_returned": 0}
    if any_allowed:
        block["finding"] = "misconfiguration: zone transfer permitted"
    status["axfr"] = "ok"
    return block, leaked


# Provider/tech detection from a verification TXT record or header fingerprint.
SAAS_TXT_HINTS = {
    "google-site-verification": "Google Workspace / Search Console",
    "MS=": "Microsoft 365",
    "atlassian-domain-verification": "Atlassian",
    "facebook-domain-verification": "Meta",
    "stripe-verification": "Stripe",
    "docusign": "DocuSign",
    "adobe-idp-site-verification": "Adobe",
    "zoom-domain-verification": "Zoom",
}


def detect_saas_from_txt(txt_records):
    hints = []
    for t in txt_records:
        for needle, label in SAAS_TXT_HINTS.items():
            if needle.lower() in t.lower():
                hints.append(label)
    return sorted(set(hints))


def fetch_web_host(fqdn, status):
    """
    No-impact active: ONE https GET (fall back to http). Collects status,
    redirect chain, server/x-powered-by headers, TLS cert, title, favicon
    hash, and presence of robots/sitemap/security.txt.
    """
    result = {
        "url": None, "status": None, "redirect_chain": [],
        "server_header": None, "powered_by": None, "title": None,
        "technologies": [], "tls": {}, "favicon_hash": None,
        "robots_txt": False, "sitemap_xml": False, "security_txt": False,
        "auth_surface": None,
        "collected_at": now_iso(), "method": "active-noimpact",
    }
    base = None
    final_host = fqdn
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{fqdn}/"
            try:
                code, headers, body, final = _http_get(url)
            except urllib.error.HTTPError as he:
                # A 401/403/404/5xx still means the host is serving HTTP and is
                # part of the attack surface — capture the error response (a
                # 401 / WWW-Authenticate challenge IS an auth surface) instead
                # of dropping the host.
                code = he.code
                headers = {k.lower(): v for k, v in he.headers.items()}
                try:
                    body = he.read(200_000) or b""
                except Exception:
                    body = b""
                final = getattr(he, "url", None) or url
            result["url"] = final
            result["status"] = code
            if final != url:
                result["redirect_chain"] = [url, final]
            result["server_header"] = headers.get("server")
            result["powered_by"] = headers.get("x-powered-by")
            m = re.search(rb"<title[^>]*>(.*?)</title>",
                          body, re.I | re.S)
            if m:
                result["title"] = m.group(1).decode(
                    "utf-8", "ignore").strip()[:200]
            result["technologies"] = _fingerprint(headers, body)
            result["auth_surface"] = _detect_auth(
                final, result["redirect_chain"], headers, body, code)
            # urllib already followed any HTTP redirects, so headers/body above
            # describe the FINAL host. Point the follow-up probes (TLS cert,
            # well-known files, favicon) at that final host too — not the
            # original, which may be a bare redirector on different
            # infrastructure (e.g. an apex that 301s to a brand domain).
            parsed = urllib.parse.urlparse(final)
            final_host = parsed.hostname or fqdn
            base = f"{parsed.scheme}://{parsed.netloc}"
            break
        except Exception:
            continue
    if base is None:
        return None  # host not serving HTTP(S)

    if base.startswith("https"):
        result["tls"] = _tls_cert(final_host)

    # Well-known files — one GET each.
    for path, key in (("/robots.txt", "robots_txt"),
                      ("/sitemap.xml", "sitemap_xml"),
                      ("/.well-known/security.txt", "security_txt")):
        try:
            code, _, _, _ = _http_get(base + path, timeout=8)
            result[key] = (code == 200)
        except Exception:
            pass
    # Favicon hash (mmh3-style pivot uses murmur, but we keep deps light and
    # use sha256 — still stable for change detection across runs).
    try:
        code, _, fav, _ = _http_get(base + "/favicon.ico", timeout=8)
        if code == 200 and fav:
            result["favicon_hash"] = hashlib.sha256(fav).hexdigest()[:32]
    except Exception:
        pass
    return result


def _fingerprint(headers, body):
    techs = []
    server = (headers.get("server") or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()
    blob = body[:50_000].lower()
    table = {
        "nginx": b"", "apache": b"", "cloudflare": b"",
        "wordpress": b"wp-content", "drupal": b"drupal",
        "react": b"react", "next.js": b"__next", "vue": b"vue",
        "django": b"csrfmiddlewaretoken",
    }
    for name, needle in table.items():
        if name in server or name in powered or (needle and needle in blob):
            techs.append(name)
    return sorted(set(techs))


# --------------------------------------------------------------------------- #
# Authentication-surface detection
# --------------------------------------------------------------------------- #
# Vendor/product signatures. Every needle is high-signal (a URL path, a vendor
# domain, a product-specific cookie/parameter, or a distinctive phrase) so the
# combined url+headers+body haystack does not false-positive on pages that
# merely mention a product. Categories drive risk tiering: remote-access and
# admin logins are flagged higher than generic logins.
AUTH_SIGNATURES = [
    # Remote-access / VPN portals — the crown jewels of an external surface.
    ("remote-access", "Fortinet SSL-VPN", ["/remote/login", "/sslvpn", "fgt_lang="]),
    ("remote-access", "Ivanti / Pulse Connect Secure", ["/dana-na/", "/dana/home"]),
    ("remote-access", "F5 BIG-IP APM", ["/my.policy", "bigipauthcookie"]),
    ("remote-access", "Cisco ASA / AnyConnect", ["/+cscoe+/", "/+webvpn+/", "/+cscou+/"]),
    ("remote-access", "Citrix Gateway / NetScaler", ["/vpn/index.html", "/logon/logonpoint", "/cgi/login", "netscaler gateway"]),
    ("remote-access", "Palo Alto GlobalProtect", ["/global-protect/login", "/ssl-vpn/login", "globalprotect portal"]),
    ("remote-access", "SonicWall SRA/SMA", ["/cgi-bin/welcome", "sonicwall"]),
    # Identity providers / SSO.
    ("sso-idp", "Okta", ["okta.com", "oktapreview.com", "okta-signin"]),
    ("sso-idp", "Microsoft Entra / ADFS / B2C", ["login.microsoftonline.com", "/adfs/ls", "b2clogin.com"]),
    ("sso-idp", "Ping Identity", ["pingidentity.com", "pingfederate", "/idp/startsso"]),
    ("sso-idp", "Auth0", ["auth0.com", "/u/login"]),
    ("sso-idp", "OneLogin", ["onelogin.com"]),
    ("sso-idp", "Keycloak", ["/auth/realms/", "/realms/", "kc-form-login"]),
    ("sso-idp", "CAS", ["/cas/login"]),
    ("sso-idp", "Shibboleth", ["/idp/profile/saml2"]),
    ("sso-idp", "SAML", ["samlrequest=", "/saml2/idp", "urn:oasis:names:tc:saml"]),
    # Mail / collaboration.
    ("login", "OWA / Exchange", ["/owa/auth", "outlook web app"]),
    # Admin panels.
    ("admin", "WordPress admin", ["wp-login.php", "/wp-admin/"]),
    ("admin", "Web admin console", ["/admin/login", "/administrator/index.php", "/manager/html"]),
]

# Generic login indicators in the request URL / redirect chain (NOT the page
# body — so a nav link to /login elsewhere on a page never triggers this; only
# the host's own landing URL does). This is what catches handler/SPA logins
# whose body carries no <input type=password> (e.g. /login.ashx?ReturnUrl=).
AUTH_URL_PATTERNS = [
    "/login", "/signin", "/sign-in", "/log-in", "/logon", "/sso/",
    "/account/login", "/users/sign_in", "/auth/realms",
    "returnurl=", "redirect_uri=", "response_type=", "samlrequest=",
]

_PWD_FIELD_RE = re.compile(r"""type\s*=\s*['"]?password""", re.I)
_LOGIN_FORM_RE = re.compile(
    r"""<form[^>]+action\s*=\s*['"][^'"]*(?:login|signin|sso|auth)""", re.I)

# Category priority (most → least specific) when several fire, and the risk
# tier each category maps to.
_AUTH_PRIORITY = ["remote-access", "admin", "sso-idp", "http-auth", "login"]
_AUTH_SEVERITY = {"remote-access": "MEDIUM", "admin": "MEDIUM",
                  "sso-idp": "INFO", "http-auth": "INFO", "login": "INFO"}


def _detect_auth(final_url, redirect_chain, headers, body, status):
    """
    Identify an authentication surface from a single fetched response.

    Returns None, or a dict:
        {"type": <label>, "category": <cat>, "severity": <SEV>,
         "detected_via": [<evidence>, ...]}

    Collects every signal it sees — URL/redirect path, body credential form,
    HTTP-auth (401) challenge, and vendor fingerprint — and reports them all in
    detected_via. The primary category/label is the most specific signal that
    fired.
    """
    url_hay = " ".join([final_url or ""] + list(redirect_chain or [])).lower()
    text = (body[:65_536].decode("utf-8", "ignore")
            if isinstance(body, (bytes, bytearray)) else (body or ""))
    hdr = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    full_hay = (url_hay + " " + hdr + " " + text).lower()

    signals = []   # list of (category, label, evidence)

    # (3) HTTP auth challenge — strongest, unambiguous.
    wa = (headers or {}).get("www-authenticate")
    if status == 401 or wa:
        scheme = (wa or "").split(" ", 1)[0].split(",")[0].strip() or "challenge"
        signals.append(("http-auth", f"HTTP auth ({scheme})",
                        f"header:WWW-Authenticate {scheme}".strip()))

    # (4) Vendor / product fingerprints. Path-style markers (those starting
    # with "/") are matched against the URL/redirect chain only — never the
    # body — because the scanner only ever fetches "/" and follows redirects
    # (it never path-brute-forces). A body that merely *links* to /wp-admin/ or
    # /remote/login is not evidence that this host IS that portal; the host's
    # own landing URL containing the path is. Domain/cookie/phrase markers
    # (e.g. okta.com, bigipauthcookie, samlrequest=) stay matched on the full
    # haystack, where they are distinctive.
    for category, label, needles in AUTH_SIGNATURES:
        hit = next((n for n in needles
                    if n in (url_hay if n.startswith("/") else full_hay)), None)
        if hit:
            signals.append((category, label, f"marker:{hit}"))

    # (1) Generic login URL / redirect patterns (matched on the URL only).
    upat = next((p for p in AUTH_URL_PATTERNS if p in url_hay), None)
    if upat:
        signals.append(("login", "login page", f"url:{upat}"))

    # (2) Credential form in the body (quote/format-insensitive).
    if _PWD_FIELD_RE.search(text):
        signals.append(("login", "login form", "body:password-field"))
    elif _LOGIN_FORM_RE.search(text):
        signals.append(("login", "login form", "body:login-form-action"))

    if not signals:
        return None

    # Primary signal = the most specific category that fired. Within a category
    # the first appended wins, which keeps vendor labels ahead of the generic
    # "login page" / "HTTP auth" fallbacks.
    best = min(signals, key=lambda s: _AUTH_PRIORITY.index(s[0]))
    return {
        "type": best[1],
        "category": best[0],
        "severity": _AUTH_SEVERITY.get(best[0], "INFO"),
        "detected_via": sorted({ev for _c, _l, ev in signals}),
    }


def _tls_cert(fqdn):
    info = {"issuer": None, "subject": None, "not_after": None, "san": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((fqdn, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cert = ssock.getpeercert()
        info["issuer"] = dict(x[0] for x in cert.get("issuer", [])).get(
            "organizationName")
        info["subject"] = dict(x[0] for x in cert.get("subject", [])).get(
            "commonName")
        info["not_after"] = cert.get("notAfter")
        info["san"] = sorted(v for k, v in cert.get(
            "subjectAltName", []) if k == "DNS")
    except Exception:
        pass
    return info


def enrich_ip(ip, status):
    """
    Passive: PTR + ASN/CIDR/org via Team Cymru DNS-based whois (no API key).
    """
    rec = {"ptr": None, "asn": None, "cidr": None,
           "as_name": None, "rir": None, "country": None}
    try:
        rec["ptr"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    if HAVE_DNS:
        try:
            rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
            ans = dnsmini.query(rev, "TXT")
            # Format: "ASN | CIDR | CC | RIR | date"
            parts = [p.strip() for p in ans[0].split("|")]
            if len(parts) >= 5:
                rec["asn"] = f"AS{parts[0].split()[0]}"
                rec["cidr"] = parts[1]
                rec["country"] = parts[2]
                rec["rir"] = parts[3]
                status["ip_enrichment"] = "ok"
            # AS-name is a secondary, best-effort lookup; its failure must not
            # mask the successful origin lookup above.
            if rec["asn"]:
                try:
                    aq = f"{rec['asn'][2:]}.asn.cymru.com"
                    ap = dnsmini.query(aq, "TXT")[0].split("|")
                    if len(ap) >= 5:
                        rec["as_name"] = ap[-1].strip()
                except Exception:
                    pass
        except Exception as e:
            status.setdefault("ip_enrichment", f"error: {type(e).__name__}")
    return rec


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def run_scan(apex_domains):
    started = now_iso()
    source_status = {}
    state = {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "scan_id": dt.datetime.now(UTC).strftime("%Y-%m-%dT%H%MZ"),
            "started_at": started,
            "completed_at": None,
            "scope": {
                "apex_domains": sorted(apex_domains),
                "regime": "passive+active-noimpact",
                "excluded": ["port-scan", "auth-attempts",
                             "dns-brute-force", "vuln-probing", "fuzzing"],
            },
            "source_status": source_status,
            "tooling": {"dns_resolver": "builtin (dnsmini, stdlib-only)",
                        "dns_available": HAVE_DNS},
        },
        "organization": {"registrant_strings": []},
        "domains": {},
        "subdomains": {},
        "dns_records": {},
        "zone_transfer": {},
        "network": {"ip_addresses": {}, "asns": {}, "cidrs": {}},
        "web_hosts": {},
        "auth_surfaces": [],
        "mail": {},
        "exposure": {
            "leaked_secrets": [],          # redacted fingerprints only
            "public_repos": [],
            "open_storage_buckets": [],
            "note": "Populated only when API-keyed sources are configured.",
        },
    }

    all_ips = set()
    registrants = set()

    for domain in sorted(apex_domains):
        # --- domain registration (passive) ---
        dom = collect_rdap_domain(domain, source_status)
        state["domains"][domain] = dom
        if dom.get("whois_registrant"):
            registrants.add(dom["whois_registrant"])

        # --- zone records (no-impact active) ---
        zr = collect_zone_records(domain, source_status)
        state["dns_records"][domain] = zr

        # --- mail posture derived from zone records ---
        state["mail"][domain] = _mail_posture(domain, zr)

        # --- SaaS hints from TXT ---
        saas = detect_saas_from_txt(zr.get("txt", []))
        if saas:
            state["domains"][domain]["saas_hints"] = saas

        # --- AXFR config audit (no-impact active) ---
        nslist = zr.get("ns") or dom.get("nameservers") or []
        axfr_block, leaked = attempt_zone_transfer(
            domain, nslist, source_status)
        state["zone_transfer"][domain] = axfr_block

        # --- subdomain discovery (passive CT, multi-source) + AXFR leak ---
        # Query every CT source and union the results, so one source being
        # down (crt.sh is frequently slow/unreachable) never zeroes out
        # enumeration. discovered_via records which source(s) saw each name.
        subs = set()
        sub_sources = {}
        for label, collector in (("crt.sh", collect_crtsh_subdomains),
                                 ("certspotter", collect_certspotter_subdomains)):
            for s in collector(domain, source_status):
                sub_sources.setdefault(s, []).append(label)
                subs.add(s)
        for s in leaked:
            sub_sources.setdefault(s, []).append("axfr")
            subs.add(s)
        subs.add(domain)  # include apex itself

        # --- resolve each subdomain (no-impact active) + web fetch ---
        for fqdn in sorted(subs):
            dns_rec = resolve_host(fqdn)
            entry = {
                "discovered_via": sorted(set(sub_sources.get(
                    fqdn, ["resolution"]))),
                "resolves": dns_rec["resolves"],
                "dns": {"a": dns_rec["a"], "aaaa": dns_rec["aaaa"],
                        "cname": dns_rec["cname"],
                        "dangling_cname": dns_rec["dangling_cname"]},
                "collected_at": now_iso(),
                "method": "active-noimpact",
            }
            state["subdomains"][fqdn] = entry
            for ip in dns_rec["a"]:
                all_ips.add(ip)

            if dns_rec["resolves"]:
                web = fetch_web_host(fqdn, source_status)
                if web:
                    state["web_hosts"][web["url"] or fqdn] = web
                    if web.get("auth_surface"):
                        asf = web["auth_surface"]
                        state["auth_surfaces"].append({
                            "url": web["url"],
                            "type": asf["type"],
                            "category": asf["category"],
                            "severity": asf["severity"],
                            "detected_via": asf["detected_via"],
                            "method": "active-noimpact",
                        })

    # --- IP enrichment (passive) ---
    for ip in sorted(all_ips):
        rec = enrich_ip(ip, source_status)
        state["network"]["ip_addresses"][ip] = rec
        if rec.get("asn"):
            state["network"]["asns"].setdefault(
                rec["asn"], {"name": rec.get("as_name"), "netblocks": []})
            if rec.get("cidr") and rec["cidr"] not in \
                    state["network"]["asns"][rec["asn"]]["netblocks"]:
                state["network"]["asns"][rec["asn"]]["netblocks"].append(
                    rec["cidr"])
        if rec.get("cidr"):
            state["network"]["cidrs"].setdefault(
                rec["cidr"], {"rir": rec.get("rir"),
                              "country": rec.get("country")})

    state["organization"]["registrant_strings"] = sorted(registrants)
    state["scan"]["completed_at"] = now_iso()
    return state


def _mail_posture(domain, zr):
    spf = zr.get("spf")
    dmarc = zr.get("dmarc") or ""
    dmarc_policy = None
    m = re.search(r"\bp=(\w+)", dmarc)
    if m:
        dmarc_policy = m.group(1)
    spf_all = None
    if spf:
        if "-all" in spf:
            spf_all = "-all"
        elif "~all" in spf:
            spf_all = "~all"
        elif "?all" in spf:
            spf_all = "?all"
        elif "+all" in spf:
            spf_all = "+all"
    # Spoofable if no DMARC enforcement AND SPF not hard-fail.
    spoofable = (dmarc_policy in (None, "none")) and (spf_all != "-all")
    mx_provider = None
    if zr.get("mx"):
        first = zr["mx"][0].split()[-1].lower()
        for needle, label in (("google", "Google Workspace"),
                              ("outlook", "Microsoft 365"),
                              ("protection.outlook", "Microsoft 365"),
                              ("pphosted", "Proofpoint"),
                              ("mimecast", "Mimecast")):
            if needle in first:
                mx_provider = label
        mx_provider = mx_provider or first
    return {"mx_provider": mx_provider, "spf_policy": spf_all,
            "dmarc_policy": dmarc_policy, "spoofable": spoofable}


# --------------------------------------------------------------------------- #
# first_seen / last_seen carry-forward + diff
# --------------------------------------------------------------------------- #

TRACKED = ["domains", "subdomains", "web_hosts", "auth_surfaces"]


def find_prior_json(outdir, exclude):
    candidates = sorted(
        p for p in Path(outdir).glob("*.json") if p != exclude)
    return candidates[-1] if candidates else None


def carry_forward_seen(state, prior, today):
    """Preserve first_seen for entities that existed in the prior run."""
    prior = prior or {}
    for fqdn, entry in state["subdomains"].items():
        prev = prior.get("subdomains", {}).get(fqdn)
        entry["first_seen"] = (prev or {}).get("first_seen", today)
        entry["last_seen"] = today


def diff_states(old, new):
    """Compute added/removed for tracked dict sections, plus key changes."""
    old = old or {}
    report = {}
    for section in ["domains", "subdomains", "web_hosts"]:
        o = set((old.get(section) or {}).keys())
        n = set(new.get(section, {}).keys())
        report[section] = {"added": sorted(n - o),
                           "removed": sorted(o - n)}
    # Changed risk flags on subdomains.
    changed = []
    for fqdn, entry in new["subdomains"].items():
        prev = (old.get("subdomains") or {}).get(fqdn)
        if not prev:
            continue
        if prev.get("dns", {}).get("dangling_cname") != \
                entry["dns"]["dangling_cname"]:
            changed.append(
                f"{fqdn}: dangling_cname "
                f"{prev['dns']['dangling_cname']} -> "
                f"{entry['dns']['dangling_cname']}")
    # Changed mail posture.
    for dom, m in new["mail"].items():
        prev = (old.get("mail") or {}).get(dom)
        if prev and prev.get("spoofable") != m.get("spoofable"):
            changed.append(
                f"{dom}: spoofable {prev['spoofable']} -> {m['spoofable']}")
    report["changed"] = changed
    return report


# --------------------------------------------------------------------------- #
# Risk extraction + report rendering
# --------------------------------------------------------------------------- #

def extract_risks(state):
    risks = []
    for dom, block in state["zone_transfer"].items():
        if block.get("finding"):
            allowed = [ns for ns, r in block["results"].items()
                       if r.get("axfr_allowed")]
            risks.append(("HIGH",
                          f"Zone transfer (AXFR) permitted on {dom} by: "
                          f"{', '.join(allowed)}. Anyone can download the "
                          f"full DNS zone. Restrict AXFR to authorized "
                          f"secondaries immediately."))
    for fqdn, e in state["subdomains"].items():
        if e["dns"]["dangling_cname"]:
            risks.append(("HIGH",
                          f"Dangling CNAME on {fqdn} -> "
                          f"{e['dns']['cname']} (target does not resolve). "
                          f"Subdomain-takeover candidate."))
    for dom, m in state["mail"].items():
        if m.get("spoofable"):
            risks.append(("MEDIUM",
                          f"{dom} is email-spoofable "
                          f"(DMARC p={m.get('dmarc_policy')}, "
                          f"SPF {m.get('spf_policy')}). Move DMARC to "
                          f"quarantine/reject and SPF to -all."))
    for url, w in state["web_hosts"].items():
        na = w.get("tls", {}).get("not_after")
        if na:
            try:
                exp = dt.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                days = (exp.replace(tzinfo=UTC) -
                        dt.datetime.now(UTC)).days
                if days < 0:
                    risks.append(("HIGH",
                                  f"TLS certificate EXPIRED for {url} "
                                  f"({na})."))
                elif days <= 21:
                    risks.append(("MEDIUM",
                                  f"TLS certificate for {url} expires in "
                                  f"{days} days ({na})."))
            except Exception:
                pass
    for a in state["auth_surfaces"]:
        sev = a.get("severity", "INFO")
        cat = a.get("category", "login")
        if cat == "remote-access":
            msg = (f"Remote-access / VPN portal exposed: {a['url']} "
                   f"({a['type']}). External login portals are high-value "
                   f"targets — require MFA, restrict source IPs where feasible, "
                   f"patch the appliance aggressively, and monitor for "
                   f"password spraying.")
        elif cat == "admin":
            msg = (f"Admin login exposed: {a['url']} ({a['type']}). Restrict "
                   f"to trusted networks/VPN, require MFA, and monitor for "
                   f"brute force.")
        else:
            msg = (f"Authentication surface exposed: {a['url']} ({a['type']}). "
                   f"Confirm it is intended to be public and protected "
                   f"(MFA, lockout, monitoring).")
        risks.append((sev, msg))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return sorted(risks, key=lambda r: order.get(r[0], 9))


def render_report(state, diff):
    s = state["scan"]
    lines = []
    L = lines.append
    L(f"# Attack-Surface Monitoring Report")
    L("")
    L(f"**Targets:** {', '.join(s['scope']['apex_domains'])}  ")
    L(f"**Scan ID:** {s['scan_id']}  ")
    L(f"**Started:** {s['started_at']}  ")
    L(f"**Completed:** {s['completed_at']}  ")
    L(f"**Regime:** {s['scope']['regime']} "
      f"(excluded: {', '.join(s['scope']['excluded'])})")
    L("")

    # --- Executive summary ---
    risks = extract_risks(state)
    highs = sum(1 for r in risks if r[0] == "HIGH")
    meds = sum(1 for r in risks if r[0] == "MEDIUM")
    L("## Executive summary")
    L("")
    L(f"- Domains monitored: {len(state['domains'])}")
    L(f"- Subdomains known: {len(state['subdomains'])} "
      f"({sum(1 for e in state['subdomains'].values() if e['resolves'])} "
      f"resolving)")
    L(f"- Live web hosts: {len(state['web_hosts'])}")
    L(f"- Authentication surfaces: {len(state['auth_surfaces'])}")
    L(f"- Distinct IPs: {len(state['network']['ip_addresses'])}; "
      f"ASNs: {len(state['network']['asns'])}")
    L(f"- **Risk findings: {highs} high, {meds} medium**")
    L("")

    # --- Changes since last run ---
    L("## Changes since last run")
    L("")
    if diff is None:
        L("_No prior scan found — this is the baseline run._")
    else:
        any_change = False
        for section, label in (("subdomains", "Subdomains"),
                               ("web_hosts", "Web hosts"),
                               ("domains", "Domains")):
            added = diff[section]["added"]
            removed = diff[section]["removed"]
            if added:
                any_change = True
                L(f"**{label} added:**")
                for x in added:
                    L(f"- 🟢 {x}")
                L("")
            if removed:
                any_change = True
                L(f"**{label} removed:**")
                for x in removed:
                    L(f"- 🔴 {x}")
                L("")
        if diff["changed"]:
            any_change = True
            L("**Posture changes:**")
            for c in diff["changed"]:
                L(f"- ⚠️ {c}")
            L("")
        if not any_change:
            L("_No changes detected since the previous scan._")
    L("")

    # --- Risk callouts ---
    L("## Risk callouts")
    L("")
    if not risks:
        L("_No risks flagged by the current ruleset._")
    else:
        for sev, msg in risks:
            badge = {"HIGH": "🔴 HIGH", "MEDIUM": "🟠 MEDIUM",
                     "LOW": "🟡 LOW", "INFO": "🔵 INFO"}[sev]
            L(f"- **{badge}** — {msg}")
    L("")

    # --- Inventory ---
    L("## Attack-surface inventory")
    L("")
    L("### Domains")
    L("")
    L("| Domain | Registrar | Expires | Nameservers |")
    L("|---|---|---|---|")
    for d, v in sorted(state["domains"].items()):
        L(f"| {d} | {v.get('registrar') or '—'} | "
          f"{v.get('expires') or '—'} | "
          f"{', '.join(v.get('nameservers', [])) or '—'} |")
    L("")

    L("### Mail posture")
    L("")
    L("| Domain | MX provider | SPF | DMARC | Spoofable |")
    L("|---|---|---|---|---|")
    for d, m in sorted(state["mail"].items()):
        L(f"| {d} | {m.get('mx_provider') or '—'} | "
          f"{m.get('spf_policy') or '—'} | "
          f"{m.get('dmarc_policy') or '—'} | "
          f"{'YES' if m.get('spoofable') else 'no'} |")
    L("")

    L("### Zone-transfer (AXFR) audit")
    L("")
    L("| Domain | Nameserver | AXFR allowed | Records |")
    L("|---|---|---|---|")
    for d, block in sorted(state["zone_transfer"].items()):
        for ns, r in sorted(block.get("results", {}).items()):
            allowed = r.get("axfr_allowed")
            mark = "🔴 YES" if allowed else ("no" if allowed is False
                                            else "n/a")
            L(f"| {d} | {ns} | {mark} | {r.get('records_returned', 0)} |")
    L("")

    L("### Live web hosts")
    L("")
    L("| Host | Status | Server | Tech | TLS issuer | Cert expires |")
    L("|---|---|---|---|---|---|")
    for url, w in sorted(state["web_hosts"].items()):
        L(f"| {url} | {w.get('status')} | "
          f"{w.get('server_header') or '—'} | "
          f"{', '.join(w.get('technologies', [])) or '—'} | "
          f"{w.get('tls', {}).get('issuer') or '—'} | "
          f"{w.get('tls', {}).get('not_after') or '—'} |")
    L("")

    if state["auth_surfaces"]:
        L("### Authentication surfaces")
        L("")
        L("| URL | Type | Category | Sev | Detected via |")
        L("|---|---|---|---|---|")
        for a in sorted(state["auth_surfaces"],
                        key=lambda x: (x.get("severity") != "MEDIUM",
                                       x["url"] or "")):
            L(f"| {a['url']} | {a['type']} | {a.get('category', '—')} | "
              f"{a.get('severity', '—')} | "
              f"{', '.join(a.get('detected_via', [])) or '—'} |")
        L("")

    L("### Network (IP / ASN / CIDR)")
    L("")
    L("| IP | PTR | ASN | AS name | CIDR | RIR |")
    L("|---|---|---|---|---|---|")
    for ip, r in sorted(state["network"]["ip_addresses"].items()):
        L(f"| {ip} | {r.get('ptr') or '—'} | {r.get('asn') or '—'} | "
          f"{r.get('as_name') or '—'} | {r.get('cidr') or '—'} | "
          f"{r.get('rir') or '—'} |")
    L("")

    # --- Subdomain appendix ---
    L("## Appendix: all known subdomains")
    L("")
    L("| Subdomain | Resolves | Discovered via | First seen | A records |")
    L("|---|---|---|---|---|")
    for fqdn, e in sorted(state["subdomains"].items()):
        L(f"| {fqdn} | {'yes' if e['resolves'] else 'no'} | "
          f"{', '.join(e['discovered_via'])} | "
          f"{e.get('first_seen', '—')} | "
          f"{', '.join(e['dns']['a']) or '—'} |")
    L("")

    # --- Source status ---
    L("## Appendix: source status")
    L("")
    L("How each data source responded this run (errors mean that slice may "
      "be incomplete):")
    L("")
    for src, st in sorted(s["source_status"].items()):
        L(f"- `{src}`: {st}")
    L("")
    if not state["scan"]["tooling"]["dns_available"]:
        L("> ⚠️ The bundled DNS module (`dnsmini`) could not be imported, so "
          "DNS records, AXFR audit, and ASN enrichment were skipped. Ensure "
          "`dnsmini.py` sits alongside `recon.py` in `scripts/`.")
        L("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Attack-surface monitoring collector "
                    "(passive + no-impact active).")
    ap.add_argument("domains", nargs="+",
                    help="Apex domain(s) you own and are authorized to "
                         "monitor, e.g. example.com example.io")
    ap.add_argument("-o", "--outdir", default="asm-output",
                    help="Directory for dated JSON + REPORT.md "
                         "(default: asm-output)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Scanning {', '.join(args.domains)} ...", file=sys.stderr)
    state = run_scan(args.domains)

    today = dt.datetime.now(UTC).strftime("%Y-%m-%d")
    json_path = outdir / f"{today}.json"

    prior_path = find_prior_json(outdir, exclude=json_path)
    prior = None
    if prior_path:
        try:
            prior = json.loads(prior_path.read_text())
            print(f"[*] Diffing against {prior_path.name}", file=sys.stderr)
        except Exception:
            prior = None

    carry_forward_seen(state, prior, today)
    diff = diff_states(prior, state) if prior else None

    json_path.write_text(json.dumps(state, indent=2, sort_keys=False))
    report = render_report(state, diff)
    (outdir / "REPORT.md").write_text(report)

    print(f"[+] Wrote {json_path}", file=sys.stderr)
    print(f"[+] Wrote {outdir / 'REPORT.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
