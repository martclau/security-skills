---
name: asm-recon
description: >
  Perform attack-surface reconnaissance and monitoring of an organization's
  OWN domains — enumerating subdomains, DNS records, mail posture (SPF/DKIM/
  DMARC), IP ranges/ASNs/CIDRs, TLS certificates, live web hosts, exposed
  login/SSO/VPN/webmail surfaces, and zone-transfer (AXFR) misconfigurations —
  and emit a dated structured JSON snapshot plus a human-readable REPORT.md
  that leads with a diff against the previous run. Use this skill whenever the
  user wants to map, inventory, audit, or MONITOR the external attack surface
  of a company or domain they control: phrases like "recon on our domain",
  "what's our external footprint", "attack-surface monitoring", "find our
  subdomains", "audit our DNS / mail / certs", "check for subdomain takeover",
  "are our nameservers leaking the zone", "external asset inventory", or "track
  what changed in our surface since last week". This is a DEFENSIVE,
  owned-assets monitoring tool — it is NOT for pentesting third parties and it
  never performs port scanning, login brute-force, directory brute-force,
  vulnerability probing, or any impactful active technique.
allowed-tools: Bash(python *), Bash(python3 *)
---

# Attack-Surface Monitoring (asm-recon)

This skill maps and continuously monitors the **external attack surface of
domains the user owns**. It runs a fixed collection pipeline and produces two
artifacts designed to work together over time:

1. **`<YYYY-MM-DD>.json`** — a structured, deterministically-ordered snapshot
   of every discovered entity (domains, subdomains, DNS records, IPs, ASNs,
   CIDRs, web hosts, TLS certs, mail posture, auth surfaces, zone-transfer
   results). This is the longitudinal record. Keeping one file per run lets the
   user diff snapshots and track how the surface changes.
2. **`REPORT.md`** — a human-readable report regenerated each run that **leads
   with the diff** against the most recent prior JSON (what was added, removed,
   or changed), followed by risk callouts and the full current inventory.

The point of the dual output is monitoring, not a one-shot scan: each run loads
the previous JSON, carries forward `first_seen` dates, and surfaces deltas.

## Scope and boundaries — read before running

This tool is **defensive and owned-assets-only**. It operates in two
collection tiers, and never beyond them:

- **Passive** — querying third-party datasets (certificate transparency,
  RDAP/WHOIS, Team Cymru ASN data). No packets to the target.
- **No-impact active** — single, client-like interactions with the target that
  are indistinguishable from ordinary traffic and cannot degrade a service:
  resolving DNS for owned hosts, one HTTP(S) GET per host, one TLS handshake
  per host, reading `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`,
  and one favicon, plus reverse-DNS lookups.

**Never performed (hard exclusions):**
- Port scanning of any kind.
- Login / authentication attempts, credential stuffing, password spraying.
- Directory or DNS-subdomain **brute-forcing** against the target. Subdomains
  come only from passive sources (certificate transparency) and are then
  resolved — never guessed against the target's DNS.
- Vulnerability probing, exploit checks, fuzzing.

**Zone transfer (AXFR) is deliberately attempted** against each of the
domain's own authoritative nameservers. This is a configuration audit, not an
attack: a correctly-configured server refuses the transfer, and a **successful
transfer is a high-severity misconfiguration finding** (the entire DNS zone is
publicly downloadable). The script first does a fast TCP/53 reachability check
so a filtered port fails quickly instead of hanging.

**Secrets are never stored in plaintext.** If a credential-exposure source is
configured, only a redacted fingerprint (a short hash prefix + length) is
written, so the JSON snapshot is safe to retain and compare over time.

Because this is an owned-assets monitoring tool, no per-run authorization
prompt is required — but if the user asks to point it at a domain they do not
control, decline and explain that this skill is for assets the user is
authorized to monitor.

## Workflow

### 1. Confirm the target domains
Identify the apex domain(s) to monitor (e.g. `example.com`, `example.io`).
These should be domains the user's organization owns. If the user names a
company but not its domains, ask for the apex domain(s) rather than guessing.

### 2. No dependencies to install
The collector is pure Python standard library — there are no pip packages to
install. DNS records, the AXFR audit, and ASN enrichment use a small bundled
resolver (`scripts/dnsmini.py`) that must sit alongside `recon.py`. If that
file is missing the script still runs but skips those slices and says so in the
report's source-status section.

Subdomain discovery queries two certificate-transparency sources (crt.sh and
SSLMate CertSpotter) and unions the results, so one source being down never
zeroes out enumeration. Both work unauthenticated; CertSpotter's free endpoint
is rate-limited and returns only its newest page of issuances. For fuller,
unthrottled CT coverage, export a CertSpotter API token:
```bash
export CERTSPOTTER_TOKEN=...   # optional
```

### 3. Run the collector
```bash
python scripts/recon.py <apex-domain> [more-domains ...] -o <output-dir>
```
For ongoing monitoring, **always point `-o` at the same directory** across
runs, so the new snapshot can be diffed against the prior one. Example:
```bash
python scripts/recon.py example.com example.io -o ./asm-output
```
The script writes `<output-dir>/<today>.json` and overwrites
`<output-dir>/REPORT.md`. It is safe to re-run; it never deletes prior
snapshots.

### 4. Present the results
Surface `REPORT.md` first (it is the human-readable view), then the dated
JSON — give the user their paths, or in claude.ai contexts present them with
the `present_files` tool. Give a brief summary highlighting:
- Any **HIGH** findings (AXFR permitted, dangling CNAMEs / takeover candidates,
  expired certs).
- The **changes since last run**, if this was not the baseline run.
- Total counts (domains, subdomains, live hosts, auth surfaces).

Do not paste the entire report back into chat — summarize and let the user open
the file.

## Interpreting the output

The JSON is organized into stable, diffable sections. Key risk signals the
report derives automatically:

- **`zone_transfer[domain].finding`** present → AXFR is permitted on at least
  one nameserver. HIGH. The per-nameserver `results` table shows exactly which
  server is misconfigured (often one stale secondary among several correct
  ones).
- **`subdomains[fqdn].dns.dangling_cname` = true** → the host has a CNAME
  pointing at a target that no longer resolves. Subdomain-takeover candidate.
  HIGH.
- **`mail[domain].spoofable` = true** → DMARC is absent/`p=none` and SPF is not
  hard-fail (`-all`). The domain can be spoofed in email. MEDIUM.
- **TLS `not_after`** within 21 days → cert expiring; already past → expired.
- **`auth_surfaces`** → exposed login/SSO/VPN/webmail/admin endpoints, detected
  from the login URL/redirect path, a credential form in the body, an HTTP
  `401`/`WWW-Authenticate` challenge, or a vendor fingerprint. Each carries a
  `category` (`remote-access` / `admin` / `sso-idp` / `http-auth` / `login`),
  the `detected_via` evidence, and a `severity`: **remote-access (VPN) and
  admin portals are MEDIUM**, everything else INFO. Confirm each is meant to be
  public and is protected (MFA, lockout, monitoring).

Every leaf carries `source`, `collected_at`, and `method`
(`passive` / `active-noimpact`) so the provenance of each finding — and whether
it touched the target — is auditable. The `scan.source_status` block records
which data sources responded; an `error` there means that slice may be
incomplete (e.g. a rate-limited API), not that the surface is clean.

## Extending coverage (optional, API-keyed sources)

The default run uses only free/public sources, which fully cover the DNS,
network, mail, AXFR, TLS, and web-host layers. Richer **subdomain** discovery
and **credential/exposure** data require API keys (e.g. passive-DNS providers,
breach-data services). These are intentionally left as stubs in the
`exposure` section. If the user has such keys and wants them wired in, add the
corresponding collector following the existing pattern in `scripts/recon.py`:
each collector takes the domain and a `source_status` dict, returns its data,
and must never raise past its own boundary (wrap everything so one failing
source never aborts the run). Continue to store any secret material as a
redacted fingerprint only.
