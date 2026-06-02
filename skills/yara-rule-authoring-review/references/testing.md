# Testing & False-Positive Debugging

A rule untested against clean files is a draft, not a detection. Read this when
validating a rule or chasing down a false positive.

## Contents

- [The Validation Workflow](#the-validation-workflow)
- [Goodware Corpus](#goodware-corpus)
- [FP Investigation Flow](#fp-investigation-flow)
- [Match-Count Thresholds](#match-count-thresholds)
- [When to Abandon an Approach](#when-to-abandon-an-approach)

## The Validation Workflow

1. **Syntax** — `yr check rule.yar`. Fix every error (YARA-X points to the
   exact line).
2. **Format** — `yr fmt -w rule.yar` for consistent style.
3. **True positives** — confirm the rule matches every intended sample:
   `yr scan -s rule.yar samples/`. The `-s` flag prints which strings matched,
   so you can verify it's matching for the *right* reasons, not by accident.
4. **Goodware** — scan a clean corpus and require **zero** matches. This is the
   step that separates a deployable rule from a liability.
5. **Embedded-artifact sanity** — if you can, scan a pagefile/dump/disk-image
   sample to confirm the header+filesize guard is doing its job and the rule
   does not fire on the container.
6. **Deploy with full metadata** and monitor for FPs in production.

If you cannot run a corpus yourself, say so explicitly and tell the user that
goodware validation is the outstanding pre-deployment step — don't imply the
rule is production-ready without it.

## Goodware Corpus

Options, roughly in order of rigor:

- **YARA-CI / VirusTotal goodware corpus** — the gold standard for pre-deploy
  testing at scale.
- **A local clean-file set** — OS system directories, common application
  installs, known-good builds of the same file type.
- **Vendor builds you keep colliding with** — when one legitimate product
  triggers your rule, add a sample of it to your test set and (if needed) a
  `$fp*` marker for its signer/copyright string.

10 malware samples is not a corpus. "It works on my samples" is the rationalization
that ships FP-prone rules.

## FP Investigation Flow

```
A goodware file matched — why?
│
├─ 1. Which string matched?
│      yr scan -s rule.yar false_positive_file
│
├─ 2. Is the string from a legitimate library/vendor?
│      → Add a $fp* marker for the vendor and `not any of ($fp*)`.
│
├─ 3. Is it a common development pattern?
│      → Replace it with a more specific, malware-only indicator.
│
├─ 4. Are several generic strings matching together?
│      → Tighten: switch any → all, add a unique $x marker.
│
├─ 5. Is the malware using a common *technique*?
│      → Target the malware's specific implementation bytes, not the technique.
│
└─ 6. Is it firing inside a huge blob (pagefile/dump/image)?
       → Your header+filesize guard is missing or too loose. Add/lower it. (House Rule 2)
```

## Match-Count Thresholds

When a rule hits the goodware corpus, the count tells you how far off it is:

- **1–2 matches** — investigate the specific files and tighten (add a marker,
  swap a string, add an `$fp*`).
- **3–5 matches** — the indicators aren't unique enough; find different ones.
- **6+ matches** — start over. The approach is wrong, not the tuning.

## When to Abandon an Approach

Stop and pivot when:

- Extraction yields only API names and generic paths → pivot to structure
  (section-name bytes, distinctive metadata) or recover stack strings with
  FLOSS. See `strings.md`.
- You can't find ~3 unique strings → the sample is probably packed; target the
  unpacked payload or the packer, not the packed bytes.
- The rule matches goodware even after tightening → the indicators are
  fundamentally too generic.
- You can't write a crisp `description` → the rule is too vague; if you can't
  say what it catches, it catches too much.
- The only viable signal is imphash or entropy → those need modules this skill
  forbids (House Rule 3); tell the user this sample isn't a fit for an
  import-free rule rather than reaching for `pe`/`math`.
