# ByteRay Advisory Authoring Standard

This document is the source of truth for advisories published on
`pop.byteray.co.uk`. It covers identifier allocation, public embargo notices,
full disclosures, proof-of-possession commitments, and the checks required
before publication.

## 1. Non-negotiable rules

1. Every advisory has one permanent identifier: `BYTERAY-YYYY-NNNN`.
2. `YYYY` is the year the identifier is assigned. `NNNN` is a zero-padded,
   four-digit sequence that restarts at `0001` each year.
3. Never reuse an identifier, including one assigned to a withdrawn report.
4. For a new advisory, the identifier, filename, and `Slug` must match exactly.
   They never change when an embargo notice becomes a full disclosure.
5. Existing `adv-NNN` files retain their filename, slug, and URL. Their
   `Advisory:` field is their public ByteRay identifier.
6. `Embargo: true` means “publish a deliberately limited notice.” It does not
   make a file private. The repository, Git history, generated HTML, Markdown
   comments, and attachments must all be treated as public.
7. Never commit the private report, exploit, proof of concept, commitment
   nonce, confidential vendor correspondence, or unapproved technical detail
   before disclosure.
8. Do not invent missing facts. Omit optional fields or use the exact fixed
   token `[WITHHELD UNTIL DISCLOSURE]` where this standard permits it.

## 2. Allocating an identifier

Before assigning an identifier, update local `main` and inspect the existing
advisories:

```bash
git pull --ff-only origin main
uv run python scripts/validate_advisories.py --next-id
```

Use the reported next identifier. If two authors need identifiers
concurrently, coordinate ownership before either advisory is published.

For example:

```text
Advisory: BYTERAY-2026-0211
Filename: content/advisories/BYTERAY-2026-0211.md
Slug: BYTERAY-2026-0211
URL: /advisory/BYTERAY-2026-0211.html
```

Legacy mapping preserves the numeric relationship and all old links:

```text
adv-021.md / Slug: adv-021 / Advisory: BYTERAY-2026-0021
adv-210.md / Slug: adv-210 / Advisory: BYTERAY-2026-0210
```

Gaps are intentional and must not be filled merely to make the sequence
continuous.

## 3. Metadata semantics

| Field | Meaning |
| --- | --- |
| `Title` | Public title. Use the formulas below. |
| `Date` | Current public release date. On full disclosure, change this to the disclosure date so the advisory resurfaces. |
| `Modified` | Date of a later material correction; omit for the first release. |
| `Slug` | Permanent URL key. Never change it after first publication. |
| `Advisory` | Permanent `BYTERAY-YYYY-NNNN` identifier. |
| `Format` | Authoring-standard version. New advisories use `1`. |
| `Severity` | `Critical`, `High`, `Medium`, `Low`, or `Info`; full disclosure only. |
| `State` | `Reported` during embargo; `Disclosed`, `Patched`, or `Won't Fix` after disclosure. |
| `Embargo` | Set to `true` only for a public embargo notice. Remove it at disclosure. |
| `Vendor`, `Product` | Publicly approved names, or the fixed withholding token. |
| `Reported` | Date first reported to the vendor, or the fixed withholding token during embargo. |
| `Disclosure` | Planned date during embargo; actual date after disclosure; the fixed withholding token is allowed. |
| `Affected`, `Fixed` | Precise affected and fixed versions; full disclosure only. |
| `CVE`, `CWE`, `CVSS` | Assigned identifiers and score/vector; full disclosure only. |
| `Credit` | Researcher attribution agreed for public disclosure. |
| `Tags` | Search terms; full disclosure only because they can reveal technical details. |
| `Commitment` | Optional `sha256:` proof-of-possession commitment. |
| `Summary` | Fixed embargo notice or a concise full-disclosure abstract. |

`Status: draft` is Pelican’s private build-state marker. It keeps an article
out of the published site. It is not interchangeable with `State:` or
`Embargo:` and must not be used for a public embargo notice.

## 4. Titles

### Embargo title

Use a fixed title that does not reveal word lengths, vulnerability type,
component, protocol, attack vector, exploitability, or impact:

```text
Vendor Product — Security Issue Under Coordinated Disclosure
```

If either name is not approved for publication:

```text
[WITHHELD UNTIL DISCLOSURE] — Security Issue Under Coordinated Disclosure
```

Do not use `████`, repeated `X` characters, asterisks, partial names, or one
placeholder character per hidden character. Those forms leak word lengths.

### Full-disclosure title

Use:

```text
Product — Vulnerability Class in Component
```

Keep it short and factual. Add the attacker or impact only when it materially
distinguishes the issue. Put versions, CVE, detailed preconditions, and the
technical mechanism in metadata or the body, not in the title.

## 5. Public embargo template

Copy this template for a new public embargo notice. Only replace placeholders
with facts explicitly approved for publication.

```markdown
Title: Vendor Product — Security Issue Under Coordinated Disclosure
Date: YYYY-MM-DD
Slug: BYTERAY-YYYY-NNNN
Advisory: BYTERAY-YYYY-NNNN
Format: 1
State: Reported
Embargo: true
Vendor: Vendor name or [WITHHELD UNTIL DISCLOSURE]
Product: Product name or [WITHHELD UNTIL DISCLOSURE]
Reported: YYYY-MM-DD or [WITHHELD UNTIL DISCLOSURE]
Disclosure: Planned YYYY-MM-DD or [WITHHELD UNTIL DISCLOSURE]
Commitment: sha256:64-lowercase-hex-characters
Summary: Technical details are withheld during coordinated disclosure.

## Disclosure Notice

Technical details are withheld during coordinated disclosure. This page will
be updated in place when disclosure is permitted.

## Proof of Possession

The commitment above records ByteRay's possession of the private report
without publishing the report or material that assists vulnerability discovery.
```

`Commitment:` is optional. If it is omitted, remove the Proof of Possession
section too. No other headings, code blocks, links, filenames, CVE/CWE/CVSS
data, severity, tags, affected versions, or technical prose are allowed in a
public embargo file.

## 6. Proof-of-possession commitments

For new work, use a salted commitment so a predictable report cannot be tested
against the public hash:

1. Finalize the exact private report bytes.
2. Generate a cryptographically random 32-byte nonce and store it privately.
3. Compute `SHA-256(nonce_bytes || report_bytes)`.
4. Publish only `sha256:<digest>` in `Commitment:`.
5. At full disclosure, publish the exact report and nonce if independent
   verification is desired.

Example commands:

```bash
openssl rand -hex 32 > report.nonce
python -c 'import hashlib, pathlib; n=bytes.fromhex(pathlib.Path("report.nonce").read_text().strip()); r=pathlib.Path("report.md").read_bytes(); print("sha256:" + hashlib.sha256(n+r).hexdigest())'
```

Keep `report.nonce` and `report.md` outside this public repository until
disclosure. A commitment proves possession only if the exact bytes and nonce
can later reproduce it.

## 7. Full-disclosure template

Promote the existing embargo file in place. Keep `Slug`, `Advisory`, and the
filename unchanged. Remove `Embargo: true`, replace the title and summary,
publish only verified facts, and use this structure:

```markdown
Title: Product — Vulnerability Class in Component
Date: YYYY-MM-DD
Slug: BYTERAY-YYYY-NNNN
Advisory: BYTERAY-YYYY-NNNN
Format: 1
Severity: High
State: Disclosed
Vendor: Vendor name
Product: Product name
Reported: YYYY-MM-DD
Disclosure: YYYY-MM-DD
Affected: Exact affected versions
Fixed: Exact fixed version or commit
CVE: CVE-YYYY-NNNN
CWE: CWE-NNN
CVSS: 0.0 (CVSS:3.1/...)
Credit: Researcher or team
Tags: short, relevant, comma-separated tags
Commitment: sha256:64-lowercase-hex-characters
Summary: One or two factual sentences describing the flaw and its impact.

## Executive Summary

Explain the issue and practical consequence in plain language.

## Affected Products and Versions

List exact products, components, configurations, and version boundaries.

## Technical Details

Describe the root cause and vulnerable data/control flow. Include only the
code, requests, or protocol details needed to understand and verify the issue.

## Reachability and Preconditions

State attacker position, authentication, privileges, user interaction,
configuration, and other prerequisites.

## Impact

Describe what exploitation gives the attacker. Separate confirmed impact from
reasonable but unverified consequences.

## Remediation and Mitigation

Link the fix and identify the first fixed version. Put mitigations after the
preferred remediation and state their limitations.

## Timeline

- YYYY-MM-DD — Reported to vendor
- YYYY-MM-DD — Vendor acknowledged
- YYYY-MM-DD — Fix released
- YYYY-MM-DD — Public disclosure

## Credits

Credit the finder, collaborators, coordinator, and vendor responders as agreed.

## References

- [Vendor advisory](https://example.com/)
- [Fix](https://example.com/)
```

Optional sections may follow References:

- `## Detection and Indicators`
- `## Proof of Concept`
- `## Proof of Possession Verification`

Omit unavailable optional metadata instead of writing `TBD`. Never guess CVSS,
affected ranges, fix status, CVE assignment, vendor position, or dates.

## 8. One-prompt workflows

### Create a public embargo advisory

Use this prompt with the private report available to the authoring agent. The
resulting public file must contain none of the private technical content.

```text
Create a public ByteRay embargo advisory from the supplied private report.

Repository rules:
- Read ADVISORY_AUTHORING.md and follow its public embargo template exactly.
- Determine the next available BYTERAY-YYYY-NNNN with
  `uv run python scripts/validate_advisories.py --next-id`.
- Use that identifier unchanged for Advisory, Slug, and filename.
- Publish only approved vendor/product names, report date, planned disclosure
  date, the fixed disclosure notice, and the supplied commitment.
- If approval is absent, use the exact token
  [WITHHELD UNTIL DISCLOSURE].
- Do not reveal severity, CVE/CWE/CVSS, vulnerability class, component,
  protocol, vector, impact, versions, tags, code, filenames, links, report
  length, PoC details, or word-length-preserving redactions.
- Do not put private facts in comments, attachments, Git history, or generated
  files.
- Run the advisory validator and Pelican production build.
- Do not commit or push.
```

### Promote the same advisory to full disclosure

```text
Promote the specified ByteRay embargo advisory to full disclosure using the
supplied final report and verified vendor information.

Repository rules:
- Read ADVISORY_AUTHORING.md and use its full-disclosure template.
- Edit the existing advisory file in place.
- Do not change its Advisory value, Slug, or filename.
- Remove Embargo: true; set State: Disclosed; set Date and Disclosure to the
  actual public disclosure date.
- Replace the generic title and summary with precise, concise text.
- Populate only verified metadata; omit unavailable optional fields.
- Replace the embargo body with the canonical full-disclosure chapters.
- Retain Commitment and add verification material only if the exact report and
  nonce are being published.
- Run the advisory validator and Pelican production build.
- Verify the output path is identical to the embargo page path.
- Do not commit or push.
```

## 9. Pre-publication checklist

### Every advisory

- Identifier is unique and matches `BYTERAY-YYYY-NNNN`.
- Year matches the identifier-assignment year.
- Filename and slug rules pass validation.
- Dates, version ranges, CVE/CWE/CVSS, links, and credits are verified.
- No unrelated or private files are staged.
- `uv run python scripts/validate_advisories.py` passes.
- `uv run pelican content --settings publishconf.py` passes.

### Embargo notice

- Vendor/product publication is approved or replaced by the fixed token.
- Title and summary use the fixed embargo wording.
- No severity or technical metadata is present.
- No hidden details appear in comments, filenames, tags, links, or attachments.
- Commitment contains only `sha256:` plus 64 lowercase hexadecimal characters.
- Private report and nonce are stored outside the public repository.

### Full disclosure

- Filename, `Slug`, and `Advisory` are unchanged from the embargo notice.
- `Embargo:` is removed and `State:` reflects the public outcome.
- Affected/fixed boundaries and remediation are actionable.
- Preconditions and confirmed impact are distinguished from speculation.
- Timeline and credits reflect the coordinated record.

## 10. Research basis

- [CERT/CC Basic Vulnerability Advisory](https://certcc.github.io/CERT-Guide-to-CVD/reference/simple_advisory/)
- [CERT/CC Vulnerability Note guidance](https://certcc.github.io/VINCE-docs/Vulnerability-Note-Help/)
- [FIRST PSIRT Services Framework](https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1)
- [OASIS Common Security Advisory Framework 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [Google Project Zero reporting transparency](https://projectzero.google/2025/07/reporting-transparency.html)
- [CVE key-details phrasing](https://cveproject.github.io/docs/content/key-details-phrasing.pdf)

