# Security Case Studies

Hands-on security analysis and remediation work — each write-up walks a real
finding from discovery through a verified fix, with the analytic method made
explicit.

These are findings from a live, internet-facing platform I architect and operate,
not lab exercises or capture-the-flag writeups. Sensitive identifiers (project
references, user IDs, customer IDs, hostnames, tokens) are redacted throughout.

## Index

| # | Case Study | Vulnerability Class | Stack | Outcome |
|---|---|---|---|---|
| 01 | [Column-Level Privilege Escalation](./case-studies/01-column-level-privilege-escalation.md) | Broken Object Property-Level Authorization (OWASP API3:2023) | Supabase / Postgres / RLS | Free tier-upgrade path closed with a role-scoped trigger; verified both directions |
| 02 | [An MFA Gate That Never Ran](./case-studies/02-mfa-gate-fail-open.md) | Identification & Authentication Failures (OWASP Web A07:2021) | Deno / Edge Functions / JWT | Two independent fail-open defects closed; MFA enforcement restored and proven in both directions |

*Further case studies in progress. An OWASP LLM Top 10 coverage assessment of the
platform's AI integration paths will be published once its open items are
remediated.*

## How these are structured

Every case study follows the same skeleton so the reasoning is easy to audit:

1. **Context** — the architecture that made the issue possible
2. **The vulnerability** — named precisely (OWASP class where applicable) and the exact gap
3. **Discovery & analytic method** — how it was found and why one passing check never implied the next
4. **Root cause**
5. **The fix** — with the design decisions defended
6. **Verification** — proven from both directions (threat path fails and legitimate path still works)
7. **Impact** — technical and business
8. **Generalizable takeaways**

## Method notes

- Findings are worked layer by layer (route -> row -> column); a pass at one layer
  is never taken as proof of the next.
- Fixes are sized before they ship — every affected path is inventoried so a
  change is provably non-breaking rather than hopeful.
- Controls are verified at the source of truth, not the surface that reports
  success.
- **Two proofs are required to call something fixed:** declared state (a query or
  config confirms the change) and runtime behavior (the system still works). A
  clean linter is declared state only.
- **Blast radius and rollback are written before a change is applied**, not after.
- **Positive evidence outranks the absence of negative evidence.** An empty error
  log proves execution never reached the logging statement — in one finding here,
  that silence was the symptom rather than the all-clear.
- **Incomplete evidence is recorded as incomplete.** Where a runtime proof had no
  safe path against production, the write-up says so rather than claiming a close
  the evidence does not support.

## Scope and disclosure

Every system described here is infrastructure I own and operate. No third-party
systems were tested at any point.

Published findings are remediated and verified. Open findings are not published.

## About

Cybersecurity analyst — endpoint security and malware analysis at a Zero Trust
security vendor, full-lifecycle incident response practice across the NIST 800-61
framework, and ongoing application security work on the platform documented here.
CompTIA Security+, CySA+, CSAP.

Jayson Sam Fong · Orlando, FL
[LinkedIn](https://www.linkedin.com/in/jayson-sam-fong) · jaysamfong@gmail.com

---

*See also: foresight/analyst portfolio — strategic analysis and structured-thinking
work (link once published).*
