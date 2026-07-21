# Security Case Studies

Hands-on security analysis and remediation work — each write-up walks a real finding from discovery through a verified fix, with the analytic method made explicit. Sensitive identifiers (project references, user IDs, tokens) are redacted throughout.

## Index

| # | Case Study | Vulnerability Class | Stack | Outcome |
|---|---|---|---|---|
| 01 | [Column-Level Privilege Escalation](./case-studies/01-column-level-privilege-escalation.md) | Broken Object Property-Level Authorization (OWASP API3) | Supabase / Postgres / RLS | Free tier-upgrade path closed with a role-scoped trigger; verified both directions |

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

- Findings are worked layer by layer (route → row → column); a pass at one layer is never taken as proof of the next.
- Fixes are sized before they ship — every affected path is inventoried so a change is provably non-breaking rather than hopeful.
- Controls are verified at the source of truth, not the surface that reports success.

---

*See also: foresight/analyst portfolio — strategic analysis and structured-thinking work (link once published).*