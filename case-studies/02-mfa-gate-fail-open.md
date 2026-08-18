# Case Study: An MFA Gate That Never Ran

> **One line:** A multi-factor authentication requirement protecting the highest-privilege feature on the platform contained two independent defects — it failed open on any upstream error, and it read assurance level from an endpoint that does not carry it — so the check never executed in either direction. I closed it by reading the assurance claim from the already-verified session token and failing closed, then proved enforcement in both directions: unverified sessions denied, verified sessions still granted.

*Identifiers (project reference, hostnames, user emails, tokens) have been redacted or genericized. Generic implementation names are kept because they carry no sensitive value and aid readability.*

---

## 1. Context: why the architecture matters

The protected resource is a live cyber range — an isolated environment issued to users on a paid tier, and the highest-privilege feature on the platform. Access is granted by a short-lived token minted by a serverless edge function.

That function runs a sequence of gates before signing anything: validate the caller's session against the auth provider, confirm the account tier server-side from the database, enforce a rate limit, and confirm that multi-factor authentication was completed **for the current session**.

Two properties of this architecture matter for what follows.

**The function is the sole gate.** There is no second checkpoint downstream. If a check inside it does not fire, nothing else catches the request.

**Edge functions deploy separately from source control.** They are published by an explicit deploy command, not by a git push. The repository shows intent; the running function shows reality, and nothing structurally enforces that the two agree.

---

## 2. The vulnerability

**Class:** Identification and Authentication Failures (OWASP A07:2021).
**Related weaknesses:** CWE-703 (Improper Check for Exceptional Conditions), CWE-287 (Improper Authentication).

Two independent defects, either of which alone was sufficient to disable the control completely.

### Defect one — the check failed open

The entire assurance-level check sat inside a conditional on the success of an upstream HTTP request, with no `else` branch:

```javascript
if (aalRes.ok) {
  // ... assurance level check ...
}
// execution continues here regardless
```

Any non-success response — a 404, a timeout, a transient network fault, a rate limit from the auth provider — skipped the check entirely and fell through to token minting. **A failed check was indistinguishable from a passed check.**

This is the failure mode that matters most in authentication code. A control that denies when it breaks is an availability problem. A control that permits when it breaks is not a control.

### Defect two — the check read the wrong data source

Inside the conditional, the code read an assurance level from the endpoint that returns *enrolled authentication factors*:

```javascript
const currentLevel = aalData?.aal?.currentLevel
if (currentLevel && currentLevel !== 'aal2') { /* deny */ }
```

Assurance level is not a property of the factors endpoint. It is a claim inside the access token issued after a challenge is satisfied. The field did not exist on that response, so `currentLevel` resolved to `undefined`, the leading truthiness guard short-circuited, and the comparison never evaluated — **even on a successful 200 response.**

Two defects, orthogonal causes, identical result. Both had to be understood before the fix could be considered complete; correcting the visible one alone would have left the gate non-functional while appearing resolved.

---

## 3. Discovery and analytic method

The finding came from source review during a scheduled hardening pass, not from a scanner and not from a user report — and there is a reason no report existed.

### Why nothing looked broken

Legitimate users completed MFA during login and reached the range, so the happy path worked. Nobody reported a lockout, because the gate never locked anyone out. And the single `console.warn` intended to signal a denial sat inside the branch that never ran — so an absence of warnings in the logs read as "no denials occurred" when it actually meant "the check never executed."

That inversion is the analytic point. **In a fail-open control, a quiet log is not evidence of health. It is the symptom.** An empty log proves execution never reached the logging statement; it says nothing about whether the condition occurred.

### Confirming the deployed artifact matched the source

Because edge functions deploy independently of git, the local file could not be assumed to be the running code. The local copy was dated roughly ten weeks earlier than two sprints that had touched adjacent code — a plausible drift signature.

I compared deployed against local before editing anything. They were byte-identical. That established two things: patching local source could not silently revert deployed behavior, and the defect had been live for the full period.

Skipping this step would have risked fixing a file that was not running — the same class of error as verifying a control at the surface that reports success rather than at the source of truth.

### Establishing where the trustworthy value lives

The function already decoded the token payload earlier in its sequence, and separately verified that token against the auth provider. That verification is what makes the decoded claims trustworthy — a decode alone proves nothing, since anyone can base64-decode a forged token.

So the assurance level was already present, already verified, and already in scope. The correct data had been inside the function the whole time. The check was reaching past it to an endpoint that did not carry it.

---

## 4. Root cause

The check conflated two different questions: **"does this user have MFA enrolled?"** and **"did this user complete MFA in this session?"** The factors endpoint answers the first. Only the session token answers the second. Querying the wrong authority for the wrong question produced a value that could never be correct.

Underneath that sits a design omission: **the failure direction of the control was never an explicit decision.** "What happens when this check itself breaks?" is a different question from "does this check work?", and only the second had been considered. Wrapping a security check in a success-conditional without an `else` is what that omission looks like in code.

---

## 5. The fix

```javascript
// Confirm MFA was verified for this session — fail closed
const aal = payload.aal
if (aal !== 'aal2') {
  console.warn('AAL2 required, token aal:', aal, 'user:', userEmail)
  return new Response(JSON.stringify({
    error: 'MFA verification required',
    detail: 'Please complete MFA verification before launching the range'
  }), { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })
}
```

### Three design decisions worth defending

**Read from the verified token, not a secondary lookup.** Fewer moving parts and no network call that can fail — which is what created defect one. The value is authoritative because the token was already validated against the provider upstream in the same function.

**Fail closed, with no conditional wrapper.** There is no path through this block that reaches token minting without an explicit `aal2`. An unexpected value, a missing claim, or a malformed payload all deny. The failure direction is now a stated property of the control rather than an accident of its structure.

**Deny with user-actionable copy, not internal error text.** The `detail` line is hand-written guidance telling the user what to do, deliberately distinct from internal error strings, which are logged server-side only.

### What was already correct — and deliberately left alone

A defect in one branch invites over-correction across the file. Inventorying what was working kept the change scoped to four lines:

- The user identifier is taken from the **verified** provider response, never from the unverified token decode. Token forgery does not pass this gate.
- Account tier is read server-side from the database, not trusted from the client.
- Rate limiting, short token expiry, and scoped issuer/audience claims were all present and functioning.

The function was well constructed. One check inside it was not.

---

## 6. Verification — proven from both directions

A denial-only test cannot distinguish a working control from one that locks out every paying customer. Both directions were required before the finding could be closed.

| Session state | Before fix | After fix |
|---|---|---|
| Password only, no MFA (`aal1`) | 200 + token issued | **403 — denied** |
| MFA completed (`aal2`) | 200 + token issued | **200 + token issued** |

The second row is the load-bearing one. Row one alone would be equally consistent with a fix that denies everybody.

**Blast radius, sized before applying:** this function is the sole gate for range access. A bad patch blocks every paying user on the affected tiers — the failure would be total, immediate, and revenue-facing.

**Rollback, prepared before applying:** the platform's function-download command retrieves the deployed pre-patch source. That retrieval was exercised and confirmed working before any edit was made, rather than assumed available.

---

## 7. Impact

- **Authentication:** MFA enforcement on the platform's highest-privilege feature was absent for approximately ten weeks. Every user reaching the range during that period did so on password-only authentication, regardless of whether they had completed a challenge.
- **Exploitability:** no exploit was required. No crafted request, no token manipulation, no timing. Ordinary use of the product bypassed the control, which means exposure was continuous rather than conditional on an attacker being present.
- **Trust and assurance:** MFA was a stated protection on a paid feature. A control that is advertised, believed to be enforced, and silently inert is worse than an absent one, because it suppresses the risk assessment that its absence would have prompted.
- **Detection:** the outage was invisible to logging by construction. The only diagnostic signal lived inside the branch that never executed, so no amount of log review would have surfaced it.

---

## 8. Adjacent findings (noted for follow-up)

- **The same reasoning error exists elsewhere, pointing the opposite way.** A client-side factor check interprets a network failure as "not enrolled," routing a correctly-enrolled user into an enrollment flow that then rejects them as a duplicate. Tracked separately. Both defects come from collapsing three states into two — the missing state in each case is *unknown, retry*.
- **Successful denials and grants are not logged.** The patched control logs only on denial; the surrounding function logs only on failure. During verification this made "the check passed" indistinguishable from "the check never ran" from the server side. A success log recording that an assurance check occurred, and what it returned, would provide an audit trail for the control's operation rather than only for its refusals.
- **Deployment drift has no structural guard.** Confirming deployed-against-local is currently a manual prerequisite performed by discipline. Nothing prevents a future edit from being made against a file that is not the running artifact.

---

## 9. Generalizable takeaways

1. **A control's failure direction is a design decision and should be stated explicitly.** "What happens when this check breaks?" is a separate question from "does this check work?" — and it is the one that goes unasked.
2. **Absence of a signal is not evidence.** An empty warning log proves execution never reached the warning. Positive evidence — an observed denial, an observed grant — is the only thing that closes a finding.
3. **Verify the deployed artifact, not the repository**, in any architecture where publishing is decoupled from source control. The repo records intent; only the running code records reality.
4. **Query the right authority for the question being asked.** Enrollment state and session assurance are different facts held by different sources. A check pointed at the wrong one returns a value that cannot be correct no matter how the comparison is written.
5. **Inventory what is already working before patching.** Knowing which controls in the file were sound kept the fix to four lines and prevented over-correction of code that was not defective.

---

*Prepared as a security case study. All sensitive identifiers redacted. Published after remediation and verification.*
