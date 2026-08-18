# Authentication Bypass: An MFA Gate That Never Ran

**Classification:** OWASP A07:2021 — Identification and Authentication Failures
**Related weaknesses:** CWE-703 (Improper Check for Exceptional Conditions), CWE-287 (Improper Authentication)
**Severity:** Critical
**Status:** Closed
**Environment:** Production platform I architect and operate

---

## Summary

A multi-factor authentication requirement protecting the highest-privilege feature on the
platform was enforced by code that could not fail. It contained two independent defects,
either of which alone would have disabled it completely. Users reached the protected
environment without ever completing MFA, and the logs showed nothing unusual — because the
only warning statement lived inside a branch that never executed.

The fix was four lines. Finding it required understanding why a control that *looked*
correct in code review produced no observable difference in behavior.

---

## Context

The protected resource is a live cyber range — an isolated environment issued to users on a
paid tier. Access is granted by a short-lived token minted by a serverless function. That
function performs a sequence of checks before signing: validate the caller's session,
confirm the account tier from the database, enforce a rate limit, and confirm that
multi-factor authentication was completed for the current session.

The last check is the one that failed.

---

## The defect

### Defect one — the check failed open

The entire assurance-level check was wrapped in a conditional on the success of an upstream
HTTP request, with no `else` branch:

```javascript
if (aalRes.ok) {
  // ... assurance level check ...
}
// execution continues here regardless
```

Any non-success response — a 404, a timeout, a transient network fault, a rate limit from
the auth provider — skipped the check entirely and fell through to token minting. A failed
check was indistinguishable from a passed check.

This is the failure mode that matters most in authentication code. A control that denies
when it breaks is an availability problem. A control that permits when it breaks is not a
control.

### Defect two — the check read the wrong data source

Inside the conditional, the code read an assurance level from the endpoint that returns
*enrolled authentication factors*:

```javascript
const currentLevel = aalData?.aal?.currentLevel
if (currentLevel && currentLevel !== 'aal2') { /* deny */ }
```

Assurance level is not a property of the factors endpoint. It is a claim inside the access
token issued after a challenge is satisfied. The field did not exist on that response, so
`currentLevel` resolved to `undefined`, the leading truthiness guard short-circuited, and
the comparison never evaluated — **even on a successful 200 response.**

Two defects, orthogonal causes, same result. Either one alone was sufficient. Both had to be
understood to be confident the fix was complete.

---

## Why this stayed hidden

Nothing about this looked broken from the outside.

Legitimate users completed MFA during login and reached the range, so the happy path worked.
Nobody was reporting a lockout, because the gate never locked anyone out. And the single
`console.warn` intended to signal a denial sat inside the branch that never ran — so the
absence of warnings in the logs read as "no denials occurred" when it actually meant "the
check never executed."

That inversion is the part worth internalizing. In a fail-open control, a quiet log is not
evidence of health. It is the symptom.

---

## Investigation

**Confirming the deployed artifact matched the source.** Serverless functions on this
platform are published by an explicit deploy command, not by a git push. The repository shows
intent; the running function shows reality, and nothing structurally enforces that they
agree. The local copy of this file was dated roughly ten weeks earlier than two sprints that
had touched adjacent code.

I compared deployed and local before editing anything. They were identical — which meant
patching local source could not silently revert deployed behavior, and meant the defect had
been live for the entire period.

Skipping this step would have risked fixing a file that wasn't running.

**Establishing where the trustworthy value lives.** The function already decoded the token
payload earlier in its sequence, and separately verified that token against the auth
provider. That verification is what makes the decoded claims trustworthy — a decode alone
proves nothing, since anyone can base64-decode a forged token.

So the assurance level was already present, already verified, and already in scope. The
correct data was in the function the whole time; the check was reaching past it to an
endpoint that didn't carry it.

---

## The fix

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

Three properties, deliberately:

**Reads from the verified token**, not from a secondary lookup. Fewer moving parts, no
network call that can fail, and the value is authoritative because the token was already
validated upstream.

**Fails closed.** There is no path through this block that reaches token minting without an
explicit `aal2`. An unexpected value denies.

**Denies with a user-actionable message**, not an internal error string. The detail line is
hand-written copy telling the user what to do, deliberately distinct from the internal error
text that gets logged server-side.

---

## Verification

A denial-only test cannot distinguish a working control from one that locks out every
legitimate customer. Both directions were required before closing.

| Session state | Before fix | After fix |
|---|---|---|
| Password only, no MFA (`aal1`) | 200 + token issued | **403 — denied** |
| MFA completed (`aal2`) | 200 + token issued | **200 + token issued** |

The second row is the load-bearing one. Row one alone would be consistent with a fix that
denies everybody.

**Blast radius before applying:** this function is the sole gate for range access. A bad
patch blocks every paying user on the affected tiers.

**Rollback prepared before the change:** the platform's function-download command retrieves
the deployed pre-patch source, which was confirmed working before editing began.

---

## What was already correct

Worth recording, because a finding in one branch invites over-correction across the file:

- The user identifier is taken from the *verified* provider response, never from the
  unverified token decode. Forgery does not pass this gate.
- Account tier is read server-side from the database, not trusted from the client.
- Rate limiting, short token expiry, and scoped issuer/audience claims were all present and
  functioning.

The function was well constructed. One check inside it was not.

---

## Generalizing

Three things came out of this that changed how I audit adjacent code:

**A control's failure direction is a design decision, and it should be stated explicitly.**
"What happens when this check itself breaks?" is a different question from "does this check
work?" and only the first one was unanswered here.

**Absence of a signal is not evidence.** An empty warning log proves execution didn't reach
the warning. It says nothing about whether the condition occurred. Positive evidence — an
observed denial, an observed grant — is the only thing that closes a finding.

**A related defect surfaced later, pointing the opposite way.** A client-side factor check
elsewhere in the application interpreted a network failure as "not enrolled," routing a
correctly-enrolled user into a setup flow that then rejected them. Same missing concept as
this finding — the absence of a third state. Not *verified* or *not verified*, but
**unknown, retry.** Both defects came from collapsing three states into two, in opposite
directions.

---

## Timeline

| Date | Event |
|---|---|
| Found | Source review during a scheduled hardening pass |
| Deployed-vs-local confirmed | Same session, before any edit |
| Fix applied and verified | Next day, both directions tested |
| Related client-side defect opened | Following day, tracked separately |

---

*Findings on infrastructure I own and operate. Identifiers, hostnames, and account details
have been redacted. Published after remediation and verification.*
