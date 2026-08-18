# Case Study: Closing a Column-Level Privilege-Escalation Gap in a Supabase App

> **One line:** Row-level authorization was correct, but there was no *column-level* authorization on a table where subscription entitlement lived as a column — so any authenticated user could grant themselves a paid tier by writing their own row. I closed it with a role-scoped database trigger that pins privileged columns for end-user roles while leaving the legitimate server-side write paths intact, and verified both the exploit closure and the absence of regression.

*Identifiers (project reference, user UUIDs, tokens) have been redacted or genericized. Table and column names are kept because they carry no sensitive value and aid readability.*

---

## 1. Context: why the architecture matters

The application is built on a Backend-as-a-Service (Supabase / PostgREST + Postgres). The browser talks **directly to the database** over an auto-generated REST API, authenticating with a **public `anon` key** that ships inside the frontend bundle.

The consequence is the crux of this entire case: **there is no server-side controller between the client and the tables for direct reads and writes.** Whatever authorization exists must be expressed in the database itself — as Row Level Security (RLS) policies or triggers. If a rule is not encoded there, it is not enforced anywhere.

Roles in this model:

| Role | Who runs as it | RLS applies? |
|---|---|---|
| `anon` | logged-out visitors | yes |
| `authenticated` | logged-in end users (the browser) | yes |
| `service_role` | edge functions, webhooks (server-side) | **no — bypasses RLS by design** |

---

## 2. The vulnerability

**Class:** Broken Object *Property*-Level Authorization (OWASP API3:2023) — a subtype of Broken Access Control. This is a more precise label than "IDOR": object-level authorization was *correct* (a user could only touch their own row); it was **property (column) level** authorization that was missing.

**The precise gap:** RLS policies authorize *which rows* a role may act on, via `USING` / `WITH CHECK`. They say nothing about *which columns*. The `profiles` table carried both user-editable fields (display name, track, onboarding flags) **and** privileged fields in the same row:

- `tier`, `subscription_status` — entitlement / billing state
- `stripe_customer_id` — billing linkage
- `xp`, `level` — gamification / progression

The update policy was, correctly:

```
policy "Users can update own profile"
  on profiles for update
  to authenticated
  using      (auth.uid() = id)
  with check (auth.uid() = id);
```

That restricts a user to **their own row** — but nothing stopped them from changing *any column in it*. So a logged-in free user could issue a direct API call against their own record:

```
PATCH /rest/v1/profiles?id=eq.<their-own-id>
{ "tier": "immersion", "subscription_status": "active" }
```

…and upgrade themselves to the top paid tier for free. The same path allowed setting arbitrary `xp` / `level`, compromising leaderboard integrity.

---

## 3. Discovery and analytic method

The finding did not come from a scanner; it came from working the layers in order and refusing to let one passing check imply the next.

1. **Route layer.** Confirmed logged-out users are redirected to login on protected routes. *Passed — but this only proves the UI is guarded, not the data.*
2. **Row-read layer (IDOR).** Inspected the actual policy definitions (`pg_policies.qual` / `with_check`). `SELECT` policies were scoped to `auth.uid() = id` / `= user_id`. *Cross-user reads: closed.*
3. **Column-write layer.** This is where the gap lived. The `UPDATE` policy's `with_check` authorized the row but not the columns, and privileged state lived in that row. Reading the policy — not running an exploit — was enough to identify it.
4. **Blast-radius sizing before any change.** Inventoried every write to `profiles` **by executing role**, so a fix could not silently break a legitimate path:
   - *Client writes* (`authenticated`): onboarding and profile edits — touched only safe columns (name, handle, track, flags). None wrote privileged columns.
   - *Server writes* (`service_role`): the Stripe webhook writes `tier`/`subscription_status`; an `increment_xp` RPC and a fallback write `xp`. The legitimate writers of every privileged column already ran server-side.

That inventory is what turned the fix from a hopeful change into a **provably zero-breakage** one: the only callers who write privileged columns are trusted (`service_role`), and the only untrusted caller (`authenticated`) never legitimately writes them.

---

## 4. Root cause

Postgres RLS is **row-level, not column-level.** When sensitive state (entitlement, progression) is stored as columns alongside user-editable fields in a table the user is allowed to update, a correct row policy still leaves those columns writable. The BaaS architecture removes the server-side layer that would normally reject such a write, so the database is the only place the rule can live.

---

## 5. The fix

A `BEFORE INSERT/UPDATE` trigger that neutralizes privileged-column writes for end-user roles, while leaving trusted callers untouched.

```sql
create or replace function public.protect_profile_privileged_columns()
returns trigger language plpgsql as $$
begin
  -- Only real end users are restricted. service_role, SECURITY DEFINER RPCs
  -- (e.g. increment_xp), cron, and admin all run as something other than
  -- authenticated/anon, so they pass through untouched.
  if current_user not in ('authenticated', 'anon') then
    return new;
  end if;

  if tg_op = 'INSERT' then
    -- new signups cannot self-grant; force safe baseline (matches column defaults)
    new.tier                := 'free';
    new.subscription_status := 'free';
    new.stripe_customer_id  := null;
    new.xp                  := 0;
    new.level               := 1;
  elsif tg_op = 'UPDATE' then
    -- users cannot change entitlement/progression on their own row
    new.tier                := old.tier;
    new.subscription_status := old.subscription_status;
    new.stripe_customer_id  := old.stripe_customer_id;
    new.xp                  := old.xp;
    new.level               := old.level;
  end if;
  return new;
end $$;

create trigger protect_profile_privileged_columns
before insert or update on public.profiles
for each row execute function public.protect_profile_privileged_columns();
```

### Two design decisions worth defending

**Pin, don't reject.** The trigger silently forces protected columns back to their prior (UPDATE) or default (INSERT) value rather than raising an error. A rejecting approach would throw on any write that happens to include a protected column, risking client breakage; pinning lets legitimate writes succeed while making the malicious portion a no-op.

**Whitelist the untrusted role; don't enumerate the trusted ones.** The guard restricts only `authenticated` / `anon` and lets everything else through. This is robust against `service_role`, `SECURITY DEFINER` RPCs (which execute as the function *owner*, not `service_role`), cron, and admin — none of which need to be named. The principle: **fail-closed on the one caller you can precisely identify as the threat; fail-open for the trusted contexts you cannot fully enumerate.**

### Why this is layered, not a replacement

RLS still answers *"which row?"*; the trigger answers *"which columns?"* They compose. The trigger does not modify any policy and does not touch the server-side write paths (those run as `service_role` and bypass it).

---

## 6. Verification — proven from both directions

A control is only verified when the **threat path fails** *and* the **legitimate path still works.**

**Threat path (must no-op).** Simulated a real end-user attack entirely inside a transaction, using role + JWT-claim simulation so nothing persisted:

```sql
begin;
  set local role authenticated;
  set local request.jwt.claims to
    '{"sub":"<user-uuid>","role":"authenticated"}';

  update public.profiles
     set tier = 'immersion', xp = 999999
   where id = '<user-uuid>';

  select tier, xp from public.profiles where id = '<user-uuid>';
rollback;
```

**Result:** the update ran without error, but the read returned `tier = free`, `xp = 0` — unchanged. The escalation was silently pinned. The `rollback` discarded everything regardless.

**Legitimate path (must still write).** Completed a ticket through the app normally. XP incremented `0 → 100` (persisted, confirmed by direct query), driven by the `increment_xp` RPC running as `service_role`, which the trigger lets through.

Both guarantees held: end users are blocked from self-granting; the server-side award path is intact.

---

## 7. Impact

- **Revenue:** eliminated a free self-upgrade to the top paid tier — a direct monetization bypass.
- **Integrity:** removed the ability to set arbitrary XP/level, protecting progression and leaderboard trust.
- **Exploitability:** the pre-fix bug required nothing exotic — any logged-in user already holds a valid token, and the guard now applies to the *role* regardless of *which* user's token is used, so a valid or stolen session token cannot escalate.

---

## 8. Adjacent findings (noted for follow-up)

- **Client-supplied `priceId` — subsequently closed.** The checkout function received
  the Stripe price identifier from the browser. Trusting a client-supplied identifier
  invites price tampering, so the server now validates every incoming identifier
  against a server-side allowlist before it reaches the payment provider. A later
  finding demonstrated the value of that control from an unexpected direction: a
  single-character typo in the allowlist was caught at the validation boundary rather
  than silently producing a mismatched entitlement.

- **Test and live billing objects are fully separate universes.** A stale test-mode
  customer identifier persisting on a downgraded account produced a "no such customer"
  error against a live-mode key at checkout. No exploit path, but it means billing
  state is not automatically reliable as a source of truth, and account resets must
  clear billing linkage explicitly. Tracked separately.

- **Key hygiene.** The `service_role` key is the one credential this trigger cannot
  defend against — it is trusted by design. It must remain server-side only, never in
  the frontend or version control, and be rotated immediately if exposed.

---

## 9. Generalizable takeaways

1. **Access control is layered** (route → row → column). A passing check at one layer implies nothing about the next; verify each independently. The highest-impact finding here lived at the deepest, least-visible layer.
2. **In a BaaS app, RLS *is* the access-control layer** for direct data operations — and RLS is row-level, so sensitive columns in a user-writable row need a separate control (trigger or column GRANTs).
3. **Size the blast radius before changing a shared table:** inventory every write by executing role, so the fix is provably non-breaking rather than hopeful.
4. **Verify a control from both directions** — threat path must fail, legitimate path must still work — and confirm state changes at the source of truth (the database row), not the surface that reports them (a UI success message).

---

*Prepared as a security case study. All sensitive identifiers redacted.*