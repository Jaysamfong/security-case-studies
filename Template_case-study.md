# Case Study: <Title>

> **One line:** <the finding, the fix, and that it was verified, in a single sentence a non-specialist can follow>

*Sensitive identifiers (project reference, user IDs, tokens) redacted or genericized.*

---

## 1. Context: why the architecture matters
<The setup that made this class of issue possible. Where does authorization actually live? What is the trust model / roles?>

## 2. The vulnerability
**Class:** <name it precisely, OWASP category where applicable, and why that label over a looser one>

**The precise gap:** <the exact mechanism. Show the relevant policy/config/code. Show the malicious request or action.>

## 3. Discovery and analytic method
<How it was found. Emphasize working the layers in order and refusing to let one passing check imply the next.>

## 4. Root cause
<The underlying reason, stated generally enough to transfer to other systems.>

## 5. The fix
<The change, with code/config.>

### Design decisions worth defending
- <Decision 1, and the trade-off it beats>
- <Decision 2, and why>

### Why this is layered, not a replacement
<How the fix composes with existing controls rather than overriding them.>

## 6. Verification — proven from both directions
**Threat path (must fail):** <the test that proves the exploit no-ops. Prefer safe, non-destructive methods.>

**Legitimate path (must still work):** <the test that proves normal behavior is intact.>

**Result:** <what actually came back, confirmed at the source of truth.>

## 7. Impact
- **<Business impact>**
- **<Technical / integrity impact>**
- **<Exploitability>**

## 8. Adjacent findings (noted for follow-up)
<Anything surfaced along the way but out of scope for this fix.>

## 9. Generalizable takeaways
1. <Transferable lesson>
2. <Transferable lesson>

---

*Prepared as a security case study. All sensitive identifiers redacted.*
