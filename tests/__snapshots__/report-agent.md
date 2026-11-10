**Penthera: Fix now.** 5 problems (3 to act on, 2 to check first), 0 likely noise. Scanned: live URL, repo.

**Do this first** (`src/lib/payments.js:14`): Roll the key in the Stripe Dashboard (Developers, API keys), then read it from a server-only environment variable. Why it matters: Anyone with this key can charge cards, refund payments and read your customers' payment details in your Stripe account.

### Act on

1. **Hardcoded Stripe secret key** [critical] in `src/lib/payments.js:14`. Why it matters: Anyone with this key can charge cards, refund payments and read your customers' payment details in your Stripe account. Fix: Roll the key in the Stripe Dashboard (Developers, API keys), then read it from a server-only environment variable. `secrets`
2. **Missing Content-Security-Policy header** [medium] in `https://shop.example/`. Why it matters: Without these headers, the browser has fewer guards against injected scripts and against your pages being framed by another site. Fix: Set the headers in next.config (headers()) or vercel.json, then check them on the live site. `headers`
3. **Session cookie without Secure \| HttpOnly &lt;flags&gt;** [medium] in `https://shop.example/login`. Why it matters: A session cookie without these flags can be read by an injected script or sent over plain HTTP, and then someone can take over the session. Fix: Set Secure, HttpOnly and SameSite on the session cookie. `cookie`

### Check first

- **Possible IDOR on /api/orders/:id** [high, needs a person] in `https://shop.example/api/orders/1001`.
- **DMARC policy is p=none** [low, pattern matched] in `https://shop.example`.

Checked one and it is not a problem? `penthera memory suppress <fid> --reason "<why>"`. It sets the finding aside on this machine; add the fid and reason to penthera.suppress.json to share that with your team. Both apply to scans with --memory, and the report lists what they hide. The fid is next to each finding in the JSON and Markdown reports.

### Not checked

- 2 suppressed (1 critical or high): not counted here. Review them with `penthera memory show --repo .` and penthera.suppress.json.
- The scan reported nothing it skipped. No finding is still not proof of safety: Penthera reports what its rules match.

---

Checked by Penthera, an open-source cyber security agent · https://github.com/danoszz/penthera
