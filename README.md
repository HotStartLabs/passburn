# passburn

One-time secret links. Paste a password or API key (optionally attach files),
get a link that burns after reading. No account, no install.

Live at [passburn.com](https://passburn.com). Sibling project of
[pastecmd.com](https://pastecmd.com); see `ARCHITECTURE.md` for the full plan.
Phase 1 (stored mode) and phase 2 (live mode + viewed notifications) are
built; phase 3 items (secret requests, bulk CSV, Turnstile) remain optional.

## How it works

- One Cloudflare Worker serves the static pages and routes `/api/secrets/*`
  to a Durable Object per secret (SQLite-backed, free tier).
- Split-key client-side encryption: the browser generates two 16-byte random
  values, derives an AES-256-GCM key from both via HKDF, and encrypts before
  anything is sent. The **public part** lives only in the URL fragment
  (`/s/<id>#<publicPart>`), which browsers never transmit; the **private
  part** is stored with the ciphertext. Neither a leaked link nor a stolen
  database alone can decrypt.
- The DO is single-threaded, so claim-and-burn is atomic by construction —
  two simultaneous opens can never both win. Expiry uses a storage alarm
  (`alarm() → deleteAll()`), exactly the pastecmd pattern.
- Two-phase reveal: `GET /s/<id>` is a static page and burns nothing (email
  scanners and chat unfurlers that pre-fetch links see only the confirmation
  screen); only the explicit `POST .../claim` consumes a view.
- Attachments are sliced into 256 KB chunks, each AES-GCM encrypted in the
  browser with AAD position binding (`"chunk-v1"+fileId+index`), stored as DO
  rows. After the final view, chunks stay downloadable for 10 minutes gated
  by a claim token, then the alarm wipes everything.
- Optional password: PBKDF2 (600k iterations) split via HKDF into a server
  verifier (gates the claim, so a wrong guess doesn't burn the view) and a
  key input (mixed into the encryption key). The password never leaves the
  browser.

### Live mode (phase 2)

- A live link stores NOTHING server-side — only a registration `{verifier,
  expiresAt}` plus a sender token. The secret, both key halves, and any files
  stay in the sender's open tab.
- The sender tab parks a hibernatable WebSocket on the secret's DO
  (`/live/:id`). The recipient's Reveal click opens a socket and **knocks**
  (carrying the password verifier if one is set — wrong passwords are
  rejected server-side and never disturb the sender). The sender sees the
  knock in real time with the requester's coarse geolocation (from
  `request.cf`) and approves or denies.
- On approve, the sender encrypts at that moment and the payload (private
  key part + ciphertext + encrypted file manifest) relays through the DO to
  the one approved recipient; file chunks follow as binary frames
  (`fileId(6) | index u32 | iv(12) | ct`, same `chunk-v1` AAD binding as
  stored mode, 50 MB total). The DO validates payload shape and relays only
  sender→approved-recipient; it remains unable to decrypt anything.
- The link burns when the recipient acknowledges full delivery — a dropped
  connection mid-transfer does NOT spend the link, so the sender can approve
  a retry. Deny also keeps the link armed.
- Wrong-password knocks are capped: 5 per socket, then the socket closes;
  25 cumulative, then the registration self-destructs and the sender is
  told (the WAF rule doesn't see messages inside an established socket, so
  the DO enforces this itself).
- Stored-mode bonus over the same socket: a sender who keeps the result tab
  open gets real-time `viewed`/burned notifications when the link is
  claimed.

## Security model

- AES-256-GCM, symmetric-only — no key exchange, no public-key crypto, so
  nothing to harvest-now-decrypt-later; post-quantum resistant by
  construction (Grover leaves a 128-bit margin).
- Every ciphertext is AAD-bound to its role (`secret-v1`, `meta-v1`+fileId,
  `chunk-v1`+fileId+index) — the server cannot replay a blob as a different
  type or reorder chunks without decryption failing.
- Strict headers on every response: CSP (no inline/external script) with
  Trusted Types enforcement, HSTS (2 years, preload), full cross-origin
  isolation (COOP/COEP/CORP), X-Frame-Options DENY, no-referrer, nosniff.
- No cookies, no analytics, no external JavaScript. Fragments never appear in
  logs because they never arrive at the server. Exactly one cross-origin
  request exists: the footer integrity badge image from `codecanary.org` (same
  owner), which attests that the served JS matches what was published — it
  learns the visitor's IP and page-open time and nothing else. `script-src` is
  `'self'` with no exceptions: enabling Cloudflare Web Analytics at the edge
  would be blocked by the CSP rather than quietly running third-party script
  on the page that holds revealed plaintext. Adding analytics requires a
  deliberate code change, not a dashboard toggle.
- Wrong-password attempts are gated by a constant-time verifier compare and
  do not consume views. Both modes cap cumulative wrong guesses per secret at
  25; past that the secret self-destructs and any watching sender tab is told
  (the link is a 128-bit secret, so a password grind means the link already
  leaked — a dead secret and a warned sender beats a longer guessing game).
- Server-side create validation is arithmetic, not just bounds: a declared
  chunk count must equal `ceil(size / 256 KB)`, so the byte cap can't be
  sidestepped by declaring tiny files with max chunk counts. Bodies are read
  incrementally against the cap (a chunked body reports no `Content-Length`).
- Residual/accepted: whoever holds the full link before it's claimed can
  read the secret (that's the trust model — send the link over one channel
  and the optional password over another); Cloudflare sees ciphertext sizes
  and connection metadata, never plaintext; a claimed-but-open browser tab
  holds the plaintext until closed.
- Limits: 100k chars of text, 5 files / 25 MB per link, 1–10 views,
  expiry 1 hour – 7 days. Delete-on-claim plus hard expiry bound the
  stored-ciphertext window.

## Gotchas learned building this

- **Durable Objects must drain forwarded request bodies.** If a DO handler
  responds while the request body is unread, workerd throws "Can't read from
  request stream after response has been sent" *after* responding, which
  kills the DO instance and 503s its next request. `Secret.fetch` buffers
  the body up front on every route.
- **...and cancelling the reader does not count as draining it.** The obvious
  way to enforce a size cap is to `break` out of the read loop and
  `reader.cancel()`. That works for a body the runtime already has in hand,
  and fails for a client still streaming: the outstanding read raises the same
  "Can't read from request stream" error the moment you respond, 503ing the
  next request to that DO. Verified with `curl -H 'Transfer-Encoding:
  chunked'`, which is also the only way to reach this path — the worker's
  `Content-Length` pre-check catches everything else. Read to the end and
  discard past the cap instead; only wire time is wasted, not memory.
- **Asset html_handling redirects break SPA-ish rewrites.** Rewriting
  `/s/<id>` to `/view.html` makes the asset layer 307-redirect to `/view`,
  destroying the path (and the id) in the browser. Rewrite to the
  extensionless `/view` instead, which serves `view.html` with a 200.

## Local development

```
npm install
cp .dev.vars.example .dev.vars   # sets ENVIRONMENT=dev so localhost is not redirected to https
npm run dev                      # http://localhost:8788
```

Create a secret on the home page, open the generated `/s/...#...` link
(fragment included), click Reveal, and reload to see the burned state.

## Deploying

1. `npx wrangler login`
2. `npm run deploy`
3. The custom domains in `wrangler.jsonc` (`passburn.com`, `www.passburn.com`)
   are bound to the Worker in the Cloudflare dashboard under Workers & Pages →
   passburn → Settings → Domains & Routes. To deploy your own instance, change
   those two route patterns to a zone on your account first.

## Hardening state (2026-07-15)

Verified from outside:

- Redirect/header matrix: exactly one 200 (canonical https), two-hop 301
  chains everywhere else, HSTS on every https response and no http response.
- Mozilla Observatory **A+ (135)**, securityheaders.com **A+** — strict CSP,
  no pragmatic compromises.
- `crossOriginIsolated === true` in production.
- `Cache-Control: no-store` on all API responses (claim bodies carry
  ciphertext + the private key part; they must never touch a cache).
- `/.well-known/security.txt` served, expires 2027-07-01.
- hstspreload.org: **submitted 2026-07-15** (status: pending). Deliberate,
  near-permanent decision: the domain can never serve plain http again.
- Minimum TLS version **1.3** at the edge (verified: 1.2 handshake refused).
  Deliberate strictness for a credential-sharing product — cuts off legacy
  corporate proxies/Android ≤9, which shouldn't be handling credentials
  anyway. 0-RTT left disabled (replay risk on non-idempotent /claim).

Zone-level controls, verified 2026-07-15:

- DNSSEC enabled, DS at the .com registry (alg 13, SHA-256 digest);
  AD flag true from both 1.1.1.1 and 8.8.8.8.
- WAF rate rule deployed and burst-tested: 10 req/10 s per IP on
  `(uri.path contains "/api/secrets/" and not uri.path contains "/chunks/")`,
  action Block — request #11 got 429; the /chunks/ exclusion confirmed
  unthrottled (attachment uploads legitimately burst ~100 requests).
  Covers both abuse surfaces: creation spam and online password guessing
  on /claim. **TODO (phase 2 follow-up):** extend the rule to also match
  `/live/` so WebSocket *connects* are rate-limited too (in-socket
  password attempts are already capped inside the DO: 5/socket,
  25 cumulative then the registration burns).
- Email: leftover Namecheap eforward MX + SPF deleted. Email Routing
  enabled — security@passburn.com forwards to the owner's mailbox;
  Cloudflare-managed MX/SPF/DKIM. Exactly one SPF and one DMARC
  (`v=DMARC1; p=reject; rua=mailto:security@passburn.com`), verified via
  DoH. Outbound product email deliberately does NOT exist: the server
  emailing links would see the key-bearing fragment (breaking
  zero-knowledge) and a free service mailing "click to reveal" links is
  phishing infrastructure. The "Share via email" button is client-side
  mailto: instead.

Declined: Bot Fight Mode — the entire product surface is fetch()-driven
API calls from our own page, exactly the traffic BFM false-positives on.

Residual/accepted, restated: a claimed secret lives in the recipient's open
tab; Cloudflare terminates TLS and sees ciphertext, private parts, and secret
ids — but never URL fragments, so it cannot decrypt anything. Online password
guessing is now both rate-limited (WAF, per IP) and hard-capped per secret at
25 cumulative wrong attempts, after which the secret self-destructs — which
means a link-holder who lacks the password can deliberately destroy the
secret. That denial-of-service is the accepted cost: they already hold the
link, and a destroyed secret plus an alerted sender is the better failure.

## Security review (2026-07-31)

Full-codebase pass; no critical or high findings. Confirmed sound: claim-and-
burn atomicity via DO input gates, constant-time token/verifier compares,
128-bit CSPRNG ids and tokens, HKDF/PBKDF2 domain separation, per-message IVs
and AAD position binding, two-phase reveal, zero HTML-injection sinks (all
`textContent`/`replaceChildren`, Trusted Types as backstop), fail-closed
`ENVIRONMENT` gate, unbiased rejection-sampled password generator.

Fixed in this pass:

- Stored-mode `/claim` had no per-secret guess cap — only the per-IP WAF rule,
  which allows on the order of 10^5 guesses/day/IP and is silent to the
  sender. Now mirrors live mode (25 cumulative, self-destruct, notify).
- `validFiles` checked chunk count and declared size independently, so five
  files declared at `size: 0` with max chunks bought ~184 MB of real storage
  against a 25 MB cap. Chunk count is now derived-and-compared.
- The DO buffered an entire request body before measuring it; the worker's
  `Content-Length` pre-check reads 0 for chunked bodies. Now read incrementally
  and capped — past the limit it keeps reading but stops retaining. See the
  second gotcha above for why it drains instead of cancelling.
- `workers_dev` / `preview_urls` pinned off in `wrangler.jsonc` — both default
  on and would serve the whole app outside the canonical-domain story.
- Password fields were `type="text"`; now masked with a Show/Hide toggle.
- Docs claimed "no external requests" and "no analytics" while the codecanary
  badge loaded cross-origin and the CSP allowlisted Cloudflare Insights. The
  Insights entries are now gone from `script-src`/`connect-src` (analytics was
  never actually enabled), and the remaining claims describe the badge
  honestly instead of rounding it away.

Deployed to production 2026-07-31 (version `97457dbb`) and smoke-tested live:
create → two wrong passwords (counter showed 24 then 23 left, view not
consumed) → correct password → decrypt → burn → sender tab's 🔥, with
`crossOriginIsolated === true`, the wss:// socket armed, and clean consoles.

Open, needs the Cloudflare dashboard: rate-limit `/live/` WebSocket connects
(carried over from the phase-2 TODO above). The free plan allows exactly one
rate-limiting rule, so this folds into the existing rule rather than getting
its own. Replace the expression and raise the threshold together:

```
(http.request.uri.path contains "/api/secrets/" and not http.request.uri.path contains "/chunks/")
or (http.request.uri.path contains "/live/")
```

at **20 requests / 10 s per IP**, action Block.

Raising 10 → 20 is not a loosening in practice, because the rule's two
original jobs have diverged. Online password guessing is now capped in the DO
itself (25 per secret, regardless of how many sockets or IPs an attacker
uses), so the rate rule no longer carries that load. What it still does is
blunt creation spam and connect floods — and for that, 20 is ample: every
legitimate flow costs 2 matched requests (create + socket, or status + claim;
chunk transfers are excluded), so 20 leaves 10x headroom.

The headroom matters because of shared IPs. At 10/10 s, five colleagues behind
one office NAT using passburn at the same time would hit the limit, and a
sender's reconnect backoff (0.5 s → 8 s) can add ~5 connects in a 10 s window
on a flaky network. That false-positive risk already exists today; folding
`/live/` in at the old threshold would sharpen it.

## Hardening follow-up (2026-08-05)

Scanner-driven pass ahead of the portfolio composite screenshot:

- SPF hardened `~all` → `-all` (`v=spf1 include:_spf.mx.cloudflare.net -all`);
  verified via DoH against 1.1.1.1 and 8.8.8.8.
- CAA records added: `issue` + `issuewild` for `letsencrypt.org`, `pki.goog`,
  `ssl.com` (Cloudflare Universal SSL's CAs). Once any CAA exists, Cloudflare
  dynamically serves its full CA set in answers (digicert/comodoca appear in
  queries without being zone records) — expected, documented behavior.
- **Cloudflare Web Analytics beacon was being edge-injected into production
  HTML.** Found while hash-verifying served code against the repo before
  re-baselining the canary: Cloudflare had auto-enabled Web Analytics with
  automatic setup (zone setting `rum=on`) when the zone was added on
  2026-07-15, injecting a `static.cloudflareinsights.com/beacon.min.js` script
  tag into every HTML response — contradicting the no-analytics claims above.
  The CSP backstop worked exactly as designed: `script-src 'self'` blocked the
  beacon from ever executing (Web Analytics recorded zero page views), at the
  cost of a CSP violation in every visitor's console. Disabled 2026-08-05 via
  the zone-level RUM setting during a Cloudflare partial outage (account-level
  RUM writes were returning 504; repeated dashboard retries landed it).
  Verified gone on `/`, `/how-it-works`, and www, cache-busted.
  - Detection note: the injection never appears on Cloudflare Worker
    subrequests — codecanary's scanner and canary rechecks fetch through
    Workers and were structurally blind to it. Only an external-vantage fetch
    sees edge-injected content.
  - The other zones in the account still have automatic setup enabled and
    should be audited the same way.
- CodeCanary monitors: both went red 2026-08-01 — correct drift detection of
  the 2026-07-31 security-fix deploy (`app.js` hash changed vs the 2026-07-20
  baselines), not tampering. Resolved 2026-08-05: the original registration
  tokens were never recorded, so the token hash was rotated directly in KV
  (record rebuilt from the public API + fresh SHA-256, gold-badge history
  preserved) and `b0f0b4c29dd2` re-verified through the official endpoint at
  16:44 UTC — green, new baseline matches the deployed code. The accidental
  duplicate monitor `48d2147cdfa5` was deleted and the host index
  consolidated. The new token lives in gitignored `.canary-token` — don't
  lose it twice.
- Post-beacon-removal scanner runs: codecanary.org **A+ zero findings**,
  securityheaders.com **A+**, Mozilla Observatory **A+ (130/100, 10/10)**.

## Costs

Free tier: Workers requests plus SQLite-backed DO storage (5 GB) comfortably
cover showcase traffic. Worst case for storage is ~200 concurrent maxed-out
25 MB links — the alarm-based wipe keeps steady-state near zero.

## License

MIT — see [LICENSE](LICENSE).
