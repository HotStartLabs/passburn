# passburn.com — Architecture

One-time secret sharing: paste a password/API key (optionally attach a file),
get a self-destructing link. Modeled on password.link's core product; built as
a sibling of pastecmd.com (`C:\Dev\pastecmd-site`) and reusing its stack,
security posture, and E2EE relay code. Pure showcase — no accounts, no billing.

Status: build started 2026-07-14. Domain `passburn.com` purchased and pointed
at Cloudflare. (Project was briefly named securepass.link during planning.)
Phase 1 (stored mode) deployed 2026-07-15; phase 2 (live mode + stored-mode
viewed notifications) built and locally verified 2026-07-15 — WS path is
`/live/:id` (not `/live` under `/api`), first message picks the role:
senders authenticate with a token from create, recipients knock.

## Goals / non-goals

**Goals:** zero-knowledge one-time links, honest "post-quantum-safe by design"
security story, encrypted attachments, a live no-storage delivery mode, ~$0
hosting on the Workers free tier, a "how it works" page worthy of a portfolio.

**Non-goals (rejected or deferred):** accounts, billing, teams, SSO,
white-labeling, geo-blocking, custom domains for users, knock-to-reveal via
Web Push (rejected: complexity without benefit), secret requests and bulk CSV
(phase 3 candidates).

## Delivery modes

The sender picks per link at creation time:

1. **Stored (default, async).** Ciphertext + the private key part sit in a
   Durable Object until claimed or expired. Recipient can open any time.
   What the server holds is undecryptable without the URL fragment, which it
   never sees. Residual risk: an attacker with BOTH the link and a DB snapshot
   taken before the claim could decrypt — mitigated by delete-on-claim and
   short default expiry.
2. **Live (never stored).** The secret exists only in the sender's open tab.
   A WebSocket parks at the DO; when the recipient opens the link the sender
   sees it in real time, approves or denies, and the payload relays
   browser-to-browser through the DO (pastecmd's model exactly). If the
   sender's tab closes, the link is dead — the creation UI must say so
   plainly. A WebSocket cannot outlive its tab; this mode is only for
   both-parties-online handoffs.

Stored-mode bonus: if the sender happens to keep the tab open, the DO pushes a
live "viewed" notification over the same WS path.

## Crypto

- All encryption/decryption in the browser via WebCrypto. AES-256-GCM — this
  is already the post-quantum-appropriate choice (Grover leaves a 128-bit
  margin; no asymmetric crypto exists anywhere in the design, so there is
  nothing for harvest-now-decrypt-later to harvest). Do NOT bolt on PQC
  libraries for the core flow; a hybrid ML-KEM handshake for live mode is at
  most a phase-3 flourish (vendored `@noble/post-quantum`, never CDN).
- Split-key design (password.link's model): browser generates two 16-byte
  random values, `publicPart` and `privatePart`.
  - Key = HKDF-SHA-256(ikm = publicPart || privatePart, salt = secretId,
    info = "passburn-v1") → 256-bit AES-GCM key.
  - `publicPart` lives ONLY in the URL fragment (`/s/<id>#<publicPart>`);
    fragments are never sent to servers.
  - `privatePart` is stored server-side with the ciphertext (stored mode) or
    held by the sender and sent over the relay (live mode).
  - Neither a leaked link nor a stolen database alone can decrypt.
- Optional link password: `pw = PBKDF2-SHA-256(password, salt = secretId,
  600k iterations)`, HKDF-expanded into two independent values — a server-side
  `verifier` that gates the claim (so a wrong password doesn't burn the one
  view) and a `keyInput` mixed into the HKDF ikm. The verifier reveals nothing
  about key material.
- Every ciphertext bound with AAD context labels, pastecmd-style:
  `"secret-v1"`, `"meta-v1"+fileId`, `"chunk-v1"+fileId+index` — the server
  can't replay a blob as a different type or reorder chunks.
- IDs: 128-bit random, base64url. Secret ID doubles as HKDF salt.

## Server design

One Cloudflare Worker (`src/worker.js`), static assets in `public/`
(vanilla JS, no framework, no external scripts — the only cross-origin
request is the footer integrity-badge image from `codecanary.org`, same
owner), `run_worker_first: true`.
Copy pastecmd's `securityHeaders()` (CSP with Trusted Types, HSTS preload,
COOP/COEP/CORP, etc.), its two-hop canonical redirect (http→https on-host,
then host fold to `passburn.com`), and its WS Origin allowlist.

**One Durable Object per secret** (`idFromName(secretId)`, SQLite-backed —
free tier supports these):

- Stored mode rows: metadata `{privatePart, iv, expiresAt, viewsRemaining,
  verifier?, mode}` + ciphertext + attachment chunks (256 KB each, well under
  the 2 MB value limit).
- The DO is single-threaded, so claim-and-delete is inherently atomic — two
  simultaneous opens cannot both win. No conditional-update tricks.
- Expiry = pastecmd's alarm pattern: `storage.setAlarm(expiresAt)`,
  `alarm() → deleteAll()`. Delete immediately when `viewsRemaining` hits 0.
- Live mode: the DO stores no payload, only relays — reuse pastecmd's
  `Session` class behaviors (control-prefix protection, message size cap,
  peer handling).

### Routes

| Route | Purpose |
|---|---|
| `GET /` | create page |
| `POST /api/secrets` | create stored secret (ciphertext, privatePart, options) or register live secret |
| `GET /s/:id` | static view page (fragment carries publicPart) |
| `GET /api/secrets/:id/status` | `{exists, mode, requiresPassword}` — nothing more |
| `POST /api/secrets/:id/claim` | atomic reveal + burn; body carries verifier if password-gated |
| `WS /live/:id` | live-mode relay + stored-mode viewed notifications |

**Two-phase reveal is mandatory in stored mode:** `GET /s/:id` is a static
page with a "Reveal" button; only the explicit `POST .../claim` burns the
secret. Email scanners and chat unfurlers pre-fetch GET URLs and would
otherwise destroy one-time links.

### Attachments

Reuse pastecmd's chunker from `public/app.js`: 256 KB slices, each
AES-GCM-encrypted with AAD binding, filenames encrypted in a meta record.
Stored mode persists chunks as DO rows (cap 25 MB/secret — free tier has 5 GB
total DO storage, so this bounds worst-case concurrent usage); live mode
relays them exactly as pastecmd does today (50 MB cap).

### Abuse control

No accounts, so: Cloudflare WAF rate rule by IP on `POST /api/secrets`,
message-size caps in the DO, `status` endpoint rate-limited and minimal.
Turnstile CAPTCHA on creation is a phase-3 option if abuse appears.

Password guessing is capped inside the DO in **both** modes (25 cumulative
wrong attempts per secret → self-destruct + notify the sender), because a WAF
rate rule is per-IP, distributes trivially, and never sees messages inside an
established WebSocket. Declared file sizes and chunk counts must agree
(`chunks === ceil(size / 256 KB)`) so the per-secret byte cap actually bounds
stored bytes.

## Phases

1. **MVP:** stored mode end-to-end — text secrets + attachments, expiry
   presets, view-count option, optional password, built-in password
   generator, two-phase reveal, full security headers, "how it works" page.
2. **Live mode:** relay handoff with sender approval, live viewed
   notifications for stored links.
3. **Optional:** secret requests (same flow reversed), bulk CSV (parsed
   client-side), Turnstile, hybrid ML-KEM handshake for live mode.

## Deploy

Mirror pastecmd: `wrangler.jsonc` with custom domains `passburn.com` +
`www.passburn.com`, `ENVIRONMENT` var gating dev, `npm run dev` /
`npm run deploy`. Prerequisite: purchase the domain and add the site to
Cloudflare. After first deploy, run the website-hardening pass (headers
scanners, DNSSEC, SPF/DMARC lockdown, security.txt) like a production site.
