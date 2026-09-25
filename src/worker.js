// passburn — one-time encrypted secret links.
// The server stores only ciphertext plus HALF the key material (the private
// part). The public part lives in the URL fragment, which browsers never send
// to servers — so neither a leaked link nor a stolen database alone can
// decrypt a secret. One Durable Object per secret: the DO is single-threaded,
// which makes claim-and-burn atomic without any locking.
//
// Two delivery modes:
//  - Stored (default): ciphertext + private part rest in the DO until claimed.
//  - Live: NOTHING is stored. The secret stays in the sender's open tab; the
//    recipient knocks over a WebSocket, the sender approves, and the payload
//    relays browser-to-browser through the DO (pastecmd's relay model). The
//    same WS path also pushes "viewed" notifications to stored-mode senders
//    who keep their tab open.

const MAX_CREATE_BYTES = 512 * 1024;      // create body: text ct + manifest
const MAX_CHUNK_BYTES = 300 * 1024;       // 256 KB plaintext + iv/GCM overhead
const CHUNK_PLAINTEXT_BYTES = 256 * 1024; // client slice size (app.js CHUNK_SIZE)
const MAX_FILES = 5;
const MAX_CHUNKS_PER_FILE = 120;
const MAX_TOTAL_FILE_BYTES = 25 * 1024 * 1024;
const MAX_VIEWS = 10;
const MIN_EXPIRY_S = 5 * 60;
const MAX_EXPIRY_S = 7 * 24 * 3600;
// After the final view, attachment chunks stay downloadable (claim token
// required) for this long, then the alarm wipes everything but a tombstone.
const CLAIM_GRACE_MS = 10 * 60 * 1000;
// Every way a secret ends leaves a tombstone for this long. Without one, a
// wiped id is free again, and anyone holding the full link could re-create a
// secret under it — so a reader who intercepted the link could re-plant it
// and the real recipient would see content instead of the "gone" warning.
const TOMBSTONE_MS = 30 * 24 * 3600 * 1000;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;

// Storage quota. The free plan has 5 GB of Durable Object storage in total,
// and past it every write fails — text secrets included. Every create
// reserves its worst-case footprint against one global Quota object first:
// its bytes until it can no longer exist, then a tombstone until that ends.
// A per-client daily cap stops one network from spending the global budget;
// the global cap keeps a many-client flood from reaching the platform limit,
// failing new creates instead of every write.
const QUOTA_GLOBAL_BYTES = 4 * 1024 ** 3;         // 1 GB headroom under 5 GB
const QUOTA_CLIENT_DAILY_BYTES = 500 * 1024 ** 2; // ~19 max-size links a day
// A SQLite-backed object costs ~12 KB even nearly empty (Cloudflare docs):
// so does every tombstone. Rounded up for row overhead.
const OBJECT_OVERHEAD_BYTES = 16 * 1024;
const HOUR_MS = 3600 * 1000;

// Live mode caps. Larger than stored mode because nothing rests on disk —
// chunks pass through the DO one message at a time (pastecmd allows the same).
const MAX_LIVE_TOTAL_FILE_BYTES = 50 * 1024 * 1024;
const MAX_LIVE_CHUNKS_PER_FILE = 200;
const MAX_LIVE_MSG_CHARS = 480_000;       // payload JSON: 360k-char ct + manifest
const LIVE_FRAME_HEADER = 22;             // binary chunk: fileId(6)+index(4)+iv(12)
const MAX_SOCKETS = 16;

// Online password guessing, both modes. The link is itself a 128-bit secret,
// so anyone guessing passwords at it already holds the link: past the
// cumulative cap the secret self-destructs and any watching sender is told.
// Live knocks also die per-socket first. Wrong guesses never reach the sender
// and never consume a view.
const MAX_BAD_PW_PER_SOCKET = 5;
const MAX_BAD_PW_TOTAL = 25;

const ID_RE = /^[A-Za-z0-9_-]{22}$/;        // 16 random bytes, base64url
const IV_RE = /^[A-Za-z0-9_-]{16}$/;        // 12-byte GCM IV
const VERIFIER_RE = /^[A-Za-z0-9_-]{43}$/;  // 32-byte password verifier
const FILE_ID_RE = /^[A-Za-z0-9_-]{8}$/;    // 6 random bytes

const ALLOWED_ORIGINS = new Set(["https://passburn.com"]);

// connect-src: pages call their own origin plus the live-mode WebSocket.
// CSP3 'self' should cover same-host wss:, but not every engine agrees, so
// the socket origin is listed explicitly — localhost ws:// in dev only.
const securityHeaders = (isDev = false) => ({
  "Content-Security-Policy":
    // script-src is 'self' with no exceptions. Notably that means enabling
    // Cloudflare Web Analytics at the edge would be BLOCKED by this header
    // rather than silently injecting a third-party script into the page that
    // holds revealed plaintext. Adding analytics has to be a deliberate edit
    // here, not a dashboard toggle — which is the point.
    "default-src 'none'; script-src 'self'; style-src 'self'; " +
    (isDev
      ? "connect-src 'self' ws://localhost:8788 ws://127.0.0.1:8788; "
      : "connect-src 'self' wss://passburn.com; ") +
    // codecanary.org: the footer integrity badge image
    "img-src 'self' https://codecanary.org; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " +
    // Any future DOM-XSS sink assignment throws at runtime instead of executing.
    "require-trusted-types-for 'script'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
});

// no-store: claim responses carry ciphertext + the private key part — none of
// the API surface may ever land in a browser or edge cache.
const json = (status, obj) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...securityHeaders(),
    },
  });

const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Constant-time string compare for tokens/verifiers (both sides are
// fixed-format base64url, so length leaks nothing secret).
function tokenEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function validSecret(s) {
  return typeof s === "object" && s !== null && IV_RE.test(s.iv ?? "") &&
    typeof s.ct === "string" && s.ct.length <= 360_000 &&
    /^[A-Za-z0-9_-]*$/.test(s.ct);
}

function validFiles(files, maxChunks, maxTotal) {
  if (!Array.isArray(files) || files.length > MAX_FILES) return "bad files";
  const seen = new Set();
  let total = 0;
  for (const f of files) {
    if (typeof f !== "object" || f === null || !FILE_ID_RE.test(f.fileId ?? "")) return "bad fileId";
    if (seen.has(f.fileId)) return "duplicate fileId";
    seen.add(f.fileId);
    if (typeof f.meta !== "object" || f.meta === null || !IV_RE.test(f.meta.iv ?? "") ||
        typeof f.meta.ct !== "string" || f.meta.ct.length > 4000 ||
        !/^[A-Za-z0-9_-]*$/.test(f.meta.ct)) return "bad file meta";
    if (!Number.isInteger(f.chunks) || f.chunks < 1 || f.chunks > maxChunks) return "bad chunks";
    if (!Number.isInteger(f.size) || f.size < 0) return "bad size";
    // Chunk count must follow from the declared size, or the byte cap below
    // means nothing: 5 files declared at size 0 with the max chunk count would
    // otherwise buy several times the intended storage per secret.
    if (f.chunks !== Math.max(1, Math.ceil(f.size / CHUNK_PLAINTEXT_BYTES))) return "bad chunk count";
    total += f.size;
  }
  if (total > maxTotal) return "too big";
  return null;
}

function validCreate(body) {
  if (typeof body !== "object" || body === null) return "bad body";
  if (body.verifier !== null && !VERIFIER_RE.test(body.verifier ?? "")) return "bad verifier";
  if (!Number.isInteger(body.expiresIn) ||
      body.expiresIn < MIN_EXPIRY_S || body.expiresIn > MAX_EXPIRY_S) return "bad expiresIn";
  if (body.mode === "live") return null; // live registration stores nothing else
  if (!ID_RE.test(body.privatePart ?? "")) return "bad privatePart";
  if (!validSecret(body.secret)) return "bad secret";
  if (!Number.isInteger(body.views) || body.views < 1 || body.views > MAX_VIEWS) return "bad views";
  return validFiles(body.files, MAX_CHUNKS_PER_FILE, MAX_TOTAL_FILE_BYTES);
}

// Live payload travels sender→recipient through us but is validated like a
// create body: the relay must not become a vector for oversized or malformed
// junk aimed at the recipient's page.
function validLivePayload(m) {
  if (!ID_RE.test(m.privatePart ?? "")) return "bad privatePart";
  if (!validSecret(m.secret)) return "bad secret";
  return validFiles(m.files, MAX_LIVE_CHUNKS_PER_FILE, MAX_LIVE_TOTAL_FILE_BYTES);
}

// Per-client key for the daily quota. IPv6 clients are grouped by /64 —
// one subscriber usually holds a whole /64, so per-address counting would
// be a quota per rotation.
function clientKey(ip) {
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t];
  return groups.slice(0, 4).map((g) => (parseInt(g, 16) || 0).toString(16)).join(":") + "::/64";
}

// One global instance. Hour-bucketed ledger of reserved bytes by the time
// they can no longer be stored, plus per-client daily totals. Client keys are
// HMACs under a random key that is replaced (and the counters dropped) at
// each UTC day: no IP is ever stored, and yesterday's keys can't be linked.
export class Quota {
  constructor(ctx) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS usage (bucket INTEGER PRIMARY KEY, bytes INTEGER NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS clients (k TEXT PRIMARY KEY, bytes INTEGER NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS day (id INTEGER PRIMARY KEY CHECK (id = 1), day TEXT NOT NULL, key TEXT NOT NULL)");
  }

  async fetch(request) {
    const { client, bytes, until, tomb, tombUntil } = await request.json();
    const now = Date.now();
    const today = new Date(now).toISOString().slice(0, 10);
    let day = this.sql.exec("SELECT day, key FROM day WHERE id = 1").toArray()[0];
    if (!day || day.day !== today) {
      day = { day: today, key: b64url(crypto.getRandomValues(new Uint8Array(32))) };
      this.sql.exec("DELETE FROM clients");
      this.sql.exec("INSERT OR REPLACE INTO day (id, day, key) VALUES (1, ?, ?)", day.day, day.key);
    }
    const te = new TextEncoder();
    const hk = await crypto.subtle.importKey(
      "raw", te.encode(day.key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const k = b64url(new Uint8Array(
      await crypto.subtle.sign("HMAC", hk, te.encode(clientKey(client || "")))).subarray(0, 16));

    // Synchronous from here on: nothing can interleave between the checks
    // and the writes, so two creates can't both squeeze into the last slot.
    const bucket = (t) => Math.ceil(t / HOUR_MS);
    this.sql.exec("DELETE FROM usage WHERE bucket < ?", bucket(now));
    const total = this.sql.exec("SELECT COALESCE(SUM(bytes), 0) AS n FROM usage").one().n;
    const used = this.sql.exec("SELECT bytes FROM clients WHERE k = ?", k).toArray()[0]?.bytes ?? 0;
    const cost = bytes + tomb;
    if (used + cost > QUOTA_CLIENT_DAILY_BYTES) return json(429, { error: "daily quota" });
    if (total + cost > QUOTA_GLOBAL_BYTES) return json(507, { error: "capacity" });
    const add = "INSERT INTO usage (bucket, bytes) VALUES (?, ?) " +
      "ON CONFLICT(bucket) DO UPDATE SET bytes = bytes + excluded.bytes";
    this.sql.exec(add, bucket(until), bytes);
    this.sql.exec(add, bucket(tombUntil), tomb);
    this.sql.exec(
      "INSERT INTO clients (k, bytes) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET bytes = bytes + excluded.bytes",
      k, cost);
    return json(200, {});
  }
}

export class Secret {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    // Live-mode / notification WebSocket. Role is decided by the FIRST
    // message: senders authenticate with the token from create, recipients
    // knock (with the password verifier if one is set). Hibernatable sockets:
    // per-socket state rides in the attachment, so a parked sender tab costs
    // nothing while it waits.
    if (request.headers.get("Upgrade") === "websocket") {
      const sockets = this.ctx.getWebSockets().filter((ws) => this.att(ws).role !== "evicted");
      if (sockets.length >= MAX_SOCKETS) {
        // A socket that never finished its handshake holds a slot for free:
        // without eviction, 16 idle connects from a link-holder would lock
        // the real sender (and recipient) out. Evict the oldest such socket;
        // it's marked first so a close that lingers can't be picked twice.
        const idle = sockets
          .filter((ws) => this.att(ws).role === "pending")
          .sort((a, b) => (this.att(a).at || 0) - (this.att(b).at || 0))[0];
        if (idle) {
          idle.serializeAttachment({ role: "evicted" });
          try { idle.close(4008, "evicted"); } catch {}
        } else {
          const rejectPair = new WebSocketPair();
          rejectPair[1].accept();
          rejectPair[1].close(4001, "full");
          return new Response(null, { status: 101, webSocket: rejectPair[0] });
        }
      }
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]);
      // Coarse geo from the upgrade request — shown to the sender when this
      // socket knocks, so they can sanity-check who's asking.
      pair[1].serializeAttachment({
        role: "pending",
        at: Date.now(),
        geo: request.cf ? { country: request.cf.country ?? null, city: request.cf.city ?? null } : null,
      });
      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // api, secrets, :id, ...
    const rest = parts.slice(3);

    // Drain the body up front, on every route: if a handler responds while a
    // forwarded request body sits unread, workerd throws "Can't read from
    // request stream after response has been sent" AFTER responding, which
    // kills the DO instance and 503s the next request to it.
    //
    // Read it incrementally rather than buffering whole-then-measuring: the
    // worker's Content-Length pre-check reads 0 for a chunked body, so this is
    // the only place an oversized upload is actually stopped.
    //
    // Past the cap we keep READING but stop KEEPING. Cancelling the reader
    // instead looks tempting and is wrong: a client still streaming when we
    // cancel leaves a read outstanding, and workerd raises the same
    // "Can't read from request stream" error described above the moment we
    // respond — verified, it 503s the next request to this DO. Draining costs
    // only wire time; the bytes are never retained.
    let raw = null;
    if (request.body) {
      const reader = request.body.getReader();
      const pieces = [];
      let size = 0, tooBig = false;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (tooBig) continue;
        if (size > MAX_CREATE_BYTES) { tooBig = true; pieces.length = 0; continue; }
        pieces.push(value);
      }
      if (tooBig) return json(413, { error: "too large" });
      raw = new Uint8Array(size);
      let off = 0;
      for (const p of pieces) { raw.set(p, off); off += p.byteLength; }
    }

    if (request.method === "PUT" && rest.length === 0) {
      return this.create(raw, request.headers.get("X-PB-Client") || "");
    }
    if (request.method === "GET" && rest[0] === "status") return this.status();
    if (request.method === "POST" && rest[0] === "claim") return this.claim(raw);
    if (rest[0] === "chunks" && FILE_ID_RE.test(rest[1] ?? "") && /^\d{1,3}$/.test(rest[2] ?? "")) {
      const fileId = rest[1], index = parseInt(rest[2], 10);
      if (request.method === "PUT") return this.uploadChunk(request, raw, fileId, index);
      if (request.method === "GET") return this.downloadChunk(request, fileId, index);
    }
    return json(404, { error: "not found" });
  }

  // --- WebSocket plumbing (hibernation-safe: no in-memory state) ---

  att(ws) {
    try { return ws.deserializeAttachment() || {}; } catch { return {}; }
  }

  peers(role, except) {
    return this.ctx.getWebSockets().filter((ws) => ws !== except && this.att(ws).role === role);
  }

  sendJson(ws, obj) {
    try { ws.send(JSON.stringify(obj)); } catch {}
  }

  notifySenders(obj, except) {
    for (const s of this.peers("sender", except)) this.sendJson(s, obj);
  }

  closeAll(reason, except) {
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === except) continue;
      try { ws.close(1000, reason); } catch {}
    }
  }

  // The end of every secret: wipe everything but a tombstone that keeps the
  // id from being re-created (see TOMBSTONE_MS). deleteAll() doesn't touch
  // the alarm; setAlarm replaces it with the tombstone's own cleanup.
  async tombstone() {
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.put("tombstone", true);
    await this.ctx.storage.setAlarm(Date.now() + TOMBSTONE_MS);
  }

  async exists() {
    for (const k of ["meta", "live", "burned", "tombstone"]) {
      if (await this.ctx.storage.get(k)) return true;
    }
    return false;
  }

  // Reserve this secret's worst-case storage with the global Quota before
  // writing anything (see QUOTA_GLOBAL_BYTES). Only valid creates get here,
  // so malformed requests can't spend anyone's budget. Returns a refusal
  // response, or null to proceed.
  async reserve(client, raw, body, now) {
    const until = now + body.expiresIn * 1000 + CLAIM_GRACE_MS;
    const files = body.mode === "live" ? [] : body.files;
    const bytes = OBJECT_OVERHEAD_BYTES + raw.byteLength + files.reduce(
      (n, f) => n + f.size + f.chunks * (GCM_IV_BYTES + GCM_TAG_BYTES), 0);
    const quota = this.env.QUOTA.get(this.env.QUOTA.idFromName("global"));
    const res = await quota.fetch("https://quota/reserve", {
      method: "POST",
      body: JSON.stringify({
        client, bytes, until, tomb: OBJECT_OVERHEAD_BYTES, tombUntil: until + TOMBSTONE_MS,
      }),
    });
    return res.ok ? null : json(res.status, await res.json());
  }

  async create(raw, client) {
    if (await this.exists()) return json(409, { error: "exists" });

    let body;
    try {
      body = JSON.parse(new TextDecoder().decode(raw));
    } catch {
      return json(400, { error: "bad json" });
    }
    const err = validCreate(body);
    if (err) return json(400, { error: err });

    const now = Date.now();
    const refused = await this.reserve(client, raw, body, now);
    if (refused) return refused;
    // The quota round-trip let other requests in; nothing may have claimed
    // this id meanwhile (only the creator knows it, but don't assume).
    if (await this.exists()) return json(409, { error: "exists" });
    // The sender token authenticates the creating tab's WebSocket — for the
    // approve/relay flow in live mode, for viewed notifications in stored.
    const senderToken = b64url(crypto.getRandomValues(new Uint8Array(16)));

    if (body.mode === "live") {
      // Nothing else is stored, ever: no ciphertext, no key material. If this
      // registration outlives the sender's tab, it's just a dead pointer.
      const live = { verifier: body.verifier, expiresAt: now + body.expiresIn * 1000 };
      await this.ctx.storage.put({ live, senderToken, attempts: 0 });
      await this.ctx.storage.setAlarm(live.expiresAt);
      return json(200, { senderToken });
    }

    const uploadToken = b64url(crypto.getRandomValues(new Uint8Array(16)));
    const meta = {
      privatePart: body.privatePart,
      verifier: body.verifier,
      views: body.views,
      expiresAt: now + body.expiresIn * 1000,
      ready: body.files.length === 0,
      files: body.files.map((f) => ({
        fileId: f.fileId, meta: f.meta, chunks: f.chunks, size: f.size, received: 0,
      })),
    };
    await this.ctx.storage.put({
      meta,
      secret: { iv: body.secret.iv, ct: body.secret.ct },
      uploadToken,
      senderToken,
      tokens: {},
    });
    await this.ctx.storage.setAlarm(meta.expiresAt);
    return json(200, meta.ready ? { senderToken } : { senderToken, uploadToken });
  }

  // Anything expired-but-not-yet-wiped must behave exactly like gone.
  async liveMeta() {
    const meta = await this.ctx.storage.get("meta");
    if (!meta || meta.views < 1 || meta.expiresAt <= Date.now()) return null;
    return meta;
  }

  async liveReg() {
    const live = await this.ctx.storage.get("live");
    if (!live || live.expiresAt <= Date.now()) return null;
    return live;
  }

  async status() {
    const live = await this.liveReg();
    if (live) {
      return json(200, {
        mode: "live",
        requiresPassword: live.verifier !== null,
        senderOnline: this.peers("sender").length > 0,
        expiresAt: live.expiresAt,
      });
    }
    const meta = await this.liveMeta();
    if (!meta) return json(404, { gone: true });
    return json(200, {
      mode: "stored",
      requiresPassword: meta.verifier !== null,
      ready: meta.ready,
      hasFiles: meta.files.length > 0,
      viewsRemaining: meta.views,
      expiresAt: meta.expiresAt,
    });
  }

  async claim(raw) {
    const meta = await this.liveMeta();
    if (!meta) return json(404, { gone: true });
    if (!meta.ready) return json(409, { error: "not ready" });

    if (meta.verifier !== null) {
      let body = {};
      try { body = JSON.parse(new TextDecoder().decode(raw)); } catch {}
      // Wrong password must NOT burn a view — the verifier gates the claim.
      if (typeof body.verifier !== "string") return json(401, { requiresPassword: true });
      if (!tokenEq(body.verifier, meta.verifier)) {
        // Same cumulative cap as live-mode knocks, for the same reason:
        // anyone guessing passwords already holds the link, so the sharing
        // channel is compromised. Destroying the secret and telling the
        // sender beats leaving an attacker to grind at the rate limit for
        // the link's whole lifetime.
        const attempts = ((await this.ctx.storage.get("attempts")) || 0) + 1;
        if (attempts >= MAX_BAD_PW_TOTAL) {
          this.notifySenders({ t: "killed" });
          this.closeAll("too many password attempts");
          await this.tombstone();
          return json(404, { gone: true });
        }
        await this.ctx.storage.put("attempts", attempts);
        // The count is no help to an attacker (they can count their own
        // guesses) and tells a recipient who mistyped what's at stake.
        return json(403, {
          error: "wrong password",
          attemptsRemaining: MAX_BAD_PW_TOTAL - attempts,
        });
      }
    }

    const now = Date.now();
    meta.views -= 1;
    const secret = await this.ctx.storage.get("secret");
    const payload = {
      privatePart: meta.privatePart,
      secret,
      files: meta.files.map((f) => ({
        fileId: f.fileId, meta: f.meta, chunks: f.chunks, size: f.size,
      })),
      viewsRemaining: meta.views,
    };

    if (meta.files.length > 0) {
      // Chunks stay fetchable for a short window, gated by a one-off token.
      const claimToken = b64url(crypto.getRandomValues(new Uint8Array(16)));
      const tokens = (await this.ctx.storage.get("tokens")) || {};
      tokens[claimToken] = now + CLAIM_GRACE_MS;
      payload.claimToken = claimToken;

      if (meta.views < 1) {
        // Final view: drop everything except chunks + tokens, wipe on alarm.
        // The alarm may land past expiresAt — acceptable, the secret metadata
        // is already gone and only the claimant's token can fetch chunks.
        await this.ctx.storage.delete(["meta", "secret", "uploadToken", "senderToken"]);
        await this.ctx.storage.put({ burned: true, tokens });
        await this.ctx.storage.setAlarm(now + CLAIM_GRACE_MS);
      } else {
        await this.ctx.storage.put({ meta, tokens });
        await this.ctx.storage.setAlarm(Math.max(meta.expiresAt, now + CLAIM_GRACE_MS));
      }
    } else if (meta.views < 1) {
      // Final view, nothing left to download: burn immediately.
      await this.tombstone();
    } else {
      await this.ctx.storage.put("meta", meta);
    }

    // A sender tab left open gets the burn-after-reading payoff in real time.
    this.notifySenders({ t: "viewed", viewsRemaining: meta.views });
    if (meta.views < 1) this.closeAll("burned");

    return json(200, payload);
  }

  async uploadChunk(request, buf, fileId, index) {
    const meta = await this.liveMeta();
    if (!meta) return json(404, { gone: true });
    if (meta.ready) return json(409, { error: "already complete" });
    const expected = await this.ctx.storage.get("uploadToken");
    if (!tokenEq(request.headers.get("X-Upload-Token") || "", expected || "")) {
      return json(403, { error: "bad token" });
    }
    const file = meta.files.find((f) => f.fileId === fileId);
    if (!file || index >= file.chunks) return json(400, { error: "bad chunk" });

    // Every chunk's length follows from the declared size — iv + slice + tag,
    // the last slice short — so stored bytes are bounded exactly, not by
    // chunk count × the per-message cap.
    const plainLen = Math.min(CHUNK_PLAINTEXT_BYTES, file.size - index * CHUNK_PLAINTEXT_BYTES);
    if (!buf || buf.byteLength !== GCM_IV_BYTES + plainLen + GCM_TAG_BYTES) {
      return json(400, { error: "bad chunk size" });
    }
    const key = `chunk:${fileId}:${index}`;
    if (await this.ctx.storage.get(key)) return json(200, {}); // idempotent retry
    await this.ctx.storage.put(key, new Uint8Array(buf));
    file.received += 1;
    meta.ready = meta.files.every((f) => f.received === f.chunks);
    await this.ctx.storage.put("meta", meta);
    return json(200, { ready: meta.ready });
  }

  async downloadChunk(request, fileId, index) {
    const tokens = (await this.ctx.storage.get("tokens")) || {};
    const token = request.headers.get("X-Claim-Token") || "";
    const match = Object.keys(tokens).find((t) => tokenEq(t, token));
    if (!match || tokens[match] < Date.now()) return json(403, { error: "bad token" });
    const bytes = await this.ctx.storage.get(`chunk:${fileId}:${index}`);
    if (!bytes) return json(404, { error: "no chunk" });
    return new Response(bytes, {
      headers: {
        "Content-Type": "application/octet-stream",
        "Cache-Control": "no-store",
        ...securityHeaders(),
      },
    });
  }

  // --- Live-mode relay + notifications ---
  //
  // Unlike pastecmd's blind relay, this DO is an active mediator: it knows
  // who the sender is (token), gates recipients (password verifier), and
  // only relays payload/chunks from the authenticated sender to the one
  // approved recipient. Payload content stays opaque — ciphertext plus the
  // private key half, exactly what a stored-mode claim response carries.

  async webSocketMessage(ws, message) {
    const att = this.att(ws);

    if (typeof message !== "string") {
      // Binary = encrypted file chunk. Only the sender may stream, and only
      // to a recipient they have approved.
      if (att.role !== "sender") return;
      if (message.byteLength > MAX_CHUNK_BYTES + LIVE_FRAME_HEADER) return;
      const rec = this.peers("recipient").find((w) => this.att(w).state === "approved");
      if (rec) { try { rec.send(message); } catch {} }
      return;
    }

    if (message.length > MAX_LIVE_MSG_CHARS) return;
    let msg;
    try { msg = JSON.parse(message); } catch { return; }

    if (att.role === "pending") {
      if (msg.t === "sender") return this.wsAuthSender(ws, att, msg);
      if (msg.t === "knock") return this.wsKnock(ws, att, msg);
      try { ws.close(4400, "bad handshake"); } catch {}
      return;
    }

    if (att.role === "sender") {
      if (msg.t === "approve") return this.wsApprove(ws, msg);
      if (msg.t === "deny") return this.wsDeny(ws, msg);
      if (msg.t === "payload") return this.wsPayload(ws, msg);
      return;
    }

    if (att.role === "recipient") {
      if (msg.t === "received" && att.state === "approved") return this.wsReceived(ws);
    }
  }

  async wsAuthSender(ws, att, msg) {
    const expected = await this.ctx.storage.get("senderToken");
    const alive = (await this.liveReg()) || (await this.liveMeta());
    if (!expected || !alive || !tokenEq(msg.token ?? "", expected)) {
      try { ws.close(4003, "denied"); } catch {}
      return;
    }
    ws.serializeAttachment({ ...att, role: "sender" });
    this.sendJson(ws, { t: "ready" });
  }

  async wsKnock(ws, att, msg) {
    const live = await this.liveReg();
    if (!live) {
      this.sendJson(ws, { t: "gone" });
      try { ws.close(4004, "gone"); } catch {}
      return;
    }

    if (live.verifier !== null &&
        !(typeof msg.verifier === "string" && tokenEq(msg.verifier, live.verifier))) {
      // Wrong password: the sender is never bothered. Per-socket and
      // cumulative caps bound online guessing (the WAF rule doesn't see
      // messages inside an established socket).
      const attempts = ((await this.ctx.storage.get("attempts")) || 0) + 1;
      await this.ctx.storage.put("attempts", attempts);
      if (attempts >= MAX_BAD_PW_TOTAL) {
        this.notifySenders({ t: "killed" });
        this.closeAll("too many password attempts");
        await this.tombstone();
        return;
      }
      const tries = (att.tries || 0) + 1;
      ws.serializeAttachment({ ...att, tries });
      this.sendJson(ws, { t: "wrong-password", attemptsRemaining: MAX_BAD_PW_TOTAL - attempts });
      if (tries >= MAX_BAD_PW_PER_SOCKET) { try { ws.close(4003, "too many attempts"); } catch {} }
      return;
    }

    if (this.peers("recipient").length > 0) {
      this.sendJson(ws, { t: "busy" });
      try { ws.close(4005, "busy"); } catch {}
      return;
    }
    const senders = this.peers("sender");
    if (senders.length === 0) {
      this.sendJson(ws, { t: "sender-offline" });
      try { ws.close(4002, "sender-offline"); } catch {}
      return;
    }

    // Each knock gets an id the sender must echo back, so an Approve click
    // releases the secret to the knock the sender actually saw — not to a
    // different recipient who knocked in the instant after the first left.
    const knock = b64url(crypto.getRandomValues(new Uint8Array(9)));
    ws.serializeAttachment({ ...att, role: "recipient", state: "knocking", knock });
    this.sendJson(ws, { t: "waiting" });
    for (const s of senders) this.sendJson(s, { t: "knock", knock, from: att.geo || null });
  }

  knocking(msg) {
    return this.peers("recipient").find((w) => {
      const a = this.att(w);
      return a.state === "knocking" && typeof msg.knock === "string" && a.knock === msg.knock;
    });
  }

  wsApprove(ws, msg) {
    const rec = this.knocking(msg);
    if (!rec) {
      // Tagged with the knock the sender clicked on, so a tab already showing
      // a newer knock ignores this rather than hiding it.
      this.sendJson(ws, { t: "recipient-gone", knock: msg.knock });
      return;
    }
    rec.serializeAttachment({ ...this.att(rec), state: "approved" });
    this.sendJson(rec, { t: "approved" });
    // Only the tab that clicked Approve is told to transmit — with several
    // sender tabs open, exactly one becomes the source.
    this.sendJson(ws, { t: "send-payload" });
  }

  wsDeny(ws, msg) {
    const rec = this.knocking(msg);
    if (!rec) return;
    this.sendJson(rec, { t: "denied" });
    try { rec.close(4006, "denied"); } catch {}
    // The registration survives a deny — the sender can approve a later knock.
    this.notifySenders({ t: "recipient-gone", knock: msg.knock }, ws);
  }

  wsPayload(ws, msg) {
    const rec = this.peers("recipient").find((w) => this.att(w).state === "approved");
    if (!rec) {
      this.sendJson(ws, { t: "recipient-gone" });
      return;
    }
    if (validLivePayload(msg)) return; // malformed — drop silently
    this.sendJson(rec, {
      t: "payload",
      privatePart: msg.privatePart,
      secret: { iv: msg.secret.iv, ct: msg.secret.ct },
      files: msg.files.map((f) => ({
        fileId: f.fileId, meta: { iv: f.meta.iv, ct: f.meta.ct }, chunks: f.chunks, size: f.size,
      })),
    });
  }

  async wsReceived(ws) {
    // Recipient confirmed full delivery: the link's one shot is spent.
    this.notifySenders({ t: "received" });
    this.closeAll("delivered");
    await this.tombstone();
  }

  webSocketClose(ws) {
    this.wsGone(ws);
  }

  webSocketError(ws) {
    this.wsGone(ws);
  }

  wsGone(ws) {
    const att = this.att(ws);
    if (att.role === "recipient") {
      // Mid-knock or mid-delivery drop: tell the sender; the registration
      // stays alive so they can approve a retry (delivery isn't confirmed
      // until the recipient acks, so nothing is considered spent).
      this.notifySenders({ t: "recipient-gone", knock: att.knock });
    } else if (att.role === "sender" && this.peers("sender", ws).length === 0) {
      for (const rec of this.peers("recipient")) {
        this.sendJson(rec, { t: "sender-offline" });
        try { rec.close(4002, "sender-offline"); } catch {}
      }
    }
  }

  async alarm() {
    // A tombstone's own alarm: the retention window is over, free the id.
    if (await this.ctx.storage.get("tombstone")) {
      await this.ctx.storage.deleteAll();
      return;
    }
    // Expiry, or the end of a final view's download grace window.
    this.closeAll("expired");
    await this.tombstone();
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isDev = env.ENVIRONMENT !== "production";

    // Two-hop canonical redirect (same scheme as pastecmd): http→https stays
    // on-host (HSTS preload rule), then www folds into the apex over https.
    // The URL fragment (public key part) survives redirects — browsers
    // re-apply it after following the Location header.
    if (url.protocol === "http:" && !isDev) {
      url.protocol = "https:";
      const headers = { Location: url.toString(), ...securityHeaders(isDev) };
      delete headers["Strict-Transport-Security"];
      return new Response(null, { status: 301, headers });
    }
    if (!isDev && url.hostname !== "passburn.com") {
      url.hostname = "passburn.com";
      return new Response(null, {
        status: 301,
        headers: { Location: url.toString(), ...securityHeaders(isDev) },
      });
    }

    // Live-mode relay / sender notification socket. Browsers enforce no
    // same-origin rule for WS, so check Origin ourselves (pastecmd pattern).
    const live = url.pathname.match(/^\/live\/([A-Za-z0-9_-]{22})$/);
    if (live) {
      if (request.headers.get("Upgrade") !== "websocket") {
        return json(426, { error: "expected websocket" });
      }
      const origin = request.headers.get("Origin");
      if (!isDev && origin && !ALLOWED_ORIGINS.has(origin)) {
        return json(403, { error: "forbidden" });
      }
      const id = env.SECRETS.idFromName(live[1]);
      return env.SECRETS.get(id).fetch(request);
    }

    const api = url.pathname.match(/^\/api\/secrets\/([A-Za-z0-9_-]{22})(\/[A-Za-z0-9_\-/]*)?$/);
    if (api) {
      // No cookies exist, but reject cross-origin browser writes anyway.
      const origin = request.headers.get("Origin");
      if (!isDev && origin && !ALLOWED_ORIGINS.has(origin) && request.method !== "GET") {
        return json(403, { error: "forbidden" });
      }
      const len = parseInt(request.headers.get("Content-Length") || "0", 10);
      if (len > MAX_CREATE_BYTES) return json(413, { error: "too large" });
      // The quota's client identity, set here so a client can't supply its
      // own: whatever X-PB-Client arrived is overwritten.
      const fwd = new Request(request);
      fwd.headers.set("X-PB-Client", request.headers.get("CF-Connecting-IP") || "");
      const id = env.SECRETS.idFromName(api[1]);
      return env.SECRETS.get(id).fetch(fwd);
    }

    // /s/<id> is the view page; the asset is static, the id and key parts are
    // parsed client-side (id from path, public key part from the fragment).
    if (/^\/s\/[A-Za-z0-9_-]{22}$/.test(url.pathname)) {
      // Extensionless on purpose: asking assets for "/view.html" makes the
      // html_handling canonicalizer 307-redirect to "/view", which would
      // replace the /s/<id> path in the browser and lose the id.
      url.pathname = "/view";
      request = new Request(url, request);
    }

    const res = await env.ASSETS.fetch(request);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(securityHeaders(isDev))) headers.set(k, v);
    // Pages hold plaintext once used (a revealed secret, a freshly typed
    // one): no-store keeps them out of the back/forward cache, so the Back
    // button on a shared machine can't restore them. JS/CSS stay cacheable.
    if ((headers.get("Content-Type") || "").startsWith("text/html")) {
      headers.set("Cache-Control", "no-store");
    }
    return new Response(res.body, { status: res.status, headers });
  },
};
