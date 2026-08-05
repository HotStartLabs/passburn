// passburn create page. The secret is encrypted here in the browser before
// anything leaves the page; the server receives ciphertext plus the private
// key half only. The public half goes into the link's #fragment.
//
// Two modes. Stored: ciphertext rests server-side until claimed. Live: the
// server stores NOTHING — this tab registers the link, parks a WebSocket,
// and when the recipient knocks the sender approves and the encrypted
// payload relays through the server between the two tabs. Either way, a
// sender who keeps this tab open watches delivery happen in real time.
(() => {
  const $ = (id) => document.getElementById(id);

  // Browsers that connect but lack WebCrypto would otherwise fail cryptically
  // on the first click — say so up front. (Anything older still — pre-ES6 —
  // never parses this script and lands on its own TLS or blank-page error.)
  if (!(window.crypto && crypto.subtle && window.TextEncoder)) {
    const card = document.createElement("div");
    card.className = "card";
    const head = document.createElement("p");
    const strong = document.createElement("strong");
    strong.textContent = "Your browser is out of date.";
    head.append(strong);
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "passburn encrypts secrets locally in your browser, which needs modern encryption support. Please update your browser to create secure links.";
    card.append(head, hint);
    document.querySelector("main").replaceChildren(card);
    return;
  }

  const CHUNK_SIZE = 256 * 1024;
  const MAX_FILES = 5;
  const MAX_TOTAL_FILE_BYTES = 25 * 1024 * 1024;       // stored mode (rests on disk)
  const MAX_LIVE_TOTAL_FILE_BYTES = 50 * 1024 * 1024;  // live mode (relay only)
  const MAX_TEXT_CHARS = 100_000;

  const fmtSize = (n) => n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB`
    : n >= 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${n} B`;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const attached = []; // { file, row }

  const mode = () => document.querySelector('input[name="mode"]:checked').value;
  const maxFileBytes = () => mode() === "live" ? MAX_LIVE_TOTAL_FILE_BYTES : MAX_TOTAL_FILE_BYTES;

  for (const radio of document.querySelectorAll('input[name="mode"]')) {
    radio.onchange = () => {
      const live = mode() === "live";
      // Views don't apply to live links: each delivery is explicitly approved
      // and the link burns after one confirmed handoff.
      $("views").disabled = live;
      $("caps-hint").textContent = live
        ? "Up to 5 files, 50 MB total — nothing is stored, so keep this tab open until it's delivered. The optional password is never sent to the server."
        : "Up to 5 files, 25 MB total. The optional password is never sent to the server — share it over a different channel than the link.";
      setError("");
      if (totalBytes() > maxFileBytes()) setError("Attachments exceed the 25 MB stored-mode limit.");
    };
  }

  function setError(msg) {
    $("create-err").textContent = msg || "";
    $("create-err").classList.toggle("hidden", !msg);
  }

  function setBusy(msg) {
    $("create-btn").disabled = !!msg;
    $("busy").textContent = msg || "";
    $("busy").classList.toggle("hidden", !msg);
  }

  // Masked by default — this field is filled in front of whoever is standing
  // behind you, and its value protects the link you're about to send.
  $("pw-toggle").onclick = () => {
    const shown = $("password").type === "text";
    $("password").type = shown ? "password" : "text";
    $("pw-toggle").textContent = shown ? "Show" : "Hide";
    $("pw-toggle").setAttribute("aria-label", shown ? "Show password" : "Hide password");
  };

  // --- Password generator: 20 chars, rejection-sampled (no modulo bias) ---
  $("gen-btn").onclick = () => {
    const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+?";
    const limit = Math.floor(256 / charset.length) * charset.length;
    let out = "";
    while (out.length < 20) {
      const [b] = crypto.getRandomValues(new Uint8Array(1));
      if (b < limit) out += charset[b % charset.length];
    }
    const box = $("secret");
    box.value = box.value ? box.value + "\n" + out : out;
    box.dispatchEvent(new Event("input"));
  };

  // --- Attachments ---
  $("file-btn").onclick = () => $("file-input").click();
  $("file-input").onchange = () => {
    for (const f of $("file-input").files) addFile(f);
    $("file-input").value = "";
  };

  function totalBytes() {
    return attached.reduce((n, a) => n + a.file.size, 0);
  }

  function addFile(file) {
    setError("");
    if (attached.length >= MAX_FILES) return setError(`Up to ${MAX_FILES} files per link.`);
    if (totalBytes() + file.size > maxFileBytes()) {
      return setError(`Attachments are limited to ${maxFileBytes() / 1024 / 1024} MB total.`);
    }
    const row = document.createElement("div");
    row.className = "transfer";
    const info = document.createElement("div");
    info.className = "t-info";
    const nameEl = document.createElement("div");
    nameEl.className = "t-name";
    nameEl.textContent = file.name;
    const subEl = document.createElement("div");
    subEl.className = "t-sub";
    subEl.textContent = fmtSize(file.size);
    info.append(nameEl, subEl);
    const rm = document.createElement("button");
    rm.textContent = "Remove";
    rm.onclick = () => {
      const i = attached.findIndex((a) => a.row === row);
      if (i >= 0) attached.splice(i, 1);
      row.remove();
    };
    row.append(info, rm);
    $("file-list").append(row);
    attached.push({ file, row });
  }

  // --- Create ---
  $("create-btn").onclick = async () => {
    setError("");
    const text = $("secret").value;
    if (!text && attached.length === 0) {
      return setError("Enter a secret or attach a file first.");
    }
    if (text.length > MAX_TEXT_CHARS) {
      return setError("Text secrets are limited to 100,000 characters.");
    }
    if (totalBytes() > maxFileBytes()) {
      return setError(`Attachments are limited to ${maxFileBytes() / 1024 / 1024} MB total in this mode.`);
    }
    try {
      if (mode() === "live") await createLive(text);
      else await create(text);
    } catch (e) {
      setBusy("");
      setError("Something went wrong — the link was not created. " + (e.message || ""));
    }
  };

  async function create(text) {
    const id = PB.b64url.encode(PB.randomBytes(16));
    const pubBytes = PB.randomBytes(16);
    const privBytes = PB.randomBytes(16);

    let pwParts = null;
    const password = $("password").value;
    if (password) {
      setBusy("Strengthening password (PBKDF2)…");
      pwParts = await PB.passwordParts(password, id);
    }
    setBusy("Encrypting in your browser…");
    const key = await PB.deriveKey(pubBytes, privBytes, pwParts && pwParts.keyInput, id);
    const enc = await PB.encrypt(key, PB.te.encode(text), PB.aadSecret());

    const manifest = [];
    for (const a of attached) {
      const fileIdBytes = PB.randomBytes(6);
      const chunks = Math.max(1, Math.ceil(a.file.size / CHUNK_SIZE));
      const metaPlain = PB.te.encode(JSON.stringify({
        name: a.file.name, size: a.file.size, mime: a.file.type, chunks,
      }));
      const meta = await PB.encrypt(key, metaPlain, PB.aadMeta(fileIdBytes));
      manifest.push({
        fileIdBytes, chunks, file: a.file, row: a.row,
        wire: {
          fileId: PB.b64url.encode(fileIdBytes),
          meta: { iv: PB.b64url.encode(meta.iv), ct: PB.b64url.encode(meta.ct) },
          chunks,
          size: a.file.size,
        },
      });
    }

    setBusy("Creating link…");
    const res = await fetch(`/api/secrets/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        privatePart: PB.b64url.encode(privBytes),
        secret: { iv: PB.b64url.encode(enc.iv), ct: PB.b64url.encode(enc.ct) },
        verifier: pwParts ? pwParts.verifier : null,
        expiresIn: parseInt($("expiry").value, 10),
        views: parseInt($("views").value, 10),
        files: manifest.map((m) => m.wire),
      }),
    });
    if (!res.ok) throw new Error(`server said ${res.status}`);
    const { senderToken, uploadToken } = await res.json();

    for (const m of manifest) {
      const bar = document.createElement("div");
      bar.className = "bar";
      bar.append(document.createElement("i"));
      m.row.querySelector(".t-info").append(bar);
      for (let i = 0; i < m.chunks; i++) {
        setBusy(`Encrypting & uploading ${m.file.name} (${i + 1}/${m.chunks})…`);
        const buf = await m.file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE).arrayBuffer();
        const c = await PB.encrypt(key, new Uint8Array(buf), PB.aadChunk(m.fileIdBytes, i));
        const up = await fetch(`/api/secrets/${id}/chunks/${m.wire.fileId}/${i}`, {
          method: "PUT",
          headers: { "X-Upload-Token": uploadToken },
          body: PB.concat(c.iv, c.ct),
        });
        if (!up.ok) throw new Error("upload failed");
        bar.querySelector("i").style.width = `${Math.round((i + 1) / m.chunks * 100)}%`;
      }
      bar.remove();
      m.row.querySelector(".t-sub").textContent = `${fmtSize(m.file.size)} · encrypted & uploaded ✓`;
      m.row.querySelector("button").remove();
    }

    setBusy("");
    showResult(id, PB.b64url.encode(pubBytes), false);
    startSender({ live: false, id, senderToken });
  }

  async function createLive(text) {
    const id = PB.b64url.encode(PB.randomBytes(16));
    const pubBytes = PB.randomBytes(16);
    const privBytes = PB.randomBytes(16);

    let pwParts = null;
    const password = $("password").value;
    if (password) {
      setBusy("Strengthening password (PBKDF2)…");
      pwParts = await PB.passwordParts(password, id);
    }

    // Registration stores no key material and no ciphertext — only the
    // password verifier and an expiry. The secret stays in this tab.
    setBusy("Registering live link…");
    const res = await fetch(`/api/secrets/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: "live",
        verifier: pwParts ? pwParts.verifier : null,
        expiresIn: parseInt($("expiry").value, 10),
      }),
    });
    if (!res.ok) throw new Error(`server said ${res.status}`);
    const { senderToken } = await res.json();

    setBusy("");
    showResult(id, PB.b64url.encode(pubBytes), true);
    startSender({
      live: true, id, senderToken, pubBytes, privBytes,
      keyInput: pwParts && pwParts.keyInput, text,
    });
  }

  function showResult(id, pub, live) {
    const link = `${location.origin}/s/${id}#${pub}`;
    $("create-card").classList.add("hidden");
    $("result-card").classList.remove("hidden");
    $("sender-panel").classList.remove("hidden");
    $("link-out").value = link;

    const expiryLabel = $("expiry").selectedOptions[0].textContent;
    if (live) {
      $("summary").textContent =
        `Live link — delivered straight from this tab when you approve · dies in ${expiryLabel}` +
        ($("password").value ? " · password required" : "");
      $("result-warn").textContent =
        "Keep this tab open: the secret exists only here. Close it and the link is dead — nothing was ever stored on a server.";
    } else {
      const views = parseInt($("views").value, 10);
      $("summary").textContent =
        `Burns after ${views} view${views === 1 ? "" : "s"} · expires in ${expiryLabel}` +
        ($("password").value ? " · password required" : "");
    }

    // QR for phone handoff — drawn to canvas directly (Trusted Types safe).
    const qr = qrcode(0, "M");
    qr.addData(link);
    qr.make();
    const n = qr.getModuleCount();
    const scale = 6;
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = n * scale;
    const g = canvas.getContext("2d");
    g.fillStyle = "#fff";
    g.fillRect(0, 0, canvas.width, canvas.height);
    g.fillStyle = "#000";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) g.fillRect(c * scale, r * scale, scale, scale);
      }
    }
    $("qr-holder").replaceChildren(canvas);

    $("copy-link").onclick = async () => {
      try {
        await navigator.clipboard.writeText(link);
        $("copy-link").textContent = "Copied!";
      } catch {
        $("copy-link").textContent = "Copy failed";
      }
      setTimeout(() => { $("copy-link").textContent = "Copy link"; }, 1500);
    };
    // mailto: is composed entirely client-side in the SENDER's own mail
    // client — the link (and its key-bearing fragment) never touches our
    // server, so the zero-knowledge property holds.
    $("email-link").onclick = () => {
      const subject = "A secure one-time link for you";
      const body =
        "Hi,\n\n" +
        "I'm sending you something confidential through a secure one-time link.\n\n" +
        "Open it here (works once, then it's permanently destroyed):\n" +
        link + "\n\n" +
        (live
          ? "It's a live link: I have to be online to release it, so it works while I have my tab open — if it says the sender is offline, ping me.\n\n"
          : "") +
        ($("password").value
          ? "It's also protected by a password — I'll send that separately.\n\n"
          : "") +
        (live
          ? ""
          : `The link expires in ${expiryLabel} even if unopened, so please open it soon.\n\n`) +
        "If it says the secret is gone and you never opened it, let me know right away.\n\n" +
        "--\n" +
        "Sent with passburn.com — encrypted in the sender's browser; the server can never read it.";
      location.href = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    };
    $("another").onclick = () => { location.href = "/"; };
  }

  // --- Sender socket: live-mode relay + stored-mode viewed notifications ---
  function startSender(cfg) {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    let ws = null, retryDelay = 500, done = false, sending = false, recipientGone = false;
    const setStatus = (cls, text) => {
      $("ws-status").className = "status-line " + cls;
      $("ws-status").textContent = text;
    };
    const hideKnock = () => $("knock-box").classList.add("hidden");
    const idleText = cfg.live
      ? "Armed — waiting for the recipient to open the link. Keep this tab open."
      : "Watching — you'll see it here the moment your link is viewed.";

    function connect() {
      ws = new WebSocket(`${proto}://${location.host}/live/${cfg.id}`);
      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        retryDelay = 500;
        ws.send(JSON.stringify({ t: "sender", token: cfg.senderToken }));
      };
      ws.onmessage = async (ev) => {
        if (typeof ev.data !== "string") return;
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (msg.t === "ready") {
          setStatus("ok", idleText);
        } else if (msg.t === "knock" && cfg.live) {
          recipientGone = false;
          const geo = msg.from && (msg.from.city || msg.from.country)
            ? ` Request came from ${[msg.from.city, msg.from.country].filter(Boolean).join(", ")}.`
            : "";
          $("knock-from").textContent =
            geo + " Only approve if you expect your recipient right now.";
          $("knock-box").classList.remove("hidden");
          setStatus("warn", "Recipient at the door — approve to send.");
        } else if (msg.t === "recipient-gone") {
          hideKnock();
          if (sending) recipientGone = true;
          else setStatus("", "Recipient left before delivery. " + idleText);
        } else if (msg.t === "send-payload") {
          hideKnock();
          await sendLivePayload();
        } else if (msg.t === "received") {
          done = true;
          setStatus("ok", "Delivered ✓ — the recipient has the secret. This link is now dead.");
        } else if (msg.t === "viewed") {
          setStatus("ok", msg.viewsRemaining === 0
            ? "Viewed just now — burning…"
            : `Viewed just now — ${msg.viewsRemaining} view${msg.viewsRemaining === 1 ? "" : "s"} remaining.`);
        } else if (msg.t === "killed") {
          done = true;
          hideKnock();
          setStatus("err", "Link destroyed: too many wrong password attempts. Someone has the link but not the password — create a fresh one and re-check your channels.");
        }
      };
      ws.onclose = (ev) => {
        if (done) return;
        if (ev.reason === "burned") {
          done = true;
          setStatus("ok", "🔥 Burned — the secret was viewed and destroyed on the server.");
          return;
        }
        if (ev.reason === "delivered") {
          done = true;
          setStatus("ok", "Delivered ✓ — the recipient has the secret. This link is now dead.");
          return;
        }
        if (ev.reason === "expired") {
          done = true;
          hideKnock();
          setStatus("err", "Expired — this link is dead.");
          return;
        }
        hideKnock();
        setStatus("err", "Connection lost — reconnecting…");
        setTimeout(() => { if (!done) connect(); }, retryDelay);
        retryDelay = Math.min(retryDelay * 2, 8000);
      };
    }
    connect();

    $("approve-btn").onclick = () => {
      hideKnock();
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "approve" }));
    };
    $("deny-btn").onclick = () => {
      hideKnock();
      setStatus("", "Denied. " + idleText);
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "deny" }));
    };

    // Encrypt-at-approval: key material and plaintext live only in this tab
    // until the moment the sender releases them into the relay.
    async function sendLivePayload() {
      sending = true;
      recipientGone = false;
      try {
        setStatus("warn", "Encrypting…");
        const key = await PB.deriveKey(cfg.pubBytes, cfg.privBytes, cfg.keyInput, cfg.id);
        const enc = await PB.encrypt(key, PB.te.encode(cfg.text), PB.aadSecret());
        const manifest = [];
        for (const a of attached) {
          const fileIdBytes = PB.randomBytes(6);
          const chunks = Math.max(1, Math.ceil(a.file.size / CHUNK_SIZE));
          const metaPlain = PB.te.encode(JSON.stringify({
            name: a.file.name, size: a.file.size, mime: a.file.type, chunks,
          }));
          const meta = await PB.encrypt(key, metaPlain, PB.aadMeta(fileIdBytes));
          manifest.push({
            fileIdBytes, chunks, file: a.file,
            wire: {
              fileId: PB.b64url.encode(fileIdBytes),
              meta: { iv: PB.b64url.encode(meta.iv), ct: PB.b64url.encode(meta.ct) },
              chunks,
              size: a.file.size,
            },
          });
        }
        ws.send(JSON.stringify({
          t: "payload",
          privatePart: PB.b64url.encode(cfg.privBytes),
          secret: { iv: PB.b64url.encode(enc.iv), ct: PB.b64url.encode(enc.ct) },
          files: manifest.map((m) => m.wire),
        }));

        for (const m of manifest) {
          const row = document.createElement("div");
          row.className = "transfer";
          const info = document.createElement("div");
          info.className = "t-info";
          const nameEl = document.createElement("div");
          nameEl.className = "t-name";
          nameEl.textContent = m.file.name;
          const bar = document.createElement("div");
          bar.className = "bar";
          bar.append(document.createElement("i"));
          info.append(nameEl, bar);
          row.append(info);
          $("send-progress").append(row);
          // Binary frame: fileId(6) | index u32(4) | iv(12) | ciphertext.
          for (let i = 0; i < m.chunks; i++) {
            if (recipientGone || ws.readyState !== WebSocket.OPEN) throw new Error("recipient gone");
            const buf = await m.file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE).arrayBuffer();
            const c = await PB.encrypt(key, new Uint8Array(buf), PB.aadChunk(m.fileIdBytes, i));
            const frame = new Uint8Array(22 + c.ct.byteLength);
            frame.set(m.fileIdBytes, 0);
            frame.set(PB.u32(i), 6);
            frame.set(c.iv, 10);
            frame.set(c.ct, 22);
            // Backpressure: don't buffer the whole file into the socket at once.
            while (ws.bufferedAmount > 4 * CHUNK_SIZE) {
              if (recipientGone || ws.readyState !== WebSocket.OPEN) throw new Error("recipient gone");
              await sleep(50);
            }
            ws.send(frame.buffer);
            bar.querySelector("i").style.width = `${Math.round((i + 1) / m.chunks * 100)}%`;
          }
          bar.remove();
        }
        setStatus("warn", "Sent — waiting for the recipient to confirm…");
      } catch {
        $("send-progress").replaceChildren();
        setStatus("err", "Delivery interrupted — the recipient disconnected. The link is still armed; they can knock again.");
      }
      sending = false;
    }
  }
})();
