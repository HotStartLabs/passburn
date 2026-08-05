// passburn view page. Two-phase reveal: this page is a static asset and the
// GET that loads it burns nothing — email scanners and link unfurlers that
// pre-fetch URLs see only the confirmation screen. Only an explicit action
// (POST /claim for stored links, a WebSocket knock for live links) consumes
// the secret. Decryption needs the public key half from the URL fragment,
// which never reached the server.
(() => {
  const $ = (id) => document.getElementById(id);

  // Same guard as app.js — and reassure the recipient: loading this page
  // burns nothing, so they can update and reopen the same link.
  if (!(window.crypto && crypto.subtle && window.TextEncoder)) {
    const card = document.createElement("div");
    card.className = "card";
    const head = document.createElement("p");
    const strong = document.createElement("strong");
    strong.textContent = "Your browser is out of date.";
    head.append(strong);
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "This secret can only be decrypted in your browser, which needs modern encryption support. Update your browser and reopen the link — the secret has not been used up.";
    card.append(head, hint);
    document.querySelector("main").replaceChildren(card);
    return;
  }

  const show = (id) => {
    for (const card of document.querySelectorAll("main .card")) card.classList.add("hidden");
    $(id).classList.remove("hidden");
  };
  const fmtSize = (n) => n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB`
    : n >= 1e3 ? `${(n / 1e3).toFixed(0)} KB` : `${n} B`;

  const idMatch = location.pathname.match(/^\/s\/([A-Za-z0-9_-]{22})$/);
  const pubMatch = location.hash.match(/^#([A-Za-z0-9_-]{22})$/);
  if (!idMatch || !pubMatch) { show("bad-card"); return; }
  const id = idMatch[1];
  const pubBytes = PB.b64url.decode(pubMatch[1]);

  let requiresPassword = false;
  let mode = "stored";

  init();
  async function init() {
    let res;
    try {
      res = await fetch(`/api/secrets/${id}/status`);
    } catch {
      $("bad-text").textContent = "Couldn't reach the server. Check your connection and reload.";
      show("bad-card");
      return;
    }
    if (!res.ok) { show("gone-card"); return; }
    const status = await res.json();
    mode = status.mode || "stored";
    requiresPassword = status.requiresPassword;

    if (mode === "live") {
      if (!status.senderOnline) { show("live-offline-card"); return; }
      $("pw-row").classList.toggle("hidden", !requiresPassword);
      $("reveal-hint").textContent =
        "This is a live link: the secret sits in the sender's open browser tab — never on a server — " +
        "and is relayed to you the moment they approve. The sender will see your request in real time.";
      show("reveal-card");
      return;
    }

    if (!status.ready) { show("not-ready-card"); return; }
    $("pw-row").classList.toggle("hidden", !requiresPassword);
    $("reveal-hint").textContent = status.viewsRemaining === 1
      ? "This link allows a single view. Once you reveal the secret, it is permanently destroyed on the server."
      : `This link allows ${status.viewsRemaining} more views, then the secret is permanently destroyed.`;
    if (status.hasFiles) $("reveal-hint").textContent += " It includes file attachments.";
    show("reveal-card");
  }

  $("retry-ready").onclick = () => { location.reload(); };
  $("retry-live").onclick = () => { location.reload(); };

  // Masked by default; reveal to check a fiddly password before spending an
  // attempt (too many wrong ones destroy the secret).
  $("pw-toggle").onclick = () => {
    const shown = $("pw-input").type === "text";
    $("pw-input").type = shown ? "password" : "text";
    $("pw-toggle").textContent = shown ? "Show" : "Hide";
    $("pw-toggle").setAttribute("aria-label", shown ? "Show password" : "Hide password");
  };

  $("reveal-btn").onclick = async () => {
    $("reveal-err").classList.add("hidden");
    $("reveal-btn").disabled = true;
    try {
      if (mode === "live") await revealLive();
      else await reveal();
    } catch {
      $("bad-text").textContent =
        "Decryption failed. The link may be incomplete or corrupted — ask the sender for a fresh one.";
      show("bad-card");
    }
    $("reveal-btn").disabled = false;
  };

  function revealError(msg) {
    $("reveal-err").textContent = msg;
    $("reveal-err").classList.remove("hidden");
  }

  // Wrong guesses never consume a view, but they are capped: past the limit
  // the secret self-destructs, so say how much room is left.
  function wrongPasswordText(msg) {
    const left = msg && msg.attemptsRemaining;
    if (!Number.isInteger(left)) return "Wrong password — nothing was used up. Try again.";
    return `Wrong password — nothing was used up. ${left} attempt${left === 1 ? "" : "s"} left before this secret is destroyed.`;
  }

  async function passwordVerifier() {
    if (!requiresPassword) return null;
    if (!$("pw-input").value) { revealError("Enter the password first."); return false; }
    $("reveal-btn").textContent = "Checking password…";
    const pwParts = await PB.passwordParts($("pw-input").value, id);
    $("reveal-btn").textContent = "Reveal secret";
    return pwParts;
  }

  // --- Stored mode: claim over HTTP ---
  async function reveal() {
    const pwParts = await passwordVerifier();
    if (pwParts === false) return;

    const res = await fetch(`/api/secrets/${id}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pwParts ? { verifier: pwParts.verifier } : {}),
    });
    if (res.status === 403) { revealError(wrongPasswordText(await res.json().catch(() => ({})))); return; }
    if (res.status === 409) { show("not-ready-card"); return; }
    if (!res.ok) { show("gone-card"); return; }
    const payload = await res.json();

    const key = await PB.deriveKey(
      pubBytes, PB.b64url.decode(payload.privatePart),
      pwParts && pwParts.keyInput, id);
    const text = PB.td.decode(await PB.decrypt(
      key, PB.b64url.decode(payload.secret.iv), PB.b64url.decode(payload.secret.ct),
      PB.aadSecret()));

    showSecret(text, payload.viewsRemaining === 0
      ? "This secret has now been destroyed on the server. Save what you need before closing this page."
      : `${payload.viewsRemaining} view${payload.viewsRemaining === 1 ? "" : "s"} remaining before this secret is destroyed.`);

    for (const f of payload.files) {
      await storedFileRow(key, f, payload.claimToken);
    }
  }

  // --- Live mode: knock over WebSocket, sender approves, payload relays ---
  async function revealLive() {
    const pwParts = await passwordVerifier();
    if (pwParts === false) return;

    show("wait-card");
    $("wait-text").textContent = "Contacting the sender…";

    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/live/${id}`);
    ws.binaryType = "arraybuffer";

    let key = null;
    let settled = false; // a terminal card has been shown
    const incoming = new Map(); // fileId -> { fileIdBytes, chunks, parts, got, row-parts }
    let expectFiles = 0, doneFiles = 0, gotPayload = false;

    const settle = (fn) => { settled = true; fn(); };

    ws.onopen = () => {
      ws.send(JSON.stringify({ t: "knock", verifier: pwParts ? pwParts.verifier : null }));
    };

    ws.onclose = () => {
      if (settled) return;
      $("bad-text").textContent = gotPayload
        ? "The connection dropped before all attachments arrived. The link is still usable — reload and knock again."
        : "The connection dropped before delivery. The link is still usable — reload and try again.";
      show("bad-card");
    };

    ws.onmessage = async (ev) => {
      if (ev.data instanceof ArrayBuffer) return onChunk(ev.data);
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      switch (msg.t) {
        case "waiting":
          $("wait-text").textContent =
            "The sender has been notified. Waiting for them to approve — keep this tab open.";
          break;
        case "approved":
          $("wait-text").textContent = "Approved — receiving…";
          break;
        case "wrong-password":
          settle(() => {
            show("reveal-card");
            revealError(wrongPasswordText(msg));
          });
          try { ws.close(); } catch {}
          break;
        case "busy":
          settle(() => {
            $("bad-text").textContent =
              "Someone else is receiving this secret right now. If that isn't you on another device, tell the sender immediately.";
            show("bad-card");
          });
          break;
        case "sender-offline":
          settle(() => show("live-offline-card"));
          break;
        case "denied":
          settle(() => show("denied-card"));
          break;
        case "gone":
          settle(() => show("gone-card"));
          break;
        case "payload":
          try {
            await onPayload(msg);
          } catch {
            settle(() => {
              $("bad-text").textContent =
                "Decryption failed. The link may be incomplete or corrupted — ask the sender for a fresh one.";
              show("bad-card");
            });
          }
          break;
      }
    };

    async function onPayload(msg) {
      key = await PB.deriveKey(
        pubBytes, PB.b64url.decode(msg.privatePart), pwParts && pwParts.keyInput, id);
      const text = PB.td.decode(await PB.decrypt(
        key, PB.b64url.decode(msg.secret.iv), PB.b64url.decode(msg.secret.ct),
        PB.aadSecret()));

      gotPayload = true;
      expectFiles = msg.files.length;
      settle(() => showSecret(text,
        "Delivered live from the sender's device — the secret was never stored on any server. This link is now dead."));

      for (const f of msg.files) {
        const fileIdBytes = PB.b64url.decode(f.fileId);
        const meta = JSON.parse(PB.td.decode(await PB.decrypt(
          key, PB.b64url.decode(f.meta.iv), PB.b64url.decode(f.meta.ct),
          PB.aadMeta(fileIdBytes))));
        const row = document.createElement("div");
        row.className = "transfer";
        const info = document.createElement("div");
        info.className = "t-info";
        const nameEl = document.createElement("div");
        nameEl.className = "t-name";
        nameEl.textContent = meta.name;
        const subEl = document.createElement("div");
        subEl.className = "t-sub";
        subEl.textContent = fmtSize(meta.size);
        const bar = document.createElement("div");
        bar.className = "bar";
        bar.append(document.createElement("i"));
        info.append(nameEl, subEl, bar);
        row.append(info);
        $("attachments").append(row);
        incoming.set(f.fileId, {
          fileIdBytes, meta, chunks: f.chunks,
          parts: new Array(f.chunks), got: 0, row, subEl, bar,
        });
      }
      if (expectFiles === 0) confirmReceived();
    }

    async function onChunk(buf) {
      if (!key || buf.byteLength < 23) return;
      const fileId = PB.b64url.encode(new Uint8Array(buf, 0, 6));
      const t = incoming.get(fileId);
      if (!t) return;
      const index = new DataView(buf).getUint32(6);
      if (index >= t.chunks || t.parts[index]) return;
      let plain;
      try {
        plain = await PB.decrypt(
          key, new Uint8Array(buf, 10, 12), new Uint8Array(buf, 22),
          PB.aadChunk(t.fileIdBytes, index));
      } catch { return; /* tampered or misplaced chunk — ignore */ }
      t.parts[index] = plain;
      t.got++;
      t.bar.querySelector("i").style.width = `${Math.round(t.got / t.chunks * 100)}%`;
      if (t.got === t.chunks) {
        t.bar.remove();
        const blob = new Blob(t.parts, { type: t.meta.mime || "application/octet-stream" });
        const btn = document.createElement("button");
        btn.className = "primary";
        btn.textContent = "Download";
        btn.onclick = () => {
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = t.meta.name || "file";
          a.click();
        };
        t.row.append(btn);
        t.subEl.textContent = `${fmtSize(t.meta.size)} · decrypted ✓`;
        doneFiles++;
        if (doneFiles === expectFiles) confirmReceived();
      }
    }

    function confirmReceived() {
      // The ack is what burns the link — only a fully delivered secret is spent.
      try { ws.send(JSON.stringify({ t: "received" })); } catch {}
    }
  }

  function showSecret(text, note) {
    if (text) {
      $("secret-out").value = text;
      $("secret-out").classList.remove("hidden");
      $("copy-btn").classList.remove("hidden");
    } else {
      $("secret-out").classList.add("hidden");
      $("copy-btn").classList.add("hidden");
    }
    $("burn-note").textContent = note;
    show("secret-card");
  }

  $("copy-btn").onclick = async () => {
    try {
      await navigator.clipboard.writeText($("secret-out").value);
      $("copy-btn").textContent = "Copied!";
    } catch {
      $("copy-btn").textContent = "Copy failed";
    }
    setTimeout(() => { $("copy-btn").textContent = "Copy"; }, 1500);
  };

  async function storedFileRow(key, f, claimToken) {
    const fileIdBytes = PB.b64url.decode(f.fileId);
    const meta = JSON.parse(PB.td.decode(await PB.decrypt(
      key, PB.b64url.decode(f.meta.iv), PB.b64url.decode(f.meta.ct),
      PB.aadMeta(fileIdBytes))));

    const row = document.createElement("div");
    row.className = "transfer";
    const info = document.createElement("div");
    info.className = "t-info";
    const nameEl = document.createElement("div");
    nameEl.className = "t-name";
    nameEl.textContent = meta.name;
    const subEl = document.createElement("div");
    subEl.className = "t-sub";
    subEl.textContent = fmtSize(meta.size);
    const bar = document.createElement("div");
    bar.className = "bar hidden";
    bar.append(document.createElement("i"));
    info.append(nameEl, subEl, bar);
    const btn = document.createElement("button");
    btn.className = "primary";
    btn.textContent = "Download";
    row.append(info, btn);
    $("attachments").append(row);

    btn.onclick = async () => {
      btn.disabled = true;
      bar.classList.remove("hidden");
      try {
        const parts = [];
        for (let i = 0; i < f.chunks; i++) {
          const res = await fetch(`/api/secrets/${id}/chunks/${f.fileId}/${i}`, {
            headers: { "X-Claim-Token": claimToken },
          });
          if (!res.ok) throw new Error("chunk fetch failed");
          const frame = new Uint8Array(await res.arrayBuffer());
          parts.push(await PB.decrypt(
            key, frame.subarray(0, 12), frame.subarray(12), PB.aadChunk(fileIdBytes, i)));
          bar.querySelector("i").style.width = `${Math.round((i + 1) / f.chunks * 100)}%`;
        }
        const blob = new Blob(parts, { type: meta.mime || "application/octet-stream" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = meta.name || "file";
        a.click();
        subEl.textContent = `${fmtSize(meta.size)} · decrypted ✓`;
        btn.disabled = false;
      } catch {
        subEl.textContent = "Download failed — the window may have expired.";
      }
      bar.classList.add("hidden");
    };
  }
})();
