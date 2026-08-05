// passburn shared crypto. All encryption happens in the browser with
// AES-256-GCM. The key is HKDF-derived from two random halves: the PUBLIC
// part lives only in the URL fragment (never sent to any server), the
// PRIVATE part is stored server-side with the ciphertext. Optionally a
// password mixes in a third, PBKDF2-stretched input. Symmetric-only crypto:
// post-quantum resistant by construction (Grover leaves a 128-bit margin).
const PB = (() => {
  const te = new TextEncoder(), td = new TextDecoder();

  const b64url = {
    encode(buf) {
      const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
      // Chunked: String.fromCharCode(...bytes) overflows the argument limit
      // on large buffers.
      let s = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
    decode(str) {
      return Uint8Array.from(
        atob(str.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    },
  };

  const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

  const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };

  const u32 = (n) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return b;
  };

  // AAD context labels bind every ciphertext to its role, so a blob can never
  // be replayed as a different type or a chunk moved to a different position.
  const aadSecret = () => te.encode("secret-v1");
  const aadMeta = (fileId) => concat(te.encode("meta-v1"), fileId);
  const aadChunk = (fileId, index) => concat(te.encode("chunk-v1"), fileId, u32(index));

  async function deriveKey(pubBytes, privBytes, keyInput, idStr) {
    const ikm = keyInput
      ? concat(pubBytes, privBytes, keyInput)
      : concat(pubBytes, privBytes);
    const hk = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: te.encode(idStr), info: te.encode("passburn-v1") },
      hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // Password → two independent HKDF outputs: a verifier the server stores to
  // gate the claim (so a wrong password doesn't burn the view), and a key
  // input mixed into the encryption key. The verifier reveals nothing about
  // the key material.
  async function passwordParts(password, idStr) {
    const pw = await crypto.subtle.importKey(
      "raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: te.encode("pb-pw:" + idStr), iterations: 600_000 },
      pw, 256);
    const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveBits"]);
    const derive = (info) => crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: te.encode(idStr), info: te.encode(info) }, hk, 256);
    return {
      verifier: b64url.encode(await derive("pb-verify")),
      keyInput: new Uint8Array(await derive("pb-key")),
    };
  }

  async function encrypt(key, bytes, aad) {
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad }, key, bytes);
    return { iv, ct: new Uint8Array(ct) };
  }

  async function decrypt(key, iv, ct, aad) {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad }, key, ct));
  }

  return {
    te, td, b64url, randomBytes, concat, u32,
    aadSecret, aadMeta, aadChunk, deriveKey, passwordParts, encrypt, decrypt,
  };
})();
