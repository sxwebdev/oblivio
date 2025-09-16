// Minimal crypto worker: HKDF, HMAC-SHA256, XChaCha20-Poly1305 via libsodium, and blind-index token helper
import sodium from "libsodium-wrappers";

type Req =
  | { type: "hkdf"; ikm_b64: string; info: string; len: number; id?: string }
  | { type: "hmac"; key_b64: string; data_b64: string; id?: string }
  | {
      type: "aead-seal";
      key_b64: string;
      nonce_b64: string;
      aad_b64: string;
      pt_b64: string;
      id?: string;
    }
  | {
      type: "aead-open";
      key_b64: string;
      nonce_b64: string;
      aad_b64: string;
      ct_b64: string;
      id?: string;
    }
  | {
      type: "blind-token";
      kSearch_b64: string;
      field: string;
      value_b64: string;
      id?: string;
    };

function b64d(s: string) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function b64e(b: Uint8Array) {
  return btoa(String.fromCharCode(...b));
}
function toBuf(u8: Uint8Array): ArrayBuffer {
  const src = u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
  // Ensure ArrayBuffer type (avoid SharedArrayBuffer typing); copy if needed
  const out = new ArrayBuffer(u8.byteLength);
  new Uint8Array(out).set(new Uint8Array(src));
  return out;
}

async function hkdf(ikm: Uint8Array, info: string, len: number) {
  const key = await crypto.subtle.importKey("raw", toBuf(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      info: new TextEncoder().encode(info),
      salt: new Uint8Array(),
    },
    key,
    len * 8,
  );
  return new Uint8Array(bits);
}

async function hmacSHA256(key: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey(
    "raw",
    toBuf(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", k, toBuf(data));
  return new Uint8Array(sig);
}

async function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
) {
  await sodium.ready;
  if (key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    throw new Error("bad key");
  if (nonce.length !== sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    throw new Error("bad nonce");
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    pt,
    aad,
    null,
    nonce,
    key,
  );
  return ct;
}

async function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
) {
  await sodium.ready;
  if (key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    throw new Error("bad key");
  if (nonce.length !== sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    throw new Error("bad nonce");
  const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ct,
    aad,
    nonce,
    key,
  );
  return pt;
}

async function blindToken(
  kSearch: Uint8Array,
  field: string,
  value: Uint8Array,
) {
  // Derive per-field key: HKDF(kSearch, info = `ix:${field}`) => 32 bytes
  const kf = await hkdf(kSearch, `ix:${field}`, 32);
  // canonicalize value: as-is binary; MAC with HMAC-SHA256
  const mac = await hmacSHA256(kf, value);
  return mac;
}

self.onmessage = async (ev: MessageEvent<Req>) => {
  const msg = ev.data;
  try {
    await sodium.ready;
    if (msg.type === "hkdf") {
      const out = await hkdf(b64d(msg.ikm_b64), msg.info, msg.len);
      (self as any).postMessage({ ok: true, id: msg.id, out_b64: b64e(out) });
      return;
    }
    if (msg.type === "hmac") {
      const out = await hmacSHA256(b64d(msg.key_b64), b64d(msg.data_b64));
      (self as any).postMessage({ ok: true, id: msg.id, mac_b64: b64e(out) });
      return;
    }
    if (msg.type === "aead-seal") {
      const ct = await aeadSeal(
        b64d(msg.key_b64),
        b64d(msg.nonce_b64),
        b64d(msg.aad_b64),
        b64d(msg.pt_b64),
      );
      (self as any).postMessage({ ok: true, id: msg.id, ct_b64: b64e(ct) });
      return;
    }
    if (msg.type === "aead-open") {
      const pt = await aeadOpen(
        b64d(msg.key_b64),
        b64d(msg.nonce_b64),
        b64d(msg.aad_b64),
        b64d(msg.ct_b64),
      );
      (self as any).postMessage({ ok: true, id: msg.id, pt_b64: b64e(pt) });
      return;
    }
    if (msg.type === "blind-token") {
      const out = await blindToken(
        b64d(msg.kSearch_b64),
        msg.field,
        b64d(msg.value_b64),
      );
      (self as any).postMessage({ ok: true, id: msg.id, token_b64: b64e(out) });
      return;
    }
  } catch (e: any) {
    (self as any).postMessage({
      ok: false,
      id: (msg as any).id,
      error: String(e?.message || e),
    });
  }
};

self.addEventListener("unload", () => {
  // zeroize? nothing persisted here
});
