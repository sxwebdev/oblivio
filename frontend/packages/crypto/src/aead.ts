// AES-256-GCM via WebCrypto. We use 12-byte random nonces and the tag is
// concatenated to the ciphertext by the WebCrypto implementation.

import { concat, randomBytes, utf8 } from "./util";

// Encrypt plaintext under key with optional AAD. Returns nonce || ciphertext+tag.
export async function encryptBlob(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array | string,
): Promise<Uint8Array> {
  const nonce = randomBytes(12);
  const ad = typeof aad === "string" ? utf8(aad) : aad;
  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce as unknown as ArrayBuffer,
      additionalData: ad as unknown as ArrayBuffer,
    },
    key,
    plaintext as unknown as ArrayBuffer,
  );
  return concat(nonce, new Uint8Array(ct));
}

// Decrypt a `nonce(12) || ciphertext+tag` envelope.
export async function decryptBlob(
  key: CryptoKey,
  blob: Uint8Array,
  aad: Uint8Array | string,
): Promise<Uint8Array> {
  if (blob.length < 12 + 16) throw new Error("blob too short");
  const nonce = blob.slice(0, 12);
  const ct = blob.slice(12);
  const ad = typeof aad === "string" ? utf8(aad) : aad;
  const pt = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce as unknown as ArrayBuffer,
      additionalData: ad as unknown as ArrayBuffer,
    },
    key,
    ct as unknown as ArrayBuffer,
  );
  return new Uint8Array(pt);
}
