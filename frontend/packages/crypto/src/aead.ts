// AES-256-GCM via WebCrypto with a 1-byte version prefix.
// Envelope layout: version(1) || nonce(12) || ciphertext+tag.

import { ENVELOPE_VERSION_V1 } from "./types"
import { concat, randomBytes, utf8 } from "./util"

// Encrypt plaintext under key with optional AAD.
// Returns version(1) || nonce(12) || ciphertext+tag.
export async function encryptBlob(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array | string
): Promise<Uint8Array> {
  const nonce = randomBytes(12)
  const ad = typeof aad === "string" ? utf8(aad) : aad
  const ct = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce as unknown as ArrayBuffer,
      additionalData: ad as unknown as ArrayBuffer,
    },
    key,
    plaintext as unknown as ArrayBuffer
  )
  return concat(
    new Uint8Array([ENVELOPE_VERSION_V1]),
    nonce,
    new Uint8Array(ct)
  )
}

// Decrypt a `version(1) || nonce(12) || ciphertext+tag` envelope.
// Unknown versions are rejected so a future protocol upgrade can co-exist.
export async function decryptBlob(
  key: CryptoKey,
  blob: Uint8Array,
  aad: Uint8Array | string
): Promise<Uint8Array> {
  if (blob.length < 1 + 12 + 16) throw new Error("blob too short")
  const version = blob[0]
  if (version !== ENVELOPE_VERSION_V1) {
    throw new Error(`unsupported envelope version 0x${version.toString(16)}`)
  }
  const nonce = blob.slice(1, 1 + 12)
  const ct = blob.slice(1 + 12)
  const ad = typeof aad === "string" ? utf8(aad) : aad
  const pt = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce as unknown as ArrayBuffer,
      additionalData: ad as unknown as ArrayBuffer,
    },
    key,
    ct as unknown as ArrayBuffer
  )
  return new Uint8Array(pt)
}
