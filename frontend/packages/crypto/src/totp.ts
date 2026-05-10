// TOTP — RFC 6238 with HMAC-SHA1 (default for authenticator apps).
//
// This module is consumed in two places:
//   1. Vault entries with kind='login' (or kind='totp') that store a TOTP
//      secret in their plaintext payload. The client decrypts the entry and
//      renders the live 6-digit code with a refresh countdown.
//   2. Login-TOTP wrap helpers (§5.3 of the plan). The TOTP secret protecting
//      the user's account login lives encrypted on the server under
//      K_login_totp = HKDF(auth_key, "oblivio/login-totp/v1"). The client
//      derives K_login_totp during Authorize and ships the encrypted secret
//      to the server; the server can re-derive K_login_totp from auth_key it
//      receives at login time, but never persists either key.

import { encryptBlob, decryptBlob } from "./aead"

// RFC 4648 base32 — uppercase, no padding when normalising user input.
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// normalizeBase32 strips spaces, dashes and padding, uppercases and validates
// the alphabet. Returns the canonical string a TOTP secret should be stored as.
export function normalizeBase32(secret: string): string {
  const s = secret.replace(/[\s\-=]/g, "").toUpperCase()
  for (let i = 0; i < s.length; i++) {
    if (!ALPHABET.includes(s[i])) {
      throw new Error(`invalid base32 character: ${s[i]}`)
    }
  }
  return s
}

// decodeBase32 turns a normalised base32 string into raw bytes.
export function decodeBase32(secret: string): Uint8Array {
  const s = normalizeBase32(secret)
  const out: number[] = []
  let buf = 0
  let bits = 0
  for (let i = 0; i < s.length; i++) {
    const v = ALPHABET.indexOf(s[i])
    buf = (buf << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((buf >> bits) & 0xff)
    }
  }
  return new Uint8Array(out)
}

// encodeBase32 produces an unpadded RFC 4648 base32 string.
export function encodeBase32(bytes: Uint8Array): string {
  let buf = 0
  let bits = 0
  let out = ""
  for (let i = 0; i < bytes.length; i++) {
    buf = (buf << 8) | bytes[i]
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET[(buf >> bits) & 0x1f]
    }
  }
  if (bits > 0) {
    out += ALPHABET[(buf << (5 - bits)) & 0x1f]
  }
  return out
}

// generateTotpSecret returns 20 random bytes (160 bits) — the size
// recommended by RFC 4226 §4 — encoded as base32 for QR display.
export function generateTotpSecret(): string {
  const raw = new Uint8Array(20)
  crypto.getRandomValues(raw)
  return encodeBase32(raw)
}

export type TotpOptions = {
  digits?: number // default 6
  period?: number // default 30s
  // Algorithm fixed to SHA-1 — virtually every authenticator app supports
  // only SHA-1. SHA-256/512 are stubbed for future use but not exposed.
}

// generateTotpCode implements RFC 6238 with HMAC-SHA1.
// `secret` is base32 (the canonical form returned by generateTotpSecret).
// `now` defaults to the current time; pass a fixed Date for testing.
export async function generateTotpCode(
  secret: string,
  now: Date = new Date(),
  opts: TotpOptions = {}
): Promise<string> {
  const digits = opts.digits ?? 6
  const period = opts.period ?? 30
  const counter = Math.floor(now.getTime() / 1000 / period)
  return hotp(decodeBase32(secret), counter, digits)
}

// totpRemainingSeconds returns how many seconds are left in the current step.
// Use this to drive the countdown ring in the UI.
export function totpRemainingSeconds(
  now: Date = new Date(),
  period = 30
): number {
  const epoch = Math.floor(now.getTime() / 1000)
  return period - (epoch % period)
}

// hotp implements RFC 4226 using WebCrypto HMAC-SHA1.
async function hotp(
  key: Uint8Array,
  counter: number,
  digits: number
): Promise<string> {
  // 8-byte big-endian counter.
  const ctr = new Uint8Array(8)
  // JavaScript bitwise ops are 32-bit so we use Math.floor for the high half.
  let v = counter
  for (let i = 7; i >= 0; i--) {
    ctr[i] = v & 0xff
    v = Math.floor(v / 256)
  }
  const k = await crypto.subtle.importKey(
    "raw",
    key as unknown as ArrayBuffer,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  )
  const sigBuf = await crypto.subtle.sign(
    "HMAC",
    k,
    ctr as unknown as ArrayBuffer
  )
  const sig = new Uint8Array(sigBuf)
  // Dynamic truncation (RFC 4226 §5.3).
  const off = sig[sig.length - 1] & 0x0f
  const code =
    ((sig[off] & 0x7f) << 24) |
    ((sig[off + 1] & 0xff) << 16) |
    ((sig[off + 2] & 0xff) << 8) |
    (sig[off + 3] & 0xff)
  const mod = 10 ** digits
  return String(code % mod).padStart(digits, "0")
}

// Login-TOTP wrap (§5.3). Encrypts a TOTP secret with K_login_totp derived
// from auth_key. Returns the raw envelope: nonce || ct+tag.
//
// AAD = "oblivio/login-totp/v1" — a fixed label so the server can verify
// integrity without per-user material. The K_login_totp itself is per-user
// because it is derived from auth_key, so this is safe.
const LOGIN_TOTP_AAD = "oblivio/login-totp/v1"

export async function wrapLoginTotpSecret(
  loginTotpKey: CryptoKey,
  secret: string
): Promise<Uint8Array> {
  const normalized = normalizeBase32(secret)
  const enc = new TextEncoder().encode(normalized)
  return encryptBlob(loginTotpKey, enc, LOGIN_TOTP_AAD)
}

export async function unwrapLoginTotpSecret(
  loginTotpKey: CryptoKey,
  blob: Uint8Array
): Promise<string> {
  const pt = await decryptBlob(loginTotpKey, blob, LOGIN_TOTP_AAD)
  return new TextDecoder().decode(pt)
}

// otpauthURI builds an `otpauth://` URI for QR-code display so the user can
// register the secret in an authenticator app on enrolment.
export function otpauthURI(opts: {
  issuer: string
  account: string
  secret: string
  digits?: number
  period?: number
}): string {
  const label = encodeURIComponent(`${opts.issuer}:${opts.account}`)
  const params = new URLSearchParams({
    secret: normalizeBase32(opts.secret),
    issuer: opts.issuer,
    algorithm: "SHA1",
    digits: String(opts.digits ?? 6),
    period: String(opts.period ?? 30),
  })
  return `otpauth://totp/${label}?${params.toString()}`
}
