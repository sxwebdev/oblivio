// Key derivation primitives:
//  • Argon2id master_key  ← (master_password, salt_user, params)
//  • HKDF auth_key        ← (master_key, info="oblivio/auth/v2", salt=salt_user)
//  • HKDF blind-index key ← (vault_key, info="oblivio/blind/v2", salt=pepper)
//
// salt for auth_key is the per-user random `salt_user` (used to also be email,
// see plan §4.1). The blind-index key takes a per-user `blind_pepper`
// random — so popular-domain dictionary attacks against a leaked K_blind don't
// work (see plan §4.4 and §6.4 metadata note).
//
// Argon2id runs in WASM via hash-wasm (single-threaded; multithreaded would
// require dedicated workers + COOP/COEP headers — Sprint 4 work).

import { argon2id } from "hash-wasm"
import type { Argon2Params } from "./types"
import { HKDF_AUTH_INFO, HKDF_BLIND_INFO, HKDF_LOGIN_TOTP_INFO } from "./types"
import { utf8 } from "./util"

// Derive a 32-byte master_key from password using Argon2id.
// Returns raw bytes; the caller wraps it into a CryptoKey when needed.
//
// Multi-thread Argon2 only works when the page is crossOriginIsolated
// (COOP/COEP set to same-origin/require-corp). When isolation is missing
// hash-wasm silently falls back; we force p=1 explicitly so the timing
// stays predictable and the user doesn't get a surprise stall.
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: Argon2Params
): Promise<Uint8Array> {
  if (!password) throw new Error("master password required")
  if (salt.length < 16) throw new Error("salt too short")

  let parallelism = params.p
  if (params.forceSingleThread || !pageSupportsMultiThread()) {
    parallelism = 1
  }

  const hash = await argon2id({
    password,
    salt,
    iterations: params.t,
    memorySize: params.mKib,
    parallelism,
    hashLength: 32,
    outputType: "binary",
  })
  return hash as Uint8Array
}

// pageSupportsMultiThread returns true only when the page is
// crossOriginIsolated AND SharedArrayBuffer is available — both required
// for hash-wasm's WASM threads. Server already ships COOP/COEP headers;
// this guard catches the dev or proxy case where they got stripped.
function pageSupportsMultiThread(): boolean {
  try {
    if (typeof globalThis === "undefined") return false
    const g = globalThis as unknown as {
      crossOriginIsolated?: boolean
      SharedArrayBuffer?: unknown
    }
    return Boolean(g.crossOriginIsolated && g.SharedArrayBuffer)
  } catch {
    return false
  }
}

// Promote raw key material into a non-extractable CryptoKey suitable for
// AES-GCM 256.
export async function importMasterKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  )
}

// HKDF-SHA256(ikm, info, salt) → 32 bytes. Used everywhere we need to derive
// a sub-key with domain separation.
export async function hkdfSha256(
  ikm: Uint8Array,
  info: string,
  salt: Uint8Array,
  length = 32
): Promise<Uint8Array> {
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    ikm as unknown as ArrayBuffer,
    "HKDF",
    false,
    ["deriveBits"]
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      info: utf8(info) as unknown as ArrayBuffer,
      salt: salt as unknown as ArrayBuffer,
    },
    ikmKey,
    length * 8
  )
  return new Uint8Array(bits)
}

// auth_key = HKDF-SHA256(master_key, info="oblivio/auth/v2", salt=salt_user).
// salt_user is the same per-user random bytes used by Argon2id; this keeps
// auth_key independent of email so the user can rotate their address without
// re-deriving their server-side credential.
export async function deriveAuthKey(
  masterKey: Uint8Array,
  saltUser: Uint8Array
): Promise<Uint8Array> {
  if (saltUser.length < 16) throw new Error("salt_user too short")
  return hkdfSha256(masterKey, HKDF_AUTH_INFO, saltUser, 32)
}

// HMAC-key for blind index over titles. Derived from vault_key with a
// per-user `pepper` mixed into the HKDF salt. The pepper is stored in
// user_kdf_params on the server and returned at login alongside salt_user;
// without it, two leaked K_blind values for the same vault would still match
// against a domain dictionary. With it, the dictionary attacker also needs
// the per-user pepper.
export async function deriveBlindIndexKey(
  vaultKey: Uint8Array,
  pepper: Uint8Array
): Promise<CryptoKey> {
  if (pepper.length < 16) throw new Error("blind pepper too short")
  const raw = await hkdfSha256(vaultKey, HKDF_BLIND_INFO, pepper, 32)
  return crypto.subtle.importKey(
    "raw",
    raw as unknown as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  )
}

// Login-TOTP wrapping key — derived from auth_key so the server can re-derive
// it during login but cannot derive it from master_password (see plan §5.3).
export async function deriveLoginTotpKey(
  authKey: Uint8Array
): Promise<CryptoKey> {
  const raw = await hkdfSha256(
    authKey,
    HKDF_LOGIN_TOTP_INFO,
    new Uint8Array(0),
    32
  )
  return crypto.subtle.importKey(
    "raw",
    raw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  )
}
