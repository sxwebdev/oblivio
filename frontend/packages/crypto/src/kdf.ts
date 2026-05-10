// Key derivation primitives:
//  • Argon2id master_key  ← (master_password, salt_user, params)
//  • HKDF auth_key        ← (master_key, info="oblivio/auth/v1", salt=email)
//  • HKDF blind-index key ← (vault_key, info="oblivio/blind/v1")
//
// Argon2id runs in WASM via hash-wasm (single-threaded; multithreaded would
// require dedicated workers + COOP/COEP headers — Sprint 4 work).

import { argon2id } from "hash-wasm"
import type { Argon2Params } from "./types"
import { HKDF_AUTH_INFO, HKDF_BLIND_INFO, HKDF_LOGIN_TOTP_INFO } from "./types"
import { utf8 } from "./util"

// Derive a 32-byte master_key from password using Argon2id.
// Returns raw bytes; the caller wraps it into a CryptoKey when needed.
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: Argon2Params
): Promise<Uint8Array> {
  if (!password) throw new Error("master password required")
  if (salt.length < 16) throw new Error("salt too short")
  const hash = await argon2id({
    password,
    salt,
    iterations: params.t,
    memorySize: params.mKib,
    parallelism: params.p,
    hashLength: 32,
    outputType: "binary",
  })
  return hash as Uint8Array
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

// auth_key = HKDF-SHA256(master_key, info="oblivio/auth/v1", salt=email).
// The lower-cased email serves as a per-user domain separator.
export async function deriveAuthKey(
  masterKey: Uint8Array,
  email: string
): Promise<Uint8Array> {
  return hkdfSha256(masterKey, HKDF_AUTH_INFO, utf8(email.toLowerCase()), 32)
}

// HMAC-key for blind index over titles. Derived from vault_key.
export async function deriveBlindIndexKey(
  vaultKey: Uint8Array
): Promise<CryptoKey> {
  const raw = await hkdfSha256(vaultKey, HKDF_BLIND_INFO, new Uint8Array(0), 32)
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
