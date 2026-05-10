// Recovery-code primitives (plan §4.5).
// At registration the client generates a 25-character base32 code displayed
// once to the user. The vault_key is wrapped under a key derived from the
// recovery_code so the user can recover their vault if they forget master_password.

import { argon2id } from "hash-wasm"
import { encryptBlob, decryptBlob } from "./aead"
import { hkdfSha256 } from "./kdf"
import { randomBytes } from "./util"
import { HKDF_AUTH_INFO, RECOVERY_WRAP_AAD } from "./types"

// 25 base32 characters in 5 groups of 5: ~125 bits of entropy.
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // RFC 4648 base32

export function generateRecoveryCode(): string {
  const bytes = randomBytes(16) // 128 random bits → 26 base32 chars
  let s = ""
  for (let i = 0; i < 25; i++) {
    s += ALPHABET[bytes[i % bytes.length] & 0x1f]
  }
  // Group as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
  return [
    s.slice(0, 5),
    s.slice(5, 10),
    s.slice(10, 15),
    s.slice(15, 20),
    s.slice(20, 25),
  ].join("-")
}

// Strip dashes and uppercase the code before any KDF.
export function normalizeRecoveryCode(code: string): string {
  return code.replace(/-/g, "").toUpperCase()
}

// Derive a 32-byte recovery_key from the recovery_code.
// Conservative Argon2id params: matches what the client uses for
// master_password. The code itself has ~125 bits so a faster KDF would
// already be fine, but matching parameters simplifies the audit story.
export async function deriveRecoveryKey(
  code: string,
  salt: Uint8Array,
  iterations = 3,
  memoryKiB = 65536
): Promise<Uint8Array> {
  const hash = await argon2id({
    password: normalizeRecoveryCode(code),
    salt,
    iterations,
    memorySize: memoryKiB,
    parallelism: 1,
    hashLength: 32,
    outputType: "binary",
  })
  return hash as Uint8Array
}

// Wrap vault_key under recovery_key. Stored in user_vault.recovery_wrapped_vault_key.
export async function wrapVaultKeyForRecovery(
  recoveryKeyRaw: Uint8Array,
  vaultKey: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    recoveryKeyRaw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  )
  return encryptBlob(key, vaultKey, RECOVERY_WRAP_AAD)
}

// Unwrap vault_key from a recovery envelope.
export async function unwrapVaultKeyFromRecovery(
  recoveryKeyRaw: Uint8Array,
  wrapped: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    recoveryKeyRaw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  )
  return decryptBlob(key, wrapped, RECOVERY_WRAP_AAD)
}

// recovery_proof = HKDF(recovery_key, "oblivio/auth/v1", new Uint8Array(0)).
// Stored hashed (Argon2id) on the server so the recovery flow can verify the
// user's claim before handing back recovery_wrapped_vault_key.
export async function deriveRecoveryProof(
  recoveryKeyRaw: Uint8Array
): Promise<Uint8Array> {
  return hkdfSha256(recoveryKeyRaw, HKDF_AUTH_INFO, new Uint8Array(0), 32)
}
