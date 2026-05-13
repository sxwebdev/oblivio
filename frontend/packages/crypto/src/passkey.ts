// Passkey-based vault unlock (WebAuthn PRF extension).
//
// The PRF (pseudo-random function) extension lets a WebAuthn authenticator
// expose a stable per-credential HMAC of an arbitrary salt. We never see
// the authenticator's PRF key — only the 32-byte HMAC output for the salt
// we pass in. That output is treated as input keying material for HKDF;
// the derived AES-256-GCM key wraps the user's vault_key.
//
//   passkey_unlock_key = HKDF-SHA256(prf_output, info=PRF_INFO, salt="")
//   unlock_wrapped_vault_key = AES-GCM(passkey_unlock_key, vault_key,
//                                       aad = user_id || credential_id)
//
// Without the authenticator, the wrapped blob is useless: there's no way
// to recover prf_output without the original passkey + user verification.
// This is what preserves the zero-knowledge property — the server only
// sees the wrapped blob and the salt, never the unlock key or vault_key.

import { encryptBlob, decryptBlob } from "./aead"
import { hkdfSha256 } from "./kdf"
import { concat, utf8 } from "./util"

// Info string for HKDF and AAD label. Bumping the version requires a
// migration (re-wrap of every stored bundle under the new info string).
export const PRF_UNLOCK_INFO = "oblivio/passkey-unlock/v1"

// PRF salt length agreed with the server (internal/api/webauthn/service.go).
// 32 bytes is the WebAuthn PRF recommendation; anything shorter weakens
// the unlock key.
export const PRF_SALT_LENGTH = 32

// derivePasskeyUnlockKey turns the raw PRF output into a CryptoKey suitable
// for AES-GCM wrap/unwrap of vault_key. The HKDF salt is intentionally
// empty: prf_output is already a uniformly-random 32-byte secret per
// (credential, salt), and the info string carries domain separation.
export async function derivePasskeyUnlockKey(
  prfOutput: Uint8Array
): Promise<CryptoKey> {
  if (prfOutput.length !== 32) {
    throw new Error(`prf output must be 32 bytes, got ${prfOutput.length}`)
  }
  const raw = await hkdfSha256(prfOutput, PRF_UNLOCK_INFO, new Uint8Array(0), 32)
  return crypto.subtle.importKey(
    "raw",
    raw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  )
}

// passkeyUnlockAAD binds the wrapped blob to the (user, credential) pair.
// AES-GCM authentication will fail if either side of the pair is
// substituted, so a leaked blob can't be re-used for a different user or
// credential.
export function passkeyUnlockAAD(
  userId: string,
  credentialId: string
): Uint8Array {
  return concat(utf8(userId), utf8("|"), utf8(credentialId))
}

// wrapVaultKeyWithPRF wraps `vaultKey` under the PRF-derived unlock key.
// Returns the standard `version(1) || nonce(12) || ct+tag` envelope.
export async function wrapVaultKeyWithPRF(
  unlockKey: CryptoKey,
  vaultKey: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  return encryptBlob(unlockKey, vaultKey, aad)
}

// unwrapVaultKeyWithPRF reverses wrapVaultKeyWithPRF. Throws on AAD
// mismatch or tampering — the caller surfaces this to the user as
// "passkey unlock failed; try the master password".
export async function unwrapVaultKeyWithPRF(
  unlockKey: CryptoKey,
  blob: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  return decryptBlob(unlockKey, blob, aad)
}

// generatePrfSalt returns 32 random bytes for prf.eval.first. The salt is
// stored server-side after EnablePasskeyUnlock; subsequent unlocks reuse
// it so the authenticator produces the same prf_output.
export function generatePrfSalt(): Uint8Array {
  const out = new Uint8Array(PRF_SALT_LENGTH)
  crypto.getRandomValues(out)
  return out
}
