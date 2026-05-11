// Argon2Params parameterises the client-side Argon2id KDF used to derive
// master_key from master_password. These are stored per-user on the server
// and returned during login (see plan §4.2).
export type Argon2Params = {
  t: number // iterations
  mKib: number // memory in KiB
  p: number // parallelism
  algo?: string // typically "argon2id"
  // forceSingleThread overrides p=1 at derivation time. Useful when the
  // page is not crossOriginIsolated (no SharedArrayBuffer) and hash-wasm
  // would otherwise hang or fall back unpredictably with p>1.
  forceSingleThread?: boolean
}

// WrappedKey is an envelope: nonce(12) || ciphertext+tag.
// AES-GCM concatenates ciphertext and tag transparently.
export type WrappedKey = {
  nonce: Uint8Array
  ciphertext: Uint8Array // includes 16-byte tag
}

// ItemEnvelope is a wrapped item key together with its sealed blob.
// blob = nonce(12) || ciphertext+tag.
export type ItemEnvelope = {
  blob: Uint8Array
  wrappedKey: WrappedKey
  aad: Uint8Array
}

// VERIFIER_PLAINTEXT is the canonical sentinel sealed under master_key during
// registration so the server can hand it back at login. Decrypting it
// successfully proves the client derived the right master_key.
export const VERIFIER_PLAINTEXT = "oblivio-verify"

// Domain separation labels for HKDF and AAD construction. Bumping these
// requires a migration; the version suffix forces the scheme into a new lane.
export const HKDF_AUTH_INFO = "oblivio/auth/v1"
export const HKDF_BLIND_INFO = "oblivio/blind/v1"
export const HKDF_LOGIN_TOTP_INFO = "oblivio/login-totp/v1"
export const VAULT_WRAP_AAD = "vault-wrap"
export const RECOVERY_WRAP_AAD = "recovery"

// Suffix labels used inside AAD strings for item-level operations.
// Per plan §4.3:
//   • item ciphertext AAD = "<item_id>|<version>|<vault_id>|item"
//   • wrapped item_key AAD = "<vault_id>|<item_id>|<version>|wrap"
// Encoding the labels as ASCII is sufficient — AAD is just a binary blob
// that both sides reconstruct identically. The pipe separator is unambiguous
// because UUIDs and decimal versions never contain it.
export const ITEM_AAD_LABEL = "item"
export const WRAP_AAD_LABEL = "wrap"
