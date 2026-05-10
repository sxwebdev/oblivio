// Argon2Params parameterises the client-side Argon2id KDF used to derive
// master_key from master_password. These are stored per-user on the server
// and returned during login (see plan §4.2).
export type Argon2Params = {
  t: number; // iterations
  mKib: number; // memory in KiB
  p: number; // parallelism
  algo?: string; // typically "argon2id"
};

// WrappedKey is an envelope: nonce(12) || ciphertext+tag.
// AES-GCM concatenates ciphertext and tag transparently.
export type WrappedKey = {
  nonce: Uint8Array;
  ciphertext: Uint8Array; // includes 16-byte tag
};

// ItemEnvelope is a wrapped item key together with its sealed blob.
// blob = nonce(12) || ciphertext+tag.
export type ItemEnvelope = {
  blob: Uint8Array;
  wrappedKey: WrappedKey;
  aad: Uint8Array;
};

// VERIFIER_PLAINTEXT is the canonical sentinel sealed under master_key during
// registration so the server can hand it back at login. Decrypting it
// successfully proves the client derived the right master_key.
export const VERIFIER_PLAINTEXT = "oblivio-verify";

// Domain separation labels for HKDF and AAD construction. Bumping these
// requires a migration; the version suffix forces the scheme into a new lane.
export const HKDF_AUTH_INFO = "oblivio/auth/v1";
export const HKDF_BLIND_INFO = "oblivio/blind/v1";
export const HKDF_LOGIN_TOTP_INFO = "oblivio/login-totp/v1";
export const VAULT_WRAP_AAD = "vault-wrap";
export const RECOVERY_WRAP_AAD = "recovery";
