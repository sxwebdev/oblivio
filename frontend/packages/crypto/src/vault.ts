// Vault-key generation and wrapping. The vault_key is a random 32-byte AES key
// generated client-side at registration and never sent to the server in
// plaintext. It's wrapped under the master_key and stored as
// `wrapped_vault_key`.

import { encryptBlob, decryptBlob } from "./aead";
import { randomBytes, utf8, utf8Decode } from "./util";
import { VAULT_WRAP_AAD, VERIFIER_PLAINTEXT } from "./types";

// generateVaultKey returns 32 random bytes. We keep the bytes (not a CryptoKey)
// so they can be re-imported as either AES-GCM or HMAC depending on use.
export function generateVaultKey(): Uint8Array {
  return randomBytes(32);
}

// importVaultKey returns a non-extractable CryptoKey for AES-GCM.
export async function importVaultKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

// Wrap vault_key under master_key. The result is the on-the-wire blob.
export async function wrapVaultKey(
  masterKey: CryptoKey,
  vaultKey: Uint8Array,
): Promise<Uint8Array> {
  return encryptBlob(masterKey, vaultKey, VAULT_WRAP_AAD);
}

// Unwrap vault_key. Returns the raw 32-byte key.
export async function unwrapVaultKey(
  masterKey: CryptoKey,
  wrapped: Uint8Array,
): Promise<Uint8Array> {
  return decryptBlob(masterKey, wrapped, VAULT_WRAP_AAD);
}

// makeVerifier seals the canonical sentinel under master_key. The server
// returns it at login so the client can sanity-check master_key derivation
// before attempting to decrypt vault material.
export async function makeVerifier(masterKey: CryptoKey): Promise<Uint8Array> {
  return encryptBlob(masterKey, utf8(VERIFIER_PLAINTEXT), VAULT_WRAP_AAD);
}

// checkVerifier returns true iff the sentinel decrypts cleanly.
export async function checkVerifier(
  masterKey: CryptoKey,
  verifier: Uint8Array,
): Promise<boolean> {
  try {
    const pt = await decryptBlob(masterKey, verifier, VAULT_WRAP_AAD);
    return utf8Decode(pt) === VERIFIER_PLAINTEXT;
  } catch {
    return false;
  }
}
