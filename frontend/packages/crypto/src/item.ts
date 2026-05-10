// Item-level key tree (plan §4.1, §4.3).
//
//   vault_key  ─ AES-GCM unwrap ─►  item_key  ─ AES-GCM ─►  encrypted field blob
//
// Each entry/note/project carries a per-record `item_key`, wrapped under
// `vault_key`. The wrap uses an AAD that binds the wrapped key to the
// (vault_id, item_id, version) triple so the server cannot swap envelopes
// between records or roll a record back to a stale version.

import { decryptBlob, encryptBlob } from "./aead";
import { randomBytes, utf8 } from "./util";
import { ITEM_AAD_LABEL, WRAP_AAD_LABEL } from "./types";

// generateItemKey returns 32 random bytes suitable for AES-256-GCM.
// Like vault_key we keep raw bytes so callers may import them with whatever
// usages they need (encrypt, decrypt, deriveBits…).
export function generateItemKey(): Uint8Array {
  return randomBytes(32);
}

// importItemKey returns a non-extractable AES-GCM CryptoKey.
export async function importItemKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw as unknown as ArrayBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

// buildItemAAD returns the canonical AAD for *encrypted_blob* (the actual
// payload bytes of an entry/project/note). The AAD binds the ciphertext to a
// specific item version so the server cannot replay a stale ciphertext under
// a newer record.
export function buildItemAAD(
  itemId: string,
  version: number | bigint,
  vaultId: string,
): Uint8Array {
  return utf8(`${itemId}|${version}|${vaultId}|${ITEM_AAD_LABEL}`);
}

// buildItemWrapAAD returns the canonical AAD for *wrapped_item_key*. It binds
// the wrap to (vault_id, item_id, version), preventing the server from
// swapping two records' wrapped_item_keys.
export function buildItemWrapAAD(
  vaultId: string,
  itemId: string,
  version: number | bigint,
): Uint8Array {
  return utf8(`${vaultId}|${itemId}|${version}|${WRAP_AAD_LABEL}`);
}

// wrapItemKey seals item_key under vault_key with the supplied AAD.
// The caller is responsible for constructing AAD via buildItemWrapAAD so the
// server can rebuild it for verification.
export async function wrapItemKey(
  vaultKey: CryptoKey,
  itemKey: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return encryptBlob(vaultKey, itemKey, aad);
}

// unwrapItemKey returns the raw item_key bytes. Throws OperationError on AAD
// mismatch or ciphertext tampering.
export async function unwrapItemKey(
  vaultKey: CryptoKey,
  wrapped: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return decryptBlob(vaultKey, wrapped, aad);
}
