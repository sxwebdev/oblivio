// High-level vault crypto adapters used by the UI layer.
//
// The @oblivio/crypto package exposes primitives (key wrap, AEAD, blind
// index). This module turns them into product-shaped operations:
//   sealProject / openProject — encrypted_blob + wrapped_item_key + name_hash
//   sealEntry   / openEntry   — encrypted_blob + wrapped_item_key + title_hash + domain_hash
//
// All operations require the in-memory `vaultKey` and a stable `vaultId`
// (the user_id, which the server uses as the vault scope per §6/§4 of the plan).

import {
  blindIndex,
  buildItemAAD,
  buildItemWrapAAD,
  decryptBlob,
  deriveBlindIndexKey,
  encryptBlob,
  generateItemKey,
  importItemKey,
  importVaultKey,
  unwrapItemKey,
  wrapItemKey,
} from "@oblivio/crypto"

// ProjectPlaintext is the JSON object stored inside `encrypted_blob` for a
// project record. Adding optional fields is forward-compatible; removing
// or renaming is a breaking change that requires a migration script.
export type ProjectPlaintext = {
  name: string
  description?: string
  color?: string // hex like "#a78bfa"
  icon?: string // lucide icon name
}

// EntryPlaintext is the JSON object stored inside `encrypted_blob` for an
// entry record. The presence of optional fields depends on `kind`.
export type EntryPlaintext = {
  title: string
  // Login-shaped fields.
  username?: string
  password?: string
  url?: string
  // TOTP shared with login or standalone (kind=totp).
  totpSecret?: string
  totpDigits?: number
  totpPeriod?: number
  // Note-shaped.
  notesMd?: string
  // Card-shaped.
  cardNumber?: string
  cardHolder?: string
  cardCvv?: string
  cardExpiry?: string
  // Identity-shaped.
  fullName?: string
  email?: string
  phone?: string
  address?: string
  // SSH-key-shaped.
  privateKey?: string
  publicKey?: string
  passphrase?: string
  // Free-form additional fields.
  customFields?: { label: string; value: string; secret?: boolean }[]
}

// SealedRecord captures the server-bound trio for a project or entry.
export type SealedRecord = {
  encryptedBlob: Uint8Array
  wrappedItemKey: Uint8Array
  titleHash: Uint8Array // also used as name_hash for projects
  domainHash?: Uint8Array
}

// utf8 helpers — duplicated locally so we don't import from internals.
const enc = new TextEncoder()
const dec = new TextDecoder()

// extractDomain best-effort parses a URL and returns its lowercase hostname.
// Returns empty string when the input is empty or unparseable; the caller
// decides whether to compute a hash on empty.
export function extractDomain(url: string | undefined | null): string {
  if (!url) return ""
  try {
    const u = new URL(/^https?:/i.test(url) ? url : `https://${url}`)
    return u.hostname.toLowerCase()
  } catch {
    return ""
  }
}

// vaultIdScope returns the id under which AADs are tied. Today it is the
// user_id; if multi-vault per user is ever introduced this is the only
// place that needs to change.
export function vaultIdScope(userId: string): string {
  return userId
}

// sealProject encrypts plaintext + wraps a fresh item_key under vault_key.
// Used both for create (caller passes a fresh UUID) and update (caller
// passes the existing id with `version+1`).
export async function sealProject(opts: {
  vaultKey: Uint8Array
  vaultId: string
  projectId: string
  version: number
  plaintext: ProjectPlaintext
}): Promise<SealedRecord> {
  const vk = await importVaultKey(opts.vaultKey)
  const itemKeyRaw = generateItemKey()
  const wrapAAD = buildItemWrapAAD(opts.vaultId, opts.projectId, opts.version)
  const wrapped = await wrapItemKey(vk, itemKeyRaw, wrapAAD)

  const itemKey = await importItemKey(itemKeyRaw)
  const aad = buildItemAAD(opts.projectId, opts.version, opts.vaultId)
  const blob = await encryptBlob(
    itemKey,
    enc.encode(JSON.stringify(opts.plaintext)),
    aad
  )
  itemKeyRaw.fill(0)

  const blindKey = await deriveBlindIndexKey(opts.vaultKey)
  const nameHash = await blindIndex(blindKey, opts.plaintext.name || "")

  return {
    encryptedBlob: blob,
    wrappedItemKey: wrapped,
    titleHash: nameHash,
  }
}

// openProject is the inverse of sealProject — unwraps and decrypts the blob.
export async function openProject(opts: {
  vaultKey: Uint8Array
  vaultId: string
  projectId: string
  version: number
  encryptedBlob: Uint8Array
  wrappedItemKey: Uint8Array
}): Promise<ProjectPlaintext> {
  const vk = await importVaultKey(opts.vaultKey)
  const wrapAAD = buildItemWrapAAD(opts.vaultId, opts.projectId, opts.version)
  const itemKeyRaw = await unwrapItemKey(vk, opts.wrappedItemKey, wrapAAD)
  const itemKey = await importItemKey(itemKeyRaw)
  const aad = buildItemAAD(opts.projectId, opts.version, opts.vaultId)
  const pt = await decryptBlob(itemKey, opts.encryptedBlob, aad)
  itemKeyRaw.fill(0)
  return JSON.parse(dec.decode(pt)) as ProjectPlaintext
}

// sealEntry encrypts an entry payload and computes blind hashes.
export async function sealEntry(opts: {
  vaultKey: Uint8Array
  vaultId: string
  entryId: string
  version: number
  plaintext: EntryPlaintext
}): Promise<SealedRecord> {
  const vk = await importVaultKey(opts.vaultKey)
  const itemKeyRaw = generateItemKey()
  const wrapAAD = buildItemWrapAAD(opts.vaultId, opts.entryId, opts.version)
  const wrapped = await wrapItemKey(vk, itemKeyRaw, wrapAAD)

  const itemKey = await importItemKey(itemKeyRaw)
  const aad = buildItemAAD(opts.entryId, opts.version, opts.vaultId)
  const blob = await encryptBlob(
    itemKey,
    enc.encode(JSON.stringify(opts.plaintext)),
    aad
  )
  itemKeyRaw.fill(0)

  const blindKey = await deriveBlindIndexKey(opts.vaultKey)
  const titleHash = await blindIndex(blindKey, opts.plaintext.title || "")
  const domain = extractDomain(opts.plaintext.url)
  const domainHash = domain ? await blindIndex(blindKey, domain) : undefined

  return {
    encryptedBlob: blob,
    wrappedItemKey: wrapped,
    titleHash,
    domainHash,
  }
}

// openEntry decrypts an entry blob into typed plaintext.
export async function openEntry(opts: {
  vaultKey: Uint8Array
  vaultId: string
  entryId: string
  version: number
  encryptedBlob: Uint8Array
  wrappedItemKey: Uint8Array
}): Promise<EntryPlaintext> {
  const vk = await importVaultKey(opts.vaultKey)
  const wrapAAD = buildItemWrapAAD(opts.vaultId, opts.entryId, opts.version)
  const itemKeyRaw = await unwrapItemKey(vk, opts.wrappedItemKey, wrapAAD)
  const itemKey = await importItemKey(itemKeyRaw)
  const aad = buildItemAAD(opts.entryId, opts.version, opts.vaultId)
  const pt = await decryptBlob(itemKey, opts.encryptedBlob, aad)
  itemKeyRaw.fill(0)
  return JSON.parse(dec.decode(pt)) as EntryPlaintext
}

// computeTitleHash hashes a title against the caller's blind-index key.
// Used by the search box to ask the server for an exact match.
export async function computeTitleHash(
  vaultKey: Uint8Array,
  title: string
): Promise<Uint8Array> {
  const blindKey = await deriveBlindIndexKey(vaultKey)
  return blindIndex(blindKey, title)
}
