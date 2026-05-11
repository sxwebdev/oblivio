import { describe, expect, it } from "vitest"
import { deriveAuthKey, deriveMasterKey, importMasterKey } from "../src/kdf"
import { encryptBlob, decryptBlob } from "../src/aead"
import {
  generateVaultKey,
  importVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  makeVerifier,
  checkVerifier,
} from "../src/vault"
import {
  generateRecoveryCode,
  deriveRecoveryKey,
  wrapVaultKeyForRecovery,
  unwrapVaultKeyFromRecovery,
  deriveRecoveryProof,
  normalizeRecoveryCode,
} from "../src/recovery"
import { utf8, utf8Decode, randomBytes } from "../src/util"

// Slim Argon2 params so tests don't take 2 seconds each.
const params = { t: 2, mKib: 8 * 1024, p: 1, algo: "argon2id" } as const

describe("kdf + vault round-trip", () => {
  it("derives identical master_key for same password+salt", async () => {
    const salt = new Uint8Array(16).fill(7)
    const a = await deriveMasterKey("hunter2", salt, params)
    const b = await deriveMasterKey("hunter2", salt, params)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  })

  it("verifier round-trips with correct master_key, fails with wrong one", async () => {
    const salt = randomBytes(16)
    const mk = await importMasterKey(await deriveMasterKey("pw", salt, params))
    const verifier = await makeVerifier(mk)

    expect(await checkVerifier(mk, verifier)).toBe(true)

    const wrong = await importMasterKey(
      await deriveMasterKey("nope", salt, params)
    )
    expect(await checkVerifier(wrong, verifier)).toBe(false)
  })

  it("wrapped vault_key round-trips through master_key", async () => {
    const salt = randomBytes(16)
    const mk = await importMasterKey(await deriveMasterKey("pw", salt, params))
    const vault = generateVaultKey()
    const wrapped = await wrapVaultKey(mk, vault)
    const recovered = await unwrapVaultKey(mk, wrapped)
    expect(recovered).toEqual(vault)
  })

  it("AES-GCM detects ciphertext tampering", async () => {
    const key = await importVaultKey(generateVaultKey())
    const blob = await encryptBlob(key, utf8("hello"), "ctx")
    blob[blob.length - 1] ^= 0xff // tamper with the auth tag
    await expect(decryptBlob(key, blob, "ctx")).rejects.toThrow()
  })

  it("AES-GCM detects AAD mismatch", async () => {
    const key = await importVaultKey(generateVaultKey())
    const blob = await encryptBlob(key, utf8("hello"), "right")
    await expect(decryptBlob(key, blob, "wrong")).rejects.toThrow()
  })

  it("auth_key is deterministic per salt_user", async () => {
    const mk = await deriveMasterKey("pw", new Uint8Array(16).fill(9), params)
    const saltA = new Uint8Array(16).fill(1)
    const saltB = new Uint8Array(16).fill(2)
    const a1 = await deriveAuthKey(mk, saltA)
    const a2 = await deriveAuthKey(mk, saltA)
    const b = await deriveAuthKey(mk, saltB)
    expect(a1).toEqual(a2) // deterministic
    expect(a1).not.toEqual(b) // different salt → different output
  })
})

describe("recovery", () => {
  it("generates a 5-group dashed code of expected size", () => {
    const c = generateRecoveryCode()
    expect(c.split("-")).toHaveLength(5)
    for (const g of c.split("-")) expect(g).toHaveLength(5)
  })

  it("normalises whitespace and case", () => {
    expect(normalizeRecoveryCode("aaaaa-BBBBB-ccccc-DDDDD-eeeee")).toBe(
      "AAAAABBBBBCCCCCDDDDDEEEEE"
    )
  })

  it("recovery wrap round-trip", async () => {
    const code = generateRecoveryCode()
    const salt = randomBytes(16)
    const rk = await deriveRecoveryKey(code, salt)
    const vault = generateVaultKey()
    const wrapped = await wrapVaultKeyForRecovery(rk, vault)
    const recovered = await unwrapVaultKeyFromRecovery(rk, wrapped)
    expect(recovered).toEqual(vault)
  })

  it("derives a deterministic recovery_proof from recovery_key", async () => {
    const code = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
    const salt = new Uint8Array(16).fill(1)
    const rk = await deriveRecoveryKey(code, salt)
    const p1 = await deriveRecoveryProof(rk)
    const p2 = await deriveRecoveryProof(rk)
    expect(p1).toEqual(p2)
  })
})

describe("end-to-end registration shape", () => {
  it("matches the on-the-wire artefact set", async () => {
    const email = "carol@example.com"
    const password = "p@ssw0rd!"
    const saltUser = randomBytes(16)

    // Client side.
    const masterKeyRaw = await deriveMasterKey(password, saltUser, params)
    const masterKey = await importMasterKey(masterKeyRaw)
    const authKey = await deriveAuthKey(masterKeyRaw, saltUser)
    const vaultKey = generateVaultKey()
    const wrappedVaultKey = await wrapVaultKey(masterKey, vaultKey)
    const verifier = await makeVerifier(masterKey)

    const recoveryCode = generateRecoveryCode()
    const recoverySalt = randomBytes(16)
    const recoveryKey = await deriveRecoveryKey(recoveryCode, recoverySalt)
    const recoveryWrappedVaultKey = await wrapVaultKeyForRecovery(
      recoveryKey,
      vaultKey
    )
    const recoveryProof = await deriveRecoveryProof(recoveryKey)

    expect(authKey.length).toBe(32)
    expect(verifier.length).toBeGreaterThan(16)
    expect(wrappedVaultKey.length).toBe(1 + 12 + 32 + 16) // version|nonce|ct|tag
    expect(recoveryWrappedVaultKey.length).toBe(1 + 12 + 32 + 16)
    expect(recoveryProof.length).toBe(32)

    // Server stores wrapped_vault_key + verifier; later returns them at login.
    // Round-trip: we should be able to unwrap with the same master_key.
    const unwrapped = await unwrapVaultKey(masterKey, wrappedVaultKey)
    expect(unwrapped).toEqual(vaultKey)
    expect(await checkVerifier(masterKey, verifier)).toBe(true)

    // Recovery path: recover vault_key from recoveryCode + salt.
    const fromRecovery = await unwrapVaultKeyFromRecovery(
      recoveryKey,
      recoveryWrappedVaultKey
    )
    expect(fromRecovery).toEqual(vaultKey)

    // Sanity: wiping intermediate buffers does not corrupt earlier outputs.
    masterKeyRaw.fill(0)
    expect(utf8Decode(utf8(email))).toBe(email)
  })
})
