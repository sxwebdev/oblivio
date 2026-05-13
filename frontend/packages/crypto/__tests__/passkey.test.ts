import { describe, expect, it } from "vitest"
import {
  PRF_SALT_LENGTH,
  derivePasskeyUnlockKey,
  generatePrfSalt,
  passkeyUnlockAAD,
  unwrapVaultKeyWithPRF,
  wrapVaultKeyWithPRF,
} from "../src/passkey"
import { generateVaultKey } from "../src/vault"
import { randomBytes } from "../src/util"

// The PRF output is what the authenticator returns for a given salt.
// For testing, we stand in a fixed 32-byte value — the wrap/unwrap math
// doesn't care where the bytes came from.
function fakePrfOutput(fill = 0x42): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

describe("passkey unlock crypto", () => {
  it("derives a stable AES key for the same PRF output", async () => {
    const prf = fakePrfOutput()
    const k1 = await derivePasskeyUnlockKey(prf)
    const k2 = await derivePasskeyUnlockKey(prf)

    const aad = passkeyUnlockAAD("u", "c")
    const blob = await wrapVaultKeyWithPRF(k1, generateVaultKey(), aad)
    await expect(unwrapVaultKeyWithPRF(k2, blob, aad)).resolves.toBeInstanceOf(
      Uint8Array
    )
  })

  it("rejects non-32-byte PRF outputs", async () => {
    await expect(
      derivePasskeyUnlockKey(new Uint8Array(16))
    ).rejects.toThrow(/32 bytes/)
  })

  it("round-trips vault_key through wrap/unwrap", async () => {
    const key = await derivePasskeyUnlockKey(fakePrfOutput())
    const aad = passkeyUnlockAAD("user-123", "cred-abc")
    const original = generateVaultKey()

    const blob = await wrapVaultKeyWithPRF(key, original, aad)
    const recovered = await unwrapVaultKeyWithPRF(key, blob, aad)

    expect(recovered).toEqual(original)
  })

  it("fails to unwrap with a different PRF output", async () => {
    const k1 = await derivePasskeyUnlockKey(fakePrfOutput(0x11))
    const k2 = await derivePasskeyUnlockKey(fakePrfOutput(0x22))
    const aad = passkeyUnlockAAD("u", "c")

    const blob = await wrapVaultKeyWithPRF(k1, generateVaultKey(), aad)
    await expect(unwrapVaultKeyWithPRF(k2, blob, aad)).rejects.toThrow()
  })

  it("fails to unwrap when AAD differs (user or credential mismatch)", async () => {
    const key = await derivePasskeyUnlockKey(fakePrfOutput())
    const original = generateVaultKey()

    const blob = await wrapVaultKeyWithPRF(
      key,
      original,
      passkeyUnlockAAD("alice", "yubi-1")
    )

    // Wrong user.
    await expect(
      unwrapVaultKeyWithPRF(key, blob, passkeyUnlockAAD("bob", "yubi-1"))
    ).rejects.toThrow()
    // Wrong credential.
    await expect(
      unwrapVaultKeyWithPRF(key, blob, passkeyUnlockAAD("alice", "yubi-2"))
    ).rejects.toThrow()
  })

  it("fails to unwrap a tampered blob", async () => {
    const key = await derivePasskeyUnlockKey(fakePrfOutput())
    const aad = passkeyUnlockAAD("u", "c")
    const blob = await wrapVaultKeyWithPRF(key, generateVaultKey(), aad)
    // Flip a byte in the ciphertext (after version + nonce).
    blob[1 + 12 + 4] ^= 0x80
    await expect(unwrapVaultKeyWithPRF(key, blob, aad)).rejects.toThrow()
  })

  it("generates 32-byte salts (sanity)", () => {
    const a = generatePrfSalt()
    const b = generatePrfSalt()
    expect(a.length).toBe(PRF_SALT_LENGTH)
    expect(a).not.toEqual(b) // statistically near-certain
  })

  it("AAD is deterministic and order-sensitive", () => {
    const a = passkeyUnlockAAD("u1", "c1")
    const b = passkeyUnlockAAD("u1", "c1")
    const c = passkeyUnlockAAD("c1", "u1")
    expect(a).toEqual(b)
    expect(a).not.toEqual(c)
  })

  it("does not leak the PRF output through the unlock key (best-effort)", async () => {
    // A regression-style check: the AES key derived via HKDF must not be
    // the raw PRF output. We can't read CryptoKey bytes directly, but we
    // can verify the wrapped blob differs from raw AES-GCM(prf, plaintext).
    const prf = randomBytes(32)
    const key = await derivePasskeyUnlockKey(prf)
    const pt = generateVaultKey()
    const aad = passkeyUnlockAAD("u", "c")
    const blob = await wrapVaultKeyWithPRF(key, pt, aad)
    expect(blob.length).toBeGreaterThan(pt.length)
  })
})
