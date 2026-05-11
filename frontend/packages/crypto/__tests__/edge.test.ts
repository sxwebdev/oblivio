// Edge-case coverage that the cross-language vectors don't reach (plan §13.3):
//
//   • KDF: empty password → error; salt too short → error.
//   • AEAD: AAD mutation rejection; nonce uniqueness across 100k seals.
//   • Wrap tree: master → vault → item full round-trip plus replay
//     resistance via AAD (substituting another item's id must fail).
//   • Verifier: wrong key returns false without throwing.
//   • Blind index: deterministic per (vault_key, title); NFKC and
//     case-folding behave per spec; distinct keys → distinct hashes.
//   • Recovery: wrong code fails to decrypt; normalization is total.
//   • Password gen: length and alphabet honoured; uniform distribution
//     (chi-squared sanity, conservative threshold).

import { describe, expect, it } from "vitest"
import {
  deriveMasterKey,
  importMasterKey,
  deriveBlindIndexKey,
} from "../src/kdf"
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
  generateItemKey,
  importItemKey,
  buildItemAAD,
  buildItemWrapAAD,
  wrapItemKey,
  unwrapItemKey,
} from "../src/item"
import { blindIndex } from "../src/blind"
import {
  generateRecoveryCode,
  deriveRecoveryKey,
  wrapVaultKeyForRecovery,
  unwrapVaultKeyFromRecovery,
  normalizeRecoveryCode,
} from "../src/recovery"
import { utf8, randomBytes } from "../src/util"
import { generatePassword, buildAlphabet } from "../src/passgen"

const fastParams = { t: 1, mKib: 1 << 10, p: 1, algo: "argon2id" } as const

describe("kdf input validation", () => {
  it("rejects empty password", async () => {
    await expect(
      deriveMasterKey("", new Uint8Array(16), fastParams)
    ).rejects.toThrow(/master password/i)
  })
  it("rejects short salt", async () => {
    await expect(
      deriveMasterKey("pw", new Uint8Array(8), fastParams)
    ).rejects.toThrow(/salt/i)
  })
})

describe("aead: AAD discipline and tampering", () => {
  it("rejects AAD mutation at decrypt", async () => {
    const key = await importVaultKey(generateVaultKey())
    const blob = await encryptBlob(key, utf8("payload"), utf8("aad-a"))
    await expect(decryptBlob(key, blob, utf8("aad-b"))).rejects.toThrow()
  })

  it("rejects a swapped ciphertext under matching AAD", async () => {
    const key = await importVaultKey(generateVaultKey())
    const blobA = await encryptBlob(key, utf8("alpha"), "ctx")
    const blobB = await encryptBlob(key, utf8("beta"), "ctx")
    // Splice A's nonce with B's tag — must not decrypt.
    const frankenstein = new Uint8Array([
      ...blobA.slice(0, 12),
      ...blobB.slice(12),
    ])
    await expect(decryptBlob(key, frankenstein, "ctx")).rejects.toThrow()
  })

  it("generates unique nonces across 100k seals", async () => {
    // We can't observe WebCrypto's internal nonces, but encryptBlob picks
    // them itself via util.randomBytes. Sampling the nonce slice should be
    // injective at the 12-byte width.
    const key = await importVaultKey(generateVaultKey())
    const seen = new Set<string>()
    const N = 100_000
    for (let i = 0; i < N; i++) {
      const blob = await encryptBlob(key, new Uint8Array(0), "ctx")
      const nonceHex = Array.from(blob.slice(0, 12))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
      if (seen.has(nonceHex)) {
        throw new Error(`duplicate nonce at iter=${i}: ${nonceHex}`)
      }
      seen.add(nonceHex)
    }
    expect(seen.size).toBe(N)
  })
})

describe("wrap tree: master → vault → item round-trip", () => {
  it("decrypts an item end-to-end and rejects swapped AAD", async () => {
    const masterRaw = await deriveMasterKey("pw", randomBytes(16), fastParams)
    const masterKey = await importMasterKey(masterRaw)
    const vaultRaw = generateVaultKey()
    const wrappedVault = await wrapVaultKey(masterKey, vaultRaw)
    const vaultRecovered = await unwrapVaultKey(masterKey, wrappedVault)
    expect(vaultRecovered).toEqual(vaultRaw)

    const vaultKey = await importVaultKey(vaultRaw)
    const itemId = "00000000-0000-0000-0000-000000000010"
    const vaultId = "00000000-0000-0000-0000-000000000001"
    const version = 1n

    const itemRaw = generateItemKey()
    const wrapAAD = buildItemWrapAAD(vaultId, itemId, version)
    const wrappedItem = await wrapItemKey(vaultKey, itemRaw, wrapAAD)
    const recoveredItem = await unwrapItemKey(vaultKey, wrappedItem, wrapAAD)
    expect(recoveredItem).toEqual(itemRaw)

    // Replay attack: try to unwrap under a different item_id (same vault_id).
    const fakeAAD = buildItemWrapAAD(
      vaultId,
      "00000000-0000-0000-0000-000000000011",
      version
    )
    await expect(
      unwrapItemKey(vaultKey, wrappedItem, fakeAAD)
    ).rejects.toThrow()

    // Rollback attack: try to unwrap under a previous version.
    const oldAAD = buildItemWrapAAD(vaultId, itemId, 0n)
    await expect(unwrapItemKey(vaultKey, wrappedItem, oldAAD)).rejects.toThrow()

    // Encrypt a payload under item_key and verify AAD binds it.
    const itemKey = await importItemKey(itemRaw)
    const payloadAAD = buildItemAAD(itemId, version, vaultId)
    const cipher = await encryptBlob(
      itemKey,
      utf8(JSON.stringify({ secret: "shhh" })),
      payloadAAD
    )
    const plaintext = await decryptBlob(itemKey, cipher, payloadAAD)
    expect(plaintext).toEqual(utf8(JSON.stringify({ secret: "shhh" })))

    // Replay payload under a wrong item_id must fail.
    const wrongAAD = buildItemAAD(
      "00000000-0000-0000-0000-000000000012",
      version,
      vaultId
    )
    await expect(decryptBlob(itemKey, cipher, wrongAAD)).rejects.toThrow()
  })
})

describe("verifier", () => {
  it("returns false (no throw) under the wrong master_key", async () => {
    const mkA = await importMasterKey(
      await deriveMasterKey("alpha", new Uint8Array(16).fill(1), fastParams)
    )
    const mkB = await importMasterKey(
      await deriveMasterKey("beta", new Uint8Array(16).fill(1), fastParams)
    )
    const verifier = await makeVerifier(mkA)
    expect(await checkVerifier(mkB, verifier)).toBe(false)
    expect(await checkVerifier(mkA, verifier)).toBe(true)
  })
})

describe("blind index", () => {
  it("is deterministic for (vault_key, title)", async () => {
    const vk = randomBytes(32)
    const k = await deriveBlindIndexKey(vk)
    const a = await blindIndex(k, "GitHub")
    const b = await blindIndex(k, "GitHub")
    expect(a).toEqual(b)
  })

  it("NFKC-normalises and case-folds inputs", async () => {
    const k = await deriveBlindIndexKey(new Uint8Array(32))
    const lower = await blindIndex(k, "github")
    const fullwidth = await blindIndex(k, "ＧｉｔＨｕｂ") // NFKC → "GitHub" → lower → "github"
    const upper = await blindIndex(k, "GITHUB")
    expect(lower).toEqual(fullwidth)
    expect(lower).toEqual(upper)
  })

  it("differs across distinct vault keys for the same title", async () => {
    const k1 = await deriveBlindIndexKey(new Uint8Array(32).fill(1))
    const k2 = await deriveBlindIndexKey(new Uint8Array(32).fill(2))
    const a = await blindIndex(k1, "GitHub")
    const b = await blindIndex(k2, "GitHub")
    expect(a).not.toEqual(b)
  })
})

describe("recovery", () => {
  it("rejects a tampered recovery code", async () => {
    const code = generateRecoveryCode()
    const salt = randomBytes(16)
    const realKey = await deriveRecoveryKey(code, salt)
    const wrapped = await wrapVaultKeyForRecovery(realKey, generateVaultKey())

    // Flip a letter in the code group.
    const broken = code.replace(/^./, (c) =>
      String.fromCharCode(c.charCodeAt(0) === 65 ? 66 : 65)
    )
    const fakeKey = await deriveRecoveryKey(broken, salt)
    await expect(unwrapVaultKeyFromRecovery(fakeKey, wrapped)).rejects.toThrow()
  })

  it("normalization strips dashes, spaces and lower-cases", () => {
    expect(normalizeRecoveryCode("aa-bb cc")).toBe("AABBCC")
  })
})

describe("password gen", () => {
  it("honours requested length and alphabet", () => {
    const pw = generatePassword({ length: 64, lowercase: true, digits: true })
    expect(pw.length).toBe(64)
    expect(pw).toMatch(/^[a-z0-9]+$/)
  })

  it("rejects empty alphabet and non-positive length", () => {
    expect(() => generatePassword({ length: 0, lowercase: true })).toThrow()
    expect(() => generatePassword({ length: 8 })).toThrow(/alphabet/)
  })

  it("output is approximately uniform (chi-squared sanity)", () => {
    const opts = {
      length: 50_000,
      lowercase: true,
      uppercase: true,
      digits: true,
    } as const
    const alphabet = buildAlphabet(opts)
    const pw = generatePassword(opts)
    const counts = new Map<string, number>()
    for (const ch of pw) counts.set(ch, (counts.get(ch) ?? 0) + 1)
    // chi^2 = sum( (obs - exp)^2 / exp )
    const exp = opts.length / alphabet.length
    let chi = 0
    for (const ch of alphabet) {
      const obs = counts.get(ch) ?? 0
      chi += (obs - exp) ** 2 / exp
    }
    // df = alphabet.length - 1. For alphabet=62, 99.9% critical value is
    // ~108. We use 150 — very loose — because flakes here trash CI without
    // catching real bias. Real bias from a broken sampler shows orders of
    // magnitude higher.
    expect(chi).toBeLessThan(150)
  })
})
