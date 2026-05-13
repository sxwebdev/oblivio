import { describe, expect, it } from "vitest"
import {
  buildItemAAD,
  buildItemWrapAAD,
  decryptBlob,
  encryptBlob,
  generateItemKey,
  generateVaultKey,
  importItemKey,
  importVaultKey,
  unwrapItemKey,
  utf8,
  utf8Decode,
  wrapItemKey,
} from "../src"

const VAULT_ID = "11111111-1111-4111-8111-111111111111"
const ITEM_A = "aaaaaaaa-1111-4111-8111-111111111111"
const ITEM_B = "bbbbbbbb-2222-4222-8222-222222222222"

describe("item-key wrap/unwrap", () => {
  it("round-trips item_key under vault_key with matching AAD", async () => {
    const vaultKey = await importVaultKey(generateVaultKey())
    const itemKey = generateItemKey()
    const aad = buildItemWrapAAD(VAULT_ID, ITEM_A, 1)

    const wrapped = await wrapItemKey(vaultKey, itemKey, aad)
    const recovered = await unwrapItemKey(vaultKey, wrapped, aad)
    expect(recovered).toEqual(itemKey)
  })

  it("rejects unwrap with a different item_id (anti-swap)", async () => {
    const vaultKey = await importVaultKey(generateVaultKey())
    const itemKey = generateItemKey()
    const wrapped = await wrapItemKey(
      vaultKey,
      itemKey,
      buildItemWrapAAD(VAULT_ID, ITEM_A, 1)
    )
    await expect(
      unwrapItemKey(vaultKey, wrapped, buildItemWrapAAD(VAULT_ID, ITEM_B, 1))
    ).rejects.toThrow()
  })

  it("rejects unwrap with a stale version (anti-rollback)", async () => {
    const vaultKey = await importVaultKey(generateVaultKey())
    const itemKey = generateItemKey()
    const wrappedV1 = await wrapItemKey(
      vaultKey,
      itemKey,
      buildItemWrapAAD(VAULT_ID, ITEM_A, 1)
    )
    await expect(
      unwrapItemKey(vaultKey, wrappedV1, buildItemWrapAAD(VAULT_ID, ITEM_A, 2))
    ).rejects.toThrow()
  })

  it("encrypts payload under item_key with item AAD round-trip", async () => {
    const vaultKey = await importVaultKey(generateVaultKey())
    const itemKeyRaw = generateItemKey()
    const itemKey = await importItemKey(itemKeyRaw)
    const wrappedItem = await wrapItemKey(
      vaultKey,
      itemKeyRaw,
      buildItemWrapAAD(VAULT_ID, ITEM_A, 1)
    )

    const aad = buildItemAAD(ITEM_A, 1, VAULT_ID)
    const blob = await encryptBlob(itemKey, utf8("secret-payload"), aad)

    // Server hands back wrapped_item_key + blob; client unwraps and decrypts.
    const recoveredRaw = await unwrapItemKey(
      vaultKey,
      wrappedItem,
      buildItemWrapAAD(VAULT_ID, ITEM_A, 1)
    )
    const recoveredKey = await importItemKey(recoveredRaw)
    const pt = await decryptBlob(recoveredKey, blob, aad)
    expect(utf8Decode(pt)).toBe("secret-payload")
  })

  it("rejects payload decrypt under wrong item AAD", async () => {
    const itemKey = await importItemKey(generateItemKey())
    const blob = await encryptBlob(
      itemKey,
      utf8("secret"),
      buildItemAAD(ITEM_A, 1, VAULT_ID)
    )
    await expect(
      decryptBlob(itemKey, blob, buildItemAAD(ITEM_B, 1, VAULT_ID))
    ).rejects.toThrow()
  })
})
