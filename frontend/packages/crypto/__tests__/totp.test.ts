// RFC 6238 / RFC 4226 conformance tests for the TOTP module.
//
// The reference secret from RFC 6238 §B is the ASCII string
// "12345678901234567890" (20 bytes). Encoded as RFC 4648 base32 (no
// padding) it becomes "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".

import { describe, expect, it } from "vitest"

import {
  decodeBase32,
  encodeBase32,
  generateTotpCode,
  normalizeBase32,
  otpauthURI,
  totpRemainingSeconds,
  unwrapLoginTotpSecret,
  wrapLoginTotpSecret,
} from "../src/totp"
import { deriveLoginTotpKey } from "../src/kdf"

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

describe("base32", () => {
  it("encodes then decodes the RFC secret to itself", () => {
    const bytes = decodeBase32(RFC_SECRET)
    // Ascii "12345678901234567890" is 20 bytes.
    expect(bytes.length).toBe(20)
    expect(new TextDecoder().decode(bytes)).toBe("12345678901234567890")
    expect(encodeBase32(bytes)).toBe(RFC_SECRET)
  })

  it("normalises hyphens, spaces and case", () => {
    expect(normalizeBase32(" gezd-gnbv ")).toBe("GEZDGNBV")
  })

  it("rejects invalid base32 characters", () => {
    expect(() => normalizeBase32("ABC1")).toThrow()
  })
})

describe("RFC 6238 8-digit vectors", () => {
  // Vectors from RFC 6238 Appendix B, SHA-1 column.
  const cases: [number, string][] = [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
  ]
  for (const [t, expected] of cases) {
    it(`T=${t} → ${expected}`, async () => {
      const code = await generateTotpCode(RFC_SECRET, new Date(t * 1000), {
        digits: 8,
      })
      expect(code).toBe(expected)
    })
  }
})

describe("RFC 6238 6-digit truncation", () => {
  it("T=59 → 287082", async () => {
    const code = await generateTotpCode(RFC_SECRET, new Date(59 * 1000))
    expect(code).toBe("287082")
  })
})

describe("totpRemainingSeconds", () => {
  it("counts down inside a 30-second step", () => {
    // 1234567890 → 1234567890 % 30 = 0 → 30 seconds remaining.
    expect(totpRemainingSeconds(new Date(1234567890 * 1000))).toBe(30)
    expect(totpRemainingSeconds(new Date(1234567905 * 1000))).toBe(15)
    expect(totpRemainingSeconds(new Date(1234567919 * 1000))).toBe(1)
  })
})

describe("otpauthURI", () => {
  it("builds a parseable otpauth URI with SHA1 / 6 / 30 defaults", () => {
    const uri = otpauthURI({
      issuer: "Oblivio",
      account: "alice@example.com",
      secret: RFC_SECRET,
    })
    expect(uri).toMatch(/^otpauth:\/\/totp\//)
    expect(uri).toContain("issuer=Oblivio")
    expect(uri).toContain("algorithm=SHA1")
    expect(uri).toContain("digits=6")
    expect(uri).toContain("period=30")
    expect(uri).toContain(`secret=${RFC_SECRET}`)
  })
})

describe("login-TOTP wrap round-trip", () => {
  it("AES-GCM(K_login_totp, secret) survives a round-trip", async () => {
    const authKey = new Uint8Array(32)
    crypto.getRandomValues(authKey)
    const key = await deriveLoginTotpKey(authKey)
    const wrapped = await wrapLoginTotpSecret(key, RFC_SECRET)
    // nonce(12) + ct(32) + tag(16) = 60 bytes
    expect(wrapped.length).toBeGreaterThan(12 + 16)
    const unwrapped = await unwrapLoginTotpSecret(key, wrapped)
    expect(unwrapped).toBe(RFC_SECRET)
  })

  it("decryption fails with a different K_login_totp", async () => {
    const ak1 = new Uint8Array(32)
    const ak2 = new Uint8Array(32)
    ak2[0] = 1 // differ by one byte
    const k1 = await deriveLoginTotpKey(ak1)
    const k2 = await deriveLoginTotpKey(ak2)
    const wrapped = await wrapLoginTotpSecret(k1, RFC_SECRET)
    await expect(unwrapLoginTotpSecret(k2, wrapped)).rejects.toThrow()
  })
})
