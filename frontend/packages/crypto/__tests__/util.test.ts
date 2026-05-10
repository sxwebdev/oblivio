// Coverage tail for util.ts — small helpers, all branches.

import { describe, expect, it } from "vitest"
import {
  utf8,
  utf8Decode,
  zeroize,
  concat,
  fromBase64,
  toBase64,
  randomBytes,
} from "../src/util"

describe("util", () => {
  it("utf8 / utf8Decode round-trip", () => {
    expect(utf8Decode(utf8("hello ✓"))).toBe("hello ✓")
  })

  it("zeroize wipes in place; ignores undefined", () => {
    const buf = new Uint8Array([1, 2, 3])
    zeroize(buf)
    expect([...buf]).toEqual([0, 0, 0])
    // No-throw on falsy input.
    // @ts-expect-error — exercising the early-return branch
    zeroize(undefined)
  })

  it("concat joins arbitrary chunks", () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]))
    expect([...out]).toEqual([1, 2, 3, 4, 5])
    expect(concat().length).toBe(0)
  })

  it("toBase64 / fromBase64 round-trip", () => {
    const b = new Uint8Array([0, 1, 2, 255])
    expect(fromBase64(toBase64(b))).toEqual(b)
  })

  it("randomBytes returns the requested length", () => {
    expect(randomBytes(16).length).toBe(16)
    expect(randomBytes(0).length).toBe(0)
  })
})
