// Cryptographically-strong password generator (plan §9.1).
//
// Rejection sampling over `crypto.getRandomValues` so the output is
// uniformly distributed across the chosen alphabet. We never use modulo on
// a random byte — that biases short alphabets toward the first
// 256 % alphabet.length characters.

const LOWER = "abcdefghijklmnopqrstuvwxyz"
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const DIGITS = "0123456789"
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"

export type PasswordOptions = {
  length: number
  lowercase?: boolean
  uppercase?: boolean
  digits?: boolean
  symbols?: boolean
}

export function buildAlphabet(opts: PasswordOptions): string {
  let alphabet = ""
  if (opts.lowercase) alphabet += LOWER
  if (opts.uppercase) alphabet += UPPER
  if (opts.digits) alphabet += DIGITS
  if (opts.symbols) alphabet += SYMBOLS
  return alphabet
}

export function generatePassword(opts: PasswordOptions): string {
  if (!Number.isInteger(opts.length) || opts.length <= 0) {
    throw new Error("length must be a positive integer")
  }
  const alphabet = buildAlphabet(opts)
  if (alphabet.length === 0) {
    throw new Error("alphabet is empty: enable at least one character class")
  }
  // Rejection sampling against the largest multiple of alphabet.length that
  // fits in a byte. Bytes above that cap are discarded.
  const max = 256 - (256 % alphabet.length)
  const out: string[] = new Array(opts.length)
  let filled = 0
  while (filled < opts.length) {
    const buf = randomChunk(opts.length * 2 + 8)
    for (let i = 0; i < buf.length && filled < opts.length; i++) {
      const b = buf[i]
      if (b >= max) continue
      out[filled++] = alphabet[b % alphabet.length]
    }
  }
  return out.join("")
}

// crypto.getRandomValues rejects buffers larger than 65 536 bytes. Cap the
// chunk size at that limit and let the caller loop.
function randomChunk(want: number): Uint8Array {
  const size = Math.min(want, 65_536)
  const out = new Uint8Array(size)
  crypto.getRandomValues(out)
  return out
}
