// Cross-environment helpers for byte/string conversion. Used by every module.

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function utf8Decode(b: Uint8Array): string {
  return new TextDecoder().decode(b)
}

// Wipe a Uint8Array in place. Best-effort — JS does not guarantee no copies
// remain, but for short-lived key buffers this raises the bar significantly.
export function zeroize(view: Uint8Array): void {
  if (!view) return
  view.fill(0)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export function fromBase64(s: string): Uint8Array {
  // atob is available in browsers and Node 16+.
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function toBase64(b: Uint8Array): string {
  let s = ""
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s)
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  crypto.getRandomValues(out)
  return out
}
