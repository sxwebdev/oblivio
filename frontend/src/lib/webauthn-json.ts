// Native WebAuthn ↔ JSON conversion.
//
// We can't use @simplewebauthn/browser's `startAuthentication` for the
// PRF flow: as of 13.3.0 it passes `extensions.prf.eval.first` through
// verbatim, so a base64url-encoded string from the JSON wire format
// lands in `navigator.credentials.get`, which expects an ArrayBuffer
// and throws `TypeError: not of type '(ArrayBuffer or ArrayBufferView)'`.
//
// This module gives us just enough JSON conversion to:
//  • take a `PublicKeyCredentialRequestOptionsJSON` produced by the
//    server (challenge / allowCredentials are base64url strings) and
//    return native `PublicKeyCredentialRequestOptions` with binary
//    fields restored;
//  • take the resulting `PublicKeyCredential` from
//    `navigator.credentials.get` and serialise it back to the JSON
//    shape the server expects.
//
// PRF extension is wired separately by the caller — they hand us the
// salts as raw bytes.

import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser"

export function bytesToBase64Url(b: Uint8Array): string {
  let s = ""
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function base64UrlToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/")
  while (s.length % 4) s += "="
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// PrfInputs lets the caller pick which PRF variant to use. Pass
// `eval` for a single salt across any matching credential, or
// `evalByCredential` to vary the salt by credential id.
export type PrfInputs = {
  eval?: { first: Uint8Array; second?: Uint8Array }
  // Keys are the AUTHENTICATOR's raw credential id, base64url-encoded.
  evalByCredential?: Record<
    string,
    { first: Uint8Array; second?: Uint8Array }
  >
}

// requestOptionsFromJSON converts the JSON wire format into the
// browser-native shape. Caller may optionally inject PRF inputs that
// arrive separately (typically from a per-credential server lookup).
export function requestOptionsFromJSON(
  json: PublicKeyCredentialRequestOptionsJSON,
  prf?: PrfInputs
): PublicKeyCredentialRequestOptions {
  const opts: PublicKeyCredentialRequestOptions = {
    challenge: base64UrlToBytes(json.challenge) as unknown as ArrayBuffer,
    timeout: json.timeout,
    rpId: json.rpId,
    userVerification: json.userVerification,
  }
  if (json.allowCredentials && json.allowCredentials.length > 0) {
    opts.allowCredentials = json.allowCredentials.map((c) => ({
      id: base64UrlToBytes(c.id) as unknown as ArrayBuffer,
      type: c.type,
      transports: c.transports as AuthenticatorTransport[] | undefined,
    }))
  }
  if (prf) {
    const ext: AuthenticationExtensionsClientInputs = {}
    const prfInput: PrfExtensionInput = {}
    if (prf.eval) {
      prfInput.eval = {
        first: prf.eval.first.buffer as ArrayBuffer,
        ...(prf.eval.second
          ? { second: prf.eval.second.buffer as ArrayBuffer }
          : {}),
      }
    }
    if (prf.evalByCredential) {
      prfInput.evalByCredential = {}
      for (const [k, v] of Object.entries(prf.evalByCredential)) {
        prfInput.evalByCredential[k] = {
          first: v.first.buffer as ArrayBuffer,
          ...(v.second ? { second: v.second.buffer as ArrayBuffer } : {}),
        }
      }
    }
    ;(ext as unknown as { prf: PrfExtensionInput }).prf = prfInput
    opts.extensions = ext
  }
  return opts
}

// assertionToJSON serialises the result of navigator.credentials.get()
// into the JSON shape the server consumes (mirrors what SimpleWebAuthn
// would have produced). PRF extension results are NOT included — the
// server doesn't need them; the caller extracts them locally via
// credential.getClientExtensionResults().
export function assertionToJSON(cred: PublicKeyCredential): unknown {
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: bytesToBase64Url(new Uint8Array(cred.rawId)),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: bytesToBase64Url(new Uint8Array(r.clientDataJSON)),
      authenticatorData: bytesToBase64Url(new Uint8Array(r.authenticatorData)),
      signature: bytesToBase64Url(new Uint8Array(r.signature)),
      userHandle: r.userHandle
        ? bytesToBase64Url(new Uint8Array(r.userHandle))
        : undefined,
    },
    // Per WebAuthn JSON spec; SimpleWebAuthn emits {} when no extensions
    // are returned. We omit PRF results here on purpose — they contain
    // unlock-key material and must not leave the page.
    clientExtensionResults: {},
  }
}

// readPrfFirst returns the 32-byte PRF output the authenticator
// computed for `eval.first` (or `evalByCredential[id].first`, depending
// on what the caller asked for). Returns null when the authenticator
// did not honour the extension.
export function readPrfFirst(cred: PublicKeyCredential): Uint8Array | null {
  const ext = cred.getClientExtensionResults() as unknown as {
    prf?: { results?: { first?: ArrayBuffer | Uint8Array } }
  }
  const first = ext?.prf?.results?.first
  if (!first) return null
  return first instanceof Uint8Array ? first : new Uint8Array(first)
}

// PrfExtensionInput mirrors the spec type. TypeScript's lib.dom.d.ts
// doesn't always include it; we typecast at the boundary.
type PrfExtensionInput = {
  eval?: { first: ArrayBuffer; second?: ArrayBuffer }
  evalByCredential?: Record<
    string,
    { first: ArrayBuffer; second?: ArrayBuffer }
  >
}
