// Blind-index over titles. Plan §4.4.
// title_hash = HMAC-SHA256(K_blind, NFKC(lowercase(title))).

import { utf8 } from "./util";

export async function blindIndex(
  blindKey: CryptoKey,
  value: string,
): Promise<Uint8Array> {
  const normalized = value.normalize("NFKC").toLowerCase();
  const sig = await crypto.subtle.sign(
    "HMAC",
    blindKey,
    utf8(normalized) as unknown as ArrayBuffer,
  );
  return new Uint8Array(sig);
}
