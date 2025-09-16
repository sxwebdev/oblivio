// Crypto client wrapper for the web worker
// Provides: hkdf, hmac, aead-seal/open, blind-token

let worker: Worker | null = null;

function getWorker() {
  if (!worker) {
    worker = new Worker(
      new URL("../workers/cryptoWorker.ts", import.meta.url),
      { type: "module" },
    );
  }
  return worker!;
}

function b64e(b: Uint8Array) {
  return btoa(String.fromCharCode(...b));
}
function b64d(s: string) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

type WorkerReq =
  | { type: "hkdf"; ikm_b64: string; info: string; len: number; id?: string }
  | { type: "hmac"; key_b64: string; data_b64: string; id?: string }
  | {
      type: "aead-seal";
      key_b64: string;
      nonce_b64: string;
      aad_b64: string;
      pt_b64: string;
      id?: string;
    }
  | {
      type: "aead-open";
      key_b64: string;
      nonce_b64: string;
      aad_b64: string;
      ct_b64: string;
      id?: string;
    }
  | {
      type: "blind-token";
      kSearch_b64: string;
      field: string;
      value_b64: string;
      id?: string;
    };

let msgId = 0;
function rpc<TRes extends { ok: boolean; id?: string }>(
  req: WorkerReq,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const id = String(++msgId);
    const w = getWorker();
    const onMsg = (ev: MessageEvent<TRes>) => {
      const data: any = ev.data;
      if (data?.id !== id) return;
      w.removeEventListener("message", onMsg);
      if (data.ok) resolve(data);
      else reject(new Error(data.error || "worker error"));
    };
    w.addEventListener("message", onMsg);
    (req as any).id = id;
    w.postMessage(req);
  });
}

export async function hkdf(ikm: Uint8Array, info: string, bytes: number) {
  const r = await rpc({ type: "hkdf", ikm_b64: b64e(ikm), info, len: bytes });
  return b64d(r.out_b64);
}
export async function hmac(key: Uint8Array, data: Uint8Array) {
  const r = await rpc({
    type: "hmac",
    key_b64: b64e(key),
    data_b64: b64e(data),
  });
  return b64d(r.mac_b64);
}
export async function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
) {
  const r = await rpc({
    type: "aead-seal",
    key_b64: b64e(key),
    nonce_b64: b64e(nonce),
    aad_b64: b64e(aad),
    pt_b64: b64e(pt),
  });
  return b64d(r.ct_b64);
}
export async function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
) {
  const r = await rpc({
    type: "aead-open",
    key_b64: b64e(key),
    nonce_b64: b64e(nonce),
    aad_b64: b64e(aad),
    ct_b64: b64e(ct),
  });
  return b64d(r.pt_b64);
}
export async function blindToken(
  kSearch: Uint8Array,
  field: string,
  value: Uint8Array,
) {
  const r = await rpc({
    type: "blind-token",
    kSearch_b64: b64e(kSearch),
    field,
    value_b64: b64e(value),
  });
  return b64d(r.token_b64);
}

export function disposeCryptoWorker() {
  if (worker) {
    worker.terminate();
    worker = null;
  }
}
