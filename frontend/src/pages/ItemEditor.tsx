import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { aeadSeal, aeadOpen, blindToken } from "@/lib/cryptoClient";
import { cryptoStore } from "@/state/crypto";
import { createItem, getItems, updateItem } from "@/api/client";
import { toast } from "sonner";

import { useSearch } from "@tanstack/react-router";

export default function ItemEditor() {
  const search = useSearch({ from: "/editor" }) as { id?: string };
  const [itemId, setItemId] = useState(search?.id ?? "");
  const [plaintext, setPlaintext] = useState(
    '{\n  "title": "Example",\n  "secret": "value"\n}',
  );
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | undefined>();

  async function onCreate() {
    setBusy(true);
    setMsg(undefined);
    try {
      const st = cryptoStore.state;
      if (!st.vmk) throw new Error("Not authed");
      // Nonce: 24 bytes random
      const nonce = crypto.getRandomValues(new Uint8Array(24));
      const aad = new TextEncoder().encode(`it:${itemId}:v1`);
      // Encrypt plaintext as UTF-8
      const pt = new TextEncoder().encode(plaintext);
      const ct = await aeadSeal(st.vmk, nonce, aad, pt);
      // Store nonce || ct
      const blob = new Uint8Array(nonce.length + ct.length);
      blob.set(nonce, 0);
      blob.set(ct, nonce.length);
      const ciphertext_b64 = btoa(String.fromCharCode(...blob));

      // Optional blind-index tokens (MVP: title)
      let tokens: Record<string, string[]> = {};
      try {
        if (st.kSearch) {
          const obj = JSON.parse(plaintext);
          if (obj && typeof obj.title === "string") {
            const tok = await blindToken(
              st.kSearch,
              "title",
              new TextEncoder().encode(obj.title),
            );
            tokens["title"] = [btoa(String.fromCharCode(...tok))];
          }
        }
      } catch {
        // ignore token derivation errors
      }

      await createItem({ item_id: itemId, version: 1, ciphertext_b64, tokens });
      toast.success("Item created");
      setItemId("");
    } catch (e: any) {
      toast.error(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }

  async function onLoad() {
    try {
      const st = cryptoStore.state;
      if (!st.vmk) throw new Error("Not authed");
      if (!itemId) throw new Error("Enter item id");
      const res = await getItems([itemId]);
      if (!res?.[0]?.ciphertext) throw new Error("Not found");
      const blob = Uint8Array.from(atob(res[0].ciphertext), (c) =>
        c.charCodeAt(0),
      );
      const nonce = blob.slice(0, 24);
      const ct = blob.slice(24);
      const aad = new TextEncoder().encode(`it:${itemId}:v1`);
      const pt = await aeadOpen(st.vmk, nonce, aad, ct);
      setPlaintext(new TextDecoder().decode(pt));
      toast.success("Loaded");
    } catch (e: any) {
      toast.error(String(e?.message || e));
    }
  }

  async function onUpdate() {
    setBusy(true);
    try {
      const st = cryptoStore.state;
      if (!st.vmk) throw new Error("Not authed");
      if (!itemId) throw new Error("Enter item id");
      const nonce = crypto.getRandomValues(new Uint8Array(24));
      const aad = new TextEncoder().encode(`it:${itemId}:v1`);
      const pt = new TextEncoder().encode(plaintext);
      const ct = await aeadSeal(st.vmk, nonce, aad, pt);
      const blob = new Uint8Array(nonce.length + ct.length);
      blob.set(nonce, 0);
      blob.set(ct, nonce.length);
      const ciphertext_b64 = btoa(String.fromCharCode(...blob));
      await updateItem(itemId, { ciphertext_b64, version: 1 });
      toast.success("Updated");
    } catch (e: any) {
      toast.error(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3 p-6">
      <h1 className="text-xl font-semibold">Item Editor</h1>
      <Input
        placeholder="item id"
        value={itemId}
        onChange={(e) => setItemId(e.target.value)}
      />
      <Textarea
        rows={10}
        value={plaintext}
        onChange={(e) => setPlaintext(e.target.value)}
      />
      <div className="flex gap-2">
        <Button disabled={busy || !itemId} onClick={onCreate}>
          Create
        </Button>
        <Button variant="outline" disabled={!itemId} onClick={onLoad}>
          Load
        </Button>
        <Button
          variant="secondary"
          disabled={busy || !itemId}
          onClick={onUpdate}
        >
          Update
        </Button>
      </div>
      {msg && <div className="text-sm text-gray-600">{msg}</div>}
    </div>
  );
}
