import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { blindToken } from "@/lib/cryptoClient";
import { cryptoStore } from "@/state/crypto";
import { searchEq } from "@/api/client";
import { toast } from "sonner";

export default function Search() {
  const [field, setField] = useState("title");
  const [value, setValue] = useState("");
  const [results, setResults] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [prevStack, setPrevStack] = useState<string[]>([]);

  async function runSearch(cursor?: string, pushPrev?: string) {
    setBusy(true);
    try {
      const st = cryptoStore.state;
      if (!st.kSearch) throw new Error("Not authed");
      const tok = await blindToken(
        st.kSearch,
        field,
        new TextEncoder().encode(value),
      );
      const res = await searchEq(
        [{ type: field, value_b64: btoa(String.fromCharCode(...tok)) }],
        25,
        cursor,
      );
      setResults(res.item_ids);
      setNextCursor(res.next_cursor);
      if (pushPrev) setPrevStack((s) => [...s, pushPrev]);
    } catch (e: any) {
      toast.error(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }
  async function onSearch() {
    setPrevStack([]);
    await runSearch();
  }
  async function goNext() {
    if (!nextCursor) return;
    await runSearch(nextCursor, nextCursor);
  }
  async function goPrev() {
    if (prevStack.length === 0) return;
    const prev = prevStack[prevStack.length - 1];
    setPrevStack((s) => s.slice(0, -1));
    await runSearch(prev);
  }

  return (
    <div className="space-y-3 p-6">
      <h1 className="text-xl font-semibold">Search</h1>
      <div className="flex gap-2">
        <Input
          placeholder="field"
          value={field}
          onChange={(e) => setField(e.target.value)}
          className="max-w-40"
        />
        <Input
          placeholder="value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <Button disabled={busy || !value} onClick={onSearch}>
          Search
        </Button>
      </div>
      <ul className="space-y-2">
        {results.map((id) => (
          <li key={id} className="rounded border p-2 text-sm">
            <a
              className="underline"
              href={`/editor?id=${encodeURIComponent(id)}`}
            >
              {id}
            </a>
          </li>
        ))}
      </ul>
      <div className="mt-2 flex gap-2">
        <Button
          variant="outline"
          disabled={busy || prevStack.length === 0}
          onClick={goPrev}
        >
          Prev
        </Button>
        <Button
          variant="outline"
          disabled={busy || !nextCursor}
          onClick={goNext}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
