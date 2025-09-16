import { useEffect, useState } from "react";
import { listItems } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Link } from "@tanstack/react-router";

export default function VaultList() {
  const [items, setItems] = useState<
    { item_id: string; updated_at: number; size: number }[]
  >([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [prevStack, setPrevStack] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const LIMIT = 25;
  useEffect(() => {
    (async () => {
      setBusy(true);
      try {
        const res = await listItems(LIMIT);
        setItems(res.items);
        setNextCursor(res.next_cursor);
        setPrevStack([]);
      } finally {
        setBusy(false);
      }
    })();
  }, []);
  async function goNext() {
    if (!nextCursor) return;
    setBusy(true);
    try {
      const res = await listItems(LIMIT, nextCursor);
      setItems(res.items);
      setPrevStack((s) => [...s, nextCursor]);
      setNextCursor(res.next_cursor);
    } finally {
      setBusy(false);
    }
  }
  async function goPrev() {
    if (prevStack.length === 0) return;
    const prev = prevStack[prevStack.length - 1];
    setBusy(true);
    try {
      const res = await listItems(LIMIT, prev);
      setItems(res.items);
      setPrevStack((s) => s.slice(0, -1));
      setNextCursor(res.next_cursor);
    } finally {
      setBusy(false);
    }
  }
  const empty = items.length === 0;
  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Vault Items</h1>
        <Button asChild>
          <Link to="/editor">New Item</Link>
        </Button>
      </div>
      {empty ? (
        <div className="rounded border p-6 text-center text-sm text-gray-600">
          No items yet.{" "}
          <Link to="/editor" className="underline">
            Create one
          </Link>
          .
        </div>
      ) : (
        <>
          <ul className="space-y-2">
            {items.map((it) => (
              <li
                key={it.item_id}
                className="flex justify-between rounded border p-2"
              >
                <span>
                  <Link
                    to="/editor"
                    search={{ id: it.item_id }}
                    className="underline"
                  >
                    {it.item_id}
                  </Link>
                </span>
                <span className="text-xs text-gray-500">
                  {new Date(it.updated_at * 1000).toLocaleString()} · {it.size}B
                </span>
              </li>
            ))}
          </ul>
          <div className="mt-4 flex gap-2">
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
        </>
      )}
    </div>
  );
}
