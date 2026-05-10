// Live TOTP code renderer.
//
// Generates a fresh 6-digit code from a base32 secret every second, drawing
// a thin ring that depletes as the 30s step elapses. The plaintext secret
// is decrypted from the vault by the parent — this component never touches
// the network and never persists the code.

import { useEffect, useState } from "react";
import { Copy } from "lucide-react";

import {
  generateTotpCode,
  totpRemainingSeconds,
} from "@oblivio/crypto";

import { Button } from "@/components/ui/button";
import { copySecret } from "@/lib/clipboard";

type Props = {
  secret: string;
  period?: number;
  digits?: number;
  label?: string;
};

export function TotpDisplay({
  secret,
  period = 30,
  digits = 6,
  label = "code",
}: Props) {
  const [code, setCode] = useState<string>("------");
  const [remaining, setRemaining] = useState<number>(period);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const now = new Date();
        const nextCode = await generateTotpCode(secret, now, { period, digits });
        const nextRem = totpRemainingSeconds(now, period);
        if (!cancelled) {
          setCode(nextCode);
          setRemaining(nextRem);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    }
    tick();
    const id = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [secret, period, digits]);

  if (error) {
    return (
      <p className="text-sm text-destructive">Invalid TOTP secret: {error}</p>
    );
  }

  const pct = Math.max(0, Math.min(1, remaining / period));
  // SVG ring geometry.
  const radius = 18;
  const circ = 2 * Math.PI * radius;
  const dash = circ * pct;

  return (
    <div className="flex items-center gap-4">
      <div className="font-mono text-2xl tracking-widest tabular-nums">
        {code.slice(0, Math.ceil(digits / 2))}
        <span className="mx-1 text-muted-foreground">·</span>
        {code.slice(Math.ceil(digits / 2))}
      </div>
      <div className="relative size-12">
        <svg viewBox="0 0 40 40" className="size-12 -rotate-90">
          <circle
            cx="20"
            cy="20"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeOpacity="0.15"
            strokeWidth="3"
          />
          <circle
            cx="20"
            cy="20"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeDasharray={`${dash} ${circ - dash}`}
            strokeLinecap="round"
            className="text-primary"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-xs tabular-nums">
          {remaining}
        </div>
      </div>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        onClick={() => copySecret(code, { label })}
        aria-label="Copy TOTP code"
      >
        <Copy className="size-4" />
      </Button>
    </div>
  );
}
