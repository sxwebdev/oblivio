import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  authRegister,
  authLogin,
  setAuthToken,
  authMFAVerify,
} from "@/api/client";
import { sessionStore } from "@/state/session";
import { cryptoStore } from "@/state/crypto";
import { hkdf } from "@/lib/cryptoClient";
import { useEffect, useRef } from "react";
// Importing qrcode sometimes lacks types; we import as any
// eslint-disable-next-line @typescript-eslint/no-var-requires
// @ts-ignore
import QRCode from "qrcode";
import { toast } from "sonner";

export default function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Render otpauth URI as QR code to canvas
  useEffect(() => {
    const uri = otpauth;
    const canvas = canvasRef.current;
    if (!uri || !canvas) return;
    QRCode.toCanvas(canvas, uri, { width: 192 }, (err: any) => {
      if (err) console.error(err);
    });
  }, [otpauth]);

  async function onRegister() {
    setBusy(true);
    try {
      const res: any = await authRegister({ username, password });
      setOtpauth(res?.otpauth_url || null);
      toast.message("Scan QR and enter TOTP code to verify MFA");
    } catch (e: any) {
      toast.error(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }
  async function onVerifyMFA() {
    setBusy(true);
    try {
      await authMFAVerify({ username, password, code });
      const resp = await authLogin({ username, password, code } as any);
      setAuthToken(resp.token);
      const enc = new TextEncoder();
      const ikm = enc.encode(password);
      const vmk = await hkdf(ikm, "vmk", 32);
      const kSearch = await hkdf(ikm, "ksearch", 32);
      cryptoStore.setState({ vmk, kSearch });
      sessionStore.setState({ isAuthed: true });
      toast.success("MFA verified & logged in");
    } catch (e: any) {
      toast.error(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-sm space-y-3 p-6">
      <h1 className="text-xl font-semibold">Register</h1>
      {!otpauth ? (
        <>
          <Input
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Button
            disabled={busy || !username || !password}
            onClick={onRegister}
          >
            Register
          </Button>
        </>
      ) : (
        <>
          <div className="text-muted-foreground text-sm">
            Add this TOTP to your authenticator app:
          </div>
          <div className="flex items-start gap-4">
            <canvas ref={canvasRef} className="rounded border" />
            <div className="max-w-[24rem] rounded border p-2 text-xs break-all">
              {otpauth}
            </div>
          </div>
          <Input
            placeholder="Enter TOTP code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <Button disabled={busy || !code} onClick={onVerifyMFA}>
            Verify & Login
          </Button>
        </>
      )}
    </div>
  );
}
