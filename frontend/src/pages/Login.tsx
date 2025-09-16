import { useState } from "react";
import { sessionStore } from "@/state/session";
import { cryptoStore } from "@/state/crypto";
import { hkdf } from "@/lib/cryptoClient";
import { authLogin, setAuthToken } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

export default function Login() {
  const [username, setUsername] = useState("");
  const [pwd, setPwd] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <div className="mx-auto max-w-sm p-6">
      <h1 className="mb-4 text-xl font-semibold">Login (MVP)</h1>
      <div className="space-y-3">
        <Input
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <Input
          type="password"
          placeholder="Password"
          value={pwd}
          onChange={(e) => setPwd(e.target.value)}
        />
        <Input
          placeholder="TOTP code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        <Button
          disabled={busy || !username || !pwd || !code}
          onClick={async () => {
            setBusy(true);
            try {
              // Backend login with MFA, plus derive in-memory keys for client crypto
              const resp = await authLogin({
                username,
                password: pwd,
                code,
              } as any);
              setAuthToken(resp.token);
              const enc = new TextEncoder();
              const ikm = enc.encode(pwd);
              const vmk = await hkdf(ikm, "vmk", 32);
              const kSearch = await hkdf(ikm, "ksearch", 32);
              cryptoStore.setState({ vmk, kSearch });
              sessionStore.setState({ isAuthed: true });
              toast.success("Logged in");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Loading…" : "Login"}
        </Button>
      </div>
    </div>
  );
}
