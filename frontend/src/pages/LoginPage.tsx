import { Fingerprint, Layers, LockKeyhole, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Navigate } from "react-router";
import { useAuth } from "../auth";
import { ErrorState } from "../ui/primitives";

export default function LoginPage() {
  const { operator, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (operator) return <Navigate to="/overview" replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <aside className="login-aside">
        <div>
          <div className="row" style={{ gap: 10, fontSize: 18, fontWeight: 700, color: "#fff" }}>
            <ShieldCheck size={22} aria-hidden /> TraceLock
          </div>
          <h1 style={{ marginTop: 48 }}>Zero-Trust file governance with a tamper-evident audit trail.</h1>
          <ul>
            <li>
              <LockKeyhole size={16} aria-hidden /> Every file access is decided by policy: identity, role, department,
              classification, ownership, grants and session.
            </li>
            <li>
              <Fingerprint size={16} aria-hidden /> Every decision is a context-enriched, SHA-256 hash-chained audit record.
            </li>
            <li>
              <Layers size={16} aria-hidden /> Records are sealed into Merkle batches and can be verified at any time.
            </li>
          </ul>
        </div>
        <p className="small" style={{ color: "#94a3b8" }}>
          Tamper-evident, not tamper-proof: changes are detected, not prevented.
        </p>
      </aside>
      <main className="login-main">
        <form className="form" onSubmit={(e) => void submit(e)} aria-label="Sign in">
          <div>
            <h2 style={{ fontSize: 20 }}>Sign in</h2>
            <p className="muted small">Use your TraceLock account.</p>
          </div>
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </label>
          <ErrorState error={error} />
          <button type="submit" className="primary" disabled={busy} style={{ height: 36 }}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="muted small" style={{ margin: 0 }}>
            Sign-ins, sign-outs and failed attempts are recorded in the system audit stream.
          </p>
        </form>
      </main>
    </div>
  );
}
