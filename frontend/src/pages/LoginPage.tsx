import { useState, type FormEvent } from "react";
import { Navigate } from "react-router";
import { useAuth } from "../auth";
import { ErrorBox } from "../components";

export default function LoginPage() {
  const { operator, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (operator) return <Navigate to="/streams" replace />;

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
    <main className="login">
      <h1>TraceLock</h1>
      <p className="subtitle">Context-enriched tamper-evident audit logging</p>
      <form className="card form" onSubmit={submit}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        <ErrorBox error={error} />
        <button type="submit" className="primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="muted small">Sign-ins, sign-outs and failed attempts are recorded in the system audit stream.</p>
      </form>
    </main>
  );
}
