import { useCallback, useEffect, useState } from "react";
import { fetchHealth, type HealthStatus } from "./api";

type State =
  | { kind: "loading" }
  | { kind: "loaded"; health: HealthStatus }
  | { kind: "unreachable" };

export default function App() {
  const [state, setState] = useState<State>({ kind: "loading" });

  const refresh = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      setState({ kind: "loaded", health: await fetchHealth() });
    } catch {
      setState({ kind: "unreachable" });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <main className="page">
      <h1>TraceLock</h1>
      <p className="subtitle">Context-enriched tamper-evident audit logging</p>

      <section className="card">
        <h2>System status</h2>
        {state.kind === "loading" && <p>Checking…</p>}
        {state.kind === "unreachable" && (
          <p className="status bad">Backend unreachable</p>
        )}
        {state.kind === "loaded" && (
          <dl className="status-list">
            <dt>API</dt>
            <dd className={state.health.status === "ok" ? "status ok" : "status bad"}>
              {state.health.status}
            </dd>
            <dt>Database</dt>
            <dd className={state.health.database === "ok" ? "status ok" : "status bad"}>
              {state.health.database}
            </dd>
          </dl>
        )}
        <button type="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </section>
    </main>
  );
}
