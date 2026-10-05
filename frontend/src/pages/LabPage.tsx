import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ApiError, api } from "../api/client";
import type { Scenario, ScenarioType, Stream, StreamDetail } from "../api/types";
import { Card, Check, ErrorBox, KindBadge, formatTime, useLoader } from "../components";

export default function LabPage() {
  const types = useLoader(() => api<ScenarioType[]>("/lab/scenario-types"), []);
  const scenarios = useLoader(() => api<Scenario[]>("/lab/scenarios"), []);
  const streams = useLoader(() => api<Stream[]>("/streams"), []);

  if (types.error instanceof ApiError && types.error.status === 404) {
    return (
      <Card title="Tamper lab">
        <p>
          The tamper lab is disabled. Set <code>TRACELOCK_LAB_ENABLED=true</code> in <code>.env</code> and restart the
          backend to enable it. It only ever modifies cloned <em>lab</em> streams.
        </p>
      </Card>
    );
  }
  const sources = (streams.data ?? []).filter((s) => s.kind !== "lab");

  return (
    <>
      <h1>Tamper lab</h1>
      <p className="muted">
        Controlled experiments: each scenario clones a source stream, records the expected outcome, tampers with the
        clone only, then verifies it. Source streams are never modified.
      </p>
      <ErrorBox error={types.error ?? scenarios.error ?? streams.error} />
      <WorkloadForm onCreated={streams.reload} />
      <ScenarioForm types={types.data ?? []} sources={sources} onDone={scenarios.reload} />
      <Card title="Scenario results">
        {scenarios.data && scenarios.data.length === 0 && <p className="muted">No scenarios run yet.</p>}
        {scenarios.data && scenarios.data.length > 0 && <ScenarioTable rows={scenarios.data} />}
      </Card>
    </>
  );
}

function WorkloadForm({ onCreated }: { onCreated: () => void }) {
  const [form, setForm] = useState({ users: 5, sessions_per_user: 4, events_per_session: 10, seed: 1, batch_size: 32 });
  const [created, setCreated] = useState<StreamDetail | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setCreated(await api<StreamDetail>("/lab/workloads", { method: "POST", body: form }));
      onCreated();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="1. Generate a synthetic workload">
      <form className="inline-form" onSubmit={submit}>
        {(Object.keys(form) as (keyof typeof form)[]).map((key) => (
          <label key={key}>
            {key.replaceAll("_", " ")}
            <input
              type="number"
              value={form[key]}
              onChange={(e) => setForm({ ...form, [key]: Number(e.target.value) })}
            />
          </label>
        ))}
        <button type="submit" className="primary" disabled={busy}>
          {busy ? "Generating…" : "Generate"}
        </button>
      </form>
      <ErrorBox error={error} />
      {created && (
        <p>
          Created <Link to={`/audit/streams/${created.id}`}>{created.name}</Link> <KindBadge kind={created.kind} /> with{" "}
          {created.record_count} records (seed {form.seed}; the same seed reproduces identical data).
        </p>
      )}
    </Card>
  );
}

function ScenarioForm({ types, sources, onDone }: { types: ScenarioType[]; sources: Stream[]; onDone: () => void }) {
  const [source, setSource] = useState("");
  const [code, setCode] = useState("S1");
  const [seed, setSeed] = useState(0);
  const [target, setTarget] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const selected = source || sources[0]?.id || "";

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api<Scenario>("/lab/scenarios", {
        method: "POST",
        body: {
          source_stream_id: selected,
          scenario_type: code,
          seed,
          ...(target ? { target_chain_index: Number(target) } : {}),
        },
      });
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="2. Run a tampering scenario">
      <form className="inline-form" onSubmit={submit}>
        <label>
          Source stream
          <select value={selected} onChange={(e) => setSource(e.target.value)}>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.kind}, {s.record_count} records)
              </option>
            ))}
          </select>
        </label>
        <label>
          Scenario
          <select value={code} onChange={(e) => setCode(e.target.value)}>
            {types.map((t) => (
              <option key={t.code} value={t.code}>
                {t.code} [{t.attacker_model}] {t.description}
              </option>
            ))}
          </select>
        </label>
        <label>
          Seed
          <input type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} />
        </label>
        <label>
          Target index (optional)
          <input type="number" min={1} value={target} onChange={(e) => setTarget(e.target.value)} />
        </label>
        <button type="submit" className="primary" disabled={busy || !selected}>
          {busy ? "Running…" : "Run scenario"}
        </button>
      </form>
      <ErrorBox error={error} />
    </Card>
  );
}

function ScenarioTable({ rows }: { rows: Scenario[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Scenario</th>
          <th>Parameters</th>
          <th>Expected</th>
          <th>Actual</th>
          <th>Outcome</th>
          <th className="num">True first</th>
          <th>Reported first</th>
          <th>Located</th>
          <th>Run at</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((s) => (
          <tr key={s.id}>
            <td>
              <strong>{s.scenario_type}</strong> <span className="muted">[{s.attacker_model}]</span>
              <div className="small">{s.description}</div>
            </td>
            <td className="small">
              {Object.entries(s.parameters)
                .map(([k, v]) => `${k}=${String(v)}`)
                .join(", ")}
            </td>
            <td>{s.expected_detected ? "detected" : "not detected"}</td>
            <td>
              <Link to={`/audit/streams/${s.lab_stream_id}/verification`}>
                {s.actual_detected === null ? "—" : s.actual_detected ? "detected" : "not detected"}
              </Link>
            </td>
            <td>
              <span className={`badge ${s.outcome === "AS_EXPECTED" ? "ok" : "bad"}`}>{s.outcome.replace("_", " ")}</span>
            </td>
            <td className="num">{s.true_first_index ?? "—"}</td>
            <td>
              {s.first_failure_index !== null ? (
                <Link to={`/audit/streams/${s.lab_stream_id}/events/${s.first_failure_index}`}>
                  #{s.first_failure_index} {s.first_failure_check}
                </Link>
              ) : (
                "—"
              )}
            </td>
            <td>
              <Check ok={s.located_correctly} />
            </td>
            <td className="small">{formatTime(s.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
