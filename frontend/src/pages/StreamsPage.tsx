import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api } from "../api/client";
import type { Stream } from "../api/types";
import { useAuth } from "../auth";
import { Card, ErrorBox, KindBadge, StatusBadge, formatTime, useLoader } from "../components";

export default function StreamsPage() {
  const { can } = useAuth();
  const streams = useLoader(() => api<Stream[]>("/streams"), []);
  const [name, setName] = useState("");
  const [batchSize, setBatchSize] = useState(64);
  const [error, setError] = useState<unknown>(null);

  async function create(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api("/streams", { method: "POST", body: { name, batch_size: batchSize } });
      setName("");
      streams.reload();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <h1>Log streams</h1>
      <p className="muted">Each stream is an independent hash chain with its own Merkle batches.</p>
      <Card>
        <ErrorBox error={streams.error} />
        {streams.data && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th className="num">Records</th>
                <th className="num">Batch size</th>
                <th>Last verification</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {streams.data.map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link to={`/audit/streams/${s.id}`}>{s.name}</Link>
                  </td>
                  <td>
                    <KindBadge kind={s.kind} />
                  </td>
                  <td className="num">{s.record_count}</td>
                  <td className="num">{s.batch_size}</td>
                  <td>
                    <StatusBadge status={s.last_verification_status} />
                  </td>
                  <td className="small">{formatTime(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {can("admin") && (
        <Card title="New primary stream">
          <form className="inline-form" onSubmit={create}>
            <label>
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} />
            </label>
            <label>
              Batch size
              <input
                type="number"
                min={1}
                max={4096}
                value={batchSize}
                onChange={(e) => setBatchSize(Number(e.target.value))}
              />
            </label>
            <button type="submit" className="primary">
              Create
            </button>
          </form>
          <ErrorBox error={error} />
        </Card>
      )}
    </>
  );
}
