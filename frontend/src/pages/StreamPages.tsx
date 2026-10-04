/** Per-stream pages: layout, events, event detail, session, batches, verification. */

import { useState, type FormEvent } from "react";
import { Link, NavLink, Outlet, useOutletContext, useParams } from "react-router";
import { api } from "../api/client";
import type { AuditEvent, Batch, EventDetail, EventPage, Proof, RunDetail, RunSummary, StreamDetail } from "../api/types";
import { useAuth } from "../auth";
import { Card, Check, DataBanner, ErrorBox, Hash, KindBadge, StatusBadge, formatTime, useLoader } from "../components";

type StreamContext = { stream: StreamDetail; reloadStream: () => void };

export function StreamLayout() {
  const { streamId = "" } = useParams();
  const stream = useLoader(() => api<StreamDetail>(`/streams/${streamId}`), [streamId]);
  if (stream.error) return <ErrorBox error={stream.error} />;
  if (!stream.data) return <p className="muted">Loading…</p>;
  const s = stream.data;
  return (
    <>
      <div className="title-row">
        <h1>{s.name}</h1>
        <KindBadge kind={s.kind} />
        <StatusBadge status={s.last_verification_status} />
      </div>
      <DataBanner kind={s.kind} />
      <p className="muted small">
        {s.record_count} records · batch size {s.batch_size} · {s.hash_scheme} / {s.merkle_scheme} · genesis{" "}
        <Hash value={s.genesis_hash} />
        {s.source_stream_id && (
          <>
            {" "}
            · cloned from <Link to={`/streams/${s.source_stream_id}`}>source stream</Link>
          </>
        )}
      </p>
      <nav className="tabs">
        <NavLink to="events">Events</NavLink>
        <NavLink to="batches">Merkle batches</NavLink>
        <NavLink to="verification">Verification</NavLink>
      </nav>
      <Outlet context={{ stream: s, reloadStream: stream.reload } satisfies StreamContext} />
    </>
  );
}

function useStream() {
  return useOutletContext<StreamContext>();
}

function EventRows({ events, streamId }: { events: AuditEvent[]; streamId: string }) {
  return (
    <table>
      <thead>
        <tr>
          <th className="num">#</th>
          <th>Timestamp (UTC)</th>
          <th>Event</th>
          <th>User</th>
          <th>Session</th>
          <th className="num">Seq</th>
          <th>Previous event</th>
          <th>Entry hash</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.chain_index}>
            <td className="num">
              <Link to={`/streams/${streamId}/events/${e.chain_index}`}>{e.chain_index}</Link>
            </td>
            <td className="small">{e.event_timestamp}</td>
            <td>{e.event_type}</td>
            <td>{e.actor_user_id ?? <span className="muted">—</span>}</td>
            <td>
              {e.session_id ? (
                <Link to={`/streams/${streamId}/sessions/${encodeURIComponent(e.session_id)}`}>{e.session_id}</Link>
              ) : (
                <span className="muted">sessionless</span>
              )}
            </td>
            <td className="num">{e.session_seq ?? "—"}</td>
            <td>{e.prev_event_type ?? "—"}</td>
            <td>
              <Hash value={e.entry_hash} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function EventsPage() {
  const { stream } = useStream();
  const [filters, setFilters] = useState({ actor_user_id: "", session_id: "", event_type: "" });
  const [applied, setApplied] = useState(filters);
  const [extra, setExtra] = useState<AuditEvent[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const page = useLoader(async () => {
    const result = await api<EventPage>(`/streams/${stream.id}/events`, { params: { ...applied, limit: 100 } });
    setExtra([]);
    setCursor(result.next_cursor);
    return result;
  }, [stream.id, applied]);
  const [error, setError] = useState<unknown>(null);

  async function more() {
    try {
      const next = await api<EventPage>(`/streams/${stream.id}/events`, {
        params: { ...applied, limit: 100, cursor: cursor ?? undefined },
      });
      setExtra((items) => [...items, ...next.items]);
      setCursor(next.next_cursor);
    } catch (e) {
      setError(e);
    }
  }

  function apply(event: FormEvent) {
    event.preventDefault();
    setApplied(filters);
  }

  return (
    <Card>
      <form className="inline-form" onSubmit={apply}>
        {(["actor_user_id", "session_id", "event_type"] as const).map((key) => (
          <label key={key}>
            {{ actor_user_id: "User", session_id: "Session", event_type: "Event type" }[key]}
            <input value={filters[key]} onChange={(e) => setFilters({ ...filters, [key]: e.target.value })} />
          </label>
        ))}
        <button type="submit">Filter</button>
      </form>
      <ErrorBox error={page.error ?? error} />
      {page.data && <EventRows events={[...page.data.items, ...extra]} streamId={stream.id} />}
      {page.data && page.data.items.length === 0 && <p className="muted">No events.</p>}
      {cursor !== null && (
        <button type="button" onClick={() => void more()}>
          Load more
        </button>
      )}
    </Card>
  );
}

export function EventDetailPage() {
  const { stream } = useStream();
  const { chainIndex = "" } = useParams();
  const detail = useLoader(() => api<EventDetail>(`/streams/${stream.id}/events/${chainIndex}`), [stream.id, chainIndex]);
  const [proof, setProof] = useState<{ proof: Proof; valid: boolean } | null>(null);
  const [error, setError] = useState<unknown>(null);

  async function loadProof() {
    setError(null);
    try {
      const p = await api<Proof>(`/streams/${stream.id}/events/${chainIndex}/proof`);
      const check = await api<{ valid: boolean }>("/proofs/verify", {
        method: "POST",
        body: { leaf: p.leaf, merkle_root: p.merkle_root, proof: p.proof },
      });
      setProof({ proof: p, valid: check.valid });
    } catch (e) {
      setError(e);
    }
  }

  if (detail.error) return <ErrorBox error={detail.error} />;
  if (!detail.data) return <p className="muted">Loading…</p>;
  const { record: r, predecessor, recomputed_hash, hash_matches, link_matches, batch } = detail.data;
  const index = r.chain_index;

  return (
    <>
      <p>
        {index > 1 && <Link to={`../events/${index - 1}`}>← #{index - 1}</Link>}{" "}
        <Link to={`../events/${index + 1}`}>#{index + 1} →</Link>
      </p>
      <Card title={`Record #${index}: ${r.event_type}`}>
        <dl className="fields">
          <dt>Timestamp</dt>
          <dd>{r.event_timestamp}</dd>
          <dt>User</dt>
          <dd>{r.actor_user_id ?? "—"}</dd>
          <dt>Session</dt>
          <dd>
            {r.session_id ? (
              <Link to={`../sessions/${encodeURIComponent(r.session_id)}`}>{r.session_id}</Link>
            ) : (
              "sessionless"
            )}
          </dd>
          <dt>Sequence no.</dt>
          <dd>{r.session_seq ?? "—"}</dd>
          <dt>Previous event</dt>
          <dd>{r.prev_event_type ?? "—"}</dd>
          <dt>Payload</dt>
          <dd>
            <pre>{JSON.stringify(r.payload, null, 2)}</pre>
          </dd>
        </dl>
      </Card>
      <Card title="Hash relationships">
        <table>
          <tbody>
            <tr>
              <th>Stored previous hash</th>
              <td>
                <Hash value={r.prev_hash} full />
              </td>
            </tr>
            <tr>
              <th>
                Actual predecessor hash{" "}
                {predecessor.chain_index ? (
                  <Link to={`../events/${predecessor.chain_index}`}>(#{predecessor.chain_index})</Link>
                ) : (
                  "(genesis)"
                )}
              </th>
              <td>
                <Hash value={predecessor.entry_hash} full />
              </td>
            </tr>
            <tr>
              <th>Link</th>
              <td>
                <Check ok={link_matches} label={link_matches ? "stored previous hash matches" : "chain link broken"} />
              </td>
            </tr>
            <tr>
              <th>Stored entry hash</th>
              <td>
                <Hash value={r.entry_hash} full />
              </td>
            </tr>
            <tr>
              <th>Recomputed entry hash</th>
              <td>{recomputed_hash ? <Hash value={recomputed_hash} full /> : <span className="status bad">record cannot be encoded</span>}</td>
            </tr>
            <tr>
              <th>Content</th>
              <td>
                <Check ok={hash_matches} label={hash_matches ? "content matches stored hash" : "content changed"} />
              </td>
            </tr>
          </tbody>
        </table>
      </Card>
      <Card title="Merkle batch membership">
        {batch ? (
          <>
            <p>
              In batch #{batch.batch_index}.{" "}
              <button type="button" onClick={() => void loadProof()}>
                Get and verify membership proof
              </button>
            </p>
            {proof && (
              <>
                <p>
                  <Check ok={proof.valid} label={proof.valid ? "proof verifies against the stored root" : "proof does not verify"} />
                </p>
                <ol className="small">
                  {proof.proof.proof.map((step, i) => (
                    <li key={i}>
                      sibling on the {step.position}: <Hash value={step.sibling} />
                    </li>
                  ))}
                </ol>
                <p className="small">
                  Root: <Hash value={proof.proof.merkle_root} full />
                </p>
              </>
            )}
          </>
        ) : (
          <p className="muted">Not yet in a sealed batch (protected by the hash chain only).</p>
        )}
        <ErrorBox error={error} />
      </Card>
    </>
  );
}

export function SessionPage() {
  const { stream } = useStream();
  const { sessionId = "" } = useParams();
  const events = useLoader(
    () => api<AuditEvent[]>(`/streams/${stream.id}/sessions/${encodeURIComponent(sessionId)}`),
    [stream.id, sessionId],
  );
  return (
    <Card title={`Session ${sessionId}`}>
      <ErrorBox error={events.error} />
      {events.data && <EventRows events={events.data} streamId={stream.id} />}
    </Card>
  );
}

export function BatchesPage() {
  const { stream, reloadStream } = useStream();
  const { can } = useAuth();
  const batches = useLoader(() => api<Batch[]>(`/streams/${stream.id}/batches`), [stream.id]);
  const [error, setError] = useState<unknown>(null);

  async function seal(includePartial: boolean) {
    setError(null);
    try {
      await api(`/streams/${stream.id}/batches/seal`, { method: "POST", body: { include_partial: includePartial } });
      batches.reload();
      reloadStream();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <Card
      title="Sealed Merkle batches"
      actions={
        can("admin") && (
          <div className="actions">
            <button type="button" onClick={() => void seal(false)}>
              Seal full batches
            </button>
            <button type="button" onClick={() => void seal(true)}>
              Seal including partial
            </button>
          </div>
        )
      }
    >
      <ErrorBox error={batches.error ?? error} />
      {batches.data && batches.data.length === 0 && <p className="muted">No sealed batches yet.</p>}
      {batches.data && batches.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th className="num">Batch</th>
              <th>Records</th>
              <th className="num">Leaves</th>
              <th>Merkle root</th>
              <th>Sealed</th>
            </tr>
          </thead>
          <tbody>
            {batches.data.map((b) => (
              <tr key={b.batch_id}>
                <td className="num">{b.batch_index}</td>
                <td>
                  <Link to={`../events/${b.first_chain_index}`}>#{b.first_chain_index}</Link> –{" "}
                  <Link to={`../events/${b.last_chain_index}`}>#{b.last_chain_index}</Link>
                </td>
                <td className="num">{b.leaf_count}</td>
                <td>
                  <Hash value={b.merkle_root} />
                </td>
                <td className="small">{formatTime(b.sealed_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function Report({ run }: { run: RunDetail }) {
  const first = run.first_failure;
  return (
    <Card title="Verification report">
      <div className="report-status">
        <StatusBadge status={run.status} />
        <span className="muted small">
          {formatTime(run.started_at)} · {run.duration_ms.toFixed(1)} ms (measured)
        </span>
      </div>
      {first && (
        <p>
          First failure: record{" "}
          {first.chain_index !== null ? <Link to={`../events/${first.chain_index}`}>#{first.chain_index}</Link> : "—"}
          {first.batch_index !== null && <> in batch #{first.batch_index}</>} — check <code>{first.check}</code>
        </p>
      )}
      <dl className="fields compact">
        <dt>Records checked</dt>
        <dd>{run.records_checked}</dd>
        <dt>Batches checked</dt>
        <dd>{run.batches_checked}</dd>
        <dt>Unbatched records</dt>
        <dd>{run.unbatched_records} (chain-protected only)</dd>
        <dt>Cascade (full recomputation)</dt>
        <dd>{run.cascade_affected_records} stored chain values disagree</dd>
        <dt>Rules</dt>
        <dd className="small">{run.rules_version}</dd>
        <dt>Schemes</dt>
        <dd>
          {run.hash_scheme} / {run.merkle_scheme}
        </dd>
      </dl>
      {Object.keys(run.failed_by_check).length > 0 && (
        <>
          <h3>Failed checks</h3>
          <table>
            <tbody>
              {Object.entries(run.failed_by_check).map(([check, count]) => (
                <tr key={check}>
                  <td>
                    <code>{check}</code>
                  </td>
                  <td className="num">{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>
            Findings (showing {run.findings.length} of {run.findings_total})
          </h3>
          <table>
            <thead>
              <tr>
                <th className="num">Record</th>
                <th>Check</th>
                <th>Expected (derived)</th>
                <th>Actual (stored)</th>
              </tr>
            </thead>
            <tbody>
              {run.findings.map((f, i) => (
                <tr key={i}>
                  <td className="num">
                    {f.chain_index !== null ? <Link to={`../events/${f.chain_index}`}>{f.chain_index}</Link> : "—"}
                  </td>
                  <td>
                    <code>{f.check}</code>
                  </td>
                  <td className="small wrap">{f.expected}</td>
                  <td className="small wrap">{f.actual}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Card>
  );
}

export function VerificationPage() {
  const { stream, reloadStream } = useStream();
  const { can } = useAuth();
  const runs = useLoader(() => api<RunSummary[]>(`/streams/${stream.id}/verification-runs`), [stream.id]);
  const [current, setCurrent] = useState<RunDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      setCurrent(await api<RunDetail>(`/streams/${stream.id}/verify`, { method: "POST" }));
      runs.reload();
      reloadStream();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  async function open(runId: string) {
    try {
      setCurrent(await api<RunDetail>(`/verification-runs/${runId}`));
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <Card
        title="Verify integrity, provenance and batches"
        actions={
          can("admin", "auditor") && (
            <button type="button" className="primary" disabled={busy} onClick={() => void verify()}>
              {busy ? "Verifying…" : "Run verification"}
            </button>
          )
        }
      >
        <p className="muted small">
          Recomputes every chain value, re-applies the five provenance checks and timestamp order, and rebuilds every
          sealed batch's Merkle root.
        </p>
        <ErrorBox error={error} />
      </Card>
      {current && <Report run={current} />}
      <Card title="History">
        <ErrorBox error={runs.error} />
        {runs.data && runs.data.length === 0 && <p className="muted">No verification runs yet.</p>}
        {runs.data && runs.data.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Status</th>
                <th>First failure</th>
                <th className="num">Records</th>
                <th className="num">ms</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.run_id}>
                  <td className="small">{formatTime(r.started_at)}</td>
                  <td>
                    <StatusBadge status={r.status} />
                  </td>
                  <td>{r.first_failure ? `#${r.first_failure.chain_index} ${r.first_failure.check}` : "—"}</td>
                  <td className="num">{r.records_checked}</td>
                  <td className="num">{r.duration_ms.toFixed(1)}</td>
                  <td>
                    <button type="button" onClick={() => void open(r.run_id)}>
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
