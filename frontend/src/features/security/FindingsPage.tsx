import { Radar } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client";
import type { Findings, SecurityEvent, UserCount } from "../../api/zt";
import { useLoader } from "../../components";
import { ClassificationBadge, DecisionBadge } from "../../ui/badges";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton, formatDate } from "../../ui/primitives";

const WINDOWS = [
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
];

export default function FindingsPage() {
  const [hours, setHours] = useState(24);
  const [threshold, setThreshold] = useState(3);
  const findings = useLoader(
    () => api<Findings>("/security/findings", { params: { since: new Date(Date.now() - hours * 3600_000).toISOString(), threshold } }),
    [hours, threshold],
  );
  const f = findings.data;
  return (
    <>
      <PageHeader
        title="Findings"
        crumbs={[{ label: "Security" }, { label: "Findings" }]}
        subtitle="Patterns in the audit chain worth a closer look. These are threshold heuristics over recorded events, not automated threat detection."
        actions={
          <>
            <div className="segmented" role="group" aria-label="Time window">
              {WINDOWS.map((w) => (
                <button key={w.hours} type="button" aria-pressed={hours === w.hours} onClick={() => setHours(w.hours)}>
                  {w.label}
                </button>
              ))}
            </div>
            <label className="row" style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
              Threshold
              <input type="number" min={1} max={1000} value={threshold} onChange={(e) => setThreshold(Math.max(1, Number(e.target.value) || 1))} style={{ width: 72 }} />
            </label>
          </>
        }
      />
      <ErrorState error={findings.error} onRetry={findings.reload} />
      {findings.loading && !f && <Skeleton height={240} />}
      {f && (
        <div className="grid cols-2">
          <Users title="Repeated denials" hint={`Users with ≥ ${threshold} denied requests`} rows={f.repeated_denials} />
          <Users title="Probing hidden or unknown files" hint="Denials for files the user may not even see" rows={f.probing_unknown_or_hidden_files} />
          <Users title="High-frequency downloads" hint={`Users with ≥ ${threshold} downloads`} rows={f.high_frequency_downloads} />
          <Users title="Unauthenticated attempts" hint="Rejected tokens on file endpoints (anonymous = not attributable)" rows={f.unauthenticated_attempts} />
          <Events title="Integrity failures" rows={f.integrity_failures} />
          <Events title="Break-glass self-grants" rows={f.break_glass_self_grants} />
          <Events title="Classification downgrades" rows={f.classification_downgrades} />
          <Events title="Deletions" rows={f.deletions} />
          <Events title="Failed re-authentications" rows={f.failed_reauthentications} />
          <Events title="Provenance violations" rows={f.provenance_violations} />
        </div>
      )}
    </>
  );
}

function Users({ title, hint, rows }: { title: string; hint: string; rows: UserCount[] }) {
  return (
    <Panel title={title} hint={hint}>
      {rows.length === 0 ? (
        <EmptyState title="Nothing found" icon={<Radar size={22} aria-hidden />} />
      ) : (
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th className="num">Count</th>
              <th className="num">Files</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.user ?? "anon"}>
                <td>{r.user ? <Link to={`/security/events?user=${encodeURIComponent(r.user)}`}>{r.user}</Link> : <span className="muted">anonymous</span>}</td>
                <td className="num">{r.count}</td>
                <td className="num">{r.distinct_files}</td>
                <td className="small muted">{formatDate(r.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function Events({ title, rows }: { title: string; rows: SecurityEvent[] }) {
  return (
    <Panel title={title} hint={`${rows.length} event(s)`}>
      {rows.length === 0 ? (
        <EmptyState title="Nothing found" icon={<Radar size={22} aria-hidden />} />
      ) : (
        <table>
          <tbody>
            {rows.slice(0, 10).map((e) => (
              <tr key={e.chain_index}>
                <td className="num small">
                  <Link to={`/security/events/${e.chain_index}`}>#{e.chain_index}</Link>
                </td>
                <td className="small">{e.user ?? "anonymous"}</td>
                <td>
                  <ClassificationBadge value={e.classification} />
                </td>
                <td>
                  <DecisionBadge value={e.decision} />
                </td>
                <td className="small muted">{formatDate(e.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
