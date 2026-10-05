import { Ban, Filter, Radar, ShieldX } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api } from "../../api/client";
import { CLASSIFICATIONS, type Findings, type SecurityEvent, type SecurityEventPage } from "../../api/zt";
import { useLoader } from "../../components";
import { ClassificationBadge, DecisionBadge } from "../../ui/badges";
import { EmptyState, ErrorState, PageHeader, Panel, SkeletonRows, formatDate } from "../../ui/primitives";

const CATEGORIES = ["denied", "unauthenticated", "integrity", "permissions", "deletion", "restoration", "replacement", "access", "authentication"];
const FIELDS = ["user", "file_id", "action", "decision", "classification", "category", "since", "until"] as const;

type Preset = "all" | "denied" | "integrity";
const PRESETS: Record<Preset, { title: string; subtitle: string; category?: string; icon: ReactNode }> = {
  all: {
    title: "Security events",
    subtitle: "Search the chained platform events. Every row is a record in the tamper-evident audit chain.",
    icon: <Filter size={16} aria-hidden />,
  },
  denied: {
    title: "Denied access",
    subtitle: "Every refused file or sharing operation, with the policy rule that refused it.",
    category: "denied",
    icon: <Ban size={16} aria-hidden />,
  },
  integrity: {
    title: "File integrity",
    subtitle: "Integrity checks and failures. Open a file to separate file damage from audit-log tampering.",
    category: "integrity",
    icon: <ShieldX size={16} aria-hidden />,
  },
};

export default function SecurityEventsPage({ preset = "all" }: { preset?: Preset }) {
  const p = PRESETS[preset];
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const filters = Object.fromEntries(FIELDS.map((f) => [f, params.get(f) ?? ""])) as Record<(typeof FIELDS)[number], string>;
  if (p.category) filters.category = p.category;
  const [draft, setDraft] = useState(filters);
  const [extra, setExtra] = useState<SecurityEvent[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const key = JSON.stringify(filters);

  const toIso = (v: string) => (v ? new Date(v).toISOString() : undefined);
  const query = { ...filters, since: toIso(filters.since), until: toIso(filters.until), limit: 100 };

  const page = useLoader(async () => {
    const result = await api<SecurityEventPage>("/security/events", { params: query });
    setExtra([]);
    setCursor(result.next_cursor);
    return result;
  }, [key]);

  async function more() {
    if (cursor === null) return;
    const next = await api<SecurityEventPage>("/security/events", { params: { ...query, cursor } });
    setExtra((e) => [...e, ...next.items]);
    setCursor(next.next_cursor);
  }

  function apply(e: FormEvent) {
    e.preventDefault();
    const next = new URLSearchParams();
    for (const f of FIELDS) if (draft[f] && !(f === "category" && p.category)) next.set(f, draft[f]);
    setParams(next);
  }

  const rows = [...(page.data?.items ?? []), ...extra];
  const filterUser = (u: string) => setParams(new URLSearchParams({ user: u }));

  return (
    <>
      <PageHeader title={p.title} subtitle={p.subtitle} crumbs={[{ label: "Security" }, { label: p.title }]} />
      {preset !== "all" && <FindingsStrip preset={preset} onUser={filterUser} />}
      <form className="filter-bar" onSubmit={apply} aria-label="Event filters">
        <label>
          User
          <input value={draft.user} onChange={(e) => setDraft({ ...draft, user: e.target.value })} maxLength={128} />
        </label>
        <label>
          File ID
          <input value={draft.file_id} onChange={(e) => setDraft({ ...draft, file_id: e.target.value })} placeholder="uuid" style={{ width: 150 }} />
        </label>
        <label>
          Action
          <select value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })}>
            <option value="">Any</option>
            {["VIEW", "DOWNLOAD", "CREATE", "UPLOAD", "UPDATE", "RENAME", "DELETE", "SHARE", "RESTORE", "VERIFY", "MANAGE_PERMISSIONS"].map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </label>
        <label>
          Decision
          <select value={draft.decision} onChange={(e) => setDraft({ ...draft, decision: e.target.value })}>
            <option value="">Any</option>
            <option>ALLOW</option>
            <option>DENY</option>
            <option>BLOCKED</option>
          </select>
        </label>
        <label>
          Classification
          <select value={draft.classification} onChange={(e) => setDraft({ ...draft, classification: e.target.value })}>
            <option value="">Any</option>
            {CLASSIFICATIONS.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </label>
        {!p.category && (
          <label>
            Category
            <select value={draft.category} onChange={(e) => setDraft({ ...draft, category: e.target.value })}>
              <option value="">Any</option>
              {CATEGORIES.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
        )}
        <label>
          From
          <input type="datetime-local" value={draft.since} onChange={(e) => setDraft({ ...draft, since: e.target.value })} />
        </label>
        <label>
          To
          <input type="datetime-local" value={draft.until} onChange={(e) => setDraft({ ...draft, until: e.target.value })} />
        </label>
        <button type="submit" className="primary">
          Apply
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => {
            setDraft(Object.fromEntries(FIELDS.map((f) => [f, ""])) as typeof draft);
            setParams(new URLSearchParams());
          }}
        >
          Reset
        </button>
      </form>
      <ErrorState error={page.error} onRetry={page.reload} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">Chain #</th>
              <th>Time</th>
              <th>Event</th>
              <th>User</th>
              <th>File</th>
              <th>Action</th>
              <th>Decision</th>
              <th>Reason</th>
            </tr>
          </thead>
          {page.loading && !page.data ? (
            <SkeletonRows cols={8} />
          ) : (
            <tbody>
              {rows.map((e) => (
                <tr key={e.chain_index} className="clickable" onClick={() => navigate(`/security/events/${e.chain_index}`)}>
                  <td className="num">
                    <Link to={`/security/events/${e.chain_index}`} onClick={(ev) => ev.stopPropagation()}>
                      {e.chain_index}
                    </Link>
                  </td>
                  <td className="small nowrap">{formatDate(e.timestamp)}</td>
                  <td>
                    <code className="small">{e.event_type}</code>
                  </td>
                  <td className="small">{e.user ?? <span className="muted">anonymous</span>}</td>
                  <td className="small">
                    {e.file_id ? (
                      <span className="row" style={{ gap: 6 }}>
                        <ClassificationBadge value={e.classification} />
                        <span className="muted">{e.filename ?? e.file_id.slice(0, 8)}</span>
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="small">{e.action ?? "—"}</td>
                  <td>
                    <DecisionBadge value={e.decision} />
                  </td>
                  <td className="small muted">{e.reason_code ?? ""}</td>
                </tr>
              ))}
            </tbody>
          )}
        </table>
        {page.data && rows.length === 0 && (
          <EmptyState title="No matching events" icon={p.icon}>
            Nothing in the audit chain matches these filters.
          </EmptyState>
        )}
        {cursor !== null && (
          <div className="table-footer">
            <span>Showing {rows.length} events, newest first</span>
            <button type="button" className="sm" onClick={() => void more()}>
              Load older events
            </button>
          </div>
        )}
      </div>
    </>
  );
}

/** Aggregates over the last 24 hours that point at where to look first. */
function FindingsStrip({ preset, onUser }: { preset: Preset; onUser: (u: string) => void }) {
  const findings = useLoader(() => api<Findings>("/security/findings", { params: { threshold: 2 } }), []);
  if (!findings.data) return null;
  if (preset === "denied") {
    const rows = findings.data.repeated_denials;
    const probes = new Set(findings.data.probing_unknown_or_hidden_files.map((r) => r.user));
    if (rows.length === 0) return null;
    return (
      <Panel title="Repeated denials (last 24 h)" hint="Users with two or more denied requests. Probing = requests for files they may not even see." actions={<Radar size={16} aria-hidden />}>
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th className="num">Denials</th>
              <th className="num">Distinct files</th>
              <th>First / last</th>
              <th>Signal</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.user ?? "anon"}>
                <td>
                  <button type="button" className="ghost sm" onClick={() => r.user && onUser(r.user)}>
                    {r.user ?? "anonymous"}
                  </button>
                </td>
                <td className="num">{r.count}</td>
                <td className="num">{r.distinct_files}</td>
                <td className="small muted">
                  {formatDate(r.first_seen)} → {formatDate(r.last_seen)}
                </td>
                <td>{probes.has(r.user) ? <span className="badge warn">PROBING</span> : <span className="badge muted">DENIALS</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    );
  }
  const failures = findings.data.integrity_failures;
  return (
    <div className={`verdict ${failures.length ? "bad" : "ok"}`}>
      {failures.length ? <ShieldX size={20} aria-hidden /> : <Radar size={20} aria-hidden />}
      <div>
        <div className="verdict-title">{failures.length ? `${failures.length} INTEGRITY FAILURE(S) IN 24 H` : "NO INTEGRITY FAILURES IN 24 H"}</div>
        <div className="verdict-body">
          Failures block downloads automatically. Open a failure to see whether the file or the audit log was altered.
        </div>
      </div>
    </div>
  );
}
