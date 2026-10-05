import { Ban, FileStack, FolderOpen, KeyRound, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { Link } from "react-router";
import { api } from "../../api/client";
import type { Stream } from "../../api/types";
import { CLASSIFICATIONS, SYSTEM_STREAM_ID, type FileList, type Findings, type SecurityEventPage } from "../../api/zt";
import { useAuth } from "../../auth";
import { useLoader } from "../../components";
import { ClassificationBadge, DecisionBadge, VerificationBadge } from "../../ui/badges";
import { DecisionsOverTime, HorizontalBars, type DayBucket } from "../../ui/charts";
import { EmptyState, ErrorState, PageHeader, Panel, Skeleton, StatTile, relativeTime } from "../../ui/primitives";
import { FileIcon } from "../files/fileParts";

const DAYS = 14;
const SAMPLE = 500;

const CATEGORY_OF: Record<string, string> = {
  FILE_ACCESS_DENIED: "Denied access",
  UNAUTHENTICATED_ACCESS: "Unauthenticated access",
  FILE_INTEGRITY_FAILURE: "Integrity failures",
  FILE_INTEGRITY_CHECK: "Integrity checks",
  FILE_SHARED: "Permission changes",
  FILE_SHARE_REVOKED: "Permission changes",
  FILE_PERMISSION_GRANTED: "Permission changes",
  FILE_PERMISSION_REVOKED: "Permission changes",
  FILE_ACCESS_POLICY_CHANGED: "Permission changes",
  FILE_DELETE: "Deletions",
  FILE_VERSION_RESTORED: "Restorations",
  FILE_VERSION_CREATED: "Replacements",
  FILE_UPLOAD: "Uploads",
  FILE_DOWNLOAD: "Downloads & views",
  FILE_VIEW: "Downloads & views",
};

async function classificationTotals() {
  const totals = await Promise.all(
    CLASSIFICATIONS.map((c) => api<FileList>("/files", { params: { classification: c, limit: 1 } }).then((r) => r.total)),
  );
  return CLASSIFICATIONS.map((c, i) => ({ classification: c, total: totals[i] }));
}

export default function OverviewPage() {
  const { operator } = useAuth();
  const security = operator?.role === "admin" || operator?.role === "auditor";
  const visible = useLoader(() => api<FileList>("/files", { params: { limit: 1 } }), []);
  const recent = useLoader(() => api<FileList>("/files", { params: { scope: "recent", limit: 6 } }), []);
  const byClass = useLoader(classificationTotals, []);

  const protectedCount = byClass.data
    ? byClass.data.filter((c) => c.classification === "RESTRICTED" || c.classification === "HIGHLY_RESTRICTED").reduce((s, c) => s + c.total, 0)
    : undefined;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={
          <span>
            Live data from the backend for <strong>{operator?.username}</strong>. File figures cover the files you are allowed to
            see; security figures are visible to administrators and auditors.
          </span>
        }
      />
      <div className="grid kpis" style={{ marginBottom: 16 }}>
        <StatTile label="Files visible to you" icon={<FileStack size={14} aria-hidden />} value={visible.data?.total ?? "—"} loading={visible.loading} to="/files" />
        <StatTile
          label="Protected files"
          icon={<ShieldAlert size={14} aria-hidden />}
          value={protectedCount ?? "—"}
          loading={byClass.loading}
          foot="Restricted + highly restricted"
          to="/files?classification=RESTRICTED"
        />
        <StatTile
          label="Recently accessed"
          icon={<FolderOpen size={14} aria-hidden />}
          value={recent.data?.total ?? "—"}
          loading={recent.loading}
          foot="Files with recorded access"
          to="/files/recent"
        />
        {security && <SecurityTiles />}
      </div>

      <div className="grid cols-2">
        {security ? <DecisionsPanel /> : null}
        <Panel title="Files by classification" hint="Files visible to you, by sensitivity">
          <ErrorState error={byClass.error} onRetry={byClass.reload} />
          {byClass.loading && !byClass.data ? (
            <Skeleton height={120} />
          ) : (
            byClass.data && (
              <HorizontalBars
                ordinal
                emptyTitle="No files yet"
                data={byClass.data.map((c) => ({ label: c.classification.replace("_", " "), value: c.total }))}
              />
            )
          )}
        </Panel>
        {security ? <CategoriesPanel /> : null}
        <Panel title="Recent file activity" hint="Your most recently accessed files" actions={<Link to="/files/recent">View all</Link>}>
          <ErrorState error={recent.error} onRetry={recent.reload} />
          {recent.loading && !recent.data && <Skeleton height={120} />}
          {recent.data && recent.data.items.length === 0 && (
            <EmptyState title="No recent activity">Files you download or preview appear here.</EmptyState>
          )}
          {recent.data && recent.data.items.length > 0 && (
            <table>
              <tbody>
                {recent.data.items.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <div className="cell-title">
                        <FileIcon extension={f.extension} />
                        <Link to={`/files/${f.id}`}>{f.display_name}</Link>
                      </div>
                    </td>
                    <td>
                      <ClassificationBadge value={f.classification} />
                    </td>
                    <td className="small muted nowrap">{relativeTime(f.last_accessed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        {security ? <RecentSecurityEvents /> : null}
      </div>
    </>
  );
}

function SecurityTiles() {
  const findings = useLoader(() => api<Findings>("/security/findings", { params: { threshold: 1 } }), []);
  const streams = useLoader(() => api<Stream[]>("/streams"), []);
  const denied = findings.data?.repeated_denials.reduce((s, r) => s + r.count, 0);
  const integrity = findings.data?.integrity_failures.length;
  const unauth = findings.data?.unauthenticated_attempts.reduce((s, r) => s + r.count, 0);
  const system = streams.data?.find((s) => s.id === SYSTEM_STREAM_ID);
  return (
    <>
      <StatTile
        label="Denied attempts (24 h)"
        icon={<Ban size={14} aria-hidden />}
        value={denied ?? "—"}
        loading={findings.loading}
        tone={denied ? "danger" : undefined}
        to="/security/denied"
      />
      <StatTile
        label="Integrity failures (24 h)"
        icon={<ShieldX size={14} aria-hidden />}
        value={integrity ?? "—"}
        loading={findings.loading}
        tone={integrity ? "danger" : "ok"}
        to="/security/integrity"
      />
      <StatTile
        label="Unauthenticated attempts (24 h)"
        icon={<KeyRound size={14} aria-hidden />}
        value={unauth ?? "—"}
        loading={findings.loading}
        tone={unauth ? "warn" : undefined}
        to="/security/events?category=unauthenticated"
      />
      <StatTile
        label="Audit chain"
        icon={<ShieldCheck size={14} aria-hidden />}
        value={streams.loading ? "" : <VerificationBadge status={system?.last_verification_status} />}
        loading={streams.loading}
        foot={system ? `${system.record_count} records · last verification` : undefined}
        to={`/audit/streams/${SYSTEM_STREAM_ID}/verification`}
      />
    </>
  );
}

function useRecentEvents() {
  const since = new Date(Date.now() - DAYS * 86400_000).toISOString();
  return useLoader(() => api<SecurityEventPage>("/security/events", { params: { since, limit: SAMPLE } }), []);
}

function DecisionsPanel() {
  const events = useRecentEvents();
  const buckets: DayBucket[] = [];
  if (events.data) {
    const byDay = new Map<string, DayBucket>();
    for (let i = DAYS - 1; i >= 0; i--) {
      const day = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      byDay.set(day, { day, allow: 0, deny: 0 });
    }
    for (const e of events.data.items) {
      const b = byDay.get(e.timestamp.slice(0, 10));
      if (!b) continue;
      if (e.decision === "ALLOW") b.allow += 1;
      else if (e.decision === "DENY") b.deny += 1;
    }
    buckets.push(...byDay.values());
  }
  return (
    <Panel title="Allow vs deny decisions" hint={`Access decisions per day, last ${DAYS} days`}>
      <ErrorState error={events.error} onRetry={events.reload} />
      {events.loading && !events.data ? (
        <Skeleton height={160} />
      ) : (
        events.data && (
          <DecisionsOverTime
            data={buckets}
            footnote={
              events.data.next_cursor
                ? `Based on the latest ${SAMPLE} security events in the window (more exist).`
                : "All security events in the window."
            }
          />
        )
      )}
    </Panel>
  );
}

function CategoriesPanel() {
  const events = useRecentEvents();
  const counts = new Map<string, number>();
  for (const e of events.data?.items ?? []) {
    const c = CATEGORY_OF[e.event_type];
    if (c) counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  const data = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));
  return (
    <Panel title="Security event categories" hint={`Last ${DAYS} days`}>
      <ErrorState error={events.error} onRetry={events.reload} />
      {events.loading && !events.data ? <Skeleton height={140} /> : <HorizontalBars data={data} emptyTitle="No security events in this window" />}
    </Panel>
  );
}

function RecentSecurityEvents() {
  const events = useLoader(() => api<SecurityEventPage>("/security/events", { params: { limit: 8 } }), []);
  return (
    <Panel title="Recent security events" actions={<Link to="/security/events">Search events</Link>}>
      <ErrorState error={events.error} onRetry={events.reload} />
      {events.loading && !events.data && <Skeleton height={140} />}
      {events.data && events.data.items.length === 0 && <EmptyState title="No security events yet" />}
      {events.data && events.data.items.length > 0 && (
        <table>
          <tbody>
            {events.data.items.map((e) => (
              <tr key={e.chain_index}>
                <td className="num small">
                  <Link to={`/security/events/${e.chain_index}`}>#{e.chain_index}</Link>
                </td>
                <td>
                  <code className="small">{e.event_type}</code>
                </td>
                <td className="small">{e.user ?? <span className="muted">anonymous</span>}</td>
                <td>
                  <DecisionBadge value={e.decision} />
                </td>
                <td className="small muted nowrap">{relativeTime(e.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
