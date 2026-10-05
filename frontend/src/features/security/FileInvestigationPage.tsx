import { FileWarning, ScrollText } from "lucide-react";
import { Link, useParams } from "react-router";
import { api } from "../../api/client";
import type { FileInvestigation, FileTimeline } from "../../api/zt";
import { useLoader } from "../../components";
import { ClassificationBadge, DecisionBadge, IntegrityBadge, VerificationBadge } from "../../ui/badges";
import { EmptyState, ErrorState, HashText, KeyValue, PageHeader, Panel, Skeleton, formatDate } from "../../ui/primitives";

export default function FileInvestigationPage() {
  const { fileId = "" } = useParams();
  const report = useLoader(() => api<FileInvestigation>(`/security/files/${fileId}/integrity`), [fileId]);
  const timeline = useLoader(() => api<FileTimeline>(`/security/files/${fileId}/timeline`), [fileId]);
  const name = report.data?.display_name ?? timeline.data?.display_name ?? "File";

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Security", to: "/security/integrity" }, { label: "Investigation" }, { label: name }]}
        title={name}
        badges={report.data && <ClassificationBadge value={report.data.classification} />}
        subtitle="File integrity and audit-log integrity are checked separately: a file can be damaged while the log is intact, and the other way round."
        actions={
          <>
            <Link className="btn" to={`/files/${fileId}`}>
              Open file
            </Link>
            <button type="button" onClick={() => report.reload()} disabled={report.loading}>
              Re-run checks
            </button>
          </>
        }
      />
      <ErrorState error={report.error} onRetry={report.reload} />
      {report.loading && !report.data && <Skeleton height={180} />}
      {report.data && <Verdicts r={report.data} />}
      {report.data && (
        <Panel title="Versions: three fingerprints compared" hint="Database hash vs the hash recorded in the chained event vs the hash of the stored bytes now">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Expected (database)</th>
                <th>Anchored (audit event)</th>
                <th>Actual (stored bytes)</th>
                <th>File</th>
                <th>Anchor event</th>
              </tr>
            </thead>
            <tbody>
              {report.data.versions.map((v) => (
                <tr key={v.version}>
                  <td>v{v.version}</td>
                  <td>
                    <HashText value={v.expected_sha256} />
                  </td>
                  <td>
                    <HashText value={v.anchored_sha256} />
                  </td>
                  <td>{v.actual_sha256 ? <HashText value={v.actual_sha256} /> : <span className="status bad">missing</span>}</td>
                  <td>
                    <IntegrityBadge value={v.file_status === "INTACT" ? "INTACT" : v.file_status} />
                  </td>
                  <td>
                    <Link to={`/security/events/${v.anchor_chain_index}`}>#{v.anchor_chain_index}</Link>{" "}
                    <VerificationBadge status={v.anchor_status === "VALID" ? "VALID" : v.anchor_status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
      <Panel title="Audit trail" hint="Every chained event about this file, oldest first" actions={<ScrollText size={16} aria-hidden />}>
        <ErrorState error={timeline.error} onRetry={timeline.reload} />
        {timeline.loading && !timeline.data && <Skeleton height={120} />}
        {timeline.data && timeline.data.events.length === 0 && <EmptyState title="No events about this file" />}
        {timeline.data && timeline.data.events.length > 0 && (
          <ol className="timeline">
            {timeline.data.events.map((e) => (
              <li key={e.chain_index}>
                <span className="small muted">{formatDate(e.timestamp)}</span>
                <span aria-hidden>•</span>
                <span className="row" style={{ gap: 8 }}>
                  <Link to={`/security/events/${e.chain_index}`}>#{e.chain_index}</Link>
                  <code className="small">{e.event_type}</code>
                  <span className="small">{e.user ?? "anonymous"}</span>
                  <DecisionBadge value={e.decision} />
                  {e.reason_code && <span className="small muted">{e.reason_code}</span>}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </>
  );
}

function Verdicts({ r }: { r: FileInvestigation }) {
  const fileOk = r.file_integrity.status === "INTACT";
  const logOk = r.audit_log_integrity.status === "VALID";
  const s = r.audit_log_integrity.stream;
  return (
    <div className="grid cols-2" style={{ marginBottom: 16 }}>
      <section className={`verdict ${fileOk ? "ok" : "bad"}`} style={{ alignItems: "flex-start", margin: 0 }} aria-label="File integrity">
        <FileWarning size={22} aria-hidden />
        <div>
          <div className="small" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            FILE INTEGRITY
          </div>
          <div className="verdict-title">{fileOk ? "VERIFIED" : "FILE INTEGRITY FAILURE"}</div>
          <div className="verdict-body">
            {fileOk ? (
              "Every version's bytes and stored hash match what an intact audit event recorded."
            ) : (
              <KeyValue
                items={[
                  ["First affected version", `v${r.file_integrity.first_affected_version}`],
                  [
                    "Recorded by",
                    <Link key="e" to={`/security/events/${r.file_integrity.first_affected_audit_event}`}>
                      audit event #{r.file_integrity.first_affected_audit_event}
                    </Link>,
                  ],
                  ["Meaning", "The stored content (or its database hash) was changed after it was recorded."],
                ]}
              />
            )}
          </div>
        </div>
      </section>
      <section className={`verdict ${logOk ? "ok" : "bad"}`} style={{ alignItems: "flex-start", margin: 0 }} aria-label="Audit log integrity">
        <ScrollText size={22} aria-hidden />
        <div>
          <div className="small" style={{ fontWeight: 600, letterSpacing: "0.05em" }}>
            AUDIT LOG INTEGRITY
          </div>
          <div className="verdict-title">{logOk ? "VALID" : "AUDIT LOG INTEGRITY FAILURE"}</div>
          <div className="verdict-body">
            <KeyValue
              items={[
                ["System stream", <VerificationBadge key="s" status={s.status} />],
                ["Records checked", s.records_checked],
                ["Unbatched records", s.unbatched_records],
                [
                  "First affected event",
                  s.first_affected_audit_event ? (
                    <Link to={`/security/events/${s.first_affected_audit_event}`}>
                      #{s.first_affected_audit_event} ({s.first_failed_check})
                    </Link>
                  ) : null,
                ],
                ["Failing anchors", r.audit_log_integrity.anchors_failing.length ? r.audit_log_integrity.anchors_failing.map((a) => `#${a}`).join(", ") : "none"],
              ]}
            />
          </div>
        </div>
      </section>
    </div>
  );
}
