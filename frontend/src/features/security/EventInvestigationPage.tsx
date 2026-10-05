import { ArrowLeft, ArrowRight, Fingerprint, KeyRound, Layers, Link2, ShieldCheck, User } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { api } from "../../api/client";
import { SYSTEM_STREAM_ID, type EventInspection, type EventVerification } from "../../api/zt";
import { useLoader } from "../../components";
import { ClassificationBadge, DecisionBadge, IntegrityBadge, PassFail, VerificationBadge } from "../../ui/badges";
import { useToast } from "../../ui/feedback";
import { EmptyState, ErrorState, HashText, KeyValue, PageHeader, Panel, Skeleton, formatDate } from "../../ui/primitives";

const MERKLE_LABEL: Record<string, string> = {
  UNSEALED: "Not sealed in a batch yet — protected by the hash chain only.",
  VALID: "The batch root recomputed from the re-hashed records equals the stored root, and this record's proof verifies.",
  ROOT_MISMATCH: "The batch no longer matches its stored root: this record or a batch-mate was altered.",
  RANGE_INCONSISTENT: "Records are missing from this batch's range.",
};

export default function EventInvestigationPage() {
  const { chainIndex = "" } = useParams();
  const n = Number(chainIndex);
  const data = useLoader(() => api<EventInspection>(`/security/events/${n}`), [n]);
  const [verification, setVerification] = useState<EventVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const toast = useToast();

  async function verify() {
    setVerifying(true);
    try {
      setVerification(await api<EventVerification>(`/security/events/${n}/verify`, { method: "POST" }));
    } catch (e) {
      toast.push("danger", "Verification failed", e instanceof Error ? e.message : String(e));
    } finally {
      setVerifying(false);
    }
  }

  const crumbs = [{ label: "Security", to: "/security/events" }, { label: "Investigation" }, { label: `Event #${n}` }];
  if (data.error)
    return (
      <>
        <PageHeader title={`Event #${n}`} crumbs={crumbs} />
        <ErrorState error={data.error} onRetry={data.reload} />
      </>
    );
  if (!data.data)
    return (
      <>
        <PageHeader title={`Event #${n}`} crumbs={crumbs} />
        <Skeleton height={200} />
      </>
    );

  const { event: e, chain, merkle, related_file: file } = data.data;
  const p = e.payload as Record<string, unknown>;
  const str = (k: string) => (typeof p[k] === "string" ? (p[k] as string) : null);
  const signals = (p.signals ?? {}) as Record<string, unknown>;
  const grantee = p.grantee as Record<string, string> | undefined;

  return (
    <>
      <PageHeader
        crumbs={crumbs}
        title={
          <span className="row" style={{ gap: 10 }}>
            <code>{e.event_type}</code>
          </span>
        }
        badges={
          <>
            <DecisionBadge value={str("decision")} />
            <VerificationBadge status={chain.status === "VALID" ? "VALID" : "AUDIT_LOG_INTEGRITY_FAILURE"} />
          </>
        }
        subtitle={`Chain record #${e.chain_index} in the system stream · ${formatDate(e.timestamp)}`}
        actions={
          <>
            <Link className="btn ghost" to={`/security/events/${n - 1}`} aria-label="Previous event">
              <ArrowLeft size={14} aria-hidden /> #{n - 1}
            </Link>
            <Link className="btn ghost" to={`/security/events/${n + 1}`} aria-label="Next event">
              #{n + 1} <ArrowRight size={14} aria-hidden />
            </Link>
            <button type="button" className="primary" onClick={() => void verify()} disabled={verifying}>
              <ShieldCheck size={14} aria-hidden /> {verifying ? "Verifying…" : "Verify this event"}
            </button>
          </>
        }
      />

      {verification && <VerificationResult v={verification} />}

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <Panel title="Decision" hint="What the policy decided and why">
          <KeyValue
            items={[
              ["Decision", <DecisionBadge key="d" value={str("decision")} />],
              ["Action", str("action") && <code>{str("action")}</code>],
              ["Reason", str("reason_code")],
              ["Required permission", str("required_permission")],
              ["Policy rule", str("rule") && <code className="small">{str("rule")}</code>],
              ["Permission source", str("permission_source")],
              ["Policy", str("policy") && <code className="small">{str("policy")!.slice(0, 32)}…</code>],
            ]}
          />
        </Panel>
        <Panel title="Who" hint="Identity and session context (hashed into the record)">
          <KeyValue
            items={[
              [
                "User",
                e.user ? (
                  <Link to={`/security/events?user=${encodeURIComponent(e.user)}`} className="row" style={{ gap: 4 }}>
                    <User size={12} aria-hidden /> {e.user}
                  </Link>
                ) : (
                  <span className="muted">anonymous / unattributed</span>
                ),
              ],
              [
                "Session",
                e.session_id ? (
                  <Link to={`/audit/streams/${SYSTEM_STREAM_ID}/sessions/${encodeURIComponent(e.session_id)}`} className="row" style={{ gap: 4 }}>
                    <KeyRound size={12} aria-hidden /> <code className="small">{e.session_id.slice(0, 18)}…</code>
                  </Link>
                ) : (
                  <span className="muted">sessionless</span>
                ),
              ],
              ["Sequence no.", e.session_seq],
              ["Previous event", e.prev_event_type && <code className="small">{e.prev_event_type}</code>],
              ["IP address", str("ip_address")],
              ["Session age", typeof signals.session_age_s === "number" ? `${Math.round((signals.session_age_s as number) / 60)} min` : null],
              ["Ownership", typeof signals.ownership === "string" ? (signals.ownership as string) : null],
            ]}
          />
        </Panel>
        <Panel title="Resource" hint="The file and the permission involved">
          {file ? (
            <KeyValue
              items={[
                ["File", <Link key="f" to={`/security/files/${file.file_id}`}>{file.display_name}</Link>],
                ["Classification", <ClassificationBadge key="c" value={file.classification} />],
                ["Current version", `v${file.current_version}${file.deleted ? " (in trash)" : ""}`],
                ["Name in event", str("filename")],
                ["Grantee", grantee ? (grantee.type === "role" ? `role ${grantee.role}` : grantee.username ?? grantee.id) : null],
                ["Permissions", Array.isArray(p.permissions) ? (p.permissions as string[]).join(", ") : null],
                ["Open", <Link key="o" to={`/files/${file.file_id}?tab=permissions`}>file permissions →</Link>],
              ]}
            />
          ) : str("file_id") ? (
            <EmptyState title="File not found">The event names a file id that does not exist (for example a probe for an unknown id).</EmptyState>
          ) : (
            <EmptyState title="No file involved" />
          )}
        </Panel>
      </div>

      <Panel title="Hash chain" hint="This record between its neighbours. Each record stores the previous record's hash." actions={<Link2 size={16} aria-hidden />}>
        <div className="chain-strip">
          <div className="chain-node">
            <div className="node-title">
              {chain.predecessor.is_genesis ? "Genesis" : chain.predecessor.chain_index ? <Link to={`/security/events/${chain.predecessor.chain_index}`}>#{chain.predecessor.chain_index}</Link> : "missing"}
            </div>
            <div className="small muted">entry hash</div>
            <HashText value={chain.predecessor.entry_hash} />
          </div>
          <div className="chain-link">
            <PassFail ok={chain.link_matches} pass="linked" fail="broken" />
            <span className="muted">prev_hash</span>
          </div>
          <div className="chain-node current">
            <div className="node-title">
              <Fingerprint size={14} aria-hidden /> #{e.chain_index} (this record)
            </div>
            <div className="small muted">stored hash</div>
            <HashText value={chain.stored_hash} />
            <div className="small muted" style={{ marginTop: 4 }}>
              recomputed from content
            </div>
            <HashText value={chain.recomputed_hash} />
            <div style={{ marginTop: 4 }}>
              <PassFail ok={chain.hash_matches} pass="content unchanged" fail="content changed" />
            </div>
          </div>
          <div className="chain-link">
            {chain.successor ? <PassFail ok={chain.successor.links_back} pass="linked" fail="broken" /> : <span className="muted">—</span>}
            <span className="muted">next.prev_hash</span>
          </div>
          <div className="chain-node">
            <div className="node-title">{chain.successor ? <Link to={`/security/events/${chain.successor.chain_index}`}>#{chain.successor.chain_index}</Link> : "newest record"}</div>
            {chain.successor ? (
              <>
                <div className="small muted">stores prev_hash</div>
                <HashText value={chain.successor.prev_hash} />
              </>
            ) : (
              <div className="small muted">No successor yet. The newest record is not protected by a later link (tail limitation).</div>
            )}
          </div>
        </div>
      </Panel>

      <div className="grid cols-2">
        <Panel title="Merkle batch" hint={MERKLE_LABEL[merkle.status]} actions={<Layers size={16} aria-hidden />}>
          <div className="row" style={{ marginBottom: 8 }}>
            <VerificationBadge status={merkle.status === "VALID" ? "VALID" : merkle.status === "UNSEALED" ? null : merkle.status} />
            {merkle.status === "UNSEALED" && <span className="badge muted">UNSEALED</span>}
          </div>
          {merkle.batch && (
            <KeyValue
              items={[
                ["Batch", <Link key="b" to={`/audit/streams/${SYSTEM_STREAM_ID}/batches`}>#{merkle.batch.batch_index}</Link>],
                ["Range", `#${merkle.batch.first_chain_index} – #${merkle.batch.last_chain_index} (${merkle.batch.leaf_count} records)`],
                ["Stored root", <HashText key="s" value={merkle.batch.stored_root} />],
                ["Recomputed root", <HashText key="r" value={merkle.recomputed_root} />],
                ["Membership proof", <span key="p">{merkle.proof?.length ?? 0} siblings · <PassFail ok={merkle.proof_valid} pass="verifies" fail="fails" /></span>],
              ]}
            />
          )}
        </Panel>
        <Panel title="Related file versions" hint="Each version is anchored by the event that created it">
          {file && file.versions.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Version</th>
                  <th>SHA-256</th>
                  <th>Anchor</th>
                  <th>Integrity</th>
                </tr>
              </thead>
              <tbody>
                {file.versions.map((v) => (
                  <tr key={v.version_number}>
                    <td>v{v.version_number}</td>
                    <td>
                      <HashText value={v.sha256} />
                    </td>
                    <td>
                      {v.audit_chain_index === e.chain_index ? (
                        <strong>#{v.audit_chain_index} (this)</strong>
                      ) : (
                        <Link to={`/security/events/${v.audit_chain_index}`}>#{v.audit_chain_index}</Link>
                      )}
                    </td>
                    <td>
                      <IntegrityBadge value={v.last_integrity_status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState title="No versions to show" />
          )}
        </Panel>
      </div>

      <Panel title="Raw payload" hint="Exactly what is hashed as the event part of this record">
        <pre>{JSON.stringify(e.payload, null, 2)}</pre>
      </Panel>
    </>
  );
}

function VerificationResult({ v }: { v: EventVerification }) {
  const ok = v.status === "VALID";
  return (
    <div className={`verdict ${ok ? "ok" : "bad"}`} role="status">
      <ShieldCheck size={20} aria-hidden />
      <div style={{ flex: 1 }}>
        <div className="verdict-title">{ok ? "AUDIT RECORD VERIFIED" : "AUDIT LOG INTEGRITY FAILURE"}</div>
        <div className="verdict-body row" style={{ gap: "4px 16px" }}>
          <span>
            Hash: <PassFail ok={v.chain.hash_matches} />
          </span>
          <span>
            Link: <PassFail ok={v.chain.link_matches} />
          </span>
          <span>
            Next link: <PassFail ok={v.chain.successor ? v.chain.successor.links_back : null} />
          </span>
          <span>Merkle: {v.merkle.status}</span>
          <span>Provenance: {v.provenance.status}</span>
        </div>
        {v.provenance.findings.length > 0 && (
          <ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {v.provenance.findings.map((f, i) => (
              <li key={i}>
                {f.check}: expected {f.expected}, found {f.actual}
              </li>
            ))}
          </ul>
        )}
        {v.note && <div className="small muted">{v.note}</div>}
      </div>
    </div>
  );
}
