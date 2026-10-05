import { ArrowLeft, Download, Eye, FilePlus2, History, Pencil, RotateCcw, Share2, ShieldCheck, Trash2, UserMinus } from "lucide-react";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { ApiError, api } from "../../api/client";
import type { FileItem, FileTimeline, Grant, VersionList } from "../../api/zt";
import { useAuth } from "../../auth";
import { useLoader } from "../../components";
import { useAccessGuard } from "../../ui/access";
import { ClassificationBadge, DecisionBadge, IntegrityBadge, classificationHelp } from "../../ui/badges";
import { ConfirmDialog, useToast } from "../../ui/feedback";
import {
  EmptyState,
  ErrorState,
  HashText,
  KeyValue,
  PageHeader,
  Panel,
  Skeleton,
  formatBytes,
  formatDate,
  relativeTime,
} from "../../ui/primitives";
import { FileIcon, INLINE, NewVersionDialog, RenameDialog, ShareDialog, useFileActions } from "./fileParts";

const TABS = ["overview", "integrity", "permissions", "versions", "history"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview",
  integrity: "Integrity",
  permissions: "Permissions",
  versions: "Versions",
  history: "Access history & audit trail",
};

export default function FileDetailPage() {
  const { fileId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = (TABS.includes(params.get("tab") as Tab) ? params.get("tab") : "overview") as Tab;
  const { operator } = useAuth();
  const file = useLoader(() => api<FileItem>(`/files/${fileId}`), [fileId]);
  const actions = useFileActions(file.reload);
  const [dialog, setDialog] = useState<"rename" | "version" | "share" | null>(null);

  if (file.error) {
    const notFound = file.error instanceof ApiError && file.error.status === 404;
    return (
      <>
        <PageHeader title="File" crumbs={[{ label: "Files", to: "/files" }, { label: "Unavailable" }]} />
        {notFound ? (
          <EmptyState title="File not found">
            It does not exist, or you are not allowed to know that it exists. The attempt was recorded in the audit chain.
          </EmptyState>
        ) : (
          <ErrorState error={file.error} onRetry={file.reload} />
        )}
      </>
    );
  }
  if (!file.data) {
    return (
      <div className="stack" aria-busy="true">
        <Skeleton width={320} height={24} />
        <Skeleton width="60%" />
        <Skeleton height={160} />
      </div>
    );
  }

  const f = file.data;
  const can = new Set(f.allowed_actions);
  const v = f.current;
  const integrity = v?.last_integrity_status;
  const security = operator?.role === "admin" || operator?.role === "auditor";

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Files", to: "/files" }, { label: f.display_name }]}
        title={
          <span className="row" style={{ gap: 10 }}>
            <FileIcon extension={f.extension} size={22} />
            {f.display_name}
          </span>
        }
        badges={
          <>
            <ClassificationBadge value={f.classification} />
            <IntegrityBadge value={integrity} />
            {f.deleted_at && <span className="badge warn">IN TRASH</span>}
            {f.origin !== "user" && <span className="badge kind-synthetic">{f.origin.toUpperCase()} DATA</span>}
          </>
        }
        subtitle={`Version ${f.current_version} · ${formatBytes(v?.size_bytes)} · modified ${relativeTime(f.updated_at)}`}
        actions={
          <>
            <Link className="btn ghost" to="/files">
              <ArrowLeft size={14} aria-hidden /> Back
            </Link>
            {can.has("DOWNLOAD") && (
              <button type="button" className="primary" onClick={() => void actions.download(f)}>
                <Download size={14} aria-hidden /> Download
              </button>
            )}
            {can.has("VIEW") && INLINE.has(f.extension) && (
              <button type="button" onClick={() => void actions.openPreview(f)}>
                <Eye size={14} aria-hidden /> Preview
              </button>
            )}
            {can.has("RENAME") && (
              <button type="button" onClick={() => setDialog("rename")}>
                <Pencil size={14} aria-hidden /> Rename
              </button>
            )}
            {can.has("UPLOAD") && (
              <button type="button" onClick={() => setDialog("version")}>
                <FilePlus2 size={14} aria-hidden /> New version
              </button>
            )}
            {(can.has("SHARE") || can.has("MANAGE_PERMISSIONS")) && (
              <button type="button" onClick={() => setDialog("share")}>
                <Share2 size={14} aria-hidden /> Share
              </button>
            )}
            {can.has("VERIFY") && (
              <button type="button" onClick={() => void actions.verify(f)}>
                <ShieldCheck size={14} aria-hidden /> Verify integrity
              </button>
            )}
            {can.has("DELETE") && (
              <button type="button" className="ghost" onClick={() => actions.askDelete(f)} aria-label="Move to trash">
                <Trash2 size={14} aria-hidden />
              </button>
            )}
          </>
        }
      />
      {f.allowed_actions.length === 0 && (
        <div className="alert info">
          <Eye size={16} aria-hidden />
          <div className="alert-body">You can see this file's metadata, but the policy allows no actions on it for you.</div>
        </div>
      )}
      <nav className="tabs" role="tablist" aria-label="File sections">
        {TABS.map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setParams({ tab: t })}>
            {TAB_LABEL[t]}
          </button>
        ))}
      </nav>

      {tab === "overview" && <Overview f={f} meId={operator?.id} />}
      {tab === "integrity" && <IntegrityTab f={f} canVerify={can.has("VERIFY")} onVerify={() => void actions.verify(f)} security={security} />}
      {tab === "permissions" && <PermissionsTab f={f} onShare={() => setDialog("share")} canShare={can.has("SHARE") || can.has("MANAGE_PERMISSIONS")} />}
      {tab === "versions" && <VersionsTab f={f} canRestore={can.has("RESTORE")} canDownload={can.has("DOWNLOAD")} onChanged={file.reload} download={actions.download} />}
      {tab === "history" && <HistoryTab f={f} security={security} />}

      {dialog === "rename" && <RenameDialog file={f} open onClose={() => setDialog(null)} onDone={file.reload} />}
      {dialog === "version" && <NewVersionDialog file={f} open onClose={() => setDialog(null)} onDone={file.reload} />}
      {dialog === "share" && (
        <ShareDialog file={f} open onClose={() => setDialog(null)} onDone={file.reload} canGrantRoles={can.has("MANAGE_PERMISSIONS")} />
      )}
      {actions.dialogs}
    </>
  );
}

function who(id: string, meId: string | undefined) {
  return id === meId ? "You" : <code className="small">{id}</code>;
}

function Overview({ f, meId }: { f: FileItem; meId: string | undefined }) {
  const v = f.current;
  return (
    <div className="grid cols-2">
      <Panel title="File">
        <KeyValue
          items={[
            ["Name", f.display_name],
            ["Type", `.${f.extension} · ${f.mime_type}`],
            ["Size", formatBytes(v?.size_bytes)],
            ["Current version", `v${f.current_version}`],
            ["SHA-256", <HashText key="h" value={v?.sha256} full />],
            ["Created", formatDate(f.created_at)],
            ["Modified", formatDate(f.updated_at)],
            ["Last accessed", formatDate(f.last_accessed_at)],
            ["Description", f.description],
          ]}
        />
      </Panel>
      <div className="stack">
        <Panel title="Security classification">
          <div className="row" style={{ marginBottom: 8 }}>
            <ClassificationBadge value={f.classification} />
          </div>
          <p className="muted small" style={{ margin: 0 }}>
            {classificationHelp(f.classification)}. Every access is decided by the backend policy and recorded in the
            audit chain.
          </p>
        </Panel>
        <Panel title="Ownership">
          <KeyValue
            items={[
              ["Owner", who(f.owner_id, meId)],
              ["Uploader", who(f.created_by, meId)],
              ["Department", f.department],
              ["Your actions", f.allowed_actions.length ? f.allowed_actions.join(", ") : "none"],
            ]}
          />
        </Panel>
      </div>
    </div>
  );
}

function IntegrityTab({ f, canVerify, onVerify, security }: { f: FileItem; canVerify: boolean; onVerify: () => void; security: boolean }) {
  const versions = useLoader(() => api<VersionList>(`/files/${f.id}/versions`), [f.id, f.current?.last_verified_at]);
  const status = f.current?.last_integrity_status;
  const verified = status === "INTACT";
  return (
    <>
      <div className={`verdict ${!status ? "neutral" : verified ? "ok" : "bad"}`}>
        <IntegrityBadge value={status} />
        <div>
          <div className="verdict-title">{!status ? "NOT VERIFIED YET" : verified ? "VERIFIED" : "INTEGRITY FAILURE"}</div>
          <div className="verdict-body">
            {status
              ? `Last check ${formatDate(f.current?.last_verified_at)}. The stored bytes, the database hash and the audit event that recorded the upload were compared.`
              : "No integrity check has been run on the current version. Every download is still verified before it is served."}
          </div>
        </div>
        <span className="spacer" />
        {canVerify && (
          <button type="button" className="primary" onClick={onVerify}>
            <ShieldCheck size={14} aria-hidden /> Verify now
          </button>
        )}
        {security && (
          <Link className="btn" to={`/security/files/${f.id}`}>
            Investigate
          </Link>
        )}
      </div>
      <Panel title="Fingerprints per version" hint="Last check result is a cache; the authoritative evidence is the chained check event.">
        <ErrorState error={versions.error} />
        <table>
          <thead>
            <tr>
              <th>Version</th>
              <th>SHA-256</th>
              <th>Recorded by audit event</th>
              <th>Last check</th>
            </tr>
          </thead>
          <tbody>
            {versions.data?.versions.map((ver) => (
              <tr key={ver.version_number}>
                <td>v{ver.version_number}</td>
                <td>
                  <HashText value={ver.sha256} />
                </td>
                <td>{security ? <Link to={`/security/events/${ver.audit_chain_index}`}>#{ver.audit_chain_index}</Link> : `#${ver.audit_chain_index}`}</td>
                <td>
                  <IntegrityBadge value={ver.last_integrity_status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </>
  );
}

function PermissionsTab({ f, canShare, onShare }: { f: FileItem; canShare: boolean; onShare: () => void }) {
  const [showHistory, setShowHistory] = useState(false);
  const grants = useLoader(
    () => api<{ grants: Grant[] }>(`/files/${f.id}/permissions${showHistory ? "/history" : ""}`),
    [f.id, showHistory, f.updated_at],
  );
  const [revoking, setRevoking] = useState<Grant | null>(null);
  const [busy, setBusy] = useState(false);
  const guard = useAccessGuard();
  const toast = useToast();
  const canManage = f.allowed_actions.includes("MANAGE_PERMISSIONS") || canShare;

  async function revoke() {
    if (!revoking) return;
    setBusy(true);
    try {
      const r = await guard.run(() => api<{ audit: { chain_index: number } }>(`/files/${f.id}/permissions/${revoking.id}`, { method: "DELETE" }));
      if (r) toast.push("ok", "Access revoked", `Recorded as audit event #${r.audit.chain_index}`);
      grants.reload();
    } catch (e) {
      toast.push("danger", "Revoke failed", e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setRevoking(null);
    }
  }

  return (
    <Panel
      title={showHistory ? "Permission history" : "Current explicit permissions"}
      hint="Role-based access from the policy also applies; these are the explicit grants on this file."
      actions={
        <>
          <button type="button" className="ghost sm" onClick={() => setShowHistory(!showHistory)} aria-pressed={showHistory}>
            <History size={14} aria-hidden /> {showHistory ? "Current" : "History"}
          </button>
          {canShare && (
            <button type="button" className="primary sm" onClick={onShare}>
              <Share2 size={14} aria-hidden /> Share
            </button>
          )}
        </>
      }
    >
      {grants.error instanceof ApiError && grants.error.status === 403 ? (
        <div className="alert info">Permission history is visible to the owner and permission managers only.</div>
      ) : (
        <ErrorState error={grants.error} onRetry={grants.reload} />
      )}
      {grants.data && grants.data.grants.length === 0 && <EmptyState title="No explicit grants">Nobody has been given access to this file individually.</EmptyState>}
      {grants.data && grants.data.grants.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Granted to</th>
              <th>Permissions</th>
              <th>Granted</th>
              <th>Expires</th>
              <th>Status</th>
              <th>Audit</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {grants.data.grants.map((g) => (
              <tr key={g.id}>
                <td>{g.grantee_role ? <span className="badge outline">ROLE: {g.grantee_role.toUpperCase()}</span> : <code className="small">{g.grantee_id}</code>}</td>
                <td className="small">{g.permissions.join(", ")}</td>
                <td className="small nowrap">{formatDate(g.created_at)}</td>
                <td className="small nowrap">{g.expires_at ? formatDate(g.expires_at) : "never"}</td>
                <td>{g.revoked_at ? <span className="badge muted">REVOKED</span> : <span className="badge ok">ACTIVE</span>}</td>
                <td className="small">
                  #{g.audit_chain_index}
                  {g.revoked_audit_chain_index ? ` → #${g.revoked_audit_chain_index}` : ""}
                </td>
                <td>
                  {!g.revoked_at && canManage && (
                    <button type="button" className="ghost sm" onClick={() => setRevoking(g)}>
                      <UserMinus size={14} aria-hidden /> Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ConfirmDialog
        open={!!revoking}
        title="Revoke access?"
        confirmLabel="Revoke"
        danger
        busy={busy}
        onConfirm={() => void revoke()}
        onClose={() => setRevoking(null)}
      >
        The grantee loses these permissions immediately (other grants or role access may still apply). The revocation is
        recorded in the audit chain.
      </ConfirmDialog>
    </Panel>
  );
}

function VersionsTab({
  f,
  canRestore,
  canDownload,
  onChanged,
  download,
}: {
  f: FileItem;
  canRestore: boolean;
  canDownload: boolean;
  onChanged: () => void;
  download: (f: FileItem, version?: number) => Promise<void>;
}) {
  const versions = useLoader(() => api<VersionList>(`/files/${f.id}/versions`), [f.id, f.current_version]);
  const [restoring, setRestoring] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const guard = useAccessGuard();
  const toast = useToast();

  async function restore() {
    if (restoring === null) return;
    setBusy(true);
    try {
      const r = await guard.run(() =>
        api<FileItem>(`/files/${f.id}/versions/${restoring}/restore`, { method: "POST", body: { base_version: f.current_version } }),
      );
      if (r) {
        toast.push("ok", `Version ${restoring} restored as v${r.current_version}`, "Nothing was overwritten; history is linear.");
        onChanged();
      }
    } catch (e) {
      toast.push("danger", "Restore failed", e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setRestoring(null);
    }
  }

  return (
    <Panel title="Versions" hint="Versions are immutable. Restoring creates a new version from an older one.">
      <ErrorState error={versions.error} onRetry={versions.reload} />
      <table>
        <thead>
          <tr>
            <th>Version</th>
            <th>Uploaded</th>
            <th className="num">Size</th>
            <th>SHA-256</th>
            <th>Note</th>
            <th>Integrity</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {versions.data?.versions.map((ver) => (
            <tr key={ver.version_number}>
              <td>
                v{ver.version_number} {ver.version_number === f.current_version && <span className="badge info">CURRENT</span>}
              </td>
              <td className="small nowrap">{formatDate(ver.created_at)}</td>
              <td className="num small">{formatBytes(ver.size_bytes)}</td>
              <td>
                <HashText value={ver.sha256} />
              </td>
              <td className="small">
                {ver.restored_from_version ? `Restored from v${ver.restored_from_version}. ` : ""}
                {ver.change_reason ?? ""}
              </td>
              <td>
                <IntegrityBadge value={ver.last_integrity_status} />
              </td>
              <td className="nowrap">
                {canDownload && (
                  <button type="button" className="ghost sm" onClick={() => void download(f, ver.version_number)} aria-label={`Download version ${ver.version_number}`}>
                    <Download size={14} aria-hidden />
                  </button>
                )}
                {canRestore && ver.version_number !== f.current_version && (
                  <button type="button" className="ghost sm" onClick={() => setRestoring(ver.version_number)}>
                    <RotateCcw size={14} aria-hidden /> Restore
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ConfirmDialog
        open={restoring !== null}
        title={`Restore version ${restoring}?`}
        confirmLabel="Restore"
        busy={busy}
        onConfirm={() => void restore()}
        onClose={() => setRestoring(null)}
      >
        A new version v{f.current_version + 1} will be created with the content of v{restoring}, after its fingerprint is
        re-verified. The current version stays in history.
      </ConfirmDialog>
    </Panel>
  );
}

function HistoryTab({ f, security }: { f: FileItem; security: boolean }) {
  const timeline = useLoader(
    () => (security ? api<FileTimeline>(`/security/files/${f.id}/timeline`) : Promise.resolve(null)),
    [f.id, security, f.updated_at],
  );
  if (!security)
    return (
      <EmptyState title="Audit trail is visible to security staff">
        Every access to this file, allowed or denied, is recorded in the tamper-evident audit chain. Administrators and auditors
        can review it.
      </EmptyState>
    );
  return (
    <Panel
      title="Access history & audit trail"
      hint="Every chained event about this file, oldest first."
      actions={
        <Link className="btn sm" to={`/security/files/${f.id}`}>
          Open investigation
        </Link>
      }
    >
      <ErrorState error={timeline.error} onRetry={timeline.reload} />
      {timeline.loading && !timeline.data && <Skeleton height={120} />}
      {timeline.data && timeline.data.events.length === 0 && <EmptyState title="No events yet" />}
      {timeline.data && timeline.data.events.length > 0 && (
        <table>
          <thead>
            <tr>
              <th className="num">#</th>
              <th>Time</th>
              <th>Event</th>
              <th>User</th>
              <th>Decision</th>
              <th>Reason / rule</th>
            </tr>
          </thead>
          <tbody>
            {timeline.data.events.map((e) => (
              <tr key={e.chain_index}>
                <td className="num">
                  <Link to={`/security/events/${e.chain_index}`}>{e.chain_index}</Link>
                </td>
                <td className="small nowrap">{formatDate(e.timestamp)}</td>
                <td>
                  <code className="small">{e.event_type}</code>
                </td>
                <td>{e.user ?? <span className="muted">—</span>}</td>
                <td>
                  <DecisionBadge value={e.decision} />
                </td>
                <td className="small muted">{e.reason_code ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {timeline.data && <div className="chart-note">Integrity reports: <IntegrityResultLink id={f.id} /></div>}
    </Panel>
  );
}

function IntegrityResultLink({ id }: { id: string }) {
  return <Link to={`/security/files/${id}`}>file vs audit-log integrity investigation</Link>;
}

