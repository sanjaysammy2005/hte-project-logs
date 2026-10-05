/** Shared file-manager pieces: icons, dialogs, and the action runner. Every action goes through
 *  the access guard, so backend denials and step-up prompts are handled in one place. */

import { File, FileImage, FileSpreadsheet, FileText, Presentation, Upload } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, errorMessage, fetchBlob, saveBlob, upload } from "../../api/client";
import type { Role } from "../../api/types";
import { CLASSIFICATIONS, GRANTABLE, type Classification, type FileItem, type IntegrityReport, type Permission } from "../../api/zt";
import { useAccessGuard } from "../../ui/access";
import { classificationHelp, IntegrityBadge } from "../../ui/badges";
import { ConfirmDialog, Dialog, useToast } from "../../ui/feedback";

export const ACCEPT = ".txt,.pdf,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.csv,.jpg,.jpeg,.png";
export const INLINE = new Set(["png", "jpg", "jpeg", "pdf"]);

export function FileIcon({ extension, size = 16 }: { extension: string; size?: number }) {
  const props = { size, "aria-hidden": true as const, style: { flex: "none", color: "var(--text-3)" } };
  if (["png", "jpg", "jpeg"].includes(extension)) return <FileImage {...props} />;
  if (["xls", "xlsx", "csv"].includes(extension)) return <FileSpreadsheet {...props} />;
  if (["ppt", "pptx"].includes(extension)) return <Presentation {...props} />;
  if (["doc", "docx", "pdf", "txt"].includes(extension)) return <FileText {...props} />;
  return <File {...props} />;
}

function ClassificationSelect({ value, onChange }: { value: Classification; onChange: (c: Classification) => void }) {
  return (
    <label>
      Classification
      <select value={value} onChange={(e) => onChange(e.target.value as Classification)}>
        {CLASSIFICATIONS.map((c) => (
          <option key={c} value={c}>
            {c.replace("_", " ")}
          </option>
        ))}
      </select>
      <span className="hint">{classificationHelp(value)}</span>
    </label>
  );
}

function Progress({ fraction }: { fraction: number }) {
  return (
    <div>
      <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(fraction * 100)}>
        <span style={{ width: `${Math.round(fraction * 100)}%` }} />
      </div>
      <div className="small muted" style={{ marginTop: 4 }}>
        {fraction < 1 ? `Uploading… ${Math.round(fraction * 100)}%` : "Verifying content and recording in the audit chain…"}
      </div>
    </div>
  );
}

export function UploadDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (f: FileItem) => void }) {
  const [file, setFile] = useState<globalThis.File | null>(null);
  const [classification, setClassification] = useState<Classification>("INTERNAL");
  const [description, setDescription] = useState("");
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<unknown>(null);
  const toast = useToast();
  const guard = useAccessGuard();

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setError(null);
    setProgress(0);
    const form = new FormData();
    form.append("file", file);
    form.append("classification", classification);
    if (description) form.append("description", description);
    try {
      const created = await guard.run(() => upload<FileItem>("/files", form, setProgress));
      if (created) {
        toast.push("ok", "File uploaded", `SHA-256 recorded as audit event #${created.audit?.chain_index}`);
        onDone(created);
        setFile(null);
        setDescription("");
        onClose();
      }
    } catch (err) {
      setError(err);
    } finally {
      setProgress(null);
    }
  }

  return (
    <Dialog open={open} title="Upload file" onClose={onClose} icon={<Upload size={18} aria-hidden />}>
      <form className="form" onSubmit={(e) => void submit(e)}>
        <label>
          File
          <input type="file" accept={ACCEPT} onChange={(e) => setFile(e.target.files?.[0] ?? null)} required />
          <span className="hint">Allowed: TXT, PDF, Office documents, CSV, JPG, PNG. The content is checked against its type.</span>
        </label>
        <ClassificationSelect value={classification} onChange={setClassification} />
        <label>
          Description <span className="hint">optional</span>
          <textarea rows={2} maxLength={1000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        {progress !== null && <Progress fraction={progress} />}
        {error ? <div className="error">{errorMessage(error)}</div> : null}
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={!file || progress !== null}>
            Upload
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function NewVersionDialog({ file, open, onClose, onDone }: { file: FileItem; open: boolean; onClose: () => void; onDone: () => void }) {
  const [blob, setBlob] = useState<globalThis.File | null>(null);
  const [reason, setReason] = useState("");
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<unknown>(null);
  const toast = useToast();
  const guard = useAccessGuard();

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!blob) return;
    setError(null);
    setProgress(0);
    const form = new FormData();
    form.append("file", blob);
    form.append("base_version", String(file.current_version));
    if (reason) form.append("change_reason", reason);
    try {
      const result = await guard.run(() => upload<FileItem>(`/files/${file.id}/versions`, form, setProgress));
      if (result) {
        toast.push("ok", `Version ${result.current_version} created`, "Earlier versions are kept unchanged.");
        onDone();
        onClose();
      }
    } catch (err) {
      setError(err);
    } finally {
      setProgress(null);
    }
  }

  return (
    <Dialog open={open} title={`New version of ${file.display_name}`} onClose={onClose}>
      <form className="form" onSubmit={(e) => void submit(e)}>
        <p className="muted small" style={{ margin: 0 }}>
          Replaces version {file.current_version}. Must be a .{file.extension} file. If someone else changed the file in the
          meantime, the upload is refused instead of overwriting their version.
        </p>
        <label>
          File
          <input type="file" accept={`.${file.extension}`} onChange={(e) => setBlob(e.target.files?.[0] ?? null)} required />
        </label>
        <label>
          Change reason <span className="hint">optional</span>
          <input maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        {progress !== null && <Progress fraction={progress} />}
        {error ? <div className="error">{errorMessage(error)}</div> : null}
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={!blob || progress !== null}>
            Upload version
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function RenameDialog({ file, open, onClose, onDone }: { file: FileItem; open: boolean; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(file.display_name);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const guard = useAccessGuard();
  const toast = useToast();
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await guard.run(() => api(`/files/${file.id}`, { method: "PATCH", body: { display_name: name } }));
      if (r) {
        toast.push("ok", "File renamed");
        onDone();
        onClose();
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog open={open} title="Rename file" onClose={onClose}>
      <form className="form" onSubmit={(e) => void submit(e)}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={255} required autoFocus />
          <span className="hint">The extension (.{file.extension}) cannot change; the file type is fixed.</span>
        </label>
        {error ? <div className="error">{errorMessage(error)}</div> : null}
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={busy}>
            Rename
          </button>
        </div>
      </form>
    </Dialog>
  );
}

const ROLES: Role[] = ["employee", "manager", "auditor", "admin"];

export function ShareDialog({
  file,
  open,
  onClose,
  onDone,
  canGrantRoles,
}: {
  file: FileItem;
  open: boolean;
  onClose: () => void;
  onDone: () => void;
  canGrantRoles: boolean;
}) {
  const [target, setTarget] = useState<"user" | "role">("user");
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<Role>("employee");
  const [perms, setPerms] = useState<Set<Permission>>(new Set(["READ"]));
  const [expires, setExpires] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const guard = useAccessGuard();
  const toast = useToast();

  function toggle(p: Permission) {
    const next = new Set(perms);
    if (next.has(p)) next.delete(p);
    else next.add(p);
    setPerms(next);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body: Record<string, unknown> = { permissions: [...perms] };
    if (target === "user") body.grantee_id = userId.trim();
    else body.grantee_role = role;
    if (expires) body.expires_at = new Date(expires).toISOString();
    if (reason) body.reason = reason;
    try {
      const r = await guard.run(() => api<{ audit: { chain_index: number } }>(`/files/${file.id}/permissions`, { method: "POST", body }));
      if (r) {
        toast.push("ok", "Access granted", `Recorded as audit event #${r.audit.chain_index}`);
        onDone();
        onClose();
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} title={`Share ${file.display_name}`} onClose={onClose}>
      <form className="form" onSubmit={(e) => void submit(e)}>
        {canGrantRoles && (
          <div className="segmented" role="group" aria-label="Grant to">
            <button type="button" aria-pressed={target === "user"} onClick={() => setTarget("user")}>
              A user
            </button>
            <button type="button" aria-pressed={target === "role"} onClick={() => setTarget("role")}>
              A role (this file only)
            </button>
          </div>
        )}
        {target === "user" ? (
          <label>
            User ID
            <input value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" required pattern="[0-9a-fA-F-]{36}" />
            <span className="hint">The user directory is not available yet; paste the user's account ID.</span>
          </label>
        ) : (
          <label>
            Role
            <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {ROLES.map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
            <span className="hint">Every user with this role gets the permissions on this one file. Permission managers only.</span>
          </label>
        )}
        <fieldset style={{ border: "1px solid var(--border)", borderRadius: 6, padding: 10 }}>
          <legend className="small muted">Permissions</legend>
          <div className="row" style={{ gap: "6px 14px" }}>
            {GRANTABLE.map((p) => (
              <label key={p} className="checkbox">
                <input type="checkbox" checked={perms.has(p)} onChange={() => toggle(p)} />
                {p}
              </label>
            ))}
          </div>
          <span className="hint small muted">You can only grant permissions you hold yourself; the backend checks this.</span>
        </fieldset>
        <div className="row" style={{ alignItems: "flex-end" }}>
          <label>
            Expires <span className="hint">optional</span>
            <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </label>
          <label style={{ flex: 1 }}>
            Reason {file.classification === "HIGHLY_RESTRICTED" ? <span className="hint">required</span> : <span className="hint">optional</span>}
            <input value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} required={file.classification === "HIGHLY_RESTRICTED"} />
          </label>
        </div>
        {error ? <div className="error">{errorMessage(error)}</div> : null}
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={busy || perms.size === 0}>
            Grant access
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/** Download / preview / verify / delete, each guarded and reported. */
export function useFileActions(onChanged: () => void) {
  const guard = useAccessGuard();
  const toast = useToast();
  const [preview, setPreview] = useState<{ url: string; name: string; kind: "image" } | null>(null);
  const [verifying, setVerifying] = useState<IntegrityReport | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<FileItem | null>(null);
  const [busy, setBusy] = useState(false);

  async function download(file: FileItem, version?: number) {
    try {
      const q = version ? `?version=${version}` : "";
      const r = await guard.run(() => fetchBlob(`/files/${file.id}/content${q}`));
      if (r) {
        saveBlob(r.blob, file.display_name);
        toast.push("ok", "Download verified", `Content matched its SHA-256; recorded as audit event #${r.auditIndex}`);
        onChanged();
      }
    } catch (e) {
      toast.push("danger", "Download failed", errorMessage(e));
    }
  }

  async function openPreview(file: FileItem) {
    try {
      const r = await guard.run(() => fetchBlob(`/files/${file.id}/content?disposition=inline`));
      if (!r) return;
      const url = URL.createObjectURL(r.blob);
      if (file.extension === "pdf") {
        window.open(url, "_blank", "noopener");
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
      } else setPreview({ url, name: file.display_name, kind: "image" });
      onChanged();
    } catch (e) {
      toast.push("danger", "Preview failed", errorMessage(e));
    }
  }

  async function verify(file: FileItem) {
    try {
      const r = await guard.run(() => api<IntegrityReport>(`/files/${file.id}/integrity`, { method: "POST" }));
      if (r) {
        setVerifying(r);
        onChanged();
      }
    } catch (e) {
      toast.push("danger", "Verification failed", errorMessage(e));
    }
  }

  async function doDelete() {
    if (!confirmDelete) return;
    setBusy(true);
    try {
      const r = await guard.run(() => api<{ chain_index: number }>(`/files/${confirmDelete.id}`, { method: "DELETE" }));
      if (r) {
        toast.push("ok", "Moved to trash", `Recorded as audit event #${r.chain_index}. Content and versions are kept.`);
        onChanged();
      }
    } catch (e) {
      toast.push("danger", "Delete failed", errorMessage(e));
    } finally {
      setBusy(false);
      setConfirmDelete(null);
    }
  }

  const dialogs = (
    <>
      <Dialog
        open={!!preview}
        title={preview?.name ?? "Preview"}
        wide
        onClose={() => {
          if (preview) URL.revokeObjectURL(preview.url);
          setPreview(null);
        }}
      >
        {preview && <img src={preview.url} alt={preview.name} style={{ maxWidth: "100%", display: "block", margin: "0 auto" }} />}
      </Dialog>
      <Dialog open={!!verifying} title="Integrity check" onClose={() => setVerifying(null)} footer={<button onClick={() => setVerifying(null)}>Close</button>}>
        {verifying && <IntegrityResult report={verifying} />}
      </Dialog>
      <ConfirmDialog
        open={!!confirmDelete}
        title="Move file to trash?"
        confirmLabel="Move to trash"
        danger
        busy={busy}
        onConfirm={() => void doDelete()}
        onClose={() => setConfirmDelete(null)}
      >
        <p style={{ marginTop: 0 }}>
          <strong>{confirmDelete?.display_name}</strong> will no longer be available to other users. Its content and every
          version are kept, and the deletion is recorded in the audit chain.
        </p>
      </ConfirmDialog>
    </>
  );

  return { download, openPreview, verify, askDelete: setConfirmDelete, dialogs };
}

export function IntegrityResult({ report }: { report: IntegrityReport }) {
  const ok = report.status === "INTACT";
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className={`verdict ${ok ? "ok" : "bad"}`}>
        <IntegrityBadge value={report.status} />
        <div>
          <div className="verdict-title">{ok ? "VERIFIED" : "INTEGRITY FAILURE"}</div>
          <div className="verdict-body">
            {ok
              ? "Every version's bytes match their SHA-256, which matches the intact audit event that recorded it."
              : "At least one version no longer matches its recorded fingerprint."}{" "}
            Check recorded as audit event #{report.audit.chain_index}.
          </div>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Version</th>
            <th>Content (bytes vs DB)</th>
            <th>Anchor (DB vs chain)</th>
            <th>Evidence (chain itself)</th>
          </tr>
        </thead>
        <tbody>
          {report.versions.map((v) => (
            <tr key={v.version}>
              <td>v{v.version}</td>
              <td>{v.content === "OK" ? <span className="status ok">OK</span> : <span className="status bad">{v.content}</span>}</td>
              <td>{v.anchor === "OK" ? <span className="status ok">OK</span> : <span className="status bad">{v.anchor}</span>}</td>
              <td>{v.evidence === "OK" ? <span className="status ok">OK</span> : <span className="status bad">{v.evidence}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
