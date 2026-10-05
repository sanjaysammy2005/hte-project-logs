import { ArrowDownUp, Download, Eye, FolderOpen, Search, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api } from "../../api/client";
import { CLASSIFICATIONS, type FileList } from "../../api/zt";
import { canCreateFiles } from "../../app/nav";
import { useAuth } from "../../auth";
import { useLoader } from "../../components";
import { ClassificationBadge, IntegrityBadge } from "../../ui/badges";
import { EmptyState, ErrorState, Menu, PageHeader, SkeletonRows, formatBytes, relativeTime } from "../../ui/primitives";
import { FileIcon, INLINE, UploadDialog, useFileActions } from "./fileParts";

export type Scope = "all" | "mine" | "shared" | "recent" | "trash";

const SCOPE_TITLE: Record<Scope, [string, string]> = {
  all: ["All files", "Every file you are allowed to see. Access is decided by the backend per file."],
  mine: ["My files", "Files you own."],
  shared: ["Shared with me", "Files someone granted you access to, personally or through your role."],
  recent: ["Recent", "Files accessed recently."],
  trash: ["Trash", "Deleted files. Content and versions are kept; only integrity checks are possible."],
};
const TYPES = ["pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "csv", "txt", "png", "jpg", "jpeg"];
const PAGE = 50;

export default function FilesPage({ scope }: { scope: Scope }) {
  const { operator } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [uploading, setUploading] = useState(false);
  const q = params.get("q") ?? "";
  const classification = params.get("classification") ?? "";
  const type = params.get("type") ?? "";
  const sort = params.get("sort") ?? "updated_at";
  const order = params.get("order") ?? "desc";
  const offset = Number(params.get("offset") ?? 0);

  const list = useLoader(
    () =>
      api<FileList>("/files", {
        params: { scope, q, classification, type, sort, order, limit: PAGE, offset },
      }),
    [scope, q, classification, type, sort, order, offset],
  );
  const actions = useFileActions(list.reload);
  const [title, subtitle] = SCOPE_TITLE[scope];

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "offset") next.delete("offset");
    setParams(next);
  }

  function search(e: FormEvent) {
    e.preventDefault();
    set("q", query.trim());
  }

  const filtered = Boolean(q || classification || type);
  const total = list.data?.total ?? 0;

  return (
    <>
      <PageHeader
        title={title}
        subtitle={subtitle}
        actions={
          operator && canCreateFiles(operator.role) && scope !== "trash" ? (
            <button type="button" className="primary" onClick={() => setUploading(true)}>
              <Upload size={16} aria-hidden /> Upload file
            </button>
          ) : undefined
        }
      />
      <form className="filter-bar" onSubmit={search} role="search">
        <label>
          <span className="sr-only">Search by name</span>
          <span className="row" style={{ gap: 0 }}>
            <input type="search" placeholder="Search by name" value={query} onChange={(e) => setQuery(e.target.value)} maxLength={200} />
            <button type="submit" className="icon" aria-label="Search">
              <Search size={16} aria-hidden />
            </button>
          </span>
        </label>
        <label>
          Classification
          <select value={classification} onChange={(e) => set("classification", e.target.value)}>
            <option value="">All</option>
            {CLASSIFICATIONS.map((c) => (
              <option key={c} value={c}>
                {c.replace("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          Type
          <select value={type} onChange={(e) => set("type", e.target.value)}>
            <option value="">All</option>
            {TYPES.map((t) => (
              <option key={t} value={t}>
                .{t}
              </option>
            ))}
          </select>
        </label>
        <label>
          Sort by
          <select value={sort} onChange={(e) => set("sort", e.target.value)} disabled={scope === "recent"}>
            <option value="updated_at">Last modified</option>
            <option value="created_at">Created</option>
            <option value="name">Name</option>
            <option value="size">Size</option>
            <option value="classification">Classification</option>
            <option value="last_accessed">Last accessed</option>
          </select>
        </label>
        <button type="button" onClick={() => set("order", order === "desc" ? "asc" : "desc")} aria-label={`Order ${order === "desc" ? "descending" : "ascending"}`}>
          <ArrowDownUp size={14} aria-hidden /> {order === "desc" ? "Desc" : "Asc"}
        </button>
        {filtered && (
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setQuery("");
              setParams(new URLSearchParams());
            }}
          >
            Clear filters
          </button>
        )}
      </form>

      <ErrorState error={list.error} onRetry={list.reload} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Classification</th>
              <th>Owner</th>
              <th>{scope === "trash" ? "Deleted" : "Last modified"}</th>
              <th className="num">Version</th>
              <th className="num">Size</th>
              <th>Integrity</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          {list.loading && !list.data ? (
            <SkeletonRows cols={8} />
          ) : (
            <tbody>
              {list.data?.items.map((f) => {
                const can = new Set(f.allowed_actions);
                return (
                  <tr key={f.id} className="clickable" onClick={() => navigate(`/files/${f.id}`)}>
                    <td>
                      <div className="cell-title">
                        <FileIcon extension={f.extension} />
                        <div style={{ minWidth: 0 }}>
                          <Link to={`/files/${f.id}`} onClick={(e) => e.stopPropagation()}>
                            {f.display_name}
                          </Link>
                          <div className="cell-sub">
                            .{f.extension}
                            {f.department ? ` · ${f.department}` : ""}
                            {f.origin !== "user" ? ` · ${f.origin.toUpperCase()} DATA` : ""}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <ClassificationBadge value={f.classification} />
                    </td>
                    <td className="small">{f.owner_id === operator?.id ? "You" : <span className="muted mono">{f.owner_id.slice(0, 8)}</span>}</td>
                    <td className="small nowrap">{relativeTime(scope === "trash" ? f.deleted_at : f.updated_at)}</td>
                    <td className="num">v{f.current_version}</td>
                    <td className="num small">{formatBytes(f.current?.size_bytes)}</td>
                    <td>
                      <IntegrityBadge value={f.current?.last_integrity_status} />
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      {(can.has("DOWNLOAD") || can.has("VERIFY") || can.has("DELETE") || (can.has("VIEW") && INLINE.has(f.extension))) && (
                        <Menu label={`Actions for ${f.display_name}`}>
                          {can.has("DOWNLOAD") && (
                            <button type="button" role="menuitem" onClick={() => void actions.download(f)}>
                              <Download size={14} aria-hidden /> Download
                            </button>
                          )}
                          {can.has("VIEW") && INLINE.has(f.extension) && (
                            <button type="button" role="menuitem" onClick={() => void actions.openPreview(f)}>
                              <Eye size={14} aria-hidden /> Preview
                            </button>
                          )}
                          {can.has("VERIFY") && (
                            <button type="button" role="menuitem" onClick={() => void actions.verify(f)}>
                              <ShieldCheck size={14} aria-hidden /> Verify integrity
                            </button>
                          )}
                          {can.has("DELETE") && (
                            <button type="button" role="menuitem" className="danger-item" onClick={() => actions.askDelete(f)}>
                              <Trash2 size={14} aria-hidden /> Move to trash
                            </button>
                          )}
                        </Menu>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          )}
        </table>
        {list.data && list.data.items.length === 0 && (
          <EmptyState title={filtered ? "No files match these filters" : scope === "trash" ? "Trash is empty" : "No files here yet"} icon={<FolderOpen size={28} aria-hidden />}>
            {filtered
              ? "Try a different search or clear the filters."
              : scope === "shared"
                ? "When someone grants you access to a file, it appears here."
                : "Files you can access appear here. Access depends on your role, department, ownership and grants."}
          </EmptyState>
        )}
        {list.data && total > 0 && (
          <div className="table-footer">
            <span>
              {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
            </span>
            <span className="row">
              <button type="button" className="sm" disabled={offset === 0} onClick={() => set("offset", String(Math.max(0, offset - PAGE)))}>
                Previous
              </button>
              <button type="button" className="sm" disabled={offset + PAGE >= total} onClick={() => set("offset", String(offset + PAGE))}>
                Next
              </button>
            </span>
          </div>
        )}
      </div>
      <UploadDialog open={uploading} onClose={() => setUploading(false)} onDone={(f) => navigate(`/files/${f.id}`)} />
      {actions.dialogs}
    </>
  );
}
