/** Layout and content primitives of the TraceLock design system. */

import { AlertTriangle, Copy, Inbox, MoreHorizontal, RefreshCw } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { ApiError, errorMessage } from "../api/client";

export function PageHeader({
  title,
  subtitle,
  actions,
  crumbs,
  badges,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  crumbs?: { label: ReactNode; to?: string }[];
  badges?: ReactNode;
}) {
  return (
    <>
      {crumbs && (
        <nav className="breadcrumbs" aria-label="Breadcrumb">
          {crumbs.map((c, i) => (
            <span key={i} className="row" style={{ gap: 6 }}>
              {i > 0 && <span aria-hidden>/</span>}
              {c.to ? <Link to={c.to}>{c.label}</Link> : <span>{c.label}</span>}
            </span>
          ))}
        </nav>
      )}
      <header className="page-header">
        <div style={{ minWidth: 0 }}>
          <div className="title-row">
            <h1>{title}</h1>
            {badges}
          </div>
          {subtitle && <div className="subtitle">{subtitle}</div>}
        </div>
        {actions && <div className="row">{actions}</div>}
      </header>
    </>
  );
}

export function Panel({
  title,
  hint,
  actions,
  children,
  flush = false,
  id,
}: {
  title?: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  id?: string;
}) {
  return (
    <section className={flush ? "card flush" : "card"} id={id} aria-label={typeof title === "string" ? title : undefined}>
      {(title || actions) && (
        <header className="card-header">
          <div>
            {title && <h2>{title}</h2>}
            {hint && <div className="hint">{hint}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatTile({
  label,
  value,
  icon,
  foot,
  tone,
  loading,
  to,
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  foot?: ReactNode;
  tone?: "danger" | "warn" | "ok";
  loading?: boolean;
  to?: string;
}) {
  const body = (
    <>
      <span className="stat-label">
        {icon}
        {label}
      </span>
      <span className="stat-value">{loading ? <Skeleton width={60} height={24} /> : value}</span>
      {foot && <span className="stat-foot">{foot}</span>}
    </>
  );
  const cls = `stat${tone ? ` tone-${tone}` : ""}`;
  return to ? (
    <Link className={cls} to={to} style={{ color: "inherit", textDecoration: "none" }}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

export function Skeleton({ width = "100%", height = 12 }: { width?: number | string; height?: number }) {
  return <span className="skeleton" style={{ width, height }} aria-hidden />;
}

/** Placeholder rows while a table loads (real requests only; no artificial delays). */
export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <tbody aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r}>
          {Array.from({ length: cols }, (_, c) => (
            <td key={c}>
              <Skeleton width={c === 0 ? "70%" : "50%"} />
            </td>
          ))}
        </tr>
      ))}
    </tbody>
  );
}

export function EmptyState({
  title,
  children,
  icon,
  action,
}: {
  title: string;
  children?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty" role="status">
      {icon ?? <Inbox size={28} aria-hidden />}
      <div className="empty-title">{title}</div>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

/** Readable error with the backend's code; offers a retry where it makes sense. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const forbidden = error instanceof ApiError && (error.status === 403 || error.status === 401);
  return (
    <div className="alert danger" role="alert">
      <AlertTriangle size={16} aria-hidden />
      <div className="alert-body">
        <strong>{forbidden ? "Not permitted" : "Something went wrong"}</strong>
        <span>{errorMessage(error)}</span>
      </div>
      {onRetry && (
        <button type="button" className="sm" onClick={onRetry} style={{ marginLeft: "auto" }}>
          <RefreshCw size={14} aria-hidden /> Retry
        </button>
      )}
    </div>
  );
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v ?? <span className="muted">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function HashText({ value, full = false }: { value: string | null | undefined; full?: boolean }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="muted">—</span>;
  async function copy() {
    try {
      await navigator.clipboard.writeText(value as string);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <span className="row" style={{ gap: 4, flexWrap: "nowrap", minWidth: 0 }}>
      <code className="hash" title={value}>
        {full ? value : `${value.slice(0, 12)}…${value.slice(-6)}`}
      </code>
      <button type="button" className="ghost icon sm" onClick={() => void copy()} aria-label="Copy hash" title={copied ? "Copied" : "Copy"}>
        <Copy size={12} aria-hidden />
      </button>
    </span>
  );
}

/** A small action menu. Items are rendered only if given; nothing is merely disabled-hidden. */
export function Menu({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);
  return (
    <div className="menu" ref={ref}>
      <button type="button" className="ghost icon sm" aria-haspopup="menu" aria-expanded={open} aria-label={label} onClick={() => setOpen(!open)}>
        <MoreHorizontal size={16} aria-hidden />
      </button>
      {open && (
        <div className="menu-list" role="menu" onClick={() => setOpen(false)}>
          {children}
        </div>
      )}
    </div>
  );
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const s = Math.round((Date.now() - then) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return formatDate(iso);
}
