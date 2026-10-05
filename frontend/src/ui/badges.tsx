/** Security status badges. Every badge carries a text label and an icon; color is never the
 *  only signal (status and classification colors are reserved tokens). */

import {
  AlertOctagon,
  Ban,
  Building2,
  CheckCircle2,
  CircleDashed,
  Globe,
  Lock,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  XCircle,
} from "lucide-react";
import type { ReactNode } from "react";
import type { StreamKind } from "../api/types";
import type { Classification } from "../api/zt";

const ICON = 12;

const CLASSIFICATION: Record<Classification, { label: string; icon: ReactNode; help: string }> = {
  PUBLIC: { label: "Public", icon: <Globe size={ICON} aria-hidden />, help: "Any signed-in user may read" },
  INTERNAL: { label: "Internal", icon: <Building2 size={ICON} aria-hidden />, help: "Own department, owner or explicit grant" },
  CONFIDENTIAL: { label: "Confidential", icon: <Lock size={ICON} aria-hidden />, help: "Managers of the department, owner or grant" },
  RESTRICTED: { label: "Restricted", icon: <ShieldAlert size={ICON} aria-hidden />, help: "Owner or explicit grant only; 60-minute sessions" },
  HIGHLY_RESTRICTED: {
    label: "Highly restricted",
    icon: <ShieldX size={ICON} aria-hidden />,
    help: "Owner or explicit grant; re-authentication required; no preview",
  },
};

export function ClassificationBadge({ value }: { value: Classification | string | null | undefined }) {
  if (!value || !(value in CLASSIFICATION)) return <span className="muted">—</span>;
  const c = CLASSIFICATION[value as Classification];
  return (
    <span className={`badge cls-${value}`} title={c.help}>
      {c.icon}
      {c.label.toUpperCase()}
    </span>
  );
}

export function classificationHelp(value: Classification): string {
  return CLASSIFICATION[value].help;
}

/** ALLOW / DENY / BLOCKED decisions of the policy engine. */
export function DecisionBadge({ value }: { value: string | null | undefined }) {
  if (value === "ALLOW")
    return (
      <span className="badge ok">
        <CheckCircle2 size={ICON} aria-hidden />
        ALLOW
      </span>
    );
  if (value === "DENY")
    return (
      <span className="badge bad">
        <Ban size={ICON} aria-hidden />
        DENY
      </span>
    );
  if (value === "BLOCKED")
    return (
      <span className="badge bad">
        <AlertOctagon size={ICON} aria-hidden />
        BLOCKED
      </span>
    );
  return <span className="muted">—</span>;
}

/** File integrity (layers L1–L3). */
export function IntegrityBadge({ value }: { value: string | null | undefined }) {
  if (!value)
    return (
      <span className="badge muted">
        <CircleDashed size={ICON} aria-hidden />
        NOT VERIFIED
      </span>
    );
  if (value === "INTACT" || value === "VERIFIED" || value === "VALID")
    return (
      <span className="badge ok">
        <ShieldCheck size={ICON} aria-hidden />
        VERIFIED
      </span>
    );
  return (
    <span className="badge bad" title={value}>
      <ShieldX size={ICON} aria-hidden />
      {value === "FILE_INTEGRITY_FAILURE" ? "INTEGRITY FAILURE" : value.replaceAll("_", " ")}
    </span>
  );
}

/** Audit-log verification results (stream runs, single events). */
export function VerificationBadge({ status }: { status: string | null | undefined }) {
  if (!status)
    return (
      <span className="badge muted">
        <CircleDashed size={ICON} aria-hidden />
        NOT VERIFIED
      </span>
    );
  if (status === "VALID")
    return (
      <span className="badge ok">
        <ShieldCheck size={ICON} aria-hidden />
        VALID
      </span>
    );
  const label =
    status === "TAMPERING_DETECTED"
      ? "TAMPER DETECTED"
      : status === "AUDIT_LOG_INTEGRITY_FAILURE"
        ? "AUDIT LOG FAILURE"
        : status.replaceAll("_", " ");
  return (
    <span className="badge bad">
      <AlertOctagon size={ICON} aria-hidden />
      {label}
    </span>
  );
}

export function PassFail({ ok, pass = "PASS", fail = "FAIL" }: { ok: boolean | null | undefined; pass?: string; fail?: string }) {
  if (ok === null || ok === undefined) return <span className="muted">—</span>;
  return ok ? (
    <span className="status ok">
      <CheckCircle2 size={14} aria-hidden /> {pass}
    </span>
  ) : (
    <span className="status bad">
      <XCircle size={14} aria-hidden /> {fail}
    </span>
  );
}

export function KindBadge({ kind }: { kind: StreamKind }) {
  const label = { primary: "PRIMARY", synthetic: "SYNTHETIC DATA", lab: "LAB DATA (TAMPERED COPY)" }[kind];
  return <span className={kind === "primary" ? "badge outline" : `badge kind-${kind}`}>{label}</span>;
}

export function RoleBadge({ role }: { role: string }) {
  return <span className="badge outline">{role.toUpperCase()}</span>;
}
