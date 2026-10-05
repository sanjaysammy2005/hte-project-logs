/** Presenting backend authorization decisions. The UI never decides access itself: it shows
 *  ``allowed_actions`` from the backend, and when an action is still refused (state changed,
 *  or a direct call), it explains the backend's DENY verbatim and links to the chained event. */

import { KeyRound, ShieldX } from "lucide-react";
import { createContext, useCallback, useContext, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { ApiError, api, errorMessage } from "../api/client";
import type { DenialDetails } from "../api/zt";
import { useAuth } from "../auth";
import { ClassificationBadge } from "./badges";
import { Dialog } from "./feedback";
import { KeyValue } from "./primitives";

const REASON_TEXT: Record<string, string> = {
  NO_PERMISSION: "No role, ownership or grant gives you this permission.",
  DEPARTMENT_MISMATCH: "Your role reaches this classification only inside your own department.",
  GRANT_REQUIRED: "This classification requires ownership or an explicit grant.",
  SESSION_TOO_OLD: "Your session is older than this classification allows. Sign in again.",
  STEP_UP_REQUIRED: "Re-enter your password to continue.",
  DENIAL_BURST: "Too many denied requests recently; sensitive files are paused for a while.",
  RATE_LIMIT: "The download limit for this classification was reached.",
  PREVIEW_NOT_ALLOWED: "This classification cannot be previewed; download instead.",
  FILE_DELETED: "The file is in the trash.",
  SHARE_ESCALATION: "You can only share permissions you hold yourself.",
  SELF_GRANT: "You cannot grant permissions to yourself.",
  NOT_GRANTABLE: "These permissions cannot be granted here.",
  GRANTEE_NOT_ELIGIBLE: "That account cannot receive file permissions.",
  OWNER_OR_MANAGER_ONLY: "Only the owner or a permission manager may share this file.",
  NOT_GRANTOR: "Only the grantor, the owner or a permission manager may revoke this grant.",
  ROLE_GRANT_NOT_ALLOWED: "Role-wide grants are not allowed at this classification.",
};

export function AccessDeniedPanel({ error }: { error: ApiError }) {
  const { can } = useAuth();
  const d = error.details as DenialDetails;
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="alert danger" role="alert">
        <ShieldX size={18} aria-hidden />
        <div className="alert-body">
          <strong>ACCESS DENIED</strong>
          <span>{error.message}</span>
          {d?.reason_code && REASON_TEXT[d.reason_code] && <span className="small">{REASON_TEXT[d.reason_code]}</span>}
        </div>
      </div>
      {d && (
        <KeyValue
          items={[
            ["Action", <code key="a">{d.action}</code>],
            ["Required permission", d.required_permission ? <code>{d.required_permission}</code> : null],
            ["Classification", <ClassificationBadge key="c" value={d.classification} />],
            ["Your role", d.your_role],
            ["Your permissions", d.your_permissions.length ? d.your_permissions.join(", ") : "none"],
            ["Decision", <span key="dec">DENY · {d.reasons.join(", ")}</span>],
            ["Policy rule", <code key="r">{d.rule}</code>],
            ["Policy", <code key="p" className="small">{d.policy.slice(0, 40)}…</code>],
            [
              "Recorded as",
              can("admin", "auditor") ? (
                <Link to={`/security/events/${d.audit.chain_index}`}>audit event #{d.audit.chain_index}</Link>
              ) : (
                <span>audit event #{d.audit.chain_index} in the system stream</span>
              ),
            ],
          ]}
        />
      )}
    </div>
  );
}

type Guard = {
  /** Run a protected action; denials and step-up prompts are handled here. Returns undefined
   *  when the action was refused (already shown to the user). */
  run: <T>(action: () => Promise<T>) => Promise<T | undefined>;
};

const GuardContext = createContext<Guard>({ run: async (a) => a() });

export function AccessGuardProvider({ children }: { children: ReactNode }) {
  const [denied, setDenied] = useState<ApiError | null>(null);
  const [stepUp, setStepUp] = useState<{ minutes?: number } | null>(null);
  const pending = useRef<{ retry: () => Promise<unknown>; resolve: (v: unknown) => void; reject: (e: unknown) => void } | null>(null);
  const [password, setPassword] = useState("");
  const [stepError, setStepError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async <T,>(action: () => Promise<T>): Promise<T | undefined> => {
    try {
      return await action();
    } catch (e) {
      if (e instanceof ApiError && e.code === "STEP_UP_REQUIRED") {
        return new Promise<T | undefined>((resolve, reject) => {
          pending.current = { retry: action, resolve: resolve as (v: unknown) => void, reject };
          setStepUp({ minutes: (e.details as DenialDetails)?.step_up_minutes });
        });
      }
      if (e instanceof ApiError && e.code === "ACCESS_DENIED") {
        setDenied(e);
        return undefined;
      }
      throw e;
    }
  }, []);

  async function submitStepUp(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setStepError(null);
    try {
      await api("/auth/reauthenticate", { method: "POST", body: { password } });
      setStepUp(null);
      setPassword("");
      const p = pending.current;
      pending.current = null;
      if (p) {
        try {
          p.resolve(await p.retry());
        } catch (e) {
          if (e instanceof ApiError && e.code === "ACCESS_DENIED") {
            setDenied(e);
            p.resolve(undefined);
          } else p.reject(e);
        }
      }
    } catch (e) {
      setStepError(e);
    } finally {
      setBusy(false);
    }
  }

  function cancelStepUp() {
    setStepUp(null);
    setPassword("");
    pending.current?.resolve(undefined);
    pending.current = null;
  }

  return (
    <GuardContext.Provider value={{ run }}>
      {children}
      <Dialog open={!!denied} title="Access denied" onClose={() => setDenied(null)} footer={<button onClick={() => setDenied(null)}>Close</button>}>
        {denied && <AccessDeniedPanel error={denied} />}
      </Dialog>
      <Dialog open={!!stepUp} title="Confirm it's you" onClose={cancelStepUp} icon={<KeyRound size={18} aria-hidden />}>
        <form className="form" onSubmit={(e) => void submitStepUp(e)}>
          <p className="muted" style={{ margin: 0 }}>
            This file's classification requires you to re-enter your password
            {stepUp?.minutes ? ` (valid for ${stepUp.minutes} minutes)` : ""}. The re-authentication is recorded in
            the audit chain. This is password re-entry, not multi-factor authentication.
          </p>
          <label>
            Password
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
          </label>
          {stepError ? <div className="error">{errorMessage(stepError)}</div> : null}
          <div className="form-actions">
            <button type="button" onClick={cancelStepUp}>
              Cancel
            </button>
            <button type="submit" className="primary" disabled={busy}>
              {busy ? "Checking…" : "Continue"}
            </button>
          </div>
        </form>
      </Dialog>
    </GuardContext.Provider>
  );
}

export function useAccessGuard(): Guard {
  return useContext(GuardContext);
}
