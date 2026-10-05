/** Dialogs (native <dialog>: focus trapping and Escape for free), confirmations and toasts. */

import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

export function Dialog({
  open,
  title,
  onClose,
  children,
  footer,
  wide = false,
  icon,
}: {
  open: boolean;
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  icon?: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    if (!open && dialog.open) {
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
    }
  }, [open]);
  return (
    <dialog
      ref={ref}
      className={wide ? "dialog wide" : "dialog"}
      onClose={onClose}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      aria-labelledby="dialog-title"
    >
      {open && (
        <>
          <div className="dialog-header">
            {icon}
            <h2 id="dialog-title">{title}</h2>
            <button type="button" className="ghost icon sm" onClick={onClose} aria-label="Close">
              <X size={16} aria-hidden />
            </button>
          </div>
          <div className="dialog-body">{children}</div>
          {footer && <div className="dialog-footer">{footer}</div>}
        </>
      )}
    </dialog>
  );
}

/** Confirmation for destructive or security-relevant actions. */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  danger = false,
  busy = false,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Dialog
      open={open}
      title={title}
      onClose={onClose}
      icon={danger ? <AlertTriangle size={18} color="var(--danger)" aria-hidden /> : undefined}
      footer={
        <>
          <button type="button" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="button" className={danger ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </>
      }
    >
      {children}
    </Dialog>
  );
}

type Toast = { id: number; tone: "ok" | "danger" | "info"; title: string; body?: ReactNode };
type ToastApi = { push: (tone: Toast["tone"], title: string, body?: ReactNode) => void };

const ToastContext = createContext<ToastApi>({ push: () => undefined });

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((tone: Toast["tone"], title: string, body?: ReactNode) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, tone, title, body }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === "danger" ? 8000 : 5000);
  }, []);
  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="toasts" aria-live="polite" aria-atomic="false">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`} role={t.tone === "danger" ? "alert" : "status"}>
            {t.tone === "ok" ? (
              <CheckCircle2 size={16} aria-hidden />
            ) : t.tone === "danger" ? (
              <AlertTriangle size={16} aria-hidden />
            ) : (
              <Info size={16} aria-hidden />
            )}
            <div>
              <strong>{t.title}</strong>
              {t.body && <div className="small muted">{t.body}</div>}
            </div>
            <button
              type="button"
              className="ghost icon sm"
              style={{ marginLeft: "auto" }}
              aria-label="Dismiss"
              onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}
            >
              <X size={14} aria-hidden />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  return useContext(ToastContext);
}
