import { Construction, UserPlus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../../api/client";
import type { Operator, Role } from "../../api/types";
import { useToast } from "../../ui/feedback";
import { EmptyState, PageHeader, Panel } from "../../ui/primitives";

const PLANNED: Record<string, { title: string; text: string }> = {
  policies: {
    title: "Access policies",
    text: "The active access policy is a versioned file on the server (config/access_policy.v1.json); every decision records its version and SHA-256. A read-only policy viewer needs a backend endpoint that is not built yet.",
  },
  requests: {
    title: "Access requests",
    text: "Users will be able to request access to a file, and owners or permission managers will approve or reject it. This workflow is planned and has no backend yet.",
  },
  roles: {
    title: "Roles",
    text: "Roles (admin, auditor, manager, employee, ingestor) and their permissions per classification are defined in the versioned policy file. Showing them here needs a policy endpoint (planned).",
  },
  permissions: {
    title: "Permissions",
    text: "File-level permissions are managed on each file's Permissions tab today. An organisation-wide permissions view is planned.",
  },
  settings: {
    title: "System settings",
    text: "Upload limits and allowed file types are configured through environment variables on the server. A read-only settings view is planned.",
  },
};

/** Navigation items whose backend is not built yet. Honest placeholder; no made-up data. */
export function PlannedPage({ which }: { which: keyof typeof PLANNED }) {
  const p = PLANNED[which];
  return (
    <>
      <PageHeader title={p.title} badges={<span className="badge muted">PLANNED</span>} />
      <Panel>
        <EmptyState title="Not available yet" icon={<Construction size={28} aria-hidden />}>
          {p.text}
        </EmptyState>
      </Panel>
    </>
  );
}

const ROLES: Role[] = ["employee", "manager", "auditor", "admin", "ingestor"];

export function UsersPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("employee");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<Operator[]>([]);
  const toast = useToast();

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const op = await api<Operator>("/operators", { method: "POST", body: { username, password, role } });
      setCreated((c) => [op, ...c]);
      toast.push("ok", `User ${op.username} created`, `Role: ${op.role}`);
      setUsername("");
      setPassword("");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Users" subtitle="Platform accounts. Passwords are stored only as Argon2id hashes." />
      <div className="grid cols-2">
        <Panel title="Create user" actions={<UserPlus size={16} aria-hidden />}>
          <form className="form" onSubmit={(e) => void submit(e)}>
            <label>
              Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={128} autoComplete="off" />
            </label>
            <label>
              Initial password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} autoComplete="new-password" />
              <span className="hint">At least 12 characters.</span>
            </label>
            <label>
              Role
              <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {ROLES.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
              <span className="hint">Departments are set by an administrator in the database for now.</span>
            </label>
            {error ? <div className="error">{errorMessage(error)}</div> : null}
            <div className="form-actions">
              <button type="submit" className="primary" disabled={busy}>
                Create user
              </button>
            </div>
          </form>
        </Panel>
        <Panel title="User directory" hint="Listing, deactivation and role changes need user-management endpoints (planned).">
          {created.length === 0 ? (
            <EmptyState title="Directory not available yet">Users created in this session are listed here with their account ID, which is needed for sharing.</EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Account ID</th>
                </tr>
              </thead>
              <tbody>
                {created.map((o) => (
                  <tr key={o.id}>
                    <td>{o.username}</td>
                    <td>{o.role}</td>
                    <td>
                      <code className="small">{o.id}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </>
  );
}
