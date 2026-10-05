/** Frontend tests: every route renders for the roles that may use it, navigation follows the
 *  role, file actions follow the backend's allowed_actions, and denials are explained. */

import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import App from "../App";
import { ApiError } from "../api/client";
import type { Role } from "../api/types";
import { navFor } from "../app/nav";
import { AuthProvider } from "../auth";
import { AccessDeniedPanel } from "../ui/access";
import { FILE_ID, SYSTEM, file, mockBackend } from "./mockApi";

function go(path: string) {
  window.history.pushState({}, "", path);
  return render(<App />);
}

async function heading() {
  return screen.findByRole("heading", { level: 1 }, { timeout: 3000 });
}

beforeEach(() => {
  sessionStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("navigation follows the role", () => {
  const labels = (role: Role) => navFor(role).flatMap((s) => [s.title ?? "", ...s.items.map((i) => i.label)]);

  it("employees and managers get files only", () => {
    for (const role of ["employee", "manager"] as Role[]) {
      const items = labels(role);
      expect(items).toContain("My files");
      expect(items).not.toContain("Security");
      expect(items).not.toContain("Audit");
      expect(items).not.toContain("Administration");
    }
  });

  it("auditors investigate but do not administer or own files", () => {
    const items = labels("auditor");
    expect(items).toEqual(expect.arrayContaining(["Security", "Denied access", "Audit", "Hash chain", "Experiments"]));
    expect(items).not.toContain("Administration");
    expect(items).not.toContain("Tamper lab");
    expect(items).not.toContain("My files");
  });

  it("admins see everything; ingestors see nothing", () => {
    expect(labels("admin")).toEqual(expect.arrayContaining(["Administration", "Users", "Tamper lab", "Access policies"]));
    expect(navFor("ingestor")).toEqual([]);
  });
});

const SECURITY_ROUTES = [
  "/security/findings",
  "/security/denied",
  "/security/integrity",
  "/security/events",
  "/security/events/7",
  `/security/files/${FILE_ID}`,
  "/audit/streams",
  `/audit/streams/${SYSTEM}/events`,
  `/audit/streams/${SYSTEM}/chain`,
  `/audit/streams/${SYSTEM}/batches`,
  `/audit/streams/${SYSTEM}/verification`,
  `/audit/streams/${SYSTEM}/sessions/S-abc`,
];
const FILE_ROUTES = ["/overview", "/files", "/files/mine", "/files/shared", "/files/recent", "/files/trash", `/files/${FILE_ID}`];
const ADMIN_ROUTES = ["/admin/users", "/admin/roles", "/admin/permissions", "/admin/settings", "/security/policies", "/security/requests", "/research/lab"];

describe("every route renders", () => {
  it.each([...FILE_ROUTES, ...SECURITY_ROUTES, ...ADMIN_ROUTES])("admin: %s", async (path) => {
    mockBackend("admin");
    go(path);
    expect(await heading()).toBeTruthy();
    expect(screen.queryByText("Something went wrong")).toBeNull();
  });

  it.each(FILE_ROUTES)("employee: %s", async (path) => {
    mockBackend("employee");
    go(path);
    expect(await heading()).toBeTruthy();
  });

  it.each(["/security/events", "/audit/streams", "/admin/users"])("employee is told %s is not for their role", async (path) => {
    mockBackend("employee");
    go(path);
    expect(await screen.findByText("Not available for your role")).toBeTruthy();
  });

  it.each([
    ["/streams", "/audit/streams"],
    [`/streams/${SYSTEM}/batches`, `/audit/streams/${SYSTEM}/batches`],
    ["/lab", "/research/lab"],
  ])("legacy %s redirects to %s", async (from, to) => {
    mockBackend("admin");
    go(from);
    await heading();
    await waitFor(() => expect(window.location.pathname).toBe(to));
  });
});

describe("file actions follow the backend's allowed_actions", () => {
  it("shows only what the backend allows", async () => {
    mockBackend("employee", { [`/files/${FILE_ID}`]: () => file({ allowed_actions: ["DOWNLOAD", "VERIFY"] }) });
    go(`/files/${FILE_ID}`);
    await heading();
    const header = screen.getByRole("heading", { level: 1 }).closest("header") as HTMLElement;
    expect(within(header).getByRole("button", { name: /download/i })).toBeTruthy();
    expect(within(header).getByRole("button", { name: /verify integrity/i })).toBeTruthy();
    for (const hidden of [/rename/i, /new version/i, /share/i, /move to trash/i]) {
      expect(within(header).queryByRole("button", { name: hidden })).toBeNull();
    }
  });

  it("explains when no action is allowed", async () => {
    mockBackend("auditor", { [`/files/${FILE_ID}`]: () => file({ allowed_actions: [] }) });
    go(`/files/${FILE_ID}`);
    expect(await screen.findByText(/the policy allows no actions/i)).toBeTruthy();
  });

  it("shows an honest not-found state for hidden or unknown files", async () => {
    mockBackend("employee", {
      [`/files/${FILE_ID}`]: () =>
        new Response(JSON.stringify({ error: { code: "FILE_NOT_FOUND", message: "File not found", details: {} } }), { status: 404 }),
    });
    go(`/files/${FILE_ID}`);
    expect(await screen.findByText("File not found")).toBeTruthy();
  });

  it("offers upload only to roles that may create files", async () => {
    mockBackend("auditor");
    go("/files");
    await heading();
    expect(screen.queryByRole("button", { name: /upload file/i })).toBeNull();
    cleanup();
    mockBackend("employee");
    go("/files");
    expect(await screen.findByRole("button", { name: /upload file/i })).toBeTruthy();
  });
});

describe("states", () => {
  it("shows an empty state when there are no files", async () => {
    mockBackend("employee", { "/files": () => ({ items: [], total: 0, limit: 50, offset: 0 }) });
    go("/files");
    expect(await screen.findByText("No files here yet")).toBeTruthy();
  });

  it("shows a readable error with retry when the API fails", async () => {
    mockBackend("employee", {
      "/files": () => new Response(JSON.stringify({ error: { code: "STORAGE_UNAVAILABLE", message: "File storage is unavailable", details: {} } }), { status: 503 }),
    });
    go("/files");
    expect(await screen.findByText(/File storage is unavailable/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /retry/i })).toBeTruthy();
  });
});

describe("access denied explanation", () => {
  it("renders the backend's decision, rule and audit reference", () => {
    const error = new ApiError(403, "ACCESS_DENIED", "You signed in successfully, but you do not have DOWNLOAD permission.", {
      action: "DOWNLOAD",
      decision: "DENY",
      reason_code: "GRANT_REQUIRED",
      reasons: ["GRANT_REQUIRED"],
      rule: "classifications.RESTRICTED.requires_explicit_access",
      rules: ["classifications.RESTRICTED.requires_explicit_access"],
      policy: "access-policy.v1 sha256:abcdef0123456789abcdef0123456789abcdef0123",
      required_permission: "DOWNLOAD",
      classification: "RESTRICTED",
      your_role: "employee",
      your_permissions: ["READ"],
      evaluated_at: "2026-10-05T11:00:00Z",
      audit: { stream_id: SYSTEM, chain_index: 42 },
    });
    mockBackend("employee");
    render(
      <AuthProvider>
        <MemoryRouter>
          <AccessDeniedPanel error={error} />
        </MemoryRouter>
      </AuthProvider>,
    );
    expect(screen.getByText("ACCESS DENIED")).toBeTruthy();
    expect(screen.getByText("classifications.RESTRICTED.requires_explicit_access")).toBeTruthy();
    expect(screen.getByText(/audit event #42/)).toBeTruthy();
    expect(screen.getByText("READ")).toBeTruthy();
  });
});
