/** A fetch mock that answers like the TraceLock backend with empty-but-valid data, so the UI can
 *  be rendered route by route in tests. Overrides let a test shape specific responses. */

import { vi } from "vitest";
import type { Role } from "../api/types";
import type { FileItem } from "../api/zt";

export const FILE_ID = "11111111-1111-4111-8111-111111111111";
export const ME = "22222222-2222-4222-8222-222222222222";
export const SYSTEM = "00000000-0000-4000-8000-000000000001";

export function file(overrides: Partial<FileItem> = {}): FileItem {
  return {
    id: FILE_ID,
    display_name: "q3-budget.xlsx",
    extension: "xlsx",
    mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    classification: "RESTRICTED",
    owner_id: ME,
    created_by: ME,
    current_version: 2,
    description: null,
    origin: "user",
    department: "Engineering",
    created_at: "2026-10-05T10:00:00Z",
    updated_at: "2026-10-05T11:00:00Z",
    deleted_at: null,
    last_accessed_at: null,
    current: {
      version_number: 2,
      sha256: "a".repeat(64),
      size_bytes: 2048,
      mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      original_filename: "q3-budget.xlsx",
      uploaded_by: ME,
      created_at: "2026-10-05T11:00:00Z",
      change_reason: null,
      restored_from_version: null,
      audit_stream_id: SYSTEM,
      audit_chain_index: 7,
      last_verified_at: null,
      last_integrity_status: null,
    },
    allowed_actions: [],
    audit: null,
    ...overrides,
  };
}

const stream = {
  id: SYSTEM,
  name: "system",
  kind: "primary",
  batch_size: 64,
  description: null,
  created_at: "2026-10-04T00:00:00Z",
  record_count: 0,
  last_verification_status: null,
  source_stream_id: null,
  genesis_hash: "0".repeat(64),
  hash_scheme: "tl-v1",
  merkle_scheme: "paper-dup-v1",
};

const emptyFindings = {
  window: { since: "", until: "" },
  threshold: 1,
  repeated_denials: [],
  unauthenticated_attempts: [],
  high_frequency_downloads: [],
  probing_unknown_or_hidden_files: [],
  integrity_failures: [],
  break_glass_self_grants: [],
  classification_downgrades: [],
  deletions: [],
  failed_reauthentications: [],
  provenance_violations: [],
};

const inspection = {
  event: {
    chain_index: 7,
    event_type: "FILE_ACCESS_DENIED",
    timestamp: "2026-10-05T11:00:00.000000Z",
    user: "eve",
    session_id: "S-abc",
    prev_event_type: "AUTHENTICATION",
    session_seq: 3,
    payload: { decision: "DENY", action: "DOWNLOAD", reason_code: "GRANT_REQUIRED", rule: "classifications.RESTRICTED.requires_explicit_access" },
    prev_hash: "b".repeat(64),
    entry_hash: "c".repeat(64),
  },
  chain: {
    status: "VALID",
    stored_hash: "c".repeat(64),
    recomputed_hash: "c".repeat(64),
    hash_matches: true,
    prev_hash: "b".repeat(64),
    predecessor: { chain_index: 6, entry_hash: "b".repeat(64), is_genesis: false, missing: false },
    link_matches: true,
    successor: null,
  },
  merkle: { status: "UNSEALED", batch: null },
  related_file: null,
};

type Handler = (url: URL, init?: RequestInit) => unknown;

function route(url: URL): unknown {
  const p = url.pathname.replace(/^\/api\/v1/, "");
  if (p === "/health") return { status: "ok", database: "ok" };
  if (p === "/files") return { items: [file()], total: 1, limit: 50, offset: 0 };
  if (/^\/files\/[^/]+\/versions$/.test(p)) return { file_id: FILE_ID, current_version: 2, versions: [], audit: null };
  if (/^\/files\/[^/]+\/permissions(\/history)?$/.test(p)) return { file_id: FILE_ID, grants: [] };
  if (/^\/files\/[^/]+$/.test(p)) return file();
  if (p === "/security/findings") return emptyFindings;
  if (p === "/security/events") return { items: [], next_cursor: null };
  if (/^\/security\/events\/\d+$/.test(p)) return inspection;
  if (/^\/security\/files\/[^/]+\/timeline$/.test(p))
    return { file_id: FILE_ID, display_name: "q3-budget.xlsx", classification: "RESTRICTED", owner_id: ME, deleted: false, versions: [], events: [] };
  if (/^\/security\/files\/[^/]+\/integrity$/.test(p))
    return {
      file_id: FILE_ID,
      display_name: "q3-budget.xlsx",
      classification: "RESTRICTED",
      file_integrity: { status: "INTACT", first_affected_version: null, first_affected_audit_event: null },
      audit_log_integrity: {
        status: "VALID",
        anchors_failing: [],
        stream: { status: "VALID", records_checked: 10, unbatched_records: 10, failed_by_check: {}, first_affected_audit_event: null, first_failed_check: null, first_failing_batch_index: null },
      },
      versions: [],
    };
  if (p === "/streams" || p === "/experiments" || p === "/lab/scenarios" || p === "/lab/scenario-types") return [];
  if (/^\/streams\/[^/]+$/.test(p)) return stream;
  if (/\/(batches|verification-runs)$/.test(p) || /\/sessions\/[^/]+$/.test(p)) return [];
  if (/\/events$/.test(p)) return { items: [], next_cursor: null };
  return {};
}

export function mockBackend(role: Role, overrides: Record<string, Handler> = {}) {
  sessionStorage.setItem("tracelock.token", "test-token");
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input.toString(), "http://localhost");
    const path = url.pathname.replace(/^\/api\/v1/, "");
    let body: unknown;
    if (path === "/auth/me") body = { id: ME, username: `${role}-user`, role };
    else if (overrides[path]) body = overrides[path](url, init);
    else body = route(url);
    if (body instanceof Response) return body;
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
