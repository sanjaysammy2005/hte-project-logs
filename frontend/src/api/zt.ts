/** Response shapes of the Zero-Trust file module and the security investigation APIs
 *  (backend/app/files/schemas.py, backend/app/access/enforcer.py, backend/app/api/v1/security.py). */

import type { ProofStep, Role } from "./types";

export type Classification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "HIGHLY_RESTRICTED";
export const CLASSIFICATIONS: Classification[] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "HIGHLY_RESTRICTED"];

export type FileAction =
  | "VIEW"
  | "DOWNLOAD"
  | "UPLOAD"
  | "UPDATE"
  | "RENAME"
  | "DELETE"
  | "RESTORE"
  | "SHARE"
  | "VERIFY"
  | "MANAGE_PERMISSIONS";

export type Permission =
  | "READ"
  | "DOWNLOAD"
  | "CREATE"
  | "UPLOAD"
  | "UPDATE"
  | "RENAME"
  | "DELETE"
  | "RESTORE"
  | "SHARE"
  | "VERIFY"
  | "MANAGE_PERMISSIONS";

/** CREATE and MANAGE_PERMISSIONS can never be granted on a file (backend rejects them). */
export const GRANTABLE: Permission[] = ["READ", "DOWNLOAD", "UPLOAD", "UPDATE", "RENAME", "DELETE", "RESTORE", "SHARE", "VERIFY"];

export type AuditRef = { stream_id: string; chain_index: number; event_type: string };

export type FileVersion = {
  version_number: number;
  sha256: string;
  size_bytes: number;
  mime_type: string;
  original_filename: string;
  uploaded_by: string;
  created_at: string;
  change_reason: string | null;
  restored_from_version: number | null;
  audit_stream_id: string;
  audit_chain_index: number;
  last_verified_at: string | null;
  last_integrity_status: string | null;
};

export type FileItem = {
  id: string;
  display_name: string;
  extension: string;
  mime_type: string;
  classification: Classification;
  owner_id: string;
  created_by: string;
  current_version: number;
  description: string | null;
  origin: string;
  department: string | null;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  last_accessed_at: string | null;
  current: FileVersion | null;
  allowed_actions: FileAction[];
  audit: AuditRef | null;
};

export type FileList = { items: FileItem[]; total: number; limit: number; offset: number };
export type VersionList = { file_id: string; current_version: number; versions: FileVersion[]; audit: AuditRef | null };

export type Grant = {
  id: string;
  file_id: string;
  grantee_id: string | null;
  grantee_role: Role | null;
  permissions: Permission[];
  granted_by: string;
  reason: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  audit_chain_index: number;
  revoked_audit_chain_index: number | null;
};

export type VersionIntegrity = {
  version: number;
  status: string;
  content: string;
  anchor: string;
  evidence: string;
  expected_sha256: string;
  actual_sha256: string | null;
  anchor_chain_index: number;
};
export type IntegrityReport = { file_id: string; status: string; versions: VersionIntegrity[]; audit: AuditRef };

/** error.details of a 403 ACCESS_DENIED / STEP_UP_REQUIRED (backend/app/access/enforcer.py). */
export type DenialDetails = {
  action: string;
  decision: "DENY";
  reason_code: string;
  reasons: string[];
  rule: string;
  rules: string[];
  policy: string;
  required_permission: string | null;
  classification: Classification | null;
  your_role: string;
  your_permissions: string[];
  evaluated_at: string;
  audit: { stream_id: string; chain_index: number };
  step_up_minutes?: number;
};

export type SecurityEvent = {
  chain_index: number;
  event_type: string;
  timestamp: string;
  user: string | null;
  session_id: string | null;
  file_id: string | null;
  filename: string | null;
  classification: Classification | null;
  action: string | null;
  decision: string | null;
  reason_code: string | null;
  rule: string | null;
};
export type SecurityEventPage = { items: SecurityEvent[]; next_cursor: number | null };

export type ChainRelationship = {
  status: "VALID" | "BROKEN";
  stored_hash: string;
  recomputed_hash: string | null;
  hash_matches: boolean;
  prev_hash: string;
  predecessor: { chain_index: number | null; entry_hash: string; is_genesis: boolean; missing: boolean };
  link_matches: boolean;
  successor: { chain_index: number; prev_hash: string; links_back: boolean } | null;
};

export type MerkleStatus = {
  status: "UNSEALED" | "VALID" | "ROOT_MISMATCH" | "RANGE_INCONSISTENT";
  batch: null | {
    batch_id: string;
    batch_index: number;
    first_chain_index: number;
    last_chain_index: number;
    leaf_count: number;
    stored_root: string;
  };
  recomputed_root?: string | null;
  proof?: ProofStep[];
  proof_valid?: boolean;
  records_present?: number;
};

export type EventInspection = {
  event: {
    chain_index: number;
    event_type: string;
    timestamp: string;
    user: string | null;
    session_id: string | null;
    prev_event_type: string | null;
    session_seq: number | null;
    payload: Record<string, unknown>;
    prev_hash: string;
    entry_hash: string;
  };
  chain: ChainRelationship;
  merkle: MerkleStatus;
  related_file: null | {
    file_id: string;
    display_name: string;
    classification: Classification;
    current_version: number;
    deleted: boolean;
    versions: FileVersion[];
  };
};

export type EventVerification = {
  chain_index: number;
  status: "VALID" | "AUDIT_LOG_INTEGRITY_FAILURE";
  chain: ChainRelationship;
  merkle: MerkleStatus;
  provenance: {
    status: string;
    session_events?: number;
    findings: { check: string; expected: string; actual: string }[];
  };
  note: string | null;
};

export type FileInvestigation = {
  file_id: string;
  display_name: string;
  classification: Classification;
  file_integrity: { status: string; first_affected_version: number | null; first_affected_audit_event: number | null };
  audit_log_integrity: {
    status: string;
    anchors_failing: number[];
    stream: {
      status: string;
      records_checked: number;
      unbatched_records: number;
      failed_by_check: Record<string, number>;
      first_affected_audit_event: number | null;
      first_failed_check: string | null;
      first_failing_batch_index: number | null;
    };
  };
  versions: {
    version: number;
    expected_sha256: string;
    anchored_sha256: string | null;
    actual_sha256: string | null;
    file_status: string;
    anchor_chain_index: number;
    anchor_status: string;
    anchor_chain_status: string | null;
    anchor_merkle_status: string | null;
  }[];
};

export type FileTimeline = {
  file_id: string;
  display_name: string;
  classification: Classification;
  owner_id: string;
  deleted: boolean;
  versions: FileVersion[];
  events: SecurityEvent[];
};

export type UserCount = {
  user: string | null;
  count: number;
  distinct_files: number;
  first_seen: string;
  last_seen: string;
  first_chain_index: number;
};

export type Findings = {
  window: { since: string; until: string };
  threshold: number;
  repeated_denials: UserCount[];
  unauthenticated_attempts: UserCount[];
  high_frequency_downloads: UserCount[];
  probing_unknown_or_hidden_files: UserCount[];
  integrity_failures: SecurityEvent[];
  break_glass_self_grants: SecurityEvent[];
  classification_downgrades: SecurityEvent[];
  deletions: SecurityEvent[];
  failed_reauthentications: SecurityEvent[];
  provenance_violations: SecurityEvent[];
};

/** The fixed id of the system stream (backend migration 0001), where all platform events live. */
export const SYSTEM_STREAM_ID = "00000000-0000-4000-8000-000000000001";
