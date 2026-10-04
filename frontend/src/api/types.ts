/** Response shapes returned by the backend (see backend/app/api/v1/*.py). */

export type Role = "admin" | "auditor" | "ingestor";

export type Operator = { id: string; username: string; role: Role };

export type StreamKind = "primary" | "synthetic" | "lab";

export type Stream = {
  id: string;
  name: string;
  kind: StreamKind;
  batch_size: number;
  description: string | null;
  created_at: string;
  record_count: number;
  last_verification_status: string | null;
};

export type StreamDetail = Stream & {
  source_stream_id: string | null;
  genesis_hash: string;
  hash_scheme: string;
  merkle_scheme: string;
};

export type AuditEvent = {
  chain_index: number;
  event_type: string;
  payload: Record<string, unknown>;
  actor_user_id: string | null;
  session_id: string | null;
  prev_event_type: string | null;
  session_seq: number | null;
  event_timestamp: string;
  prev_hash: string;
  entry_hash: string;
};

export type EventPage = { items: AuditEvent[]; next_cursor: number | null };

export type EventDetail = {
  record: AuditEvent;
  predecessor: { chain_index: number | null; entry_hash: string };
  recomputed_hash: string | null;
  hash_matches: boolean;
  link_matches: boolean;
  batch: { batch_id: string; batch_index: number } | null;
};

export type Batch = {
  batch_id: string;
  batch_index: number;
  first_chain_index: number;
  last_chain_index: number;
  leaf_count: number;
  merkle_root: string;
  sealed_at: string;
};

export type ProofStep = { sibling: string; position: "left" | "right" };

export type Proof = {
  chain_index: number;
  leaf: string;
  batch_id: string;
  batch_index: number;
  merkle_root: string;
  proof: ProofStep[];
};

export type Finding = {
  chain_index: number | null;
  batch_id: string | null;
  check: string;
  expected: string;
  actual: string;
};

export type RunSummary = {
  run_id: string;
  stream_id: string;
  status: "VALID" | "TAMPERING_DETECTED" | "ERROR";
  first_failure: { chain_index: number | null; batch_id: string | null; batch_index: number | null; check: string } | null;
  records_checked: number;
  unbatched_records: number;
  batches_checked: number;
  failed_by_check: Record<string, number>;
  findings_total: number;
  cascade_affected_records: number;
  rules_version: string;
  hash_scheme: string;
  merkle_scheme: string;
  started_at: string;
  duration_ms: number;
};

export type RunDetail = RunSummary & { findings: Finding[]; findings_stored: number };

export type ScenarioType = { code: string; attacker_model: string; description: string };

export type Scenario = {
  id: string;
  scenario_type: string;
  attacker_model: string;
  description: string;
  source_stream_id: string;
  lab_stream_id: string;
  parameters: Record<string, unknown>;
  expected_detected: boolean;
  true_first_index: number | null;
  verification_run_id: string | null;
  actual_detected: boolean | null;
  first_failure_index: number | null;
  first_failure_check: string | null;
  located_correctly: boolean | null;
  outcome: "AS_EXPECTED" | "UNEXPECTED" | "PENDING";
  created_at: string;
};
