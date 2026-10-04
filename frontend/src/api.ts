export type HealthStatus = {
  status: "ok" | "degraded";
  database: "ok" | "unavailable";
};

/** Fetches backend health. A 503 still carries a HealthStatus body. */
export async function fetchHealth(): Promise<HealthStatus> {
  const response = await fetch("/api/v1/health");
  if (response.status !== 200 && response.status !== 503) {
    throw new Error(`Unexpected response ${response.status}`);
  }
  return (await response.json()) as HealthStatus;
}
