/**
 * Experiment results. Every chart and table is computed ONLY from results persisted by the
 * backend; this file must never contain metric values (checked by
 * scripts/check-no-hardcoded-metrics.mjs).
 */

import { useState } from "react";
import createPlotlyComponent from "react-plotly.js/factory";
import Plotly from "plotly.js-basic-dist-min";
import { api } from "../api/client";
import { Card, ErrorBox, formatTime, useLoader } from "../components";

const Plot = createPlotlyComponent(Plotly);

type Proportion = { successes: number; n: number; rate: number | null; ci95: [number, number] | null };
type Stats = { n: number; median: number | null; q1: number | null; q3: number | null; iqr: number | null };
type Summary = {
  detection: { size: number; scenario: string; expected_detected: boolean | null; detection: Proportion; localization: Proportion; errors: number }[];
  false_positive: { size: number; false_positive: Proportion; findings_on_untampered: number; records_checked: number }[];
  timing: { size: number; batch_size: number; records: number; batches: number; all_valid: boolean; total_ms: Stats; check_ms: Stats; load_ms: Stats; chain_ms: Stats; provenance_ms: Stats; merkle_ms: Stats }[];
  proofs: { batch_size: number; proof_length: number; generate_us: Stats; verify_us: Stats }[];
  storage: { size: number; records: number; tuple_overhead_bytes_per_record: number; page_overhead_bytes_per_record: number; batch_bytes_per_record: number }[];
};
type Experiment = {
  id: string;
  name: string;
  status: string;
  config: Record<string, unknown>;
  environment: Record<string, unknown> | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  summary: Summary | null;
};

const pct = (p: Proportion) => (p.rate === null ? "—" : `${(p.rate * 100).toFixed(1)}% (${p.successes}/${p.n})`);
const ci = (p: Proportion) => (p.ci95 ? `[${(p.ci95[0] * 100).toFixed(1)}, ${(p.ci95[1] * 100).toFixed(1)}]` : "—");
const ms = (s: Stats) => (s.median === null ? "—" : `${s.median.toFixed(2)} (IQR ${(s.iqr ?? 0).toFixed(2)})`);

/** Upper and lower error-bar lengths; NaN (no bar) when there is no data. */
function errorBars(p: Proportion): [number, number] {
  const value = p.rate;
  const bounds = p.ci95;
  if (value === null || bounds === null) return [Number.NaN, Number.NaN];
  return [bounds[1] - value, value - bounds[0]];
}

function usePlotTheme() {
  const dark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  return {
    paper_bgcolor: "rgba(0,0,0,0)",
    plot_bgcolor: "rgba(0,0,0,0)",
    font: { color: dark ? "#e6e9ef" : "#1c2330" },
    margin: { t: 48, r: 16, b: 56, l: 64 },
    autosize: true,
  };
}

function Results({ run }: { run: Experiment }) {
  const theme = usePlotTheme();
  const s = run.summary;
  if (!s) return <p className="muted">No summary yet (status: {run.status}).</p>;
  const sizes = [...new Set(s.detection.map((d) => d.size))];
  const batchSizes = [...new Set(s.timing.map((t) => t.batch_size))];

  return (
    <>
      <Card title="Detection rate per scenario (95% Wilson interval)">
        <Plot
          data={sizes.map((size) => {
            const rows = s.detection.filter((d) => d.size === size);
            return {
              type: "bar" as const,
              name: `N≈${size}`,
              x: rows.map((d) => d.scenario),
              y: rows.map((d) => d.detection.rate ?? Number.NaN),
              error_y: {
                type: "data" as const,
                symmetric: false,
                array: rows.map((d) => errorBars(d.detection)[0]),
                arrayminus: rows.map((d) => errorBars(d.detection)[1]),
              },
            };
          })}
          layout={{ ...theme, barmode: "group", yaxis: { title: { text: "Detection rate" }, range: [0, 1.05] }, xaxis: { title: { text: "Scenario" } } }}
          config={{ displaylogo: false, responsive: true }}
          style={{ width: "100%", height: 340 }}
          useResizeHandler
        />
        <table>
          <thead>
            <tr>
              <th>N</th>
              <th>Scenario</th>
              <th>Expected</th>
              <th>Detection rate</th>
              <th>95% CI</th>
              <th>Localization accuracy</th>
              <th className="num">Errors</th>
            </tr>
          </thead>
          <tbody>
            {s.detection.map((d) => (
              <tr key={`${d.size}-${d.scenario}`}>
                <td>{d.size}</td>
                <td>{d.scenario}</td>
                <td>{d.expected_detected === null ? "—" : d.expected_detected ? "detected" : "not detected"}</td>
                <td>{pct(d.detection)}</td>
                <td className="small">{ci(d.detection)}</td>
                <td>{pct(d.localization)}</td>
                <td className="num">{d.errors}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title="False-positive rate on untampered streams">
        <table>
          <thead>
            <tr>
              <th>N</th>
              <th>False-positive rate</th>
              <th>95% CI</th>
              <th className="num">Findings</th>
              <th className="num">Records checked</th>
            </tr>
          </thead>
          <tbody>
            {s.false_positive.map((f) => (
              <tr key={f.size}>
                <td>{f.size}</td>
                <td>{pct(f.false_positive)}</td>
                <td className="small">{ci(f.false_positive)}</td>
                <td className="num">{f.findings_on_untampered}</td>
                <td className="num">{f.records_checked}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title="Verification time (median of measured repetitions)">
        <Plot
          data={batchSizes.map((m) => {
            const rows = s.timing.filter((t) => t.batch_size === m).sort((a, b) => a.records - b.records);
            return {
              type: "scatter" as const,
              mode: "lines+markers" as const,
              name: `m=${m}`,
              x: rows.map((t) => t.records),
              y: rows.map((t) => t.total_ms.median ?? 0),
            };
          })}
          layout={{ ...theme, xaxis: { title: { text: "Records" } }, yaxis: { title: { text: "Total verification time (ms)" } } }}
          config={{ displaylogo: false, responsive: true }}
          style={{ width: "100%", height: 320 }}
          useResizeHandler
        />
        <table>
          <thead>
            <tr>
              <th className="num">Records</th>
              <th className="num">Batch size</th>
              <th>Total ms</th>
              <th>Load ms</th>
              <th>Chain ms</th>
              <th>Provenance ms</th>
              <th>Merkle ms</th>
              <th>All VALID</th>
            </tr>
          </thead>
          <tbody>
            {s.timing.map((t) => (
              <tr key={`${t.size}-${t.batch_size}`}>
                <td className="num">{t.records}</td>
                <td className="num">{t.batch_size}</td>
                <td>{ms(t.total_ms)}</td>
                <td>{ms(t.load_ms)}</td>
                <td>{ms(t.chain_ms)}</td>
                <td>{ms(t.provenance_ms)}</td>
                <td>{ms(t.merkle_ms)}</td>
                <td>{t.all_valid ? "yes" : "NO"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title="Membership proofs and storage overhead">
        <table>
          <thead>
            <tr>
              <th className="num">Batch size</th>
              <th className="num">Proof length</th>
              <th>Generate µs (median)</th>
              <th>Verify µs (median)</th>
            </tr>
          </thead>
          <tbody>
            {s.proofs.map((p) => (
              <tr key={p.batch_size}>
                <td className="num">{p.batch_size}</td>
                <td className="num">{p.proof_length}</td>
                <td>{ms(p.generate_us)}</td>
                <td>{ms(p.verify_us)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <h3>Storage (bytes per record; indexes excluded)</h3>
        <table>
          <thead>
            <tr>
              <th className="num">Records</th>
              <th className="num">Tuple overhead</th>
              <th className="num">Page overhead</th>
              <th className="num">Batch table</th>
            </tr>
          </thead>
          <tbody>
            {s.storage.map((st) => (
              <tr key={st.size}>
                <td className="num">{st.records}</td>
                <td className="num">{st.tuple_overhead_bytes_per_record.toFixed(1)}</td>
                <td className="num">{st.page_overhead_bytes_per_record.toFixed(1)}</td>
                <td className="num">{st.batch_bytes_per_record.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title="Test conditions">
        <pre className="small">{JSON.stringify({ config: run.config, environment: run.environment }, null, 2)}</pre>
      </Card>
    </>
  );
}

export default function ExperimentsPage() {
  const runs = useLoader(() => api<Experiment[]>("/experiments"), []);
  const [selected, setSelected] = useState<string | null>(null);
  const runId = selected ?? runs.data?.find((r) => r.status === "completed")?.id ?? null;
  const detail = useLoader(() => (runId ? api<Experiment>(`/experiments/${runId}`) : Promise.resolve(null)), [runId]);

  return (
    <>
      <h1>Experiments</h1>
      <p className="muted">
        Measured results stored by the experiment harness (<code>python -m app.experiments</code>). Nothing here is
        estimated or hard-coded; each run records its configuration and machine.
      </p>
      <Card title="Runs">
        <ErrorBox error={runs.error} />
        {runs.data && runs.data.length === 0 && <p className="muted">No experiment runs yet.</p>}
        {runs.data && runs.data.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Started</th>
                <th>Finished</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>{r.status}</td>
                  <td className="small">{r.started_at ? formatTime(r.started_at) : "—"}</td>
                  <td className="small">{r.finished_at ? formatTime(r.finished_at) : "—"}</td>
                  <td>
                    <button type="button" disabled={r.id === runId} onClick={() => setSelected(r.id)}>
                      {r.id === runId ? "Shown" : "Show"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <ErrorBox error={detail.error} />
      {detail.data?.error && <ErrorBox error={new Error(`Run failed: ${detail.data.error}`)} />}
      {detail.data && <Results run={detail.data} />}
    </>
  );
}
