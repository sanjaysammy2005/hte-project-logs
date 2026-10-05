/** Small, dependency-free SVG charts for the overview (Plotly stays on the research page).
 *  Following the dataviz method: status hues only for status (ALLOW/DENY) with icon + label in
 *  the legend, a one-hue ordinal ramp for classification, thin marks with a 2px gap, rounded
 *  data-ends, a recessive grid, hover <title> on every mark, and a table view. Values come only
 *  from the API; an empty series renders an empty state, never placeholder numbers. */

import { Ban, CheckCircle2, Table2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { EmptyState } from "./primitives";

function niceMax(v: number): number {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  return Math.ceil(v / p) * p;
}

function ViewToggle({ table, onToggle }: { table: boolean; onToggle: () => void }) {
  return (
    <button type="button" className="ghost sm" onClick={onToggle} aria-pressed={table}>
      <Table2 size={14} aria-hidden /> {table ? "Chart" : "Table"}
    </button>
  );
}

export type DayBucket = { day: string; allow: number; deny: number };

/** Stacked daily bars: ALLOW (good) and DENY (critical). */
export function DecisionsOverTime({ data, footnote }: { data: DayBucket[]; footnote?: ReactNode }) {
  const [table, setTable] = useState(false);
  const total = data.reduce((s, d) => s + d.allow + d.deny, 0);
  if (total === 0) return <EmptyState title="No access decisions in this window">Decisions appear here as users access files.</EmptyState>;
  const W = 640;
  const H = 180;
  const pad = { l: 32, r: 8, t: 8, b: 22 };
  const max = niceMax(Math.max(...data.map((d) => d.allow + d.deny)));
  const band = (W - pad.l - pad.r) / data.length;
  const barW = Math.max(4, Math.min(22, band - 6));
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
  const ticks = [0, max / 2, max];
  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div className="chart-legend" role="list">
          <span role="listitem">
            <span className="swatch" style={{ background: "var(--chart-good)" }} />
            <CheckCircle2 size={12} aria-hidden /> ALLOW
          </span>
          <span role="listitem">
            <span className="swatch" style={{ background: "var(--chart-critical)" }} />
            <Ban size={12} aria-hidden /> DENY
          </span>
        </div>
        <ViewToggle table={table} onToggle={() => setTable(!table)} />
      </div>
      {table ? (
        <table>
          <thead>
            <tr>
              <th>Day</th>
              <th className="num">Allow</th>
              <th className="num">Deny</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.day}>
                <td>{d.day}</td>
                <td className="num">{d.allow}</td>
                <td className="num">{d.deny}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Allow and deny decisions per day">
          {ticks.map((t) => (
            <g key={t}>
              <line className="grid-line" x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} />
              <text x={pad.l - 6} y={y(t) + 4} textAnchor="end">
                {Math.round(t)}
              </text>
            </g>
          ))}
          {data.map((d, i) => {
            const x = pad.l + i * band + (band - barW) / 2;
            const allowTop = y(d.allow);
            const denyTop = y(d.allow + d.deny);
            const label = data.length <= 16 || i % Math.ceil(data.length / 8) === 0;
            return (
              <g key={d.day}>
                <title>{`${d.day}: ${d.allow} allowed, ${d.deny} denied`}</title>
                {d.allow > 0 && (
                  <rect x={x} y={allowTop} width={barW} height={y(0) - allowTop} rx={2} fill="var(--chart-good)" />
                )}
                {d.deny > 0 && (
                  <rect x={x} y={denyTop} width={barW} height={Math.max(1, allowTop - denyTop - 2)} rx={2} fill="var(--chart-critical)" />
                )}
                <rect x={pad.l + i * band} y={pad.t} width={band} height={H - pad.t - pad.b} fill="transparent" />
                {label && (
                  <text x={x + barW / 2} y={H - 6} textAnchor="middle">
                    {d.day.slice(5)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
      {footnote && <div className="chart-note">{footnote}</div>}
    </div>
  );
}

export type BarDatum = { label: string; value: number; icon?: ReactNode };

/** Horizontal bars with direct value labels. ``ordinal`` uses the one-hue ramp (light → dark)
 *  for ordered categories such as classification; otherwise a single series hue. */
export function HorizontalBars({
  data,
  ordinal = false,
  footnote,
  emptyTitle = "Nothing to show yet",
}: {
  data: BarDatum[];
  ordinal?: boolean;
  footnote?: ReactNode;
  emptyTitle?: string;
}) {
  const [table, setTable] = useState(false);
  const total = data.reduce((s, d) => s + d.value, 0);
  if (total === 0) return <EmptyState title={emptyTitle} />;
  const max = Math.max(...data.map((d) => d.value));
  const ramp = ["var(--chart-seq-1)", "var(--chart-seq-2)", "var(--chart-seq-3)", "var(--chart-seq-4)", "var(--chart-seq-5)"];
  return (
    <div>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <ViewToggle table={table} onToggle={() => setTable(!table)} />
      </div>
      {table ? (
        <table>
          <tbody>
            {data.map((d) => (
              <tr key={d.label}>
                <td>{d.label}</td>
                <td className="num">{d.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div role="img" aria-label={data.map((d) => `${d.label}: ${d.value}`).join(", ")}>
          {data.map((d, i) => (
            <div
              key={d.label}
              title={`${d.label}: ${d.value}`}
              style={{ display: "grid", gridTemplateColumns: "150px minmax(0,1fr) 44px", alignItems: "center", gap: 8, padding: "4px 0" }}
            >
              <span className="small row" style={{ gap: 6, color: "var(--text-2)", flexWrap: "nowrap" }}>
                {d.icon}
                {d.label}
              </span>
              <span style={{ background: "var(--surface-sunken)", borderRadius: 4, height: 12, overflow: "hidden" }}>
                <span
                  style={{
                    display: "block",
                    height: "100%",
                    width: `${max ? (d.value / max) * 100 : 0}%`,
                    minWidth: d.value > 0 ? 3 : 0,
                    borderRadius: 4,
                    background: ordinal ? ramp[Math.min(i, ramp.length - 1)] : "var(--chart-1)",
                  }}
                />
              </span>
              <span className="small num" style={{ color: "var(--text-2)", fontWeight: 600 }}>
                {d.value}
              </span>
            </div>
          ))}
        </div>
      )}
      {footnote && <div className="chart-note">{footnote}</div>}
    </div>
  );
}
