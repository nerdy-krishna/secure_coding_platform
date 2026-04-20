// secure-code-ui/src/shared/ui/DashboardPrimitives.tsx
//
// Reusable dashboard atoms ported from the SCCAP design bundle.
// Cross-imported by DevDashboard / EnterpriseDashboard / AdminSnapshot.

import React, { useMemo } from "react";

// ============================================================================
// MetricCard — label + big number + optional delta + optional sparkline
// ============================================================================

export type MetricTone = "good" | "bad" | "warn" | "default";

export interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  delta?: React.ReactNode;
  tone?: MetricTone;
  spark?: React.ReactNode;
}

const TONE_COLORS: Record<MetricTone, string> = {
  good: "var(--success)",
  bad: "var(--critical)",
  warn: "var(--high)",
  default: "var(--fg-muted)",
};

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  delta,
  tone = "default",
  spark,
}) => (
  <div className="sccap-card" style={{ padding: 18 }}>
    <div style={{ fontSize: 12, color: "var(--fg-muted)", fontWeight: 500 }}>
      {label}
    </div>
    <div
      style={{
        display: "flex",
        alignItems: "baseline",
        gap: 10,
        marginTop: 6,
      }}
    >
      <div
        style={{
          fontSize: 28,
          fontWeight: 600,
          letterSpacing: "-0.02em",
          fontVariantNumeric: "tabular-nums",
          color: "var(--fg)",
        }}
      >
        {value}
      </div>
      {delta && (
        <div
          style={{ fontSize: 12, color: TONE_COLORS[tone], fontWeight: 500 }}
        >
          {delta}
        </div>
      )}
    </div>
    {spark && <div style={{ marginTop: 10 }}>{spark}</div>}
  </div>
);

// ============================================================================
// Spark — inline SVG sparkline with gradient under-fill
// ============================================================================

export interface SparkProps {
  data: number[];
  tone?: "primary" | "critical";
  /** Unique gradient id prefix — required when multiple sparks render on one
   * page so the <defs> gradient ids don't collide. */
  idKey?: string;
}

export const Spark: React.FC<SparkProps> = ({ data, tone = "primary", idKey }) => {
  const { points, color, gradientId } = useMemo(() => {
    const safe = data.length >= 2 ? data : [0, 0];
    const max = Math.max(...safe);
    const min = Math.min(...safe);
    const w = 180;
    const h = 32;
    const pts = safe
      .map(
        (d, i) =>
          `${(i / (safe.length - 1)) * w},${h - ((d - min) / (max - min || 1)) * h}`,
      )
      .join(" ");
    const color = tone === "critical" ? "var(--critical)" : "var(--primary)";
    const gradientId = `spark-${idKey ?? tone}-${Math.random().toString(36).slice(2, 8)}`;
    return { points: pts, color, gradientId };
  }, [data, tone, idKey]);

  const w = 180;
  const h = 32;

  return (
    <svg
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      style={{ width: "100%", display: "block" }}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity=".25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline
        points={`0,${h} ${points} ${w},${h}`}
        fill={`url(#${gradientId})`}
      />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
};

// ============================================================================
// SevBar — stacked horizontal bar showing severity proportions
// ============================================================================

export interface SevBarProps {
  crit?: number;
  high?: number;
  med?: number;
  low?: number;
  info?: number;
}

export const SevBar: React.FC<SevBarProps> = ({
  crit = 0,
  high = 0,
  med = 0,
  low = 0,
  info = 0,
}) => {
  const total = crit + high + med + low + info || 1;
  const pct = (n: number) => `${((n / total) * 100).toFixed(1)}%`;
  return (
    <div className="stat-bar" aria-label="Severity breakdown">
      <span style={{ width: pct(crit), background: "var(--critical)" }} />
      <span style={{ width: pct(high), background: "var(--high)" }} />
      <span style={{ width: pct(med), background: "var(--medium)" }} />
      <span style={{ width: pct(low), background: "var(--low)" }} />
      <span style={{ width: pct(info), background: "var(--info)" }} />
    </div>
  );
};

// ============================================================================
// RiskRing — SVG arc with score in the center
// ============================================================================

export interface RiskRingProps {
  score?: number;
  label?: string;
  size?: number;
}

function ringColor(score: number): string {
  if (score >= 80) return "var(--success)";
  if (score >= 60) return "var(--medium)";
  if (score >= 40) return "var(--high)";
  return "var(--critical)";
}

export const RiskRing: React.FC<RiskRingProps> = ({
  score = 72,
  label = "Posture",
  size = 120,
}) => {
  const r = 48;
  const c = 2 * Math.PI * r;
  const off = c - (score / 100) * c;
  const color = ringColor(score);

  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 120 120"
        style={{ transform: "rotate(-90deg)" }}
        aria-hidden="true"
      >
        <circle
          cx="60"
          cy="60"
          r={r}
          stroke="var(--bg-soft)"
          strokeWidth="10"
          fill="none"
        />
        <circle
          cx="60"
          cy="60"
          r={r}
          stroke={color}
          strokeWidth="10"
          fill="none"
          strokeDasharray={c}
          strokeDashoffset={off}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset .8s var(--ease)" }}
        />
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "grid",
          placeItems: "center",
          textAlign: "center",
        }}
      >
        <div>
          <div
            style={{
              fontSize: 28,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              color: "var(--fg)",
            }}
          >
            {score}
          </div>
          <div
            style={{
              fontSize: 10.5,
              color: "var(--fg-muted)",
              textTransform: "uppercase",
              letterSpacing: ".08em",
            }}
          >
            {label}
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// SectionHead — small header used across cards
// ============================================================================

export const SectionHead: React.FC<{
  title: React.ReactNode;
  right?: React.ReactNode;
  style?: React.CSSProperties;
}> = ({ title, right, style }) => (
  <div className="section-head" style={style}>
    <h3 style={{ margin: 0, color: "var(--fg)" }}>{title}</h3>
    {right}
  </div>
);
