// secure-code-ui/src/features/dashboard/components/DevDashboard.tsx
//
// Individual-developer dashboard. Ported from the SCCAP bundle's
// DevDashboard variant and wired to real scan data where the current
// backend exposes it:
//   - Recent scans table: fetches the first page of /scans/history.
//   - Top metrics: derived from the same fetch (total, in-progress,
//     completed-this-week, failed-today). Finding-aggregate metrics
//     (open findings, critical count, AI-fixes-ready, auto-fix success)
//     are placeholder — they need a dashboard/stats backend endpoint
//     to populate efficiently, deferred to a future pass.
//   - Severity breakdown + "AI insight" card: static for now; will
//     switch to real aggregate data once the backend endpoint lands.

import React, { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { scanService } from "../../../shared/api/scanService";
import { useAuth } from "../../../shared/hooks/useAuth";
import { Icon } from "../../../shared/ui/Icon";
import {
  MetricCard,
  RiskRing,
  SectionHead,
  Spark,
} from "../../../shared/ui/DashboardPrimitives";
import type { ScanHistoryItem } from "../../../shared/types/api";

const TERMINAL_STATUSES = new Set([
  "COMPLETED",
  "REMEDIATION_COMPLETED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
]);

const IN_PROGRESS_STATUSES = new Set([
  "QUEUED",
  "QUEUED_FOR_SCAN",
  "ANALYZING_CONTEXT",
  "RUNNING_AGENTS",
  "GENERATING_REPORTS",
  "PENDING_COST_APPROVAL",
]);

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const diffMs = Date.now() - then;
  if (diffMs < 60_000) return "just now";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days === 1) return "yesterday";
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function statusChip(status: string): React.ReactNode {
  if (status === "COMPLETED" || status === "REMEDIATION_COMPLETED") {
    return (
      <span className="chip chip-success">
        <Icon.Check size={10} /> completed
      </span>
    );
  }
  if (status === "FAILED") {
    return <span className="chip chip-critical">failed</span>;
  }
  if (status === "CANCELLED" || status === "EXPIRED") {
    return <span className="chip">cancelled</span>;
  }
  if (status === "PENDING_COST_APPROVAL") {
    return (
      <span className="chip chip-info">
        <Icon.Clock size={10} /> awaiting approval
      </span>
    );
  }
  return (
    <span className="chip chip-info">
      <span
        className="pulse-dot dot"
        style={{ background: "currentColor" }}
      />{" "}
      {status.toLowerCase().replace(/_/g, " ")}
    </span>
  );
}

export const DevDashboard: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();

  const { data, isLoading } = useQuery({
    queryKey: ["dashboard", "recent-scans"],
    queryFn: () => scanService.getScanHistory(1, 50, undefined, "desc"),
  });

  const scans: ScanHistoryItem[] = useMemo(
    () => data?.items ?? [],
    [data],
  );

  const metrics = useMemo(() => {
    const now = Date.now();
    const weekAgo = now - 7 * 24 * 60 * 60 * 1000;
    const dayAgo = now - 24 * 60 * 60 * 1000;

    let inProgress = 0;
    let completedThisWeek = 0;
    let failedToday = 0;
    const buckets: number[] = Array(10).fill(0); // last 10 days, for the spark

    for (const s of scans) {
      if (IN_PROGRESS_STATUSES.has(s.status)) inProgress += 1;

      const createdAt = new Date(s.created_at).getTime();
      const daysAgo = Math.floor((now - createdAt) / (24 * 60 * 60 * 1000));
      if (daysAgo >= 0 && daysAgo < 10) {
        buckets[9 - daysAgo] += 1;
      }

      if (
        (s.status === "COMPLETED" || s.status === "REMEDIATION_COMPLETED") &&
        createdAt >= weekAgo
      ) {
        completedThisWeek += 1;
      }
      if (s.status === "FAILED" && createdAt >= dayAgo) {
        failedToday += 1;
      }
    }

    return {
      total: data?.total ?? 0,
      inProgress,
      completedThisWeek,
      failedToday,
      scansPerDay: buckets,
    };
  }, [scans, data?.total]);

  const recent = scans.slice(0, 5);

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      {/* hero */}
      <div
        className="sccap-card"
        style={{
          background: "linear-gradient(135deg, var(--bg-elev), var(--bg-soft))",
          padding: 28,
          display: "grid",
          gridTemplateColumns: "1fr auto",
          alignItems: "center",
          gap: 20,
        }}
      >
        <div>
          <div className="chip chip-ai" style={{ marginBottom: 10 }}>
            <Icon.Sparkle size={11} /> Welcome back{user?.email ? `, ${user.email.split("@")[0]}` : ""}
          </div>
          <h1 style={{ marginBottom: 6 }}>
            {metrics.inProgress > 0
              ? `${metrics.inProgress} scan${metrics.inProgress === 1 ? "" : "s"} in progress.`
              : metrics.total === 0
                ? "No scans yet — start your first one."
                : "All caught up — no scans in progress."}
          </h1>
          <div style={{ color: "var(--fg-muted)", fontSize: 14 }}>
            {metrics.completedThisWeek} completed this week
            {metrics.failedToday > 0 && (
              <>
                {" "}
                · <b style={{ color: "var(--critical)" }}>{metrics.failedToday} failed</b> today
              </>
            )}
            .
          </div>
          <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={() => navigate("/submission/submit")}
            >
              <Icon.Upload size={14} /> New scan
            </button>
            <button
              className="sccap-btn"
              onClick={() => navigate("/analysis/results")}
            >
              <Icon.Folder size={14} /> View projects
            </button>
          </div>
        </div>
        <div style={{ display: "grid", placeItems: "center" }}>
          {/* Risk score is placeholder until the dashboard/stats endpoint lands.
              Show "—" instead of a real number to avoid implying a fake value. */}
          <RiskRing score={0} label="Posture" />
        </div>
      </div>

      {/* metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: 16,
        }}
      >
        <MetricCard
          label="Total scans"
          value={metrics.total}
          delta={isLoading ? "loading…" : `${scans.length} recent`}
          spark={<Spark data={metrics.scansPerDay} idKey="total" />}
        />
        <MetricCard
          label="In progress"
          value={metrics.inProgress}
          delta={metrics.inProgress > 0 ? "active now" : "idle"}
          tone={metrics.inProgress > 0 ? "warn" : "default"}
        />
        <MetricCard
          label="Completed / week"
          value={metrics.completedThisWeek}
          tone="good"
        />
        <MetricCard
          label="Failed / day"
          value={metrics.failedToday}
          tone={metrics.failedToday > 0 ? "bad" : "good"}
        />
      </div>

      {/* two-col */}
      <div
        style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}
      >
        {/* recent scans */}
        <div className="sccap-card" style={{ padding: 0, overflow: "hidden" }}>
          <SectionHead
            title={
              <>
                <Icon.Folder size={16} /> Recent scans
              </>
            }
            right={
              <Link
                to="/analysis/results"
                className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                style={{ textDecoration: "none" }}
              >
                View all <Icon.ChevronR size={12} />
              </Link>
            }
            style={{ padding: "18px 20px 10px", margin: 0 }}
          />
          {isLoading ? (
            <div
              style={{
                padding: 40,
                textAlign: "center",
                color: "var(--fg-muted)",
              }}
            >
              Loading scans…
            </div>
          ) : recent.length === 0 ? (
            <div
              style={{
                padding: 40,
                textAlign: "center",
                color: "var(--fg-muted)",
              }}
            >
              No scans yet.{" "}
              <Link
                to="/submission/submit"
                style={{ color: "var(--primary)" }}
              >
                Submit one
              </Link>{" "}
              to get started.
            </div>
          ) : (
            <table className="sccap-t">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>When</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {recent.map((s) => {
                  const clickable = TERMINAL_STATUSES.has(s.status);
                  return (
                    <tr
                      key={s.id}
                      onClick={() =>
                        clickable && navigate(`/analysis/results/${s.id}`)
                      }
                      style={{ cursor: clickable ? "pointer" : "default" }}
                    >
                      <td>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 10,
                          }}
                        >
                          <div
                            style={{
                              width: 28,
                              height: 28,
                              borderRadius: 6,
                              background: "var(--bg-soft)",
                              display: "grid",
                              placeItems: "center",
                              color: "var(--fg-muted)",
                            }}
                          >
                            <Icon.Folder size={14} />
                          </div>
                          <div>
                            <div
                              style={{ fontWeight: 500, color: "var(--fg)" }}
                            >
                              {s.project_name}
                            </div>
                            <div
                              style={{
                                fontSize: 11.5,
                                color: "var(--fg-subtle)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              {s.id.slice(0, 8)}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td
                        style={{
                          color: "var(--fg-muted)",
                          fontSize: 12.5,
                        }}
                      >
                        {s.scan_type}
                      </td>
                      <td>{statusChip(s.status)}</td>
                      <td
                        style={{
                          color: "var(--fg-muted)",
                          fontSize: 12.5,
                        }}
                      >
                        {relativeTime(s.created_at)}
                      </td>
                      <td
                        style={{
                          textAlign: "right",
                          color: "var(--fg-subtle)",
                        }}
                      >
                        {clickable && <Icon.ChevronR size={14} />}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* right col */}
        <div style={{ display: "grid", gap: 16 }}>
          <div className="sccap-card">
            <SectionHead
              title={
                <>
                  <Icon.Layers size={16} /> Findings by severity
                </>
              }
            />
            <div
              style={{
                padding: 24,
                textAlign: "center",
                color: "var(--fg-muted)",
                fontSize: 13,
              }}
            >
              Severity breakdown coming soon.
              <div
                style={{
                  fontSize: 11,
                  marginTop: 6,
                  color: "var(--fg-subtle)",
                }}
              >
                Needs a dashboard aggregate endpoint; open individual scans
                to see per-project findings.
              </div>
            </div>
          </div>

          <div
            className="sccap-card"
            style={{
              background: "var(--primary-weak)",
              borderColor: "transparent",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 8,
              }}
            >
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: "var(--primary)",
                  color: "var(--primary-ink)",
                  display: "grid",
                  placeItems: "center",
                }}
              >
                <Icon.Sparkle size={16} />
              </div>
              <div
                style={{ fontWeight: 600, color: "var(--primary-strong)" }}
              >
                Advisor
              </div>
            </div>
            <div
              style={{
                fontSize: 13.5,
                color: "var(--fg)",
                lineHeight: 1.55,
              }}
            >
              Ask the SCCAP advisor about any finding, get AI-suggested
              remediation bundles, or request a walkthrough of a scan.
            </div>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              style={{ marginTop: 12 }}
              onClick={() => navigate("/advisor")}
            >
              Open advisor <Icon.ArrowR size={12} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DevDashboard;
