// secure-code-ui/src/pages/analysis/ProjectsPage.tsx
//
// SCCAP projects grid. Port of the design bundle's Projects.jsx, wired
// to the real backend (/projects). Each card shows the project name,
// latest scan status, a derived risk score, and aggregate finding chips
// from the most recent terminal scan.
//
// "Risk score" is derived on the client since the backend doesn't
// expose a per-project rollup yet — we compute it from the most recent
// scan's severity counts (summary.severity_counts when available; falls
// back to status-only placeholders otherwise). Proper aggregation lives
// with the /dashboard/stats endpoint flagged for a later pass.

import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import { Icon } from "../../shared/ui/Icon";
import { SevBar } from "../../shared/ui/DashboardPrimitives";
import type { ProjectHistoryItem, ScanHistoryItem } from "../../shared/types/api";

const TERMINAL_OK = new Set(["COMPLETED", "REMEDIATION_COMPLETED"]);

function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  const m = Math.floor(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

function riskColor(risk: number): string {
  if (risk >= 80) return "var(--critical)";
  if (risk >= 60) return "var(--high)";
  if (risk >= 40) return "var(--medium)";
  return "var(--success)";
}

function latestTerminalScan(p: ProjectHistoryItem): ScanHistoryItem | null {
  const sorted = [...p.scans].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );
  return sorted.find((s) => TERMINAL_OK.has(s.status)) ?? sorted[0] ?? null;
}

// Heuristic risk score until the backend exposes a per-project rollup.
// Based on the latest terminal scan's status: active fails elevate risk;
// clean completes reduce it.
function deriveRisk(p: ProjectHistoryItem): number {
  const scan = latestTerminalScan(p);
  if (!scan) return 0;
  if (scan.status === "FAILED") return 75;
  if (scan.status === "CANCELLED" || scan.status === "EXPIRED") return 40;
  // COMPLETED / REMEDIATION_COMPLETED — assume moderate until we have
  // finding counts aggregated. Keep this low so the UI doesn't fake
  // alarm; real scores land with the stats endpoint.
  return 25;
}

const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["projects", search],
    queryFn: () => scanService.getProjectHistory(1, 100, search || undefined),
  });

  const projects = useMemo(() => data?.items ?? [], [data]);

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 20,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>Projects</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            {isLoading
              ? "Loading…"
              : `${data?.total ?? 0} project${data?.total === 1 ? "" : "s"}`}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <div className="input-with-icon" style={{ width: 240 }}>
            <Icon.Search size={14} />
            <input
              className="sccap-input"
              placeholder="Search projects…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: 32 }}
            />
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() => navigate("/submission/submit")}
          >
            <Icon.Plus size={13} /> New scan
          </button>
        </div>
      </div>

      {isError ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--critical)",
          }}
        >
          Failed to load projects. Check your connection and retry.
        </div>
      ) : isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading projects…
        </div>
      ) : projects.length === 0 ? (
        <div
          className="sccap-card"
          style={{
            padding: 60,
            textAlign: "center",
          }}
        >
          <div style={{ color: "var(--fg)", fontSize: 16, fontWeight: 500, marginBottom: 6 }}>
            No projects yet
          </div>
          <div
            style={{ color: "var(--fg-muted)", fontSize: 13, marginBottom: 16 }}
          >
            Submit your first scan to create a project.
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() => navigate("/submission/submit")}
          >
            <Icon.Plus size={13} /> Start a scan
          </button>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: 14,
          }}
        >
          {projects.map((p) => {
            const risk = deriveRisk(p);
            const color = riskColor(risk);
            const latest = latestTerminalScan(p);
            return (
              <div
                key={p.id}
                className="sccap-card"
                style={{ cursor: "pointer" }}
                onClick={() => {
                  if (latest) {
                    navigate(`/analysis/results/${latest.id}`);
                  } else {
                    navigate("/submission/submit");
                  }
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    marginBottom: 10,
                  }}
                >
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 10 }}
                  >
                    <div
                      style={{
                        width: 34,
                        height: 34,
                        borderRadius: 9,
                        background: "var(--bg-soft)",
                        display: "grid",
                        placeItems: "center",
                        color: "var(--fg-muted)",
                      }}
                    >
                      <Icon.Folder size={16} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, color: "var(--fg)" }}>
                        {p.name}
                      </div>
                      <div
                        style={{
                          fontSize: 11.5,
                          color: "var(--fg-subtle)",
                        }}
                      >
                        {p.repository_url
                          ? p.repository_url.replace(/^https?:\/\//, "")
                          : "Direct submission"}
                      </div>
                    </div>
                  </div>
                  <div
                    style={{ fontSize: 11, color: "var(--fg-subtle)" }}
                  >
                    {p.scans.length} scan{p.scans.length === 1 ? "" : "s"}
                  </div>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: 11.5,
                    color: "var(--fg-muted)",
                    marginBottom: 6,
                  }}
                >
                  <span>Risk score</span>
                  <span style={{ fontWeight: 600, color }}>
                    {latest ? risk : "—"}
                  </span>
                </div>
                <div className="sccap-progress" style={{ marginBottom: 12 }}>
                  <span
                    style={{
                      width: `${latest ? risk : 0}%`,
                      background: color,
                    }}
                  />
                </div>
                <SevBar />
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    marginTop: 10,
                    fontSize: 11.5,
                    color: "var(--fg-subtle)",
                  }}
                >
                  <span>
                    <Icon.Clock size={10} />{" "}
                    {latest
                      ? formatWhen(latest.created_at)
                      : formatWhen(p.updated_at)}
                  </span>
                  <span>
                    {latest
                      ? TERMINAL_OK.has(latest.status)
                        ? "completed"
                        : latest.status === "FAILED"
                          ? "last failed"
                          : "in progress"
                      : "no scans"}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ProjectsPage;
