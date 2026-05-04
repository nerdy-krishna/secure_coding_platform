// secure-code-ui/src/pages/analysis/ProjectDetailPage.tsx
//
// Per-project scan list. Reached from the Projects grid (clicking a card
// no longer jumps straight to the latest scan; users now land here and
// pick the scan they want). Each row routes via scanRouteFor so an
// in-progress / pending-approval scan opens on ScanRunningPage and a
// terminal scan opens on ResultsPage.

import { useQuery } from "@tanstack/react-query";
import React, { useMemo } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import { scanRouteFor } from "../../shared/lib/scanRoute";
import type { ScanHistoryItem } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";

interface NavState {
  projectName?: string;
  repoUrl?: string | null;
}

function relativeTime(iso: string | null | undefined): string {
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
  if (
    status === "CANCELLED" ||
    status === "EXPIRED" ||
    status === "BLOCKED_USER_DECLINE"
  ) {
    return <span className="chip">{status.toLowerCase().replace(/_/g, " ")}</span>;
  }
  if (status === "BLOCKED_PRE_LLM") {
    return <span className="chip chip-critical">blocked pre llm</span>;
  }
  if (status === "PENDING_COST_APPROVAL") {
    return (
      <span className="chip chip-info">
        <Icon.Clock size={10} /> awaiting approval
      </span>
    );
  }
  if (status === "PENDING_PRESCAN_APPROVAL") {
    return (
      <span className="chip chip-info">
        <Icon.Clock size={10} /> prescan review
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

const ProjectDetailPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const navState = (location.state ?? {}) as NavState;

  const { data, isLoading, isError } = useQuery({
    queryKey: ["project-scans", projectId],
    queryFn: () => scanService.getScansForProject(projectId!, 1, 100),
    enabled: !!projectId,
  });

  const scans = useMemo<ScanHistoryItem[]>(
    () =>
      [...(data?.items ?? [])].sort(
        (a, b) =>
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [data],
  );

  // Project name fallback chain: state from the previous page → first
  // scan's project_name → "Project". Repo URL similarly.
  const projectName =
    navState.projectName ?? scans[0]?.project_name ?? "Project";
  const repoUrl = navState.repoUrl ?? null;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <button
          className="sccap-btn sccap-btn-sm sccap-btn-ghost"
          onClick={() => navigate("/analysis/results")}
          style={{ marginBottom: 10 }}
        >
          <Icon.ChevronL size={12} /> Projects
        </button>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            gap: 20,
          }}
        >
          <div>
            <h1 style={{ color: "var(--fg)" }}>{projectName}</h1>
            <div
              style={{
                color: "var(--fg-muted)",
                marginTop: 4,
                fontSize: 13,
                display: "flex",
                gap: 10,
                alignItems: "center",
                flexWrap: "wrap",
              }}
            >
              <span>
                {data?.total ?? scans.length} scan
                {(data?.total ?? scans.length) === 1 ? "" : "s"}
              </span>
              {repoUrl && (
                <span style={{ color: "var(--fg-subtle)" }}>
                  · {repoUrl.replace(/^https?:\/\//, "")}
                </span>
              )}
            </div>
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() =>
              navigate("/submission/submit", {
                state: {
                  projectId,
                  projectName,
                  repoUrl,
                },
              })
            }
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
          Failed to load scans for this project.
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
          Loading scans…
        </div>
      ) : scans.length === 0 ? (
        <div
          className="sccap-card"
          style={{
            padding: 60,
            textAlign: "center",
          }}
        >
          <div
            style={{
              color: "var(--fg)",
              fontSize: 16,
              fontWeight: 500,
              marginBottom: 6,
            }}
          >
            No scans yet for this project
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            style={{ marginTop: 12 }}
            onClick={() =>
              navigate("/submission/submit", {
                state: {
                  projectId,
                  projectName,
                  repoUrl,
                },
              })
            }
          >
            <Icon.Plus size={13} /> Start a scan
          </button>
        </div>
      ) : (
        <div className="sccap-card" style={{ padding: 0, overflow: "hidden" }}>
          <table className="sccap-t">
            <thead>
              <tr>
                <th>Scan</th>
                <th>Type</th>
                <th>Status</th>
                <th>When</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr
                  key={s.id}
                  onClick={() => navigate(scanRouteFor(s.id, s.status))}
                  style={{ cursor: "pointer" }}
                >
                  <td>
                    <div
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 12.5,
                        color: "var(--fg)",
                      }}
                    >
                      {s.id.slice(0, 8)}
                    </div>
                  </td>
                  <td style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
                    {s.scan_type}
                  </td>
                  <td>{statusChip(s.status)}</td>
                  <td style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
                    {relativeTime(s.created_at)}
                  </td>
                  <td
                    style={{
                      textAlign: "right",
                      color: "var(--fg-subtle)",
                    }}
                  >
                    <Icon.ChevronR size={14} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ProjectDetailPage;
