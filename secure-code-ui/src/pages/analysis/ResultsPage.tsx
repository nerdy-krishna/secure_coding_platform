// secure-code-ui/src/pages/analysis/ResultsPage.tsx
//
// SCCAP scan-result view. Port of the design bundle's Results.jsx,
// wired to the real backend via scanService.getScanResult.
//
// Layout:
//   - Breadcrumb + header with project + scan summary
//   - Summary strip (risk score + severity counts + AI-fix count)
//   - Two-column body: findings list (filterable) + detail pane
//
// The detail pane renders description, remediation, compliance chips,
// and (when a fix suggestion exists) a side-by-side diff using the
// design's `.diff` / `.diff-row` utilities. Actions: SARIF download,
// navigate to LLM logs, apply selective fix.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import { isSafeHttpUrl } from "../../shared/lib/safeUrl";
import { isTerminalStatus } from "../../shared/lib/scanRoute";
import { Icon } from "../../shared/ui/Icon";
import { SevBar } from "../../shared/ui/DashboardPrimitives";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";
import type {
  Finding,
  ScanResultResponse,
  SubmittedFile,
  SummaryReport,
} from "../../shared/types/api";

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
  INFORMATIONAL: "var(--info)",
};

function flattenFindings(summary?: SummaryReport): Finding[] {
  if (!summary) return [];
  return summary.files_analyzed.flatMap((f: SubmittedFile) =>
    f.findings.map((finding) => ({ ...finding, file_path: f.file_path })),
  );
}

function severityRank(s: string): number {
  const order: Record<string, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFORMATIONAL: 0,
  };
  return order[s?.toUpperCase()] ?? 0;
}

const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [sevFilter, setSevFilter] = useState<SeverityFilter>("all");
  const [search, setSearch] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [applyingId, setApplyingId] = useState<number | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;

  const { data, isLoading, isError, error } = useQuery<ScanResultResponse>({
    queryKey: ["scan-result", scanId],
    queryFn: () => scanService.getScanResult(scanId!),
    enabled: !!scanId,
  });

  // If the scan isn't terminal yet (queued, running, or awaiting approval)
  // the live progress + approval UI lives on /analysis/scanning/:id. Bounce
  // there so deep-links from search/admin/back-button always end up where
  // the user can act on the scan.
  useEffect(() => {
    if (data?.status && scanId && !isTerminalStatus(data.status)) {
      navigate(`/analysis/scanning/${scanId}`, { replace: true });
    }
  }, [data?.status, scanId, navigate]);

  const applyFix = useMutation({
    mutationFn: (findingId: number) =>
      scanService.applySelectiveFixes(scanId!, [findingId]),
    onSuccess: () => {
      toast.success("Fix applied. Refreshing results…");
      queryClient.invalidateQueries({ queryKey: ["scan-result", scanId] });
    },
    onError: (err: Error) => toast.error(err.message || "Apply failed"),
  });

  const allFindings = useMemo(
    () =>
      flattenFindings(data?.summary_report).sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity),
      ),
    [data],
  );

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 };
    for (const f of allFindings) {
      const s = (f.severity || "").toUpperCase();
      if (s in counts) counts[s as keyof typeof counts] += 1;
    }
    return counts;
  }, [allFindings]);

  const fixesReady = useMemo(
    () => allFindings.filter((f) => !!f.fixes?.code).length,
    [allFindings],
  );

  const filtered = useMemo(
    () =>
      allFindings.filter((f) => {
        if (sevFilter !== "all" && f.severity?.toLowerCase() !== sevFilter)
          return false;
        if (
          search &&
          !(
            f.title.toLowerCase().includes(search.toLowerCase()) ||
            f.file_path.toLowerCase().includes(search.toLowerCase()) ||
            (f.cwe || "").toLowerCase().includes(search.toLowerCase())
          )
        )
          return false;
        return true;
      }),
    [allFindings, sevFilter, search],
  );

  const selected =
    filtered.find((f) => f.id === selectedFindingId) ?? filtered[0] ?? null;

  // Prefer the always-present top-level project pointers (backend
  // populates these from the Scan row even when `summary_report` is
  // null because the scan never reached report-generation — e.g. a
  // CANCELLED scan the user opened from the project page). Fall back
  // to the report's copy for older API payloads served from cache.
  const projectId = data?.project_id ?? data?.summary_report?.project_id;
  const projectName =
    data?.project_name ?? data?.summary_report?.project_name;

  const handleDelete = useCallback(async () => {
    if (!scanId) return;
    setDeleting(true);
    try {
      await scanService.deleteScan(scanId);
      toast.info("Scan deleted.");
      queryClient.invalidateQueries({ queryKey: ["project-scans", projectId] });
      queryClient.invalidateQueries({ queryKey: ["projects"] });
      if (projectId) {
        navigate(`/analysis/projects/${projectId}`, {
          state: projectName ? { projectName } : undefined,
        });
      } else {
        navigate("/analysis/results");
      }
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to delete scan");
    } finally {
      setDeleting(false);
      setDeleteConfirmOpen(false);
    }
  }, [scanId, projectId, projectName, navigate, queryClient, toast]);


  if (isLoading) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 40,
          textAlign: "center",
          color: "var(--fg-muted)",
        }}
      >
        Loading scan results…
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 40,
          textAlign: "center",
          color: "var(--critical)",
        }}
      >
        Failed to load scan: {(error as Error)?.message || "unknown error"}
      </div>
    );
  }

  const report = data.summary_report;
  const riskScore = report?.overall_risk_score?.score;
  const riskLabel = typeof riskScore === "number" ? riskScore : riskScore || "—";

  // Navigate back to the project this scan belongs to. Prefers the
  // top-level pointers (always present), falls back to the summary
  // report (also fine on completed scans). When neither is known
  // (extremely-early failure), bounces to the projects index.
  const goToProject = () => {
    if (projectId) {
      navigate(`/analysis/projects/${projectId}`, {
        state: projectName ? { projectName } : undefined,
      });
    } else {
      navigate("/analysis/results");
    }
  };
  // Display name for the project — prefer the top-level field over the
  // report copy so an in-progress / cancelled scan still shows it.
  const displayProjectName =
    projectName ?? report?.project_name ?? null;

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      {/* header */}
      <div>
        {/* Back button — prominent so users coming from the project page
            see an obvious way home. Falls through to the projects grid
            if the project pointer is somehow missing. */}
        <button
          className="sccap-btn sccap-btn-sm sccap-btn-ghost"
          onClick={goToProject}
          style={{ marginBottom: 10 }}
        >
          <Icon.ChevronL size={12} />{" "}
          {displayProjectName
            ? `Back to ${displayProjectName}`
            : "Back to projects"}
        </button>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            color: "var(--fg-muted)",
            fontSize: 12,
            marginBottom: 8,
          }}
        >
          <button
            className="sccap-btn sccap-btn-sm sccap-btn-ghost"
            onClick={() => navigate("/analysis/results")}
          >
            Projects
          </button>
          <span>/</span>
          {projectId ? (
            <button
              className="sccap-btn sccap-btn-sm sccap-btn-ghost"
              onClick={goToProject}
            >
              {displayProjectName ?? "…"}
            </button>
          ) : (
            <span>{displayProjectName ?? "…"}</span>
          )}
          <span>/</span>
          <span style={{ color: "var(--fg)", fontFamily: "var(--font-mono)" }}>
            {scanId?.slice(0, 8)}
          </span>
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            gap: 20,
          }}
        >
          <div>
            <h1 style={{ color: "var(--fg)" }}>
              {displayProjectName ?? "Scan"}{" "}
              <span
                style={{
                  color: "var(--fg-subtle)",
                  fontWeight: 400,
                  fontSize: 20,
                }}
              >
                / {report?.scan_type ?? data.status}
              </span>
            </h1>
            <div
              style={{
                color: "var(--fg-muted)",
                marginTop: 4,
                fontSize: 13,
                display: "flex",
                alignItems: "center",
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              {data.status === "CANCELLED" || data.status === "EXPIRED" ? (
                <span className="chip">{data.status.toLowerCase()}</span>
              ) : data.status === "FAILED" ||
                data.status === "BLOCKED_PRE_LLM" ||
                data.status === "BLOCKED_USER_DECLINE" ? (
                <span className="chip chip-critical">
                  {data.status.toLowerCase().replace(/_/g, " ")}
                </span>
              ) : null}
              <span>
                {allFindings.length} finding
                {allFindings.length === 1 ? "" : "s"}
              </span>
              {fixesReady > 0 && (
                <span className="chip chip-ai">
                  <Icon.Sparkle size={10} /> {fixesReady} AI fix
                  {fixesReady === 1 ? "" : "es"} ready
                </span>
              )}
              {report?.selected_frameworks?.length ? (
                <span style={{ color: "var(--fg-subtle)" }}>
                  · {report.selected_frameworks.join(", ")}
                </span>
              ) : null}
            </div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => navigate(`/analysis/scanning/${scanId}`)}
              title="View the scan event timeline"
            >
              <Icon.Clock size={13} /> Timeline
            </button>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => navigate(`/scans/${scanId}/llm-logs`)}
            >
              <Icon.Terminal size={13} /> LLM logs
            </button>
            {isSuperuser && (
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setDeleteConfirmOpen(true)}
                disabled={deleting}
                style={{ color: "var(--critical)" }}
              >
                <Icon.Alert size={13} /> {deleting ? "Deleting…" : "Delete"}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* summary strip */}
      <div
        className="surface"
        style={{
          padding: 16,
          display: "grid",
          gridTemplateColumns: "1.5fr repeat(5, 1fr)",
          gap: 16,
          alignItems: "center",
        }}
      >
        <div>
          <div
            style={{
              fontSize: 11,
              color: "var(--fg-muted)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
            }}
          >
            Risk score
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              gap: 10,
              marginTop: 4,
            }}
          >
            <div
              style={{
                fontSize: 28,
                fontWeight: 600,
                color:
                  typeof riskScore === "number"
                    ? riskScore >= 7
                      ? "var(--critical)"
                      : riskScore >= 4
                        ? "var(--high)"
                        : "var(--medium)"
                    : "var(--fg)",
                letterSpacing: "-0.02em",
              }}
            >
              {riskLabel}
            </div>
          </div>
          <div style={{ marginTop: 6 }}>
            <SevBar
              crit={severityCounts.CRITICAL}
              high={severityCounts.HIGH}
              med={severityCounts.MEDIUM}
              low={severityCounts.LOW}
              info={severityCounts.INFORMATIONAL}
            />
          </div>
        </div>
        {[
          { k: "Critical", v: severityCounts.CRITICAL, c: "var(--critical)" },
          { k: "High", v: severityCounts.HIGH, c: "var(--high)" },
          { k: "Medium", v: severityCounts.MEDIUM, c: "var(--medium)" },
          { k: "Low", v: severityCounts.LOW, c: "var(--low)" },
          { k: "AI fixes", v: fixesReady, c: "var(--primary)" },
        ].map((m) => (
          <div key={m.k}>
            <div
              style={{
                fontSize: 11,
                color: "var(--fg-muted)",
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              {m.k}
            </div>
            <div
              style={{
                fontSize: 28,
                fontWeight: 600,
                color: m.c,
                letterSpacing: "-0.02em",
              }}
            >
              {m.v}
            </div>
          </div>
        ))}
      </div>

      {/* Per-source counter row (sast-prescan-followups Group D2). */}
      {data.source_counts && Object.keys(data.source_counts).length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 8,
            marginTop: 8,
            marginBottom: 8,
            alignItems: "center",
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: "var(--fg-muted)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
            }}
          >
            By source:
          </span>
          {Object.entries(data.source_counts).map(([source, count]) => {
            const colorMap: Record<string, string> = {
              bandit: "#3b82f6",
              semgrep: "#a855f7",
              gitleaks: "#dc2626",
              agent: "#6b7280",
            };
            return (
              <span
                key={source}
                style={{
                  padding: "4px 10px",
                  borderRadius: 12,
                  background: colorMap[source] || "#6b7280",
                  color: "white",
                  fontSize: 12,
                  fontWeight: 600,
                }}
              >
                {source}: {count}
              </span>
            );
          })}
        </div>
      )}

      {/* body */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "380px 1fr",
          gap: 16,
          minHeight: 640,
        }}
      >
        {/* findings list */}
        <div
          className="surface"
          style={{
            padding: 0,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: 12,
              borderBottom: "1px solid var(--border)",
              display: "grid",
              gap: 8,
            }}
          >
            <div className="input-with-icon">
              <Icon.Search size={14} />
              <input
                className="sccap-input"
                placeholder="Filter findings…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ paddingLeft: 32, height: 32 }}
              />
            </div>
            <div className="radio-group" style={{ width: "100%" }}>
              {(
                ["all", "critical", "high", "medium", "low"] as SeverityFilter[]
              ).map((s) => (
                <button
                  key={s}
                  className={sevFilter === s ? "active" : ""}
                  onClick={() => setSevFilter(s)}
                  style={{ flex: 1, textTransform: "capitalize" }}
                >
                  {s}
                  {s !== "all" && (
                    <span style={{ color: "var(--fg-subtle)", marginLeft: 4 }}>
                      ·
                      {
                        allFindings.filter(
                          (f) => f.severity?.toLowerCase() === s,
                        ).length
                      }
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>
          <div style={{ flex: 1, overflow: "auto" }}>
            {filtered.length === 0 ? (
              <div
                style={{
                  padding: 40,
                  textAlign: "center",
                  color: "var(--fg-muted)",
                }}
              >
                No findings match this filter.
              </div>
            ) : (
              filtered.map((f) => {
                const sev = (f.severity || "").toUpperCase();
                const color = SEV_COLOR[sev] ?? "var(--fg-muted)";
                const isSel = selected?.id === f.id;
                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    style={{
                      padding: "12px 14px",
                      cursor: "pointer",
                      borderLeft: `3px solid ${isSel ? color : "transparent"}`,
                      background: isSel ? "var(--bg-soft)" : "transparent",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        marginBottom: 4,
                      }}
                    >
                      <span
                        style={{
                          width: 6,
                          height: 6,
                          borderRadius: 99,
                          background: color,
                        }}
                      />
                      <span
                        style={{
                          fontSize: 10.5,
                          textTransform: "uppercase",
                          color,
                          fontWeight: 600,
                          letterSpacing: ".04em",
                        }}
                      >
                        {sev}
                      </span>
                      <span
                        style={{
                          fontSize: 10.5,
                          color: "var(--fg-subtle)",
                          marginLeft: "auto",
                        }}
                        className="mono"
                      >
                        {f.cwe}
                      </span>
                    </div>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 500,
                        lineHeight: 1.35,
                        marginBottom: 6,
                        color: "var(--fg)",
                      }}
                    >
                      {f.title}
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        color: "var(--fg-muted)",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          fontSize: 11,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          maxWidth: 200,
                        }}
                      >
                        {f.file_path}:{f.line_number}
                      </span>
                      {f.fixes?.code && (
                        <span
                          className="chip chip-ai"
                          style={{ fontSize: 10, padding: "1px 7px" }}
                        >
                          <Icon.Sparkle size={9} /> fix
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* detail */}
        {selected ? (
          <FindingDetail
            f={selected}
            applying={applyingId === selected.id && applyFix.isPending}
            onApply={() => {
              setApplyingId(selected.id);
              applyFix.mutate(selected.id);
            }}
          />
        ) : (
          <div
            className="surface"
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
              alignSelf: "start",
            }}
          >
            {allFindings.length === 0
              ? "No findings in this scan."
              : "Select a finding on the left."}
          </div>
        )}
      </div>

      <Modal
        open={deleteConfirmOpen}
        onClose={() => (deleting ? undefined : setDeleteConfirmOpen(false))}
        title="Delete this scan permanently?"
        footer={
          <>
            <button
              className="sccap-btn"
              onClick={() => setDeleteConfirmOpen(false)}
              disabled={deleting}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={handleDelete}
              disabled={deleting}
              style={{ background: "var(--critical)" }}
            >
              {deleting ? "Deleting…" : "Delete scan"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          This removes the scan, its findings, and event log from the
          database. The action cannot be undone.
        </div>
      </Modal>
    </div>
  );
};

// ============================================================================
// Detail pane
// ============================================================================

const FindingDetail: React.FC<{
  f: Finding;
  applying: boolean;
  onApply: () => void;
}> = ({ f, applying, onApply }) => {
  const sev = (f.severity || "").toUpperCase();
  const sevColor = SEV_COLOR[sev] ?? "var(--fg-muted)";
  const hasFix = !!f.fixes?.code;
  const beforeLines = (f.fixes?.original_snippet || "").split("\n");
  const afterLines = (f.fixes?.code || "").split("\n");
  const alreadyApplied = f.is_applied_in_remediation;

  return (
    <div
      className="surface"
      style={{ padding: 24, overflow: "auto", alignSelf: "start" }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 16,
          marginBottom: 12,
        }}
      >
        <div style={{ flex: 1 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 8,
              flexWrap: "wrap",
            }}
          >
            <span className={"chip chip-" + sev.toLowerCase()}>
              <Icon.Alert size={10} /> {sev}
            </span>
            {f.cwe && (
              <span className="chip mono" style={{ fontSize: 10.5 }}>
                {f.cwe}
              </span>
            )}
            {typeof f.cvss_score === "number" && (
              <span
                className="chip"
                style={{
                  background: sevColor + "22",
                  color: sevColor,
                  border: "none",
                }}
              >
                CVSS {f.cvss_score.toFixed(1)}
              </span>
            )}
            {f.confidence && (
              <span className="chip" style={{ fontSize: 10.5 }}>
                {f.confidence} confidence
              </span>
            )}
          </div>
          <h2 style={{ marginBottom: 8, color: "var(--fg)" }}>{f.title}</h2>
          <div style={{ fontSize: 12.5, color: "var(--fg-muted)" }}>
            <span className="mono">{f.file_path}</span> · line{" "}
            <span className="mono">{f.line_number}</span>
            {f.corroborating_agents && f.corroborating_agents.length > 0 && (
              <>
                <span style={{ margin: "0 8px" }}>·</span>
                Corroborated by{" "}
                {f.corroborating_agents.map((a, i) => (
                  <span
                    key={i}
                    className="chip"
                    style={{
                      fontSize: 10,
                      padding: "1px 7px",
                      marginLeft: 4,
                    }}
                  >
                    {a}
                  </span>
                ))}
              </>
            )}
          </div>
        </div>
      </div>

      <div className="sccap-divider" />

      <div style={{ display: "grid", gap: 18 }}>
        {f.description && (
          <div>
            <h4
              style={{
                marginBottom: 6,
                color: "var(--fg-muted)",
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              Description
            </h4>
            <div
              style={{
                fontSize: 13.5,
                lineHeight: 1.6,
                color: "var(--fg)",
                whiteSpace: "pre-wrap",
              }}
            >
              {f.description}
            </div>
          </div>
        )}

        {f.remediation && (
          <div>
            <h4
              style={{
                marginBottom: 6,
                color: "var(--fg-muted)",
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              Remediation
            </h4>
            <div
              style={{
                fontSize: 13.5,
                lineHeight: 1.6,
                color: "var(--fg)",
                whiteSpace: "pre-wrap",
              }}
            >
              {f.remediation}
            </div>
          </div>
        )}

        {hasFix && (
          <div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 10,
                flexWrap: "wrap",
                gap: 8,
              }}
            >
              <h4
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  color: "var(--fg)",
                  margin: 0,
                }}
              >
                <div
                  style={{
                    width: 20,
                    height: 20,
                    borderRadius: 5,
                    background: "var(--primary)",
                    color: "var(--primary-ink)",
                    display: "grid",
                    placeItems: "center",
                  }}
                >
                  <Icon.Sparkle size={11} />
                </div>
                AI-suggested fix
              </h4>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  className="sccap-btn sccap-btn-sm sccap-btn-primary"
                  onClick={onApply}
                  disabled={applying || alreadyApplied}
                >
                  {alreadyApplied ? (
                    <>
                      <Icon.Check size={12} /> Applied
                    </>
                  ) : applying ? (
                    "Applying…"
                  ) : (
                    <>
                      <Icon.Zap size={12} /> Apply fix
                    </>
                  )}
                </button>
              </div>
            </div>

            {f.fixes?.description && (
              <div
                style={{
                  background: "var(--primary-weak)",
                  borderRadius: 8,
                  padding: "10px 12px",
                  marginBottom: 10,
                  fontSize: 12.5,
                  color: "var(--fg)",
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                }}
              >
                <Icon.Sparkle size={14} color="var(--primary)" />
                <div>
                  <b>Why this fix:</b> {f.fixes.description}
                </div>
              </div>
            )}

            <div className="diff">
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  background: "var(--bg-soft)",
                  fontSize: 11,
                  color: "var(--fg-muted)",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                <div
                  style={{
                    padding: "8px 14px",
                    borderRight: "1px solid var(--border)",
                  }}
                >
                  <span className="mono" style={{ color: "var(--critical)" }}>
                    −
                  </span>{" "}
                  before · {f.file_path}
                </div>
                <div style={{ padding: "8px 14px" }}>
                  <span className="mono" style={{ color: "var(--success)" }}>
                    +
                  </span>{" "}
                  after · {f.file_path}
                </div>
              </div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  borderTop: "1px solid var(--border)",
                }}
              >
                <div style={{ borderRight: "1px solid var(--border)" }}>
                  {beforeLines.map((l, i) => (
                    <div
                      key={i}
                      className="diff-row del"
                      style={{ gridTemplateColumns: "40px 1fr" }}
                    >
                      <span>{(f.line_number ?? 1) + i}</span>
                      <span>{l}</span>
                    </div>
                  ))}
                </div>
                <div>
                  {afterLines.map((l, i) => (
                    <div
                      key={i}
                      className="diff-row add"
                      style={{ gridTemplateColumns: "40px 1fr" }}
                    >
                      <span>{(f.line_number ?? 1) + i}</span>
                      <span>{l}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {f.references && f.references.length > 0 && (
          <div>
            <h4
              style={{
                marginBottom: 8,
                color: "var(--fg-muted)",
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              References
            </h4>
            <div style={{ display: "grid", gap: 4 }}>
              {f.references.map((r, i) =>
                isSafeHttpUrl(r) ? (
                  <a
                    key={i}
                    href={r}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: "var(--primary)",
                      fontSize: 12.5,
                      wordBreak: "break-all",
                    }}
                  >
                    <Icon.Link size={11} /> {r}
                  </a>
                ) : (
                  // Reference came in with a non-http(s) scheme (e.g.
                  // `javascript:` from a tampered upstream advisory) —
                  // render as plain text instead of a clickable link.
                  <span
                    key={i}
                    title="Unsafe URL scheme — rendered as plain text"
                    style={{
                      color: "var(--fg-muted)",
                      fontSize: 12.5,
                      wordBreak: "break-all",
                    }}
                  >
                    <Icon.Link size={11} /> {r}
                  </span>
                ),
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ResultsPage;
