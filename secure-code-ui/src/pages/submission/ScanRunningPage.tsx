// secure-code-ui/src/pages/submission/ScanRunningPage.tsx
//
// Port of the SCCAP design bundle's ScanRunning screen, wired to the
// real backend via the SSE endpoint added in F.5.3c:
//   GET /api/v1/scans/{scan_id}/stream
// Emits three event types: scan_state (status transitions), scan_event
// (new ScanEvent rows), done (terminal status reached). We render each
// scan_event as a pipeline stage and advance the progress bar against a
// fixed stage list that mirrors the worker graph.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { message as antdMessage } from "antd";
import { scanService } from "../../shared/api/scanService";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";

interface ScanEventMsg {
  scan_id: string;
  event_id: number;
  stage_name: string;
  status: string; // "COMPLETED" / "STARTED" / "FAILED" for the event itself
  timestamp: string | null;
}

interface ScanStateMsg {
  scan_id: string;
  status: string;
}

// Known pipeline stages, in order. The backend emits stage_name values
// matching these keys; unknown stage names are appended live.
interface Stage {
  key: string;
  label: string;
  icon: React.ReactNode;
}

const KNOWN_STAGES: Stage[] = [
  { key: "QUEUED", label: "Queued", icon: <Icon.Clock size={14} /> },
  { key: "ANALYZING_CONTEXT", label: "Analyzing context", icon: <Icon.Folder size={14} /> },
  { key: "ESTIMATING_COST", label: "Estimating cost", icon: <Icon.Dollar size={14} /> },
  { key: "QUEUED_FOR_SCAN", label: "Queued for scan", icon: <Icon.Clock size={14} /> },
  { key: "RUNNING_AGENTS", label: "Running security agents", icon: <Icon.Cpu size={14} /> },
  { key: "CORRELATING", label: "Correlating findings", icon: <Icon.Layers size={14} /> },
  { key: "GENERATING_REPORTS", label: "Generating reports", icon: <Icon.File size={14} /> },
];

const TERMINAL_STATUSES = new Set([
  "COMPLETED",
  "REMEDIATION_COMPLETED",
  "FAILED",
  "CANCELLED",
  "EXPIRED",
]);

function progressFromStages(seenStages: Set<string>, currentStatus: string): number {
  if (currentStatus === "COMPLETED" || currentStatus === "REMEDIATION_COMPLETED") return 100;
  if (currentStatus === "FAILED" || currentStatus === "CANCELLED") return 100;
  // Count how many known stages we've seen as a proportion of total.
  const known = KNOWN_STAGES.filter((s) => seenStages.has(s.key)).length;
  // Ensure we don't show 100% while still running.
  return Math.min(95, Math.round((known / KNOWN_STAGES.length) * 100));
}

function fmtStatus(status: string): string {
  return status.replace(/_/g, " ").toLowerCase();
}

const ScanRunningPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [status, setStatus] = useState<string>("QUEUED");
  const [seenStages, setSeenStages] = useState<Set<string>>(new Set());
  const [events, setEvents] = useState<ScanEventMsg[]>([]);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  // Open the SSE stream on mount; close on unmount or when status goes terminal.
  useEffect(() => {
    if (!scanId) return;
    const apiBase = (import.meta.env.VITE_API_BASE_URL as string) || "/api/v1";
    // EventSource doesn't send the axios bearer token automatically; the
    // cookie-based session (refresh token) authenticates us with the stream
    // endpoint through nginx's proxy. If the browser blocks that, fall back
    // to polling (not implemented in this pass — flagged as a follow-up).
    const url = `${apiBase}/scans/${scanId}/stream`;
    const es = new EventSource(url, { withCredentials: true });
    esRef.current = es;

    es.addEventListener("scan_state", (ev) => {
      try {
        const payload = JSON.parse((ev as MessageEvent).data) as ScanStateMsg;
        setStatus(payload.status);
      } catch {
        // noop
      }
    });

    es.addEventListener("scan_event", (ev) => {
      try {
        const payload = JSON.parse((ev as MessageEvent).data) as ScanEventMsg;
        setEvents((prev) => [...prev, payload]);
        if (payload.stage_name) {
          setSeenStages((prev) => {
            const next = new Set(prev);
            next.add(payload.stage_name);
            return next;
          });
        }
      } catch {
        // noop
      }
    });

    es.addEventListener("done", (ev) => {
      try {
        const payload = JSON.parse((ev as MessageEvent).data) as ScanStateMsg;
        setStatus(payload.status);
      } catch {
        // noop
      }
      es.close();
    });

    es.onerror = () => {
      // Browsers fire onerror on transient disconnects; only surface an
      // error when the readyState is actually closed.
      if (es.readyState === EventSource.CLOSED) {
        setStreamError("Lost connection to the scan stream.");
      }
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [scanId]);

  // When scan reaches a terminal completed status, auto-navigate to results.
  useEffect(() => {
    if (!scanId) return;
    if (status === "COMPLETED" || status === "REMEDIATION_COMPLETED") {
      const t = setTimeout(() => navigate(`/analysis/results/${scanId}`), 1500);
      return () => clearTimeout(t);
    }
  }, [status, scanId, navigate]);

  const progress = useMemo(
    () => progressFromStages(seenStages, status),
    [seenStages, status],
  );

  const isPendingApproval = status === "PENDING_COST_APPROVAL";
  const isTerminal = TERMINAL_STATUSES.has(status);
  const isFailed = status === "FAILED" || status === "CANCELLED" || status === "EXPIRED";

  const handleApprove = useCallback(async () => {
    if (!scanId) return;
    setApproving(true);
    try {
      await scanService.approveScan(scanId);
      antdMessage.success("Scan approved. Analysis resuming.");
    } catch (err) {
      const e = err as { message?: string };
      antdMessage.error(e.message || "Failed to approve scan");
    } finally {
      setApproving(false);
    }
  }, [scanId]);

  const handleCancel = useCallback(async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      await scanService.cancelScan(scanId);
      antdMessage.info("Scan cancelled.");
      navigate("/account/dashboard");
    } catch (err) {
      const e = err as { message?: string };
      antdMessage.error(e.message || "Failed to cancel scan");
    } finally {
      setCancelling(false);
    }
  }, [scanId, navigate]);

  return (
    <div
      className="fade-in"
      style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 20 }}
    >
      <div style={{ display: "grid", gap: 16 }}>
        <div>
          <div
            className={`chip ${isFailed ? "chip-critical" : "chip-info"}`}
            style={{ marginBottom: 8 }}
          >
            {!isTerminal && (
              <span
                className="pulse-dot dot"
                style={{ background: "currentColor" }}
              />
            )}
            {isFailed ? <Icon.Alert size={11} /> : null}
            Scan{" "}
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
              {scanId?.slice(0, 8)}
            </span>{" "}
            · {fmtStatus(status)}
          </div>
          <h1 style={{ color: "var(--fg)" }}>
            {isPendingApproval
              ? "Ready to run — approve the estimated cost"
              : status === "COMPLETED" || status === "REMEDIATION_COMPLETED"
                ? "Scan complete — redirecting to results…"
                : isFailed
                  ? "Scan did not complete"
                  : "Analyzing your code"}
          </h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            You can leave this page — the scan continues in the background and
            results appear on the Projects list when done.
          </div>
        </div>

        {/* progress + stages */}
        <div className="surface" style={{ padding: 24 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "baseline",
              marginBottom: 12,
            }}
          >
            <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
              Overall progress
            </div>
            <div
              style={{
                fontSize: 13,
                fontVariantNumeric: "tabular-nums",
                fontWeight: 500,
                color: "var(--fg)",
              }}
            >
              {progress}%
            </div>
          </div>
          <div className="sccap-progress">
            <span
              style={{
                width: `${progress}%`,
                background: isFailed ? "var(--critical)" : "var(--primary)",
              }}
            />
          </div>

          <div style={{ display: "grid", gap: 10, marginTop: 22 }}>
            {KNOWN_STAGES.map((s, i) => {
              const seen = seenStages.has(s.key);
              // "Active" if we've seen the prior stage but not this one yet.
              const priorDone = i === 0 || seenStages.has(KNOWN_STAGES[i - 1].key);
              const active = !seen && priorDone && !isTerminal;
              const state: "done" | "active" | "pending" = seen
                ? "done"
                : active
                  ? "active"
                  : "pending";

              return (
                <div
                  key={s.key}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "auto 1fr",
                    gap: 12,
                    alignItems: "center",
                    padding: "10px 12px",
                    borderRadius: 8,
                    background: active ? "var(--primary-weak)" : "transparent",
                    transition: "background .3s var(--ease)",
                  }}
                >
                  <div
                    style={{
                      width: 26,
                      height: 26,
                      borderRadius: "50%",
                      display: "grid",
                      placeItems: "center",
                      background:
                        state === "done"
                          ? "var(--success)"
                          : state === "active"
                            ? "var(--primary)"
                            : "var(--bg-soft)",
                      color: state === "pending" ? "var(--fg-subtle)" : "white",
                      border:
                        "1px solid " +
                        (state === "pending" ? "var(--border)" : "transparent"),
                    }}
                  >
                    {state === "done" ? (
                      <Icon.Check size={12} />
                    ) : state === "active" ? (
                      <div
                        className="sccap-spin"
                        style={{
                          width: 10,
                          height: 10,
                          border: "2px solid currentColor",
                          borderTopColor: "transparent",
                          borderRadius: "50%",
                        }}
                      />
                    ) : (
                      s.icon
                    )}
                  </div>
                  <div
                    style={{
                      fontSize: 13.5,
                      fontWeight: state === "active" ? 600 : 400,
                      color:
                        state === "pending"
                          ? "var(--fg-subtle)"
                          : "var(--fg)",
                    }}
                  >
                    {s.label}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* pending-approval banner + actions */}
        {isPendingApproval && (
          <div
            className="sccap-card"
            style={{
              background: "var(--primary-weak)",
              borderColor: "transparent",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
            }}
          >
            <div>
              <div
                style={{
                  fontWeight: 600,
                  color: "var(--primary-strong)",
                  marginBottom: 4,
                }}
              >
                Cost estimate ready
              </div>
              <div style={{ color: "var(--fg)", fontSize: 13 }}>
                Review the estimate on the Projects page, then approve to run
                the full analysis.
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="sccap-btn"
                onClick={handleCancel}
                disabled={cancelling}
              >
                {cancelling ? "Cancelling…" : "Cancel"}
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                onClick={handleApprove}
                disabled={approving}
              >
                <Icon.Check size={12} />{" "}
                {approving ? "Approving…" : "Approve & run"}
              </button>
            </div>
          </div>
        )}

        {isFailed && (
          <div
            className="sccap-card"
            style={{
              background: "var(--critical-weak)",
              borderColor: "transparent",
            }}
          >
            <div
              style={{ fontWeight: 600, color: "var(--critical)", marginBottom: 4 }}
            >
              {status === "CANCELLED" ? "Scan cancelled" : "Scan failed"}
            </div>
            <div style={{ color: "var(--fg)", fontSize: 13 }}>
              Check the worker logs for details, or try resubmitting the same
              source. The scan record is preserved under the Projects list.
            </div>
          </div>
        )}

        {/* live event log */}
        <div className="surface" style={{ padding: 18 }}>
          <SectionHead
            title={
              <>
                <Icon.Terminal size={14} /> Live event log
              </>
            }
          />
          {streamError && (
            <div
              style={{
                fontSize: 12,
                color: "var(--critical)",
                marginBottom: 8,
              }}
            >
              {streamError}
            </div>
          )}
          <pre
            className="sccap-code"
            style={{
              maxHeight: 240,
              overflow: "auto",
              fontSize: 11.5,
              margin: 0,
            }}
          >
            {events.length === 0
              ? "Waiting for events…\n"
              : events
                  .map(
                    (e) =>
                      `[${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "—"}] ${e.stage_name} · ${e.status}`,
                  )
                  .join("\n")}
          </pre>
        </div>
      </div>

      <aside style={{ display: "grid", gap: 12, alignContent: "start" }}>
        <div className="sccap-card">
          <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>Status</div>
          <div
            style={{
              fontSize: 18,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              marginTop: 4,
              color: isFailed
                ? "var(--critical)"
                : isTerminal
                  ? "var(--success)"
                  : "var(--fg)",
              textTransform: "capitalize",
            }}
          >
            {fmtStatus(status)}
          </div>
          <div
            style={{ marginTop: 10, fontSize: 12, color: "var(--fg-muted)" }}
          >
            {seenStages.size} stage{seenStages.size === 1 ? "" : "s"} complete
          </div>
        </div>

        <button
          className="sccap-btn sccap-btn-primary"
          onClick={() => navigate(`/analysis/results/${scanId}`)}
          disabled={!isTerminal || isFailed}
          style={{
            opacity: !isTerminal || isFailed ? 0.6 : 1,
          }}
        >
          {!isTerminal
            ? "Scanning…"
            : isFailed
              ? "No results"
              : (
                  <>
                    View results <Icon.ArrowR size={12} />
                  </>
                )}
        </button>
        <button
          className="sccap-btn"
          onClick={() => navigate("/account/dashboard")}
        >
          Back to dashboard
        </button>
      </aside>
    </div>
  );
};

export default ScanRunningPage;
