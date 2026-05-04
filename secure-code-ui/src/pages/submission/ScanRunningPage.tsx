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
import { CriticalSecretOverrideModal } from "../../features/prescan-approval/CriticalSecretOverrideModal";
import { PrescanReviewCard } from "../../features/prescan-approval/PrescanReviewCard";
import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import { useNotificationPermission } from "../../shared/hooks/useNotificationPermission";
import type { PrescanReviewResponse } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

interface ScanEventMsg {
  scan_id: string;
  event_id: number;
  stage_name: string;
  status: string; // "COMPLETED" / "STARTED" / "FAILED" for the event itself
  timestamp: string | null;
  // §3.10b — per-event payload. Carries `{file_path, findings_count,
  // fixes_count}` for `FILE_ANALYZED` events; null for legacy stage
  // events (QUEUED / ANALYZING_CONTEXT / etc.).
  details?: {
    file_path?: string;
    findings_count?: number;
    fixes_count?: number;
  } | null;
}

// One row in the per-file analysis log surfaced by §3.10b. Keyed by
// file_path so the same file showing up twice (e.g. multi-chunk
// analysis) collapses to a single row with the latest counts.
interface FileProgressItem {
  file_path: string;
  findings_count: number;
  fixes_count: number;
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
  "BLOCKED_PRE_LLM",
  "BLOCKED_USER_DECLINE",
]);

function progressFromStages(seenStages: Set<string>, currentStatus: string): number {
  if (currentStatus === "COMPLETED" || currentStatus === "REMEDIATION_COMPLETED") return 100;
  if (
    currentStatus === "FAILED" ||
    currentStatus === "CANCELLED" ||
    currentStatus === "BLOCKED_PRE_LLM" ||
    currentStatus === "BLOCKED_USER_DECLINE"
  )
    return 100;
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
  const toast = useToast();
  const notificationPerm = useNotificationPermission();
  const [status, setStatus] = useState<string>("QUEUED");
  const [seenStages, setSeenStages] = useState<Set<string>>(new Set());
  const [events, setEvents] = useState<ScanEventMsg[]>([]);
  // §3.10b — per-file analysis progress, keyed by file_path so a file
  // showing up multiple times collapses to one row. Renders below the
  // pipeline stages while RUNNING_AGENTS is active.
  const [fileProgress, setFileProgress] = useState<
    Record<string, FileProgressItem>
  >({});
  const [streamError, setStreamError] = useState<string | null>(null);
  const [costDetails, setCostDetails] = useState<{
    total_estimated_cost?: number;
    total_input_tokens?: number;
    predicted_output_tokens?: number;
  } | null>(null);
  const [approving, setApproving] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [stopConfirmOpen, setStopConfirmOpen] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;
  const [prescanReview, setPrescanReview] = useState<PrescanReviewResponse | null>(
    null,
  );
  const [prescanLoading, setPrescanLoading] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [declining, setDeclining] = useState(false);
  const lastFetchedStatusRef = useRef<string | null>(null);
  const esRef = useRef<EventSource | null>(null);
  // N3: dedupe — only one notification per scan_id per page lifetime,
  // even if SSE reconnects after the `done` event.
  const notifiedRef = useRef<Record<string, boolean>>({});

  // Seed `status` from a one-shot HTTP fetch on mount. The SSE stream
  // emits live updates only and currently can't authenticate (cookie
  // path not wired in `current_active_user_sse`); without this seed the
  // page stays at the initial "QUEUED" string forever for any scan
  // that's already terminal (CANCELLED / FAILED / COMPLETED) when the
  // user lands here.
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    scanService
      .getScanResult(scanId)
      .then((r) => {
        if (cancelled) return;
        if (typeof r.status === "string" && r.status.length < 64) {
          setStatus(r.status);
        }
        if (r.cost_details) {
          setCostDetails(r.cost_details);
        }
      })
      .catch(() => {
        // Best-effort — leave the SSE stream to fill in if it can. The
        // user will still see "Lost connection to the scan stream"
        // below if both paths fail.
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // Open the SSE stream on mount; close on unmount or when status goes
  // terminal. EventSource cannot send Authorization headers, so we
  // mint a short-TTL, scan-id-bound JWT first (POST /stream-token,
  // 60s TTL, audience "sse:scan-stream") and pass it as
  // ?access_token=… The token's narrow audience + scan-binding +
  // short lifetime mitigates the access-log exposure that disqualifies
  // raw access tokens from URLs (V16.2.5).
  useEffect(() => {
    if (!scanId) return;
    const apiBase = (import.meta.env.VITE_API_BASE_URL as string) || "/api/v1";
    let cancelled = false;

    const attachListeners = (es: EventSource) => {
      es.addEventListener("scan_state", (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data) as ScanStateMsg;
          if (
            typeof payload.status !== "string" ||
            payload.status.length >= 64
          ) {
            return;
          }
          setStatus(payload.status);
        } catch {
          // noop
        }
      });

      es.addEventListener("scan_event", (ev) => {
        try {
          const payload = JSON.parse((ev as MessageEvent).data) as ScanEventMsg;
          if (
            typeof payload.status !== "string" ||
            payload.status.length >= 64
          ) {
            return;
          }
          if (
            typeof payload.stage_name !== "string" ||
            payload.stage_name.length >= 64
          ) {
            return;
          }
          setEvents((prev) => [...prev, payload].slice(-500));
          setSeenStages((prev) => {
            const next = new Set(prev);
            next.add(payload.stage_name);
            return next;
          });
          if (
            payload.stage_name === "FILE_ANALYZED" &&
            payload.details?.file_path
          ) {
            const filePath = String(payload.details.file_path).slice(0, 512);
            if (!filePath) return;
            const findingsCount = Math.max(
              0,
              Number(payload.details?.findings_count) | 0,
            );
            const fixesCount = Math.max(
              0,
              Number(payload.details?.fixes_count) | 0,
            );
            setFileProgress((prev) => {
              const next = {
                ...prev,
                [filePath]: {
                  file_path: filePath,
                  findings_count: findingsCount,
                  fixes_count: fixesCount,
                  timestamp: payload.timestamp,
                },
              };
              const keys = Object.keys(next);
              if (keys.length > 1000) {
                const oldest = keys.reduce((a, b) =>
                  (next[a].timestamp ?? "") <= (next[b].timestamp ?? "") ? a : b,
                );
                delete next[oldest];
              }
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
          if (
            typeof payload.status !== "string" ||
            payload.status.length >= 64
          ) {
            es.close();
            return;
          }
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
    };

    const connect = async () => {
      let token: string;
      try {
        const issued = await scanService.getStreamToken(scanId);
        token = issued.access_token;
      } catch (err) {
        if (cancelled) return;
        const e = err as { message?: string };
        setStreamError(
          e.message || "Could not authorize the live scan stream.",
        );
        return;
      }
      if (cancelled) return;
      const url =
        `${apiBase}/scans/${encodeURIComponent(scanId)}/stream` +
        `?access_token=${encodeURIComponent(token)}`;
      const es = new EventSource(url, { withCredentials: true });
      esRef.current = es;
      attachListeners(es);
    };

    void connect();

    return () => {
      cancelled = true;
      esRef.current?.close();
      esRef.current = null;
    };
  }, [scanId]);

  // When scan reaches a terminal status (success or BLOCKED_PRE_LLM
  // short-circuit), auto-navigate to the results page so the user
  // sees the outcome — including why a scan was blocked.
  useEffect(() => {
    if (!scanId) return;
    if (
      status === "COMPLETED" ||
      status === "REMEDIATION_COMPLETED" ||
      status === "BLOCKED_PRE_LLM"
    ) {
      const t = setTimeout(() => navigate(`/analysis/results/${scanId}`), 1500);
      return () => clearTimeout(t);
    }
  }, [status, scanId, navigate]);

  // §6 desktop notification on terminal status. Lives in its own
  // effect so it picks up the latest `notificationPerm` state (the
  // SSE listener captures stale values at registration time).
  // Threat-model mitigations:
  //   N1 — generic body, no findings count / severity / file paths
  //   N3 — `tag: scan_id` + `notifiedRef` dedupes per-scan
  useEffect(() => {
    if (!scanId) return;
    if (!TERMINAL_STATUSES.has(status)) return;
    if (notifiedRef.current[scanId]) return;

    if (
      notificationPerm.supported &&
      notificationPerm.permission === "granted"
    ) {
      try {
        new Notification("SCCAP — Scan finished", {
          body: "Scan finished",
          tag: scanId,
        });
      } catch {
        // Notification constructor can throw on iOS Safari etc.
        // Fail silently — the in-app redirect still happens.
      }
      notifiedRef.current[scanId] = true;
    } else if (notificationPerm.supported && !notificationPerm.dismissed) {
      // Fallback nudge — once per scan only.
      toast.info(
        "Scan finished — turn on desktop notifications from the top bar to get pings next time.",
      );
      notifiedRef.current[scanId] = true;
    }
  }, [
    status,
    scanId,
    notificationPerm.supported,
    notificationPerm.permission,
    notificationPerm.dismissed,
    toast,
  ]);

  const progress = useMemo(
    () => progressFromStages(seenStages, status),
    [seenStages, status],
  );

  const isPendingApproval = status === "PENDING_COST_APPROVAL";
  const isPendingPrescan = status === "PENDING_PRESCAN_APPROVAL";
  const isTerminal = TERMINAL_STATUSES.has(status);
  const isFailed =
    status === "FAILED" ||
    status === "CANCELLED" ||
    status === "EXPIRED" ||
    status === "BLOCKED_PRE_LLM" ||
    status === "BLOCKED_USER_DECLINE";

  // Fetch the prescan review whenever the scan enters the prescan-
  // approval gate or one of its terminal states. Re-fetches on every
  // distinct entry so a refresh / reconnect lands the latest data.
  useEffect(() => {
    if (!scanId) return;
    const reviewable =
      status === "PENDING_PRESCAN_APPROVAL" ||
      status === "BLOCKED_PRE_LLM" ||
      status === "BLOCKED_USER_DECLINE";
    if (!reviewable) {
      lastFetchedStatusRef.current = null;
      return;
    }
    if (lastFetchedStatusRef.current === status) return;
    lastFetchedStatusRef.current = status;
    let cancelled = false;
    setPrescanLoading(true);
    scanService
      .getPrescanReview(scanId)
      .then((data) => {
        if (!cancelled) setPrescanReview(data);
      })
      .catch((err: { message?: string }) => {
        if (!cancelled) toast.error(err.message || "Failed to load prescan findings");
      })
      .finally(() => {
        if (!cancelled) setPrescanLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, status, toast]);

  const handleApprove = useCallback(async () => {
    if (!scanId) return;
    setApproving(true);
    try {
      await scanService.approveScan(scanId);
      toast.success("Scan approved. Analysis resuming.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to approve scan");
    } finally {
      setApproving(false);
    }
  }, [scanId, toast]);

  const submitPrescanApproval = useCallback(
    async (override: boolean) => {
      if (!scanId) return;
      setApproving(true);
      try {
        await scanService.approveScan(scanId, {
          kind: "prescan_approval",
          approved: true,
          override_critical_secret: override,
        });
        toast.success(
          override
            ? "Override recorded. Continuing to LLM analysis."
            : "Continuing to LLM analysis.",
        );
        setOverrideOpen(false);
      } catch (err) {
        const e = err as { message?: string };
        toast.error(e.message || "Failed to continue scan");
      } finally {
        setApproving(false);
      }
    },
    [scanId, toast],
  );

  const handlePrescanContinue = useCallback(() => {
    if (prescanReview?.has_critical_secret) {
      setOverrideOpen(true);
      return;
    }
    void submitPrescanApproval(false);
  }, [prescanReview, submitPrescanApproval]);

  const handlePrescanStop = useCallback(async () => {
    if (!scanId) return;
    setDeclining(true);
    try {
      await scanService.approveScan(scanId, {
        kind: "prescan_approval",
        approved: false,
        override_critical_secret: false,
      });
      toast.info("Scan stopped before LLM analysis.");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to stop scan");
    } finally {
      setDeclining(false);
    }
  }, [scanId, toast]);

  const handleCancel = useCallback(async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      await scanService.cancelScan(scanId);
      toast.info("Scan cancelled.");
      navigate("/account/dashboard");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to cancel scan");
    } finally {
      setCancelling(false);
      setStopConfirmOpen(false);
    }
  }, [scanId, navigate, toast]);

  const handleDelete = useCallback(async () => {
    if (!scanId) return;
    setDeleting(true);
    try {
      await scanService.deleteScan(scanId);
      toast.info("Scan deleted.");
      navigate("/account/dashboard");
    } catch (err) {
      const e = err as { message?: string };
      toast.error(e.message || "Failed to delete scan");
    } finally {
      setDeleting(false);
      setDeleteConfirmOpen(false);
    }
  }, [scanId, navigate, toast]);

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      {/* Header — full width above the 2-col body so the Status card on
          the right aligns with the Overall progress card on the left. */}
      <div>
        <button
          className="sccap-btn sccap-btn-sm sccap-btn-ghost"
          onClick={() => navigate(-1)}
          style={{ marginBottom: 10 }}
        >
          <Icon.ChevronL size={12} /> Back
        </button>
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
          {isPendingPrescan
            ? "Pre-LLM scan complete — review before continuing"
            : isPendingApproval
              ? "Ready to run — approve the estimated cost"
              : status === "COMPLETED" || status === "REMEDIATION_COMPLETED"
                ? "Scan complete — redirecting to results…"
                : status === "BLOCKED_PRE_LLM"
                  ? "Scan stopped — Critical secret detected"
                  : status === "BLOCKED_USER_DECLINE"
                    ? "Scan stopped at your request"
                    : isFailed
                      ? "Scan did not complete"
                      : "Analyzing your code"}
        </h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          You can leave this page — the scan continues in the background and
          results appear on the Projects list when done.
        </div>
      </div>

      {/* Body — 2-col grid, content + sidebar. */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 360px",
          gap: 20,
          alignItems: "start",
        }}
      >
        <div style={{ display: "grid", gap: 16 }}>
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

        {/* prescan-approval gate (ADR-009 / G6) — render the review
            card while the scan is paused at PENDING_PRESCAN_APPROVAL,
            and also after a terminal decline so the operator can audit
            the findings that drove the block. */}
        {(isPendingPrescan ||
          status === "BLOCKED_PRE_LLM" ||
          status === "BLOCKED_USER_DECLINE") && (
          <>
            {prescanLoading && !prescanReview && (
              <div
                className="sccap-card"
                style={{ color: "var(--fg-muted)", fontSize: 13 }}
              >
                Loading prescan findings…
              </div>
            )}
            {prescanReview && (
              <PrescanReviewCard
                findings={prescanReview.findings}
                hasCriticalSecret={prescanReview.has_critical_secret}
                approving={approving}
                declining={declining}
                onContinue={handlePrescanContinue}
                onStop={handlePrescanStop}
                readOnly={!isPendingPrescan}
              />
            )}
          </>
        )}

        <CriticalSecretOverrideModal
          open={overrideOpen}
          submitting={approving}
          onCancel={() => setOverrideOpen(false)}
          onConfirm={() => void submitPrescanApproval(true)}
        />

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
                {typeof costDetails?.total_estimated_cost === "number" && (
                  <span
                    style={{
                      marginLeft: 10,
                      color: "var(--fg)",
                      fontSize: 16,
                      fontVariantNumeric: "tabular-nums",
                    }}
                  >
                    · ${costDetails.total_estimated_cost.toFixed(4)}
                  </span>
                )}
              </div>
              <div style={{ color: "var(--fg)", fontSize: 13 }}>
                {typeof costDetails?.total_input_tokens === "number" &&
                typeof costDetails?.predicted_output_tokens === "number"
                  ? `~${costDetails.total_input_tokens.toLocaleString()} input tokens + ~${costDetails.predicted_output_tokens.toLocaleString()} predicted output tokens. Approve to run the full analysis.`
                  : "Approve to run the full analysis."}
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

        {/* §3.10b — per-file progress, only while there's something to show. */}
        {Object.keys(fileProgress).length > 0 && (
          <div className="surface" style={{ padding: 18 }}>
            <SectionHead
              title={
                <>
                  <Icon.File size={14} /> Files analyzed (live)
                </>
              }
            />
            <div
              style={{
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 8,
              }}
            >
              {Object.keys(fileProgress).length} file
              {Object.keys(fileProgress).length === 1 ? "" : "s"} processed
              {(() => {
                const totalFindings = Object.values(fileProgress).reduce(
                  (s, f) => s + f.findings_count,
                  0,
                );
                const totalFixes = Object.values(fileProgress).reduce(
                  (s, f) => s + f.fixes_count,
                  0,
                );
                return ` — ${totalFindings} finding${totalFindings === 1 ? "" : "s"}, ${totalFixes} fix${totalFixes === 1 ? "" : "es"}`;
              })()}
            </div>
            <div
              style={{
                maxHeight: 200,
                overflow: "auto",
                display: "grid",
                gap: 4,
                fontSize: 12,
                fontFamily: "var(--font-mono)",
              }}
            >
              {Object.values(fileProgress)
                .sort((a, b) =>
                  (b.timestamp ?? "").localeCompare(a.timestamp ?? ""),
                )
                .map((f) => (
                  <div
                    key={f.file_path}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 12,
                      padding: "4px 0",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <span
                      style={{
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: "var(--fg)",
                      }}
                      title={f.file_path}
                    >
                      {f.file_path}
                    </span>
                    <span
                      style={{
                        color:
                          f.findings_count > 0
                            ? "var(--high)"
                            : "var(--fg-muted)",
                        flexShrink: 0,
                      }}
                    >
                      {f.findings_count} finding
                      {f.findings_count === 1 ? "" : "s"}
                      {f.fixes_count > 0 && ` · ${f.fixes_count} fix${f.fixes_count === 1 ? "" : "es"}`}
                    </span>
                  </div>
                ))}
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
        {!isTerminal && (
          <button
            className="sccap-btn"
            onClick={() => setStopConfirmOpen(true)}
            disabled={cancelling}
            style={{ color: "var(--critical)" }}
          >
            <Icon.X size={12} /> {cancelling ? "Stopping…" : "Stop scan"}
          </button>
        )}
        {isSuperuser && (
          <button
            className="sccap-btn"
            onClick={() => setDeleteConfirmOpen(true)}
            disabled={deleting}
            style={{ color: "var(--critical)" }}
          >
            <Icon.Alert size={12} /> {deleting ? "Deleting…" : "Delete scan"}
          </button>
        )}
        <button
          className="sccap-btn"
          onClick={() => navigate("/account/dashboard")}
        >
          Back to dashboard
        </button>
      </aside>
      </div>

      <Modal
        open={stopConfirmOpen}
        onClose={() => (cancelling ? undefined : setStopConfirmOpen(false))}
        title="Stop this scan?"
        footer={
          <>
            <button
              className="sccap-btn"
              onClick={() => setStopConfirmOpen(false)}
              disabled={cancelling}
            >
              Keep running
            </button>
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={handleCancel}
              disabled={cancelling}
              style={{ background: "var(--critical)" }}
            >
              {cancelling ? "Stopping…" : "Stop scan"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg)", fontSize: 13.5, lineHeight: 1.55 }}>
          The scan will transition to <b>CANCELLED</b>. Any partial progress is
          discarded — no findings or fixes are produced. You can submit the
          project again later.
        </div>
      </Modal>

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
          database. The action cannot be undone.{" "}
          {!isTerminal && (
            <b style={{ color: "var(--critical)" }}>
              The worker may still be processing this scan in the background —
              consider stopping it first.
            </b>
          )}
        </div>
      </Modal>
    </div>
  );
};

export default ScanRunningPage;
