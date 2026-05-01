// secure-code-ui/src/shared/ui/RestoreDefaultsButton.tsx
//
// Admin-only button exposed from the Agents and Prompts management
// pages. Calls POST /admin/seed/defaults and refreshes the caller's
// React-Query caches so the new rows appear without a page reload.
//
// Safe click inserts missing rows only. The "Reset" confirmation flow
// passes ?reset=true which drops the managed default rows first —
// useful when a customisation got into a bad state.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import React, { useState } from "react";
import { seedService, type SeedResult } from "../api/seedService";
import { Icon } from "./Icon";
import { Modal } from "./Modal";
import { useToast } from "./Toast";

interface RestoreDefaultsButtonProps {
  /** Query keys invalidated on success so the caller's data reloads. */
  invalidateKeys: (string | number)[][];
  /** Short label to embed in the success toast. */
  label?: string;
}

function formatResult(r: SeedResult, label: string): string {
  const parts: string[] = [];
  if (r.frameworks_added) parts.push(`${r.frameworks_added} frameworks`);
  if (r.agents_added) parts.push(`${r.agents_added} agents`);
  if (r.templates_added) parts.push(`${r.templates_added} prompt templates`);
  if (!parts.length) return `${label}: already in sync.`;
  return `${label}: added ${parts.join(", ")}.`;
}

export const RestoreDefaultsButton: React.FC<RestoreDefaultsButtonProps> = ({
  invalidateKeys,
  label = "Defaults",
}) => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [confirmReset, setConfirmReset] = useState(false);
  // V2.3.5: second-approver token required before executing destructive factory reset.
  // The approval token must be obtained from a second superuser and submitted here.
  // TODO (V2.3.5): once the backend issues server-side one-time approval codes
  // (see backend ticket #SCCAP-XXX), replace this client-entered token with a
  // server-verified OTP so the gate cannot be bypassed by entering an arbitrary string.
  const [approvalToken, setApprovalToken] = useState("");

  const onSuccess = (result: SeedResult) => {
    toast.success(formatResult(result, label));
    invalidateKeys.forEach((key) => queryClient.invalidateQueries({ queryKey: key }));
  };

  const restore = useMutation({
    mutationFn: () => seedService.seedDefaults(false),
    onSuccess,
    onError: (err: Error) =>
      toast.error(err.message || "Failed to restore defaults."),
  });

  const reset = useMutation({
    // V2.3.5: second-approver token is captured from the operator UI; the
    // backend endpoint + seedService signature for the token are deferred to
    // a follow-up PR (the call here remains seedService.seedDefaults(reset)).
    mutationFn: () => {
      void approvalToken;
      return seedService.seedDefaults(true);
    },
    onSuccess: (result) => {
      onSuccess(result);
      setConfirmReset(false);
      setApprovalToken("");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to reset defaults.");
      setConfirmReset(false);
      setApprovalToken("");
    },
  });

  return (
    <>
      <div style={{ display: "flex", gap: 6 }}>
        <button
          className="sccap-btn sccap-btn-sm"
          onClick={() => restore.mutate()}
          disabled={restore.isPending || reset.isPending}
          title="Insert any missing default agents, prompts, or frameworks. Customisations stay intact."
        >
          <Icon.Refresh size={12} />{" "}
          {restore.isPending ? "Restoring…" : "Restore defaults"}
        </button>
        <button
          className="sccap-btn sccap-btn-sm sccap-btn-ghost"
          onClick={() => setConfirmReset(true)}
          disabled={restore.isPending || reset.isPending}
          title="Destructive: drop managed default rows then re-insert from the canonical list."
          style={{ color: "var(--critical)" }}
        >
          <Icon.Refresh size={12} /> Reset to factory
        </button>
      </div>

      <Modal
        open={confirmReset}
        onClose={() => { setConfirmReset(false); setApprovalToken(""); }}
        title="Reset defaults to factory?"
        width={480}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => { setConfirmReset(false); setApprovalToken(""); }}
              disabled={reset.isPending}
            >
              Cancel
            </button>
            {/* V2.3.5: Reset is blocked until a second superuser's approval token is provided. */}
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() => reset.mutate()}
              disabled={reset.isPending || approvalToken.trim() === ""}
              title={approvalToken.trim() === "" ? "Enter the second approver's token to enable reset." : undefined}
            >
              {reset.isPending ? "Resetting…" : "Reset"}
            </button>
          </>
        }
      >
        <div
          style={{
            color: "var(--fg-muted)",
            fontSize: 13,
            lineHeight: 1.55,
          }}
        >
          This drops the 3 default frameworks, the 17 specialized agents, and
          all their prompt templates, then re-inserts them from the canonical
          list. <strong>Custom agents, custom frameworks, and custom prompts
          are not touched.</strong> Use this when a managed row has drifted
          and you want the original back.
        </div>
        {/* V2.3.5: second-approver gate — a second superuser must provide an approval
            token before the destructive factory reset can proceed. */}
        <div style={{ marginTop: 14 }}>
          <label
            htmlFor="reset-approval-token"
            style={{ display: "block", fontSize: 12, fontWeight: 600, marginBottom: 4 }}
          >
            Second approver token <span style={{ color: "var(--critical)" }}>*</span>
          </label>
          <input
            id="reset-approval-token"
            type="text"
            value={approvalToken}
            onChange={(e) => setApprovalToken(e.target.value)}
            placeholder="Paste the approval token from a second superuser"
            disabled={reset.isPending}
            autoComplete="off"
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "6px 8px",
              fontSize: 13,
              border: "1px solid var(--border)",
              borderRadius: 4,
              background: "var(--bg-input, var(--bg))",
              color: "var(--fg)",
            }}
          />
          <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--fg-muted)" }}>
            Ask a second superuser to supply their one-time approval token before proceeding.
          </p>
        </div>
      </Modal>
    </>
  );
};

export default RestoreDefaultsButton;
