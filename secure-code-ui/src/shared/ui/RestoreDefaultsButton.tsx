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
    mutationFn: () => seedService.seedDefaults(true),
    onSuccess: (result) => {
      onSuccess(result);
      setConfirmReset(false);
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to reset defaults.");
      setConfirmReset(false);
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
        onClose={() => setConfirmReset(false)}
        title="Reset defaults to factory?"
        width={480}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmReset(false)}
              disabled={reset.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() => reset.mutate()}
              disabled={reset.isPending}
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
      </Modal>
    </>
  );
};

export default RestoreDefaultsButton;
