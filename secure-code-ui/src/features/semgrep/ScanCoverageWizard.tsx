// src/features/semgrep/ScanCoverageWizard.tsx
//
// Blocking modal shown before scan submission when detected languages have
// no ingested Semgrep rules. Superusers can enable & sync sources inline;
// regular users see a contact-admin message.

import React, { useState } from "react";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import type { ScanCoverageResponse, RuleSourceRead } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

export interface ScanCoverageWizardProps {
  open: boolean;
  languages: string[];
  coverage: ScanCoverageResponse | null;
  isSuperuser: boolean;
  onSkip: () => void;
  onProceed: () => void;
  onClose: () => void;
}

interface SourceEnableState {
  enabling: boolean;
  syncing: boolean;
  done: boolean;
  error: string | null;
}

const ScanCoverageWizard: React.FC<ScanCoverageWizardProps> = ({
  open,
  languages,
  coverage,
  isSuperuser,
  onSkip,
  onProceed,
  onClose,
}) => {
  const toast = useToast();
  const [sourceStates, setSourceStates] = useState<Record<string, SourceEnableState>>({});

  if (!open) return null;

  const uncoveredLanguages = coverage
    ? languages.filter((lang) => {
        const entry = coverage.coverage[lang];
        return entry && !entry.covered;
      })
    : languages;

  // Collect all recommended sources across uncovered languages, de-duped by id
  const recommendedSourcesMap = new Map<string, RuleSourceRead>();
  if (coverage) {
    for (const lang of uncoveredLanguages) {
      const entry = coverage.coverage[lang];
      if (entry) {
        for (const src of entry.recommended_sources) {
          recommendedSourcesMap.set(src.id, src);
        }
      }
    }
  }
  const recommendedSources = Array.from(recommendedSourcesMap.values());

  const setSourceState = (id: string, patch: Partial<SourceEnableState>) => {
    setSourceStates((prev) => {
      const defaults: SourceEnableState = { enabling: false, syncing: false, done: false, error: null };
      return { ...prev, [id]: { ...defaults, ...(prev[id] ?? {}), ...patch } };
    });
  };

  const handleEnableAndSync = async (source: RuleSourceRead) => {
    setSourceState(source.id, { enabling: true, error: null });
    try {
      await ruleSourcesService.updateSource(source.id, { enabled: true });
      setSourceState(source.id, { enabling: false, syncing: true });
      await ruleSourcesService.triggerSync(source.id);
      setSourceState(source.id, { syncing: false, done: true });
      toast.success(`Sync triggered for "${source.display_name}".`);
    } catch (err) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg = e.response?.data?.detail ?? e.message ?? "Failed";
      setSourceState(source.id, { enabling: false, syncing: false, error: typeof msg === "string" ? msg : "Failed" });
    }
  };

  const allDone =
    recommendedSources.length > 0 &&
    recommendedSources.every((s) => sourceStates[s.id]?.done);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Semgrep Rules Missing"
      width={600}
      footer={
        <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
          <button
            className="sccap-btn sccap-btn-ghost sccap-btn-sm"
            onClick={onSkip}
            style={{ fontSize: 12.5, color: "var(--fg-muted)" }}
          >
            Skip for now
          </button>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            onClick={onProceed}
          >
            <Icon.Play size={12} /> Start Scan →
          </button>
        </div>
      }
    >
      <div style={{ display: "grid", gap: 16 }}>
        {uncoveredLanguages.length === 0 ? (
          <div style={{ color: "var(--success)", display: "flex", alignItems: "center", gap: 8 }}>
            <Icon.Check size={14} /> All detected languages have coverage.
          </div>
        ) : (
          <>
            <div>
              <div style={{ fontWeight: 500, color: "var(--fg)", marginBottom: 6 }}>
                No Semgrep rules found for:
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {uncoveredLanguages.map((lang) => (
                  <span
                    key={lang}
                    className="chip"
                    style={{ background: "rgba(239,68,68,0.10)", color: "var(--error)", fontSize: 12 }}
                  >
                    {lang}
                  </span>
                ))}
              </div>
              <div style={{ marginTop: 8, fontSize: 12.5, color: "var(--fg-muted)" }}>
                Semgrep will be skipped for these languages unless rules are enabled. You can
                still proceed — the scan will run Bandit / Gitleaks / OSV checks regardless.
              </div>
            </div>

            {!isSuperuser ? (
              <div
                style={{
                  padding: "12px 16px",
                  background: "var(--bg-soft)",
                  borderRadius: "var(--r-md)",
                  fontSize: 13,
                  color: "var(--fg-muted)",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                <Icon.Lock size={13} />
                Ask your admin to enable Semgrep rules for these languages.
              </div>
            ) : recommendedSources.length === 0 ? (
              <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
                No recommended rule sources found for these languages. You can add sources in
                Admin → Frameworks → Semgrep Rules.
              </div>
            ) : (
              <div style={{ display: "grid", gap: 8 }}>
                <div style={{ fontSize: 12, color: "var(--fg-muted)", fontWeight: 500 }}>
                  Recommended sources:
                </div>
                {recommendedSources.map((src) => {
                  const state = sourceStates[src.id] ?? {
                    enabling: false,
                    syncing: false,
                    done: false,
                    error: null,
                  };
                  return (
                    <div
                      key={src.id}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "10px 14px",
                        borderRadius: "var(--r-md)",
                        border: "1px solid var(--border)",
                        gap: 12,
                      }}
                    >
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 500, fontSize: 13, color: "var(--fg)" }}>
                          {src.display_name}
                        </div>
                        <div
                          style={{
                            display: "flex",
                            gap: 8,
                            marginTop: 3,
                            alignItems: "center",
                          }}
                        >
                          <span className="chip" style={{ fontSize: 10.5 }}>
                            {src.license_spdx}
                          </span>
                          <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                            {src.rule_count.toLocaleString()} rules
                          </span>
                          <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                            by {src.author}
                          </span>
                        </div>
                        {state.error && (
                          <div style={{ fontSize: 11, color: "var(--error)", marginTop: 3 }}>
                            {state.error}
                          </div>
                        )}
                      </div>
                      <div>
                        {state.done ? (
                          <span
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 4,
                              color: "var(--success)",
                              fontSize: 12,
                            }}
                          >
                            <Icon.Check size={12} /> Sync queued
                          </span>
                        ) : state.enabling || state.syncing ? (
                          <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                            {state.enabling ? "Enabling…" : "Syncing…"}
                          </span>
                        ) : (
                          <button
                            className="sccap-btn sccap-btn-sm"
                            onClick={() => handleEnableAndSync(src)}
                            disabled={src.enabled && src.last_sync_status === "running"}
                          >
                            <Icon.Zap size={11} />
                            {src.enabled ? " Sync" : " Enable & Sync"}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
                {allDone && (
                  <div
                    style={{
                      padding: "10px 14px",
                      background: "rgba(34,197,94,0.08)",
                      borderRadius: "var(--r-md)",
                      color: "var(--success)",
                      fontSize: 12.5,
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                    }}
                  >
                    <Icon.Check size={13} />
                    Syncs queued. Rules will be available once syncing completes. You can
                    proceed with the scan now.
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </Modal>
  );
};

export default ScanCoverageWizard;
