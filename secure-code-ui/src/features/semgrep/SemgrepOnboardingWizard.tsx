// src/features/semgrep/SemgrepOnboardingWizard.tsx
//
// Shown when 0 rule sources are configured. Lets the operator seed the
// built-in community library with a single click.

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

const SemgrepOnboardingWizard: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [loading, setLoading] = useState(false);

  const handleSeed = async () => {
    setLoading(true);
    try {
      const sources = await ruleSourcesService.seedSources();
      toast.success(`Loaded ${sources.length} rule source${sources.length === 1 ? "" : "s"}.`);
      await queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
    } catch (err) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg = e.response?.data?.detail ?? e.message ?? "Failed to seed sources";
      toast.error(typeof msg === "string" ? msg : "Failed to seed sources");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="sccap-card"
      style={{
        padding: 48,
        textAlign: "center",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 16,
      }}
    >
      <div style={{ color: "var(--primary)" }}>
        <Icon.Code size={36} />
      </div>
      <div>
        <div style={{ fontWeight: 600, fontSize: 15, color: "var(--fg)", marginBottom: 6 }}>
          No Semgrep rule sources configured
        </div>
        <div style={{ fontSize: 13, color: "var(--fg-muted)", maxWidth: 480, lineHeight: 1.6 }}>
          Load the built-in library of community rule sources to get started. Each source
          maps to a curated set of Semgrep rules for a specific language or category.
        </div>
      </div>
      <button
        className="sccap-btn sccap-btn-primary"
        onClick={handleSeed}
        disabled={loading}
        style={{ marginTop: 4 }}
      >
        <Icon.Download size={13} />
        {loading ? " Loading sources…" : " Load built-in sources"}
      </button>
    </div>
  );
};

export default SemgrepOnboardingWizard;
