// secure-code-ui/src/pages/analysis/ExecutiveSummaryPage.tsx
//
// SCCAP executive summary. Ported off antd; data wiring unchanged.

import { useQuery } from "@tanstack/react-query";
import { saveAs } from "file-saver";
import React, { useState } from "react";
import { Link, useParams } from "react-router-dom";
import apiClient from "../../shared/api/apiClient";
import { scanService } from "../../shared/api/scanService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

const ExecutiveSummaryPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const toast = useToast();
  const [downloading, setDownloading] = useState(false);

  const { data: result, isLoading, isError, error } = useQuery({
    queryKey: ["scanResult", scanId],
    queryFn: () => {
      if (!scanId) throw new Error("Submission ID is required");
      return scanService.getScanResult(scanId);
    },
    enabled: !!scanId,
  });

  const handleDownload = async () => {
    if (!scanId) return;
    setDownloading(true);
    try {
      const response = await apiClient.get(
        `/scans/${scanId}/executive-summary/download`,
        { responseType: "blob" },
      );
      saveAs(response.data, `executive-summary-${scanId}.pdf`);
    } catch (err) {
      console.error("PDF Download failed", err);
      toast.error("Could not download the report. Please try again.");
    } finally {
      setDownloading(false);
    }
  };

  if (isLoading) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 60,
          textAlign: "center",
          color: "var(--fg-muted)",
          margin: 20,
        }}
      >
        Loading executive summary…
      </div>
    );
  }

  if (isError) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 20,
          margin: 20,
          background: "var(--critical-weak)",
          borderColor: "var(--critical)",
          color: "var(--critical)",
        }}
      >
        Failed to load report: {error?.message}
      </div>
    );
  }

  if (!result || !result.impact_report) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 20,
          margin: 20,
          background: "var(--medium-weak)",
          borderColor: "var(--medium)",
          color: "var(--medium)",
        }}
      >
        The executive summary for this submission could not be found.
      </div>
    );
  }

  const { impact_report, summary_report } = result;

  return (
    <div
      className="fade-in"
      style={{ maxWidth: 960, margin: "0 auto", padding: 24, display: "grid", gap: 16 }}
    >
      <Link
        to={`/analysis/results/${scanId}`}
        style={{ textDecoration: "none" }}
      >
        <button className="sccap-btn sccap-btn-sm">
          <Icon.ChevronL size={12} /> Back to full report
        </button>
      </Link>

      <div className="surface" style={{ padding: 28 }}>
        <div style={{ textAlign: "center" }}>
          <h1 style={{ color: "var(--fg)" }}>Executive security summary</h1>
          <div
            style={{
              color: "var(--fg-muted)",
              fontSize: 12.5,
              marginTop: 4,
            }}
          >
            Project: {summary_report?.project_name || "N/A"} · Submission{" "}
            <span className="mono">{scanId?.slice(0, 8)}</span>
          </div>
        </div>

        <div className="sccap-divider" />

        <Section
          title={
            <>
              <Icon.Info size={14} /> Executive overview
            </>
          }
        >
          {impact_report.executive_summary}
        </Section>

        <Section
          title={
            <>
              <Icon.Layers size={14} /> Vulnerability analysis
            </>
          }
        >
          {impact_report.vulnerability_overview}
        </Section>

        <Section
          title={
            <>
              <Icon.Shield size={14} /> High-risk findings
            </>
          }
        >
          <ul
            style={{
              margin: 0,
              paddingLeft: 20,
              display: "grid",
              gap: 4,
              color: "var(--fg-muted)",
            }}
          >
            {impact_report.high_risk_findings_summary.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        </Section>

        <Section
          title={
            <>
              <Icon.Settings size={14} /> Remediation strategy
            </>
          }
        >
          {impact_report.remediation_strategy}
        </Section>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: 14,
            marginBottom: 18,
          }}
        >
          <InfoCard label="Architectural changes required">
            {impact_report.required_architectural_changes.length > 0 &&
            impact_report.required_architectural_changes[0] !== "None" ? (
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 20,
                  color: "var(--fg-muted)",
                  fontSize: 12.5,
                }}
              >
                {impact_report.required_architectural_changes.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            ) : (
              <span style={{ color: "var(--fg-subtle)", fontSize: 12.5 }}>
                None
              </span>
            )}
          </InfoCard>
          <InfoCard label="Estimated effort">
            <span className="chip chip-medium" style={{ fontSize: 13 }}>
              {impact_report.estimated_remediation_effort}
            </span>
          </InfoCard>
          <InfoCard label="Vulnerability categories">
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {impact_report.vulnerability_categories.map((cat, i) => (
                <span key={i} className="chip chip-info">
                  {cat}
                </span>
              ))}
            </div>
          </InfoCard>
        </div>

        <div className="sccap-divider" />
        <div style={{ textAlign: "center" }}>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-lg"
            onClick={handleDownload}
            disabled={downloading}
          >
            <Icon.Download size={14} />{" "}
            {downloading ? "Preparing…" : "Download as PDF"}
          </button>
        </div>
      </div>
    </div>
  );
};

const Section: React.FC<{ title: React.ReactNode; children: React.ReactNode }> = ({
  title,
  children,
}) => (
  <div style={{ marginBottom: 20 }}>
    <h3
      style={{
        color: "var(--fg)",
        marginBottom: 8,
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}
    >
      {title}
    </h3>
    <div style={{ color: "var(--fg-muted)", lineHeight: 1.6, fontSize: 13 }}>
      {children}
    </div>
  </div>
);

const InfoCard: React.FC<{ label: string; children: React.ReactNode }> = ({
  label,
  children,
}) => (
  <div
    className="inset"
    style={{
      padding: 14,
    }}
  >
    <div
      style={{
        fontSize: 10.5,
        color: "var(--fg-subtle)",
        textTransform: "uppercase",
        letterSpacing: ".06em",
        marginBottom: 8,
      }}
    >
      {label}
    </div>
    <div>{children}</div>
  </div>
);

export default ExecutiveSummaryPage;
