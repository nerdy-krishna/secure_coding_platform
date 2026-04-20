// secure-code-ui/src/pages/compliance/CompliancePage.tsx
//
// SCCAP compliance overview. Wired to /api/v1/compliance/stats — returns
// real per-framework doc/findings/score rollups. The 3 default
// frameworks (ASVS, Proactive Controls, Cheatsheets) always render,
// even when not yet ingested, so users see the shape of their program.
// Custom frameworks (from the `frameworks` table) follow.
//
// Admins get inline "Configure" actions that deep-link into /admin/rag
// with query params that auto-open the right ingestion dialog.

import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  complianceService,
  type ComplianceControl,
  type ComplianceFrameworkStats,
  type FrameworkIngestMode,
} from "../../shared/api/complianceService";
import { useAuth } from "../../shared/hooks/useAuth";
import { Icon } from "../../shared/ui/Icon";
import {
  RiskRing,
  SectionHead,
  SevBar,
} from "../../shared/ui/DashboardPrimitives";

function formatWhen(iso: string | null): string {
  if (!iso) return "Never scanned";
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

function ingestHref(name: string, mode: FrameworkIngestMode | null): string {
  if (mode === "csv") return `/admin/rag?framework=${name}&action=git-ingest`;
  if (mode === "git_url")
    return `/admin/rag?framework=${name}&action=git-ingest`;
  return "/admin/rag";
}

const CompliancePage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const isAdmin = !!user?.is_superuser;

  const { data, isLoading, isError } = useQuery<ComplianceFrameworkStats[]>({
    queryKey: ["compliance", "stats"],
    queryFn: complianceService.getStats,
    refetchOnWindowFocus: false,
  });

  const [selectedName, setSelectedName] = useState<string | null>(null);
  const selected = useMemo(
    () => data?.find((f) => f.name === selectedName) ?? null,
    [data, selectedName],
  );

  const { data: controls, isLoading: loadingControls } = useQuery<
    ComplianceControl[]
  >({
    queryKey: ["compliance", "controls", selected?.name],
    queryFn: () => complianceService.getControls(selected!.name),
    enabled: !!selected?.is_installed,
  });

  const defaults = (data ?? []).filter(
    (f) => f.framework_type === "default",
  );
  const customs = (data ?? []).filter((f) => f.framework_type === "custom");

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Compliance</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Per-framework posture from your scans. Default frameworks always
          appear; custom frameworks show once configured under Admin.
        </div>
      </div>

      {isError && (
        <div
          className="sccap-card"
          style={{
            padding: 14,
            background: "var(--critical-weak)",
            borderColor: "var(--critical)",
            color: "var(--critical)",
            fontSize: 13,
          }}
        >
          Failed to load compliance stats. Check your connection and retry.
        </div>
      )}

      {isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading frameworks…
        </div>
      ) : (
        <>
          <SectionHead
            title={
              <>
                <Icon.Shield size={16} /> Default frameworks
              </>
            }
            right={
              isAdmin ? (
                <button
                  className="sccap-btn sccap-btn-sm"
                  onClick={() => navigate("/admin/rag")}
                >
                  <Icon.Settings size={12} /> Manage ingestion
                </button>
              ) : null
            }
          />
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
              gap: 14,
            }}
          >
            {defaults.map((fw) => (
              <FrameworkCard
                key={fw.name}
                fw={fw}
                active={selectedName === fw.name}
                isAdmin={isAdmin}
                onClick={() =>
                  setSelectedName(selectedName === fw.name ? null : fw.name)
                }
                onConfigure={() => navigate(ingestHref(fw.name, fw.ingest_mode))}
              />
            ))}
          </div>

          {customs.length > 0 && (
            <>
              <SectionHead
                title={
                  <>
                    <Icon.Layers size={16} /> Custom frameworks
                  </>
                }
              />
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns:
                    "repeat(auto-fill, minmax(320px, 1fr))",
                  gap: 14,
                }}
              >
                {customs.map((fw) => (
                  <FrameworkCard
                    key={fw.name}
                    fw={fw}
                    active={selectedName === fw.name}
                    isAdmin={isAdmin}
                    onClick={() =>
                      setSelectedName(
                        selectedName === fw.name ? null : fw.name,
                      )
                    }
                    onConfigure={() => navigate("/admin/frameworks")}
                  />
                ))}
              </div>
            </>
          )}

          {selected && (
            <div className="surface" style={{ padding: 0 }}>
              <SectionHead
                title={
                  <>
                    <Icon.BookOpen size={16} /> {selected.display_name} ·
                    controls
                  </>
                }
                right={
                  isAdmin && (
                    <button
                      className="sccap-btn sccap-btn-sm"
                      onClick={() =>
                        navigate(
                          ingestHref(selected.name, selected.ingest_mode),
                        )
                      }
                    >
                      <Icon.Edit size={12} />{" "}
                      {selected.is_installed ? "Update" : "Configure"}
                    </button>
                  )
                }
                style={{ padding: "18px 20px 10px" }}
              />
              {!selected.is_installed ? (
                <div
                  style={{
                    padding: 40,
                    textAlign: "center",
                    color: "var(--fg-muted)",
                    fontSize: 13,
                  }}
                >
                  Not configured yet. {isAdmin ? "" : "Ask an admin to "}
                  ingest this framework to see its controls here.
                </div>
              ) : loadingControls ? (
                <div
                  style={{
                    padding: 40,
                    textAlign: "center",
                    color: "var(--fg-muted)",
                  }}
                >
                  Loading controls…
                </div>
              ) : !controls || controls.length === 0 ? (
                <div
                  style={{
                    padding: 40,
                    textAlign: "center",
                    color: "var(--fg-muted)",
                  }}
                >
                  No controls returned for this framework.
                </div>
              ) : (
                <table className="sccap-t">
                  <thead>
                    <tr>
                      <th style={{ width: 140 }}>Control</th>
                      <th>Title</th>
                      <th style={{ width: 80, textAlign: "right" }}>Docs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {controls.map((c) => (
                      <tr key={c.control_id} style={{ cursor: "default" }}>
                        <td className="mono" style={{ fontSize: 12 }}>
                          {c.control_id}
                        </td>
                        <td
                          style={{ color: "var(--fg-muted)", fontSize: 12.5 }}
                        >
                          {c.title}
                        </td>
                        <td
                          style={{
                            textAlign: "right",
                            fontVariantNumeric: "tabular-nums",
                          }}
                        >
                          {c.count}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};

const FrameworkCard: React.FC<{
  fw: ComplianceFrameworkStats;
  active: boolean;
  isAdmin: boolean;
  onClick: () => void;
  onConfigure: () => void;
}> = ({ fw, active, isAdmin, onClick, onConfigure }) => (
  <div
    className="sccap-card"
    onClick={onClick}
    style={{
      cursor: "pointer",
      borderColor: active ? "var(--primary)" : "var(--border)",
      boxShadow: active ? "var(--shadow-sm)" : undefined,
    }}
  >
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "flex-start",
        marginBottom: 12,
      }}
    >
      <div>
        <div
          style={{
            fontSize: 10.5,
            color: "var(--fg-subtle)",
            textTransform: "uppercase",
            letterSpacing: ".06em",
          }}
        >
          {fw.framework_type === "default" ? "Default" : "Custom"}
        </div>
        <h3 style={{ marginTop: 2, color: "var(--fg)", fontSize: 15 }}>
          {fw.display_name}
        </h3>
      </div>
      <div style={{ width: 56, height: 56, flex: "none" }}>
        <RiskRing score={fw.score} label="" size={56} />
      </div>
    </div>

    {fw.description && (
      <div
        style={{
          fontSize: 12.5,
          color: "var(--fg-muted)",
          marginBottom: 10,
          lineHeight: 1.5,
          minHeight: 36,
          display: "-webkit-box",
          WebkitLineClamp: 2,
          WebkitBoxOrient: "vertical",
          overflow: "hidden",
        }}
      >
        {fw.description}
      </div>
    )}

    <div
      style={{
        display: "flex",
        gap: 6,
        flexWrap: "wrap",
        marginBottom: 10,
      }}
    >
      {fw.is_installed ? (
        <span className="chip chip-success">
          <Icon.Check size={10} /> Installed
        </span>
      ) : (
        <span
          className="chip"
          style={{
            color: "var(--fg-subtle)",
            borderStyle: "dashed",
          }}
        >
          Not configured
        </span>
      )}
      {fw.is_installed && fw.doc_count > 0 && (
        <span className="chip chip-info">{fw.doc_count} docs</span>
      )}
      {fw.open_findings > 0 && (
        <span className="chip chip-critical">
          {fw.open_findings} open finding
          {fw.open_findings === 1 ? "" : "s"}
        </span>
      )}
    </div>

    {fw.findings_matched > 0 && <SevBar />}

    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginTop: 10,
        paddingTop: 10,
        borderTop: "1px solid var(--border)",
        fontSize: 11.5,
        color: "var(--fg-subtle)",
      }}
    >
      <span>
        <Icon.Clock size={10} /> {formatWhen(fw.last_scanned_at)}
      </span>
      {!fw.is_installed && isAdmin && (
        <button
          className="sccap-btn sccap-btn-sm sccap-btn-primary"
          onClick={(e) => {
            e.stopPropagation();
            onConfigure();
          }}
          style={{ padding: "4px 10px" }}
        >
          <Icon.Plus size={11} /> Configure
        </button>
      )}
    </div>
  </div>
);

export default CompliancePage;
