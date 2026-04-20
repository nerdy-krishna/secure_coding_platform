// secure-code-ui/src/pages/compliance/CompliancePage.tsx
//
// SCCAP compliance overview. Port of the design bundle's Misc.jsx
// Compliance page, adapted for the real backend state.
//
// Backend scope today: the list of *configured* frameworks comes from
// /frameworks (frameworkService.getFrameworks). The backend does not
// yet expose per-framework passing/total controls, so the prototype's
// 94 / 64-style rollups are stubbed with a clear banner. When a
// /compliance/stats endpoint lands, the cards swap to live numbers
// without changing the page's shape.

import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { frameworkService } from "../../shared/api/frameworkService";
import { Icon } from "../../shared/ui/Icon";
import { RiskRing, SectionHead } from "../../shared/ui/DashboardPrimitives";
import type { FrameworkRead } from "../../shared/types/api";

const CompliancePage: React.FC = () => {
  const navigate = useNavigate();
  const { data: frameworks, isLoading } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selected = useMemo(
    () => frameworks?.find((f) => f.id === selectedId) ?? null,
    [frameworks, selectedId],
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Compliance</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Live mapping of your code findings to configured security frameworks.
        </div>
      </div>

      <div
        style={{
          padding: "10px 14px",
          background: "var(--info-weak)",
          color: "var(--info)",
          borderRadius: "var(--r-md)",
          fontSize: 13,
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          width: "fit-content",
        }}
      >
        <Icon.Info size={14} /> Per-framework scoring is a design placeholder —
        a backend /compliance/stats endpoint will populate passing / total
        control counts. Today the page lists every configured framework and
        lets you drill in to see associated agents.
      </div>

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
      ) : !frameworks || frameworks.length === 0 ? (
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
            No frameworks configured
          </div>
          <div
            style={{ color: "var(--fg-muted)", fontSize: 13, marginBottom: 16 }}
          >
            Configure frameworks under Admin → Frameworks so scans can map
            findings to them.
          </div>
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() => navigate("/admin/frameworks")}
          >
            Open admin
          </button>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: 14,
          }}
        >
          {frameworks.map((f) => {
            // Placeholder score distribution until /compliance/stats lands.
            const placeholderScore = 80;
            const active = selectedId === f.id;
            return (
              <div
                key={f.id}
                className="sccap-card"
                onClick={() => setSelectedId(active ? null : f.id)}
                style={{
                  cursor: "pointer",
                  borderColor: active
                    ? "var(--primary)"
                    : "var(--border)",
                  boxShadow: active ? "var(--shadow-sm)" : undefined,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    marginBottom: 14,
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: 11,
                        color: "var(--fg-subtle)",
                        textTransform: "uppercase",
                        letterSpacing: ".06em",
                      }}
                    >
                      Framework
                    </div>
                    <h3 style={{ marginTop: 2, color: "var(--fg)" }}>
                      {f.name}
                    </h3>
                  </div>
                  <div style={{ width: 54, height: 54 }}>
                    <RiskRing score={placeholderScore} label="" size={54} />
                  </div>
                </div>
                {f.description && (
                  <div
                    style={{
                      fontSize: 12.5,
                      color: "var(--fg-muted)",
                      marginBottom: 10,
                      lineHeight: 1.5,
                    }}
                  >
                    {f.description}
                  </div>
                )}
                <div
                  style={{
                    fontSize: 11,
                    color: "var(--fg-subtle)",
                    display: "flex",
                    gap: 10,
                  }}
                >
                  <span>
                    <Icon.Cpu size={10} /> {f.agents?.length ?? 0} agent
                    {f.agents?.length === 1 ? "" : "s"}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {selected && (
        <div className="surface" style={{ padding: 0 }}>
          <SectionHead
            title={
              <>
                <Icon.Shield size={16} /> {selected.name} · mapped agents
              </>
            }
            right={
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => navigate("/admin/frameworks")}
              >
                <Icon.Edit size={12} /> Edit mappings
              </button>
            }
            style={{ padding: "18px 20px 10px" }}
          />
          {selected.agents && selected.agents.length > 0 ? (
            <table className="sccap-t">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Description</th>
                  <th>Domain query</th>
                </tr>
              </thead>
              <tbody>
                {selected.agents.map((a) => (
                  <tr key={a.id}>
                    <td style={{ fontWeight: 500, color: "var(--fg)" }}>
                      {a.name}
                    </td>
                    <td style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
                      {a.description}
                    </td>
                    <td
                      style={{
                        color: "var(--fg-subtle)",
                        fontSize: 11.5,
                        fontFamily: "var(--font-mono)",
                        maxWidth: 320,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={JSON.stringify(a.domain_query)}
                    >
                      {JSON.stringify(a.domain_query)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div
              style={{
                padding: 40,
                textAlign: "center",
                color: "var(--fg-muted)",
              }}
            >
              No agents mapped to this framework yet.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CompliancePage;
