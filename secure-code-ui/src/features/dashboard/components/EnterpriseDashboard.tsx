// secure-code-ui/src/features/dashboard/components/EnterpriseDashboard.tsx
//
// AppSec-Lead view. Port of the SCCAP bundle's EnterpriseDashboard,
// currently on mocked data — the backend has no team / org / multi-tenant
// model yet. Surfaced to users only via the Tweaks role-preview toggle
// (the TopNav only exposes "admin" for real superusers). Keeping the
// full data-dense layout so the eventual multi-tenant milestone has a
// finished UI to plug into.

import React from "react";
import { useNavigate } from "react-router-dom";
import { Icon } from "../../../shared/ui/Icon";
import {
  MetricCard,
  RiskRing,
  SectionHead,
  SevBar,
  Spark,
} from "../../../shared/ui/DashboardPrimitives";

const MOCKED_BANNER = (
  <div
    style={{
      padding: "8px 14px",
      background: "var(--info-weak)",
      color: "var(--info)",
      borderRadius: "var(--r-md)",
      fontSize: 12.5,
      display: "inline-flex",
      alignItems: "center",
      gap: 8,
    }}
  >
    <Icon.Info size={13} /> Preview only — wiring to real org data lands with
    multi-tenant support.
  </div>
);

function riskColor(risk: number): string {
  if (risk >= 80) return "var(--critical)";
  if (risk >= 60) return "var(--high)";
  if (risk >= 40) return "var(--medium)";
  return "var(--success)";
}

const PROJECT_ROWS = [
  { name: "payments-api", team: "Core Platform", c: 2, h: 4, m: 8, l: 11, i: 3, risk: 91, when: "2m ago" },
  { name: "auth-service", team: "Identity", c: 1, h: 3, m: 5, l: 6, i: 2, risk: 78, when: "18m" },
  { name: "checkout-web", team: "Commerce", c: 0, h: 0, m: 2, l: 4, i: 1, risk: 34, when: "1h" },
  { name: "ml-pipeline", team: "Data", c: 0, h: 2, m: 3, l: 8, i: 4, risk: 56, when: "3h" },
  { name: "admin-console", team: "Internal", c: 0, h: 1, m: 4, l: 2, i: 0, risk: 45, when: "6h" },
  { name: "reports-api", team: "Analytics", c: 0, h: 0, m: 1, l: 3, i: 1, risk: 22, when: "yesterday" },
];

const COMPLIANCE_ROWS: { k: string; v: number }[] = [
  { k: "SOC 2 Type II", v: 94 },
  { k: "ISO 27001", v: 88 },
  { k: "PCI DSS 4.0", v: 76 },
  { k: "OWASP Top 10", v: 91 },
  { k: "HIPAA", v: 82 },
];

export const EnterpriseDashboard: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr auto",
          alignItems: "end",
          gap: 20,
        }}
      >
        <div>
          <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
            <div className="chip">
              <Icon.Flag size={11} /> Acme Corp · 47 projects · 18 teams
            </div>
            {MOCKED_BANNER}
          </div>
          <h1 style={{ color: "var(--fg)" }}>Security posture</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Org-wide view of active risk, compliance, and remediation velocity.
          </div>
        </div>
        <div className="radio-group" role="tablist" aria-label="Time range">
          <button className="active">7d</button>
          <button>30d</button>
          <button>90d</button>
          <button>YTD</button>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.2fr 1fr 1fr 1fr",
          gap: 16,
        }}
      >
        <div
          className="sccap-card"
          style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr",
            gap: 20,
            alignItems: "center",
          }}
        >
          <RiskRing score={86} label="Risk score" />
          <div>
            <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Enterprise risk score
            </div>
            <div
              style={{
                fontSize: 30,
                fontWeight: 600,
                letterSpacing: "-0.02em",
                color: "var(--fg)",
              }}
            >
              86{" "}
              <span
                style={{
                  fontSize: 14,
                  color: "var(--success)",
                  fontWeight: 500,
                }}
              >
                +4.2
              </span>
            </div>
            <div
              style={{ marginTop: 6, fontSize: 12, color: "var(--fg-muted)" }}
            >
              Above industry median (72)
            </div>
            <div style={{ marginTop: 8 }}>
              <SevBar crit={3} high={12} med={41} low={78} info={24} />
            </div>
          </div>
        </div>
        <MetricCard
          label="Critical findings"
          value={11}
          delta="−3 this week"
          tone="good"
          spark={
            <Spark
              data={[18, 17, 16, 15, 14, 13, 12, 12, 11, 11]}
              tone="critical"
              idKey="ent-crit"
            />
          }
        />
        <MetricCard
          label="Mean time to fix"
          value="3.2d"
          delta="−0.8d"
          tone="good"
          spark={
            <Spark
              data={[5, 4.8, 4.5, 4.2, 4, 3.8, 3.6, 3.4, 3.3, 3.2]}
              idKey="ent-mttf"
            />
          }
        />
        <MetricCard
          label="Compliance"
          value="92%"
          delta="SOC 2: on track"
          tone="good"
          spark={
            <Spark
              data={[80, 82, 83, 85, 86, 87, 89, 90, 91, 92]}
              idKey="ent-compliance"
            />
          }
        />
      </div>

      <div
        style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}
      >
        <div className="sccap-card" style={{ padding: 0 }}>
          <SectionHead
            title={
              <>
                <Icon.Folder size={16} /> Projects by risk
              </>
            }
            right={
              <div style={{ display: "flex", gap: 6 }}>
                <div className="input-with-icon" style={{ width: 180 }}>
                  <Icon.Search size={14} />
                  <input
                    className="sccap-input"
                    placeholder="Filter projects…"
                    style={{ paddingLeft: 30, height: 30, fontSize: 12 }}
                    disabled
                  />
                </div>
                <button className="sccap-btn sccap-btn-sm sccap-btn-ghost" disabled>
                  <Icon.Filter size={12} /> Team
                </button>
              </div>
            }
            style={{ padding: "18px 20px 10px" }}
          />
          <table className="sccap-t">
            <thead>
              <tr>
                <th>Project</th>
                <th>Team</th>
                <th>Severity breakdown</th>
                <th>Risk</th>
                <th>Last scan</th>
              </tr>
            </thead>
            <tbody>
              {PROJECT_ROWS.map((r) => (
                <tr
                  key={r.name}
                  onClick={() => navigate("/analysis/results")}
                  style={{ cursor: "pointer" }}
                >
                  <td>
                    <div style={{ fontWeight: 500, color: "var(--fg)" }}>
                      {r.name}
                    </div>
                  </td>
                  <td style={{ color: "var(--fg-muted)" }}>{r.team}</td>
                  <td style={{ width: "32%" }}>
                    <SevBar crit={r.c} high={r.h} med={r.m} low={r.l} info={r.i} />
                  </td>
                  <td>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <div
                        style={{
                          fontWeight: 600,
                          fontVariantNumeric: "tabular-nums",
                          width: 28,
                          color: riskColor(r.risk),
                        }}
                      >
                        {r.risk}
                      </div>
                      <div
                        style={{
                          flex: 1,
                          height: 4,
                          background: "var(--bg-soft)",
                          borderRadius: 99,
                          minWidth: 60,
                        }}
                      >
                        <div
                          style={{
                            width: `${r.risk}%`,
                            height: "100%",
                            background: riskColor(r.risk),
                            borderRadius: 99,
                          }}
                        />
                      </div>
                    </div>
                  </td>
                  <td
                    style={{
                      color: "var(--fg-muted)",
                      fontSize: 12.5,
                    }}
                  >
                    {r.when}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: "grid", gap: 16 }}>
          <div className="sccap-card">
            <SectionHead
              title={
                <>
                  <Icon.Shield size={16} /> Compliance status
                </>
              }
              right={
                <button
                  className="sccap-btn sccap-btn-sm sccap-btn-ghost"
                  onClick={() => navigate("/compliance")}
                >
                  Details <Icon.ChevronR size={12} />
                </button>
              }
            />
            <div style={{ display: "grid", gap: 10 }}>
              {COMPLIANCE_ROWS.map((c) => {
                const bad = c.v < 80;
                return (
                  <div key={c.k}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        fontSize: 12.5,
                        marginBottom: 4,
                      }}
                    >
                      <span style={{ fontWeight: 500, color: "var(--fg)" }}>
                        {c.k}
                      </span>
                      <span
                        style={{
                          color: bad ? "var(--high)" : "var(--success)",
                          fontVariantNumeric: "tabular-nums",
                        }}
                      >
                        {c.v}%
                      </span>
                    </div>
                    <div className="sccap-progress">
                      <span
                        style={{
                          width: `${c.v}%`,
                          background: bad ? "var(--high)" : "var(--success)",
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="sccap-card">
            <SectionHead
              title={
                <>
                  <Icon.Clock size={16} /> Remediation velocity
                </>
              }
            />
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "auto 1fr",
                gap: 16,
                alignItems: "center",
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: 30,
                    fontWeight: 600,
                    fontVariantNumeric: "tabular-nums",
                    color: "var(--fg)",
                  }}
                >
                  68%
                </div>
                <div style={{ fontSize: 11, color: "var(--fg-muted)" }}>
                  AI-assisted fixes accepted
                </div>
              </div>
              <Spark
                data={[42, 48, 52, 55, 58, 60, 63, 65, 67, 68]}
                idKey="ent-velocity"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnterpriseDashboard;
