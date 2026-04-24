// secure-code-ui/src/widgets/Tweaks/Tweaks.tsx
//
// Floating theme/variant/accent/role-preview panel — port of the SCCAP
// design bundle's Tweaks.jsx. The prototype gated visibility behind an
// `__activate_edit_mode` iframe message (Claude Design editor hook); in
// production we keep the trigger always visible so users can toggle
// theme/variant at will. Role preview stays opt-in via the explicit
// "Role preview" section — routing + admin gates still honor real
// user.is_superuser state.

import React, { useState } from "react";
import { useTheme, type SccapRole } from "../../app/providers/ThemeProvider";
import { Icon } from "../../shared/ui/Icon";

interface Accent {
  id: string;
  hex: string;
  name: string;
}

const ACCENTS: Record<"A" | "B", Accent[]> = {
  A: [
    { id: "indigo", hex: "#4f46e5", name: "Indigo (default)" },
    { id: "plum", hex: "#9333ea", name: "Plum" },
    { id: "ember", hex: "#ea580c", name: "Ember" },
    { id: "forest", hex: "#059669", name: "Forest" },
  ],
  B: [
    { id: "teal", hex: "#0d9488", name: "Teal (default)" },
    { id: "azure", hex: "#2563eb", name: "Azure" },
    { id: "rose", hex: "#e11d48", name: "Rose" },
    { id: "amber", hex: "#d97706", name: "Amber" },
  ],
};

const SectionLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      fontSize: 11,
      color: "var(--fg-muted)",
      textTransform: "uppercase",
      letterSpacing: ".06em",
      marginBottom: 6,
    }}
  >
    {children}
  </div>
);

export const Tweaks: React.FC = () => {
  const [open, setOpen] = useState(false);
  const {
    theme,
    variant,
    accent,
    role,
    setTheme,
    setVariant,
    setAccent,
    setRole,
  } = useTheme();

  return (
    <div style={{ position: "fixed", bottom: 16, right: 16, zIndex: 100 }}>
      {open && (
        <div
          className="surface fade-in"
          role="dialog"
          aria-label="Appearance tweaks"
          style={{
            padding: 16,
            width: 300,
            marginBottom: 8,
            boxShadow: "var(--shadow-lg)",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 12,
            }}
          >
            <h4 style={{ margin: 0, color: "var(--fg)" }}>Tweaks</h4>
            <button
              className="sccap-btn sccap-btn-icon sccap-btn-ghost"
              onClick={() => setOpen(false)}
              aria-label="Close tweaks"
            >
              <Icon.X size={13} />
            </button>
          </div>

          <div style={{ marginBottom: 14 }}>
            <SectionLabel>Variation</SectionLabel>
            <div className="radio-group" style={{ width: "100%" }}>
              <button
                className={variant === "A" ? "active" : ""}
                onClick={() => setVariant("A")}
                style={{ flex: 1 }}
              >
                A · Indigo + Warm
              </button>
              <button
                className={variant === "B" ? "active" : ""}
                onClick={() => setVariant("B")}
                style={{ flex: 1 }}
              >
                B · Teal + Cool
              </button>
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <SectionLabel>Theme</SectionLabel>
            <div className="radio-group" style={{ width: "100%" }}>
              <button
                className={theme === "light" ? "active" : ""}
                onClick={() => setTheme("light")}
                style={{ flex: 1, display: "inline-flex", gap: 6 }}
              >
                <Icon.Sun size={11} /> Light
              </button>
              <button
                className={theme === "dark" ? "active" : ""}
                onClick={() => setTheme("dark")}
                style={{ flex: 1, display: "inline-flex", gap: 6 }}
              >
                <Icon.Moon size={11} /> Dark
              </button>
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <SectionLabel>Accent color</SectionLabel>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap: 6,
              }}
            >
              {ACCENTS[variant].map((a) => {
                const isActive = accent === a.hex;
                return (
                  <button
                    key={a.id}
                    onClick={() => setAccent(isActive ? "" : a.hex)}
                    title={a.name}
                    aria-label={a.name}
                    aria-pressed={isActive}
                    style={{
                      height: 36,
                      borderRadius: 8,
                      border: isActive
                        ? "2px solid var(--fg)"
                        : "1px solid var(--border)",
                      background: a.hex,
                      cursor: "pointer",
                    }}
                  />
                );
              })}
            </div>
          </div>

          <div style={{ marginBottom: 4 }}>
            <SectionLabel>Role preview</SectionLabel>
            <div className="radio-group" style={{ width: "100%" }}>
              {(["user", "admin"] as SccapRole[]).map((r) => (
                <button
                  key={r}
                  className={role === r ? "active" : ""}
                  onClick={() => setRole(r)}
                  style={{ flex: 1, textTransform: "capitalize" }}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
      <button
        className="sccap-btn sccap-btn-primary"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-label="Open appearance tweaks"
        style={{ boxShadow: "var(--shadow-md)" }}
      >
        <Icon.Settings size={13} /> Tweaks
      </button>
    </div>
  );
};

export default Tweaks;
