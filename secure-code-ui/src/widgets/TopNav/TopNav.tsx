// secure-code-ui/src/widgets/TopNav/TopNav.tsx
//
// The SCCAP top-nav shell. Port of the design bundle's AppShell.jsx,
// adapted to the real app: React Router for active-item detection,
// useAuth for logout + superuser gate, useTheme for theme + role state.

import React, { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../shared/hooks/useAuth";
import { useTheme, type SccapRole } from "../../app/providers/ThemeProvider";
import { Icon } from "../../shared/ui/Icon";

interface NavItem {
  id: string;
  label: string;
  /** Path prefix that marks this item active when the current URL starts with it. */
  match: string;
  /** Actual route to navigate to. */
  to: string;
}

// Order matches the design's center nav. Compliance routes to /compliance
// which doesn't exist yet — G.5 builds that page; the link is ready.
const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Dashboard", match: "/account/dashboard", to: "/account/dashboard" },
  { id: "submit", label: "Submit", match: "/submission", to: "/submission/submit" },
  { id: "projects", label: "Projects", match: "/analysis", to: "/analysis/results" },
  { id: "compliance", label: "Compliance", match: "/compliance", to: "/compliance" },
  { id: "advisor", label: "Advisor", match: "/advisor", to: "/advisor" },
  { id: "history", label: "History", match: "/account/history", to: "/account/history" },
];

// Admin item appears only for superusers; shown after the main nav.
const ADMIN_ITEM: NavItem = {
  id: "admin",
  label: "Admin",
  match: "/admin",
  to: "/admin/system",
};

const ROLE_LABELS: Record<SccapRole, string> = {
  dev: "Individual Dev",
  enterprise: "AppSec Lead",
  admin: "Admin",
};

const ROLE_INITIALS: Record<SccapRole, string> = {
  dev: "DV",
  enterprise: "EL",
  admin: "AD",
};

export const TopNav: React.FC = () => {
  const location = useLocation();
  const { theme, toggleTheme, role, setRole } = useTheme();
  const { user } = useAuth();
  const isSuperuser = !!user?.is_superuser;

  // Effective nav: append Admin item when the user is actually a superuser.
  // Previewing "admin" role via Tweaks doesn't grant admin access; route
  // guards enforce that.
  const items = isSuperuser ? [...NAV_ITEMS, ADMIN_ITEM] : NAV_ITEMS;

  const activeId =
    items.find((it) => location.pathname.startsWith(it.match))?.id ?? null;

  return (
    <header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 20,
        background:
          "color-mix(in oklch, var(--bg-elev) 92%, transparent)",
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr auto 1fr",
          alignItems: "center",
          padding: "10px 24px",
          gap: 20,
          maxWidth: 1600,
          margin: "0 auto",
        }}
      >
        <Brand />

        <nav
          aria-label="Primary"
          style={{
            display: "flex",
            gap: 2,
            background: "var(--bg-soft)",
            padding: 4,
            borderRadius: 999,
            border: "1px solid var(--border)",
          }}
        >
          {items.map((it) => {
            const isActive = activeId === it.id;
            return (
              <Link
                key={it.id}
                to={it.to}
                style={{
                  padding: "6px 14px",
                  borderRadius: 999,
                  background: isActive ? "var(--bg-elev)" : "transparent",
                  color: isActive ? "var(--fg)" : "var(--fg-muted)",
                  fontSize: 13,
                  fontWeight: 500,
                  boxShadow: isActive ? "var(--shadow-xs)" : "none",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  transition: "all .15s var(--ease)",
                }}
              >
                {it.id === "admin" && <Icon.Settings size={12} />}
                {it.label}
              </Link>
            );
          })}
        </nav>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "flex-end",
          }}
        >
          <SearchStub />
          <button
            className="sccap-btn sccap-btn-icon sccap-btn-ghost"
            title="Settings"
            aria-label="Settings"
          >
            <Icon.Settings size={16} />
          </button>
          <button
            className="sccap-btn sccap-btn-icon sccap-btn-ghost"
            style={{ position: "relative" }}
            title="Notifications"
            aria-label="Notifications"
          >
            <Icon.Bell size={16} />
            <span className="notif-dot" />
          </button>
          <button
            className="sccap-btn sccap-btn-icon sccap-btn-ghost"
            onClick={toggleTheme}
            title={theme === "light" ? "Switch to dark" : "Switch to light"}
            aria-label="Toggle theme"
          >
            {theme === "light" ? <Icon.Moon size={16} /> : <Icon.Sun size={16} />}
          </button>
          <RoleMenu role={role} setRole={setRole} email={user?.email} />
        </div>
      </div>
    </header>
  );
};

const Brand: React.FC = () => (
  <Link
    to="/account/dashboard"
    style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      textDecoration: "none",
      color: "inherit",
    }}
  >
    <div
      style={{
        width: 30,
        height: 30,
        borderRadius: 8,
        background:
          "linear-gradient(135deg, var(--primary), color-mix(in oklch, var(--primary) 60%, var(--accent)))",
        display: "grid",
        placeItems: "center",
        color: "var(--primary-ink)",
        boxShadow: "0 2px 8px color-mix(in oklch, var(--primary) 30%, transparent)",
      }}
    >
      <Icon.Shield size={16} />
    </div>
    <div style={{ lineHeight: 1.1 }}>
      <div
        style={{
          fontWeight: 600,
          fontSize: 14,
          letterSpacing: "-.01em",
          color: "var(--fg)",
        }}
      >
        SCCAP
      </div>
      <div
        style={{
          fontSize: 10.5,
          color: "var(--fg-subtle)",
          textTransform: "uppercase",
          letterSpacing: ".08em",
        }}
      >
        Secure Coding &amp; Compliance
      </div>
    </div>
  </Link>
);

const SearchStub: React.FC = () => (
  // UI-only stub for G.1 — wiring to a real search endpoint is a follow-up.
  <div className="input-with-icon" style={{ width: 220 }}>
    <Icon.Search size={14} />
    <input
      className="sccap-input"
      placeholder="Search projects, findings…"
      style={{ paddingLeft: 32, height: 34 }}
      disabled
      aria-label="Search (coming soon)"
    />
  </div>
);

interface RoleMenuProps {
  role: SccapRole;
  setRole: (r: SccapRole) => void;
  email?: string;
}

const RoleMenu: React.FC<RoleMenuProps> = ({ role, setRole, email }) => {
  const [open, setOpen] = useState(false);
  const { logout } = useAuth();
  const navigate = useNavigate();
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", handler);
    return () => document.removeEventListener("click", handler);
  }, []);

  const handleSignOut = async () => {
    setOpen(false);
    try {
      await logout();
    } catch {
      // logout best-effort; on failure still redirect to login.
    }
    navigate("/login", { replace: true });
  };

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        className="sccap-btn sccap-btn-ghost"
        onClick={() => setOpen((o) => !o)}
        style={{ padding: "4px 10px 4px 4px", gap: 8 }}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            background: "var(--primary-weak)",
            color: "var(--primary)",
            display: "grid",
            placeItems: "center",
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          {ROLE_INITIALS[role]}
        </div>
        <div style={{ textAlign: "left", lineHeight: 1.15 }}>
          <div style={{ fontSize: 12.5, fontWeight: 500, color: "var(--fg)" }}>
            {ROLE_LABELS[role]}
          </div>
          <div style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
            {email ?? ""}
          </div>
        </div>
        <Icon.ChevronD size={12} />
      </button>
      {open && (
        <div
          className="surface fade-in"
          role="menu"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            right: 0,
            width: 240,
            padding: 6,
            boxShadow: "var(--shadow-md)",
            zIndex: 30,
          }}
        >
          <div
            style={{
              padding: "6px 10px",
              fontSize: 11,
              color: "var(--fg-subtle)",
              textTransform: "uppercase",
              letterSpacing: ".06em",
            }}
          >
            View as (preview)
          </div>
          {(["dev", "enterprise", "admin"] as SccapRole[]).map((r) => (
            <button
              key={r}
              role="menuitemradio"
              aria-checked={role === r}
              onClick={() => {
                setRole(r);
                setOpen(false);
              }}
              style={{
                display: "flex",
                width: "100%",
                alignItems: "center",
                gap: 10,
                padding: "8px 10px",
                borderRadius: 6,
                border: "none",
                background: role === r ? "var(--bg-soft)" : "transparent",
                color: "var(--fg)",
                cursor: "pointer",
                textAlign: "left",
                fontFamily: "inherit",
                fontSize: 13,
              }}
            >
              <span style={{ flex: 1 }}>{ROLE_LABELS[r]}</span>
              {role === r && <Icon.Check size={14} />}
            </button>
          ))}
          <div
            style={{ height: 1, background: "var(--border)", margin: "6px 0" }}
          />
          <button
            onClick={handleSignOut}
            style={{
              display: "flex",
              width: "100%",
              alignItems: "center",
              gap: 10,
              padding: "8px 10px",
              borderRadius: 6,
              border: "none",
              background: "transparent",
              color: "var(--fg-muted)",
              cursor: "pointer",
              fontFamily: "inherit",
              fontSize: 13,
            }}
          >
            <Icon.Lock size={14} /> <span>Sign out</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default TopNav;
