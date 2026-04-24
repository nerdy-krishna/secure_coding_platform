// secure-code-ui/src/widgets/AdminSubNav.tsx
//
// Horizontal sub-nav rendered by DashboardLayout on /admin/* routes so
// users can move between admin surfaces without typing URLs. The top
// nav still has a single "Admin" link; this strip carries the detail.

import React from "react";
import { Link, useLocation } from "react-router-dom";

interface AdminLink {
  to: string;
  label: string;
}

const ADMIN_LINKS: AdminLink[] = [
  { to: "/admin/system", label: "Platform" },
  { to: "/admin/users", label: "Users" },
  { to: "/admin/user-groups", label: "Groups" },
  { to: "/admin/agents", label: "Agents" },
  { to: "/admin/frameworks", label: "Frameworks" },
  { to: "/admin/prompts", label: "Prompts" },
  { to: "/admin/smtp", label: "SMTP" },
  { to: "/account/settings/llm", label: "LLM configs" },
];

export const AdminSubNav: React.FC = () => {
  const { pathname } = useLocation();
  return (
    <div
      style={{
        display: "flex",
        gap: 4,
        flexWrap: "wrap",
        padding: 4,
        borderRadius: 12,
        border: "1px solid var(--border)",
        background: "var(--bg-soft)",
        marginBottom: 20,
      }}
    >
      {ADMIN_LINKS.map((l) => {
        const active = pathname === l.to || pathname.startsWith(l.to + "/");
        return (
          <Link
            key={l.to}
            to={l.to}
            style={{
              padding: "6px 12px",
              borderRadius: 8,
              fontSize: 12.5,
              fontWeight: 500,
              textDecoration: "none",
              background: active ? "var(--bg-elev)" : "transparent",
              color: active ? "var(--fg)" : "var(--fg-muted)",
              boxShadow: active ? "var(--shadow-xs)" : "none",
            }}
          >
            {l.label}
          </Link>
        );
      })}
    </div>
  );
};

export default AdminSubNav;
