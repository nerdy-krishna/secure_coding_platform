// secure-code-ui/src/widgets/DashboardLayout.tsx
//
// Phase G.1 shell: top-nav + centered content + floating Tweaks panel.
// Replaces the previous Ant Sider/Header layout. The `children` prop
// keeps the route guards in App.tsx working unchanged — they wrap each
// authenticated route in this layout.
//
// The body background + color are driven by the SCCAP design tokens
// (--bg / --fg) so light/dark/variant toggles apply globally even
// though the inner pages still render Ant components for now. Ant's
// own surfaces (`.ant-card`, `.ant-table`, etc.) keep their white
// backgrounds — a jarring-ish transition while G.2–G.6 port each page,
// but acceptable since each page swap is independent.

import React from "react";
import { useLocation } from "react-router-dom";
import AdminSubNav from "./AdminSubNav";
import { TopNav } from "./TopNav/TopNav";
import { Tweaks } from "./Tweaks/Tweaks";

const DashboardLayout: React.FC<{ children?: React.ReactNode }> = ({
  children,
}) => {
  const { pathname } = useLocation();
  const isAdminArea =
    pathname.startsWith("/admin") ||
    pathname.startsWith("/account/settings/llm");
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg)",
        color: "var(--fg)",
        fontFamily: "var(--font-sans)",
      }}
    >
      <TopNav />
      <main
        style={{
          padding: "24px 28px 80px",
          maxWidth: 1440,
          margin: "0 auto",
        }}
      >
        {isAdminArea && <AdminSubNav />}
        {children}
      </main>
      <Tweaks />
    </div>
  );
};

export default DashboardLayout;
