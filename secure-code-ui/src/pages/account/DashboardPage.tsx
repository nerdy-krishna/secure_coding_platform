// secure-code-ui/src/pages/account/DashboardPage.tsx
//
// Role-aware dashboard router. Matches the SCCAP design bundle's
// top-level Dashboard component — picks one of three variants based
// on the previewed role. Per the plan, `admin` reuses the enterprise
// view until the backend has a dedicated admin-snapshot dataset; the
// sign-in gate still enforces real is_superuser for the /admin/*
// routes regardless of what role is previewed here.

import React from "react";
import { useTheme } from "../../app/providers/ThemeProvider";
import { DevDashboard } from "../../features/dashboard/components/DevDashboard";
import { EnterpriseDashboard } from "../../features/dashboard/components/EnterpriseDashboard";

const DashboardPage: React.FC = () => {
  const { role } = useTheme();

  if (role === "enterprise" || role === "admin") {
    return <EnterpriseDashboard />;
  }
  return <DevDashboard />;
};

export default DashboardPage;
