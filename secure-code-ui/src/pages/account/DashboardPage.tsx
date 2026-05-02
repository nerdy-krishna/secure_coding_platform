// secure-code-ui/src/pages/account/DashboardPage.tsx
//
// Role-aware dashboard router. H.3 dropped the enterprise variant and
// narrowed roles to user + admin. The choice is driven by the real
// `user.is_superuser` flag, which is also what the route guards use.

import React from "react";
import { AdminSnapshot } from "../../features/dashboard/components/AdminSnapshot";
import { UserDashboard } from "../../features/dashboard/components/UserDashboard";
import { useAuth } from "../../shared/hooks/useAuth";

const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  return user?.is_superuser ? <AdminSnapshot /> : <UserDashboard />;
};

export default DashboardPage;
