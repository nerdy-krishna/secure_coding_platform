// secure-code-ui/src/shared/api/dashboardService.ts
import apiClient from "./apiClient";

export interface DashboardOpenFindings {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface DashboardStats {
  risk_score: number;
  open_findings: DashboardOpenFindings;
  fixes_ready: number;
  scans_this_month: number;
  scans_trend: number[];
  cost_this_month_usd: number;
}

export const dashboardService = {
  getStats: async (): Promise<DashboardStats> => {
    const res = await apiClient.get<DashboardStats>("/dashboard/stats");
    return res.data;
  },
};
