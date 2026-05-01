// secure-code-ui/src/shared/api/adminFindings.ts
//
// Cross-tenant findings list (sast-prescan-followups Group D1).
// Backed by GET /api/v1/admin/findings — superuser-only, scoped via
// `visible_user_ids` server-side. Cursor pagination via finding id.

import apiClient from "./apiClient";

export type AdminFindingSource = "bandit" | "semgrep" | "gitleaks" | "agent";

export interface AdminFindingItem {
  id: number;
  scan_id: string;
  file_path: string;
  line_number: number | null;
  title: string;
  severity: string | null;
  cwe: string | null;
  confidence: string | null;
  source: string | null;
}

export interface AdminFindingsResponse {
  items: AdminFindingItem[];
  next_cursor: number | null;
  requested_at: string;
}

export interface AdminFindingsQuery {
  source?: AdminFindingSource;
  limit?: number;
  cursor?: number;
}

export async function listAdminFindings(
  query: AdminFindingsQuery = {},
): Promise<AdminFindingsResponse> {
  const params: Record<string, string | number> = {};
  if (query.source && ['bandit', 'semgrep', 'gitleaks', 'agent'].includes(query.source)) {
    params.source = query.source;
  }
  if (query.limit !== undefined) {
    const lim = Math.max(1, Math.min(500, Math.trunc(query.limit)));
    params.limit = lim;
  }
  if (query.cursor !== undefined) {
    const c = Math.max(0, Math.trunc(query.cursor));
    if (Number.isFinite(c)) params.cursor = c;
  }
  const response = await apiClient.get<AdminFindingsResponse>(
    "/admin/findings",
    { params },
  );
  return response.data;
}
