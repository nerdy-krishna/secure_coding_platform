// secure-code-ui/src/shared/api/complianceService.ts
import apiClient from "./apiClient";

export type FrameworkIngestMode = "csv" | "git_url";

export interface ComplianceFrameworkStats {
  name: string;
  display_name: string;
  description: string;
  framework_type: "default" | "custom";
  ingest_mode: FrameworkIngestMode | null;
  is_installed: boolean;
  doc_count: number;
  findings_matched: number;
  open_findings: number;
  score: number;
  last_scanned_at: string | null;
}

export interface ComplianceControl {
  control_id: string;
  title: string;
  count: number;
  sample: string | null;
}

export const complianceService = {
  getStats: async (): Promise<ComplianceFrameworkStats[]> => {
    const res = await apiClient.get<ComplianceFrameworkStats[]>(
      "/compliance/stats",
    );
    return res.data;
  },

  getControls: async (
    frameworkName: string,
  ): Promise<ComplianceControl[]> => {
    const res = await apiClient.get<ComplianceControl[]>(
      `/compliance/frameworks/${encodeURIComponent(frameworkName)}/controls`,
    );
    return res.data;
  },
};
