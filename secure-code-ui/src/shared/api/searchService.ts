// secure-code-ui/src/shared/api/searchService.ts
import apiClient from "./apiClient";

export interface SearchProjectHit {
  id: string;
  name: string;
  matched_on: "name";
}

export interface SearchScanHit {
  id: string;
  project_name: string;
  status: string;
  matched_on: "scan_id_prefix";
}

export interface SearchFindingHit {
  id: number;
  scan_id: string;
  title: string;
  file_path: string;
  severity: string | null;
  matched_on: "title" | "file_path";
}

export interface SearchResults {
  projects: SearchProjectHit[];
  scans: SearchScanHit[];
  findings: SearchFindingHit[];
}

export const searchService = {
  search: async (q: string, limit = 10): Promise<SearchResults> => {
    const res = await apiClient.get<SearchResults>("/search", {
      params: { q, limit },
    });
    return res.data;
  },
};
