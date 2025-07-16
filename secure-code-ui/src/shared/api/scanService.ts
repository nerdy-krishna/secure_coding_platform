import {
  type GitRepoPreviewRequest,
  type JsonValue,
  type LLMInteractionResponse,
  type PaginatedProjectHistoryResponse,
  type PaginatedScanHistoryResponse,
  type ScanResponse,
  type ScanResultResponse
} from "../types/api";
import apiClient from "./apiClient";

export const scanService = {
  /**
   * Submits code for a new scan under a project.
   */
  createScan: async (payload: FormData): Promise<ScanResponse> => {
    const response = await apiClient.post<ScanResponse>("/scans", payload);
    return response.data;
  },

  /**
   * Fetches the file list from a remote Git repository for preview.
   */
  previewGitRepo: async (repoUrl: string): Promise<string[]> => {
    const requestPayload: GitRepoPreviewRequest = { repo_url: repoUrl };
    const response = await apiClient.post<{ files: string[] }>(
      "/scans/preview-git",
      requestPayload
    );
    return response.data.files;
  },

  /**
   * Fetches the file list from an uploaded archive for preview.
   */
  previewArchive: async (archiveFile: File): Promise<string[]> => {
    const formData = new FormData();
    formData.append("archive_file", archiveFile);
    const response = await apiClient.post<{ files: string[] }>(
      "/scans/preview-archive",
      formData
    );
    return response.data.files;
  },

  /**
   * Fetches the full analysis result for a given scan.
   */
  getScanResult: async (scanId: string): Promise<ScanResultResponse> => {
    const response = await apiClient.get<ScanResultResponse>(`/scans/${scanId}/result`);
    return response.data;
  },

  /**
   * Fetches a paginated list of all projects for the current user.
   */
  getProjectHistory: async (
    page: number,
    pageSize: number,
    search?: string,
  ): Promise<PaginatedProjectHistoryResponse> => {
    const response = await apiClient.get<PaginatedProjectHistoryResponse>("/projects", {
        params: {
            skip: (page - 1) * pageSize,
            limit: pageSize,
            search: search || undefined,
        }
    });
    return response.data;
  },
  
  /**
   * Searches for projects by name for autocomplete.
   */
  searchProjects: async (query: string): Promise<string[]> => {
    if (!query) return [];
    const response = await apiClient.get<string[]>("/projects/search", {
      params: { q: query },
    });
    return response.data;
  },

  /**
   * Fetches a paginated list of all scans for the current user.
   */
  getScanHistory: async (
    page: number,
    pageSize: number,
    search?: string,
    sortOrder?: string,
    status?: string,
  ): Promise<PaginatedScanHistoryResponse> => {
    const response = await apiClient.get<PaginatedScanHistoryResponse>("/scans/history", {
        params: {
            page,
            page_size: pageSize,
            search: search || undefined,
            sort_order: sortOrder,
            status: status === 'All' ? undefined : status,
        }
    });
    return response.data;
  },

  /**
   * Fetches the SARIF report for a specific scan.
   */
  downloadSarifReport: async (scanId: string): Promise<JsonValue> => {
    const response = await apiClient.get(`/scans/${scanId}/sarif`);
    return response.data;
  },

  /**
   * Fetches a paginated list of scans for a specific project.
   */
  getScansForProject: async (
    projectId: string,
    page: number,
    pageSize: number
  ): Promise<PaginatedScanHistoryResponse> => {
    const response = await apiClient.get<PaginatedScanHistoryResponse>(`/projects/${projectId}/scans`, {
      params: {
        skip: (page - 1) * pageSize,
        limit: pageSize,
      },
    });
    return response.data;
  },

  /**
   * Sends an approval request for a scan pending cost confirmation.
   */
  approveScan: async (scanId: string): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(`/scans/${scanId}/approve`);
    return response.data;
  },

  /**
   * Fetches the LLM interactions for a specific scan.
   */
  getLlmInteractionsForScan: async (scanId: string): Promise<LLMInteractionResponse[]> => {
    const response = await apiClient.get<LLMInteractionResponse[]>(`/scans/${scanId}/llm-interactions`);
    return response.data;
  },

  /**
   * Cancels a scan that is pending approval.
   */
  cancelScan: async (scanId: string): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(`/scans/${scanId}/cancel`);
    return response.data;
  },

  /**
   * Triggers the application of selected fixes for a completed scan.
   */
  applySelectiveFixes: async (scanId: string, findingIds: number[]): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(
      `/scans/${scanId}/apply-fixes`,
      { finding_ids: findingIds } // Send the finding IDs in the request body
    );
    return response.data;
  },

  deleteScan: async (scanId: string): Promise<void> => {
    await apiClient.delete(`/scans/${scanId}`);
  },

  deleteProject: async (projectId: string): Promise<void> => {
    await apiClient.delete(`/projects/${projectId}`);
  },
};