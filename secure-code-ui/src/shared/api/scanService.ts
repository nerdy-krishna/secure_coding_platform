import {
  type GitRepoPreviewRequest,
  type LLMInteractionResponse,
  type PaginatedProjectHistoryResponse,
  type PaginatedScanHistoryResponse,
  type PrescanReviewResponse,
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
   * Fetches deterministic-scanner findings for the prescan-approval card.
   *
   * Only valid while the scan is at PENDING_PRESCAN_APPROVAL (gate) or
   * already in one of the prescan-terminal states (BLOCKED_PRE_LLM /
   * BLOCKED_USER_DECLINE). Other statuses return 400. ADR-009 / G6.
   */
  getPrescanReview: async (scanId: string): Promise<PrescanReviewResponse> => {
    const response = await apiClient.get<PrescanReviewResponse>(
      `/scans/${scanId}/prescan-findings`,
    );
    return response.data;
  },

  /**
   * Resume a scan paused at one of the worker-graph interrupt points.
   *
   * Two interrupt points exist (ADR-009): the new prescan-approval
   * gate (status PENDING_PRESCAN_APPROVAL) and the existing cost-
   * approval gate (status PENDING_COST_APPROVAL). The body's `kind`
   * field discriminates; missing body defaults to `cost_approval`
   * for backward-compat with older callers.
   */
  approveScan: async (
    scanId: string,
    payload?: {
      kind?: "prescan_approval" | "cost_approval";
      approved?: boolean;
      override_critical_secret?: boolean;
    },
  ): Promise<{ message: string }> => {
    const body =
      payload && (payload.kind || payload.approved !== undefined || payload.override_critical_secret !== undefined)
        ? {
            kind: payload.kind ?? "cost_approval",
            approved: payload.approved ?? true,
            override_critical_secret: payload.override_critical_secret ?? false,
          }
        : undefined;
    const response = await apiClient.post<{ message: string }>(
      `/scans/${scanId}/approve`,
      body,
    );
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

  createProject: async (name: string): Promise<{ id: string; name: string }> => {
    const response = await apiClient.post<{ id: string; name: string }>("/projects", { name });
    return response.data;
  },

  deleteScan: async (scanId: string): Promise<void> => {
    await apiClient.delete(`/scans/${scanId}`);
  },

  deleteProject: async (projectId: string): Promise<void> => {
    await apiClient.delete(`/projects/${projectId}`);
  },
};