// secure-code-ui/src/shared/api/submissionService.ts
import {
  type AnalysisResultResponse,
  type CodeSubmissionResponse,
  type PaginatedResultsResponse,
  type PaginatedSubmissionHistoryResponse,
  type RemediationRequest // ADDED
} from "../types/api";
import apiClient from "./apiClient";


export const submissionService = {
  /**
   * Submits code for analysis.
   * @param payload The FormData object containing files and other submission data.
   */
  submitCode: async (
    payload: FormData
  ): Promise<CodeSubmissionResponse> => {
    const response = await apiClient.post<CodeSubmissionResponse>(
      "/submit",
      payload,
      {
        // Axios automatically sets the 'Content-Type' header for FormData
      }
    );
    return response.data;
  },

  /**
   * Fetches the file list from a remote Git repository for preview.
   */
  previewGitRepo: async (repoUrl: string): Promise<string[]> => {
    const response = await apiClient.post<{ files: string[] }>(
      "/submit/preview-git",
      { repo_url: repoUrl }
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
      "/submit/preview-archive",
      formData
    );
    return response.data.files;
  },

  /**
   * Fetches the full analysis result for a given submission.
   */
  getAnalysisResult: async (
    submissionId: string
  ): Promise<AnalysisResultResponse> => { // Corrected: Return type is AnalysisResultResponse
    const response = await apiClient.get<AnalysisResultResponse>(
      `/result/${submissionId}`
    );
    return response.data;
  },

  /**
   * Fetches the list of past submissions for the current user.
   */
  getSubmissionHistory: async (
    page: number,
    pageSize: number,
    search?: string,
  ): Promise<PaginatedSubmissionHistoryResponse> => {
    const response = await apiClient.get<PaginatedSubmissionHistoryResponse>("/history", {
        params: {
            skip: (page - 1) * pageSize,
            limit: pageSize,
            search: search || undefined, // Only include search param if it's not empty
        }
    });
    return response.data;
  },

  /**
   * Fetches a paginated list of all completed analysis results.
   * @param page The current page number.
   * @param pageSize The number of items per page.
   * @param search An optional search term.
   */
  getResults: async (
    page: number,
    pageSize: number,
    search?: string,
  ): Promise<PaginatedResultsResponse> => {
    const response = await apiClient.get<PaginatedResultsResponse>("/results", {
      params: {
        skip: (page - 1) * pageSize,
        limit: pageSize,
        search: search || undefined,
      },
    });
    return response.data;
  },
};

/**
 * Sends a request to trigger the remediation workflow for a submission.
 * @param submissionId The ID of the submission to remediate.
 * @param remediationData The categories to be fixed.
 * @returns A promise that resolves with the server's confirmation message.
 */
export const triggerRemediation = async (
    submissionId: string,
    remediationData: RemediationRequest
): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(
        `/submissions/${submissionId}/remediate`,
        remediationData
    );
    return response.data;
};

/**
 * Sends an approval request for a submission pending cost confirmation.
 * @param submissionId The ID of the submission to approve.
 * @returns A promise that resolves with the server's confirmation message.
 */
export const approveSubmission = async (submissionId: string): Promise<{ message: string }> => {
  try {
    const response = await apiClient.post<{ message: string }>(`/submissions/${submissionId}/approve`);
    return response.data;
  } catch (error) {
    // Axios errors can be handled here or in the calling component
    console.error(`Error approving submission ${submissionId}:`, error);
    throw error;
  }
};

/**
 * Sends a cancellation request for a submission.
 * @param submissionId The ID of the submission to cancel.
 * @returns A promise that resolves with the server's confirmation message.
 */
export const cancelSubmission = async (submissionId: string): Promise<{ message: string }> => {
  try {
    const response = await apiClient.post<{ message: string }>(`/submissions/${submissionId}/cancel`);
    return response.data;
  } catch (error) {
    console.error(`Error cancelling submission ${submissionId}:`, error);
    throw error;
  }
};

/**
 * Sends a delete request for a submission. (Superuser only)
 * @param submissionId The ID of the submission to delete.
 */
export const deleteSubmission = async (submissionId: string): Promise<void> => {
    await apiClient.delete(`/submissions/${submissionId}`);
};