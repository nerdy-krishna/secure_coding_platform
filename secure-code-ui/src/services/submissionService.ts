// secure-code-ui/src/services/submissionService.ts
import {
  type AnalysisResultResponse,
  type CodeSubmissionRequest,
  type CodeSubmissionResponse,
  type SubmissionHistoryItem,
} from "../types/api";
import apiClient from "./apiClient";

// Remove any const API_BASE_PATH = "/api/v1"; from here.

export const submissionService = {
  submitCode: async (
    payload: CodeSubmissionRequest,
  ): Promise<CodeSubmissionResponse> => {
    const response = await apiClient.post<CodeSubmissionResponse>(
      "/analyze", // Path relative to apiClient.baseURL
      payload,
    );
    return response.data;
  },

  getAnalysisResult: async (
    submissionId: string,
  ): Promise<AnalysisResultResponse> => {
    const response = await apiClient.get<AnalysisResultResponse>(
      `/results/${submissionId}`, // Path relative to apiClient.baseURL
    );
    return response.data;
  },

  getSubmissionHistory: async (): Promise<SubmissionHistoryItem[]> => {
    const response = await apiClient.get<SubmissionHistoryItem[]>(
      "/users/me/submissions", // Path relative to apiClient.baseURL
    );
    return response.data;
  },
};
