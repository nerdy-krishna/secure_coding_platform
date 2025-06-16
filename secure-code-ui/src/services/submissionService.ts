// secure-code-ui/src/services/submissionService.ts
import {
  // Corrected: Use the type names exported from your api.ts
  type AnalysisResultResponse,
  type CodeSubmissionResponse,
  type SubmissionHistoryItem,
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
  getSubmissionHistory: async (): Promise<SubmissionHistoryItem[]> => { // Corrected: Return type is an array of SubmissionHistoryItem
    const response = await apiClient.get<SubmissionHistoryItem[]>("/history");
    return response.data;
  },
};