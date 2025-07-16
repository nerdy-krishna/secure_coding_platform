// src/shared/api/ragService.ts
import type {
  JsonValue,
  PreprocessingResponse,
  RAGDocument,
  RAGJobStartResponse,
  RAGJobStatusResponse,
} from "../types/api";
import apiClient from "./apiClient";

interface GetDocumentsResponse {
  ids: string[];
  documents: string[];
  metadatas: Record<string, JsonValue>[];
}

export const ragService = {
  /**
   * Ingests a CSV file for a specific framework.
   */
  ingestDocuments: async (
    frameworkName: string,
    file: File,
  ): Promise<{ message: string }> => {
    const formData = new FormData();
    formData.append("framework_name", frameworkName);
    formData.append("file", file);

    const response = await apiClient.post<{ message: string }>(
      "/admin/rag/ingest",
      formData,
      {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      },
    );
    return response.data;
  },

  /**
   * Gets all documents for a specific framework.
   */
  getDocuments: async (frameworkName: string): Promise<RAGDocument[]> => {
    const response = await apiClient.get<GetDocumentsResponse>(
      `/admin/rag/frameworks/${frameworkName}`,
    );
    // Ensure we handle cases where parts of the response might be null or undefined
    const ids = response.data?.ids || [];
    const documents = response.data?.documents || [];
    const metadatas = response.data?.metadatas || [];

    return ids.map((id, index) => ({
      id,
      document: documents[index] || "",
      metadata: metadatas[index] || {},
    }));
  },

  /**
   * Deletes a list of documents by their IDs.
   */
  deleteDocuments: async (documentIds: string[]): Promise<void> => {
    await apiClient.delete("/admin/rag/documents", {
      data: { document_ids: documentIds },
    });
  },

  preprocessFramework: async (
    formData: FormData,
  ): Promise<PreprocessingResponse> => {
    const response = await apiClient.post<PreprocessingResponse>(
      "/admin/rag/preprocess-framework",
      formData,
      {
        headers: { "Content-Type": "multipart/form-data" },
      },
    );
    return response.data;
  },

  ingestProcessed: async (
    payload: PreprocessingResponse,
  ): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(
      "/admin/rag/ingest-processed",
      payload,
    );
    return response.data;
  },

  startPreprocessing: async (
    formData: FormData,
  ): Promise<RAGJobStartResponse> => {
    const response = await apiClient.post<RAGJobStartResponse>(
      "/admin/rag/preprocess/start",
      formData,
    );
    return response.data;
  },

  approveJob: async (jobId: string): Promise<{ message: string }> => {
    const response = await apiClient.post<{ message: string }>(
      `/admin/rag/preprocess/${jobId}/approve`,
    );
    return response.data;
  },

  getJobStatus: async (jobId: string): Promise<RAGJobStatusResponse> => {
    const response = await apiClient.get<RAGJobStatusResponse>(
      `/admin/rag/preprocess/${jobId}/status`,
    );
    return response.data;
  },
};