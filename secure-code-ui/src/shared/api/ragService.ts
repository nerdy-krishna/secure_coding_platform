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

    return ids.map((id: string, index: number) => ({
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
    targetLanguages: string[] = []
  ): Promise<RAGJobStartResponse> => {
    targetLanguages.forEach(lang => formData.append('target_languages', lang));
    const response = await apiClient.post<RAGJobStartResponse>(
      "/admin/rag/preprocess/start",
      formData,
    );
    return response.data;
  },

  reprocessFramework: async (
    frameworkName: string,
    targetLanguages: string[],
    llmConfigId: string
  ): Promise<RAGJobStartResponse> => {
    const response = await apiClient.post<RAGJobStartResponse>(
      "/admin/rag/preprocess/reprocess",
      {
        framework_name: frameworkName,
        target_languages: targetLanguages,
        llm_config_id: llmConfigId,
      }
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

  // --- Security Standards Ingestion ---

  ingestASVS: async (file: File): Promise<{ message: string; count: number }> => {
    const formData = new FormData();
    formData.append("file", file);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/asvs",
      formData,
    );
    return response.data;
  },

  ingestProactiveControls: async (url: string): Promise<{ message: string; count: number }> => {
    const formData = new FormData();
    formData.append("url", url);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/proactive-controls",
      formData,
    );
    return response.data;
  },

  ingestCheatsheet: async (url: string): Promise<{ message: string; count: number }> => {
    const formData = new FormData();
    formData.append("url", url);
    const response = await apiClient.post<{ message: string; count: number }>(
      "/admin/rag/ingest/standards/cheatsheets",
      formData,
    );
    return response.data;
  },

  getStats: async (): Promise<Record<string, number>> => {
    const response = await apiClient.get<Record<string, number>>("/admin/rag/ingest/stats");
    return response.data;
  },
};