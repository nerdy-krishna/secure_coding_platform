// src/shared/api/ragService.ts
import type { JsonValue, RAGDocument } from "../types/api";
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
    const { ids, documents, metadatas } = response.data;
    return ids.map((id, index) => ({
      id,
      document: documents[index],
      metadata: metadatas[index],
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
};