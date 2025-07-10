// src/shared/api/promptService.ts
import type {
    PromptTemplateCreate,
    PromptTemplateRead,
    PromptTemplateUpdate,
} from "../types/api";
import apiClient from "./apiClient";

export const promptService = {
  /**
   * Fetches all prompt templates.
   */
  getPrompts: async (): Promise<PromptTemplateRead[]> => {
    const response = await apiClient.get<PromptTemplateRead[]>("/admin/prompts/");
    return response.data;
  },

  /**
   * Creates a new prompt template.
   */
  createPrompt: async (
    promptData: PromptTemplateCreate,
  ): Promise<PromptTemplateRead> => {
    const response = await apiClient.post<PromptTemplateRead>(
      "/admin/prompts/",
      promptData,
    );
    return response.data;
  },

  /**
   * Updates an existing prompt template.
   */
  updatePrompt: async (
    templateId: string,
    promptData: PromptTemplateUpdate,
  ): Promise<PromptTemplateRead> => {
    const response = await apiClient.patch<PromptTemplateRead>(
      `/admin/prompts/${templateId}`,
      promptData,
    );
    return response.data;
  },

  /**
   * Deletes a prompt template by its ID.
   */
  deletePrompt: async (templateId: string): Promise<void> => {
    await apiClient.delete(`/admin/prompts/${templateId}`);
  },
};