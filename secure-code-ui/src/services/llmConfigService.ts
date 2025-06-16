// secure-code-ui/src/services/llmConfigService.ts
import {
  type LLMConfiguration,
  type LLMConfigurationCreate,
} from "../types/api";
import apiClient from "./apiClient";

export const llmConfigService = {
  /**
   * Fetches all available LLM configurations.
   * API keys are not included in the response.
   */
  getLlmConfigs: async (): Promise<LLMConfiguration[]> => {
    const response = await apiClient.get<LLMConfiguration[]>(
      "/admin/llm-configs/",
    );
    return response.data;
  },

  /**
   * Creates a new LLM provider configuration.
   * Requires superuser privileges.
   * @param configData The data for the new configuration, including the API key.
   */
  createLlmConfig: async (
    configData: LLMConfigurationCreate,
  ): Promise<LLMConfiguration> => {
    const response = await apiClient.post<LLMConfiguration>(
      "/admin/llm-configs/",
      configData,
    );
    return response.data;
  },

  /**
   * Deletes an LLM configuration by its ID.
   * Requires superuser privileges.
   * @param configId The UUID of the configuration to delete.
   */
  deleteLlmConfig: async (configId: string): Promise<void> => {
    await apiClient.delete(`/admin/llm-configs/${configId}`);
  },
};