import {
  type LLMConfiguration,
  type LLMConfigurationCreate,
} from "../types/api";
import apiClient from "./apiClient";

// Use Partial to make all fields optional for the update payload
export type LLMConfigurationUpdate = Partial<Omit<LLMConfigurationCreate, 'api_key'>> & { api_key?: string };


export const llmConfigService = {
  /**
   * Fetches all available LLM configurations.
   */
  getLlmConfigs: async (): Promise<LLMConfiguration[]> => {
    const response = await apiClient.get<LLMConfiguration[]>(
      "/admin/llm-configs/",
    );
    return response.data;
  },

  /**
   * Creates a new LLM provider configuration.
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
   * (NEW) Updates an existing LLM configuration.
   * @param configId The ID of the configuration to update.
   * @param configData The data to update. API key is optional.
   */
  updateLlmConfig: async (
    configId: string,
    configData: LLMConfigurationUpdate,
  ): Promise<LLMConfiguration> => {
    const response = await apiClient.patch<LLMConfiguration>(
      `/admin/llm-configs/${configId}`,
      configData,
    );
    return response.data;
  },

  /**
   * Deletes an LLM configuration by its ID.
   */
  deleteLlmConfig: async (configId: string): Promise<void> => {
    await apiClient.delete(`/admin/llm-configs/${configId}`);
  },
};