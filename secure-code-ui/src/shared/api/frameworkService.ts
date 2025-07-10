// src/shared/api/frameworkService.ts
import type {
  FrameworkAgentMappingUpdate,
  FrameworkCreate,
  FrameworkRead,
  FrameworkUpdate,
} from "../types/api";
import apiClient from "./apiClient";

export const frameworkService = {
  /**
   * Fetches all security frameworks.
   */
  getFrameworks: async (): Promise<FrameworkRead[]> => {
    const response = await apiClient.get<FrameworkRead[]>("/admin/frameworks/");
    return response.data;
  },

  /**
   * Creates a new security framework.
   */
  createFramework: async (
    frameworkData: FrameworkCreate,
  ): Promise<FrameworkRead> => {
    const response = await apiClient.post<FrameworkRead>(
      "/admin/frameworks/",
      frameworkData,
    );
    return response.data;
  },

  /**
   * Updates an existing security framework.
   */
  updateFramework: async (
    frameworkId: string,
    frameworkData: FrameworkUpdate,
  ): Promise<FrameworkRead> => {
    const response = await apiClient.patch<FrameworkRead>(
      `/admin/frameworks/${frameworkId}`,
      frameworkData,
    );
    return response.data;
  },

  /**
  * Deletes a security framework by its ID.
   */
  deleteFramework: async (frameworkId: string): Promise<void> => {
    await apiClient.delete(`/admin/frameworks/${frameworkId}`);
  },

  /**
   * Updates the agent mappings for a framework.
   */
  updateAgentMappings: async (
    frameworkId: string,
    agentIds: string[],
  ): Promise<FrameworkRead> => {
    const payload: FrameworkAgentMappingUpdate = { agent_ids: agentIds };
    const response = await apiClient.post<FrameworkRead>(
      `/admin/frameworks/${frameworkId}/agents`,
      payload,
    );
    return response.data;
  },
};