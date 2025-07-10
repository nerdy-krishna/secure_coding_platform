// src/shared/api/agentService.ts
import type { AgentRead } from "../types/api";
import { type AgentCreate, type AgentUpdate } from "../types/api"; // Added types
import apiClient from "./apiClient";

export const agentService = {
  /**
   * Fetches all specialized agents.
   */
  getAgents: async (): Promise<AgentRead[]> => {
    const response = await apiClient.get<AgentRead[]>("/admin/agents/");
    return response.data;
  },

  /**
   * Creates a new agent.
   */
  createAgent: async (agentData: AgentCreate): Promise<AgentRead> => {
    const response = await apiClient.post<AgentRead>(
      "/admin/agents/",
      agentData,
    );
    return response.data;
  },

  /**
   * Updates an existing agent.
   */
  updateAgent: async (
    agentId: string,
    agentData: AgentUpdate,
  ): Promise<AgentRead> => {
    const response = await apiClient.patch<AgentRead>(
      `/admin/agents/${agentId}`,
      agentData,
    );
    return response.data;
  },

  /**
   * Deletes an agent.
   */
  deleteAgent: async (agentId: string): Promise<void> => {
    await apiClient.delete(`/admin/agents/${agentId}`);
  },
};