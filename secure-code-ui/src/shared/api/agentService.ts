// src/shared/api/agentService.ts
import type { AgentRead } from "../types/api";
import apiClient from "./apiClient";

export const agentService = {
  /**
   * Fetches all specialized agents.
   */
  getAgents: async (): Promise<AgentRead[]> => {
    const response = await apiClient.get<AgentRead[]>("/admin/agents/");
    return response.data;
  },
};