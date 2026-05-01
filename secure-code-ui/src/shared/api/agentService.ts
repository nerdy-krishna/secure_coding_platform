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
    // V02.2.1: Runtime guard — reject non-UUID agent ids before interpolation.
    if (!/^[0-9a-fA-F-]{32,36}$/.test(agentId)) {
      throw new Error("Invalid agent id");
    }
    // V15.3.3: Explicit allow-list payload (defense-in-depth; backend also enforces mass-assignment guards).
    const payload: AgentUpdate = {
      name: agentData.name,
      description: agentData.description,
    };
    // V01.2.2: URL-encode the path parameter to prevent path-component escape.
    const response = await apiClient.patch<AgentRead>(
      `/admin/agents/${encodeURIComponent(agentId)}`,
      payload,
    );
    return response.data;
  },

  /**
   * Deletes an agent.
   */
  deleteAgent: async (agentId: string): Promise<void> => {
    // V02.2.1: Runtime guard — reject non-UUID agent ids before interpolation.
    if (!/^[0-9a-fA-F-]{32,36}$/.test(agentId)) {
      throw new Error("Invalid agent id");
    }
    // V01.2.2: URL-encode the path parameter to prevent path-component escape.
    await apiClient.delete(`/admin/agents/${encodeURIComponent(agentId)}`);
  },
};