// src/shared/api/frameworkService.ts
import type {
  FrameworkAgentMappingUpdate,
  FrameworkCreate,
  FrameworkRead,
  FrameworkUpdate,
} from "../types/api";
import apiClient from "./apiClient";

// V02.2.1: UUID-format guard used for all path-interpolated IDs.
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function assertUuid(id: string): void {
  if (!UUID_RE.test(id)) {
    throw new Error(`Invalid UUID: ${id}`);
  }
}

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
    // V02.2.1: Validate name / display_name length at runtime.
    if (
      typeof frameworkData.name !== "string" ||
      frameworkData.name.length > 100
    ) {
      throw new Error("name must be a string of at most 100 characters");
    }
    // V15.3.3: Send only the fields the form actually edits; backend
    // mass-assignment guards remain authoritative for any extra fields.
    const payload = {
      name: frameworkData.name,
      description: frameworkData.description,
    };
    const response = await apiClient.post<FrameworkRead>(
      "/admin/frameworks/",
      payload,
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
    // V02.2.1: Reject non-UUID framework ids before path interpolation.
    assertUuid(frameworkId);
    // V02.2.1: Validate name length at runtime.
    if (
      frameworkData.name !== undefined &&
      frameworkData.name !== null &&
      (typeof frameworkData.name !== "string" ||
        frameworkData.name.length > 100)
    ) {
      throw new Error("name must be a string of at most 100 characters");
    }
    // V15.3.3: Send only the fields the form actually edits; backend
    // mass-assignment guards remain authoritative for any extra fields.
    const payload = {
      name: frameworkData.name,
      description: frameworkData.description,
    };
    // V01.2.2: encodeURIComponent prevents URL path manipulation via the id.
    const response = await apiClient.patch<FrameworkRead>(
      `/admin/frameworks/${encodeURIComponent(frameworkId)}`,
      payload,
    );
    return response.data;
  },

  /**
  * Deletes a security framework by its ID.
   */
  deleteFramework: async (frameworkId: string): Promise<void> => {
    // V02.2.1: Reject non-UUID framework ids before path interpolation.
    assertUuid(frameworkId);
    // V01.2.2: encodeURIComponent prevents URL path manipulation via the id.
    await apiClient.delete(
      `/admin/frameworks/${encodeURIComponent(frameworkId)}`,
    );
  },

  /**
   * Updates the agent mappings for a framework.
   */
  updateAgentMappings: async (
    frameworkId: string,
    agentIds: string[],
  ): Promise<FrameworkRead> => {
    // V02.2.1: Reject non-UUID framework ids before path interpolation.
    assertUuid(frameworkId);
    // V02.2.1: Validate agentIds array length and each id format.
    if (!Array.isArray(agentIds) || agentIds.length > 100) {
      throw new Error("Invalid agent ids: must be an array of at most 100 ids");
    }
    for (const agentId of agentIds) {
      assertUuid(agentId);
    }
    const payload: FrameworkAgentMappingUpdate = { agent_ids: agentIds };
    // V01.2.2: encodeURIComponent prevents URL path manipulation via the id.
    const response = await apiClient.post<FrameworkRead>(
      `/admin/frameworks/${encodeURIComponent(frameworkId)}/agents`,
      payload,
    );
    return response.data;
  },
};
