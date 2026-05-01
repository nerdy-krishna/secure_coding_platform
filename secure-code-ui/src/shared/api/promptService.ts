// src/shared/api/promptService.ts
//
// DANGEROUS FUNCTIONALITY (V15.1.5): mutating prompt templates here changes
// the system prompts used by every audit/remediation agent run downstream.
// This is a supply-chain / prompt-injection surface — the admin UI must
// confirm with operators before save, and changes must be reviewable in an
// audit log server-side. Treat any new mutating endpoint added here with
// the same caution.
import type {
    PromptTemplateCreate,
    PromptTemplateRead,
    PromptTemplateUpdate,
} from "../types/api";
import apiClient from "./apiClient";

// V02.2.1: UUID format guard for template IDs used in URL paths.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function assertUuid(id: string): void {
  if (!UUID_RE.test(id)) {
    throw new Error("Invalid prompt");
  }
}

// V02.2.1: Field-length guard for prompt template payloads.
function assertFieldLengths(data: {
  name?: string | null;
  template_type?: string | null;
  agent_name?: string | null;
  variant?: string | null;
  version?: number | null;
  template_text?: string | null;
}): void {
  if (typeof data.name === "string" && data.name.length > 100) {
    throw new Error("Invalid prompt");
  }
  if (typeof data.template_text === "string" && data.template_text.length > 64_000) {
    throw new Error("Invalid prompt");
  }
}

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
    // V02.2.1: validate field lengths before sending.
    assertFieldLengths(promptData);
    // V15.3.3: build an explicit allow-list payload instead of forwarding the raw object.
    const payload: PromptTemplateCreate = {
      name: promptData.name,
      template_type: promptData.template_type,
      agent_name: promptData.agent_name,
      variant: promptData.variant,
      version: promptData.version,
      template_text: promptData.template_text,
    };
    const response = await apiClient.post<PromptTemplateRead>(
      "/admin/prompts/",
      payload,
    );
    return response.data;
  },

  /**
   * Updates an existing prompt template.
   *
   * WARNING (V15.1.5): changing a prompt template alters the system prompt
   * used by every downstream audit and remediation agent. This is a
   * prompt-injection / supply-chain risk — ensure operator confirmation and
   * server-side audit logging before persisting.
   */
  updatePrompt: async (
    templateId: string,
    promptData: PromptTemplateUpdate,
  ): Promise<PromptTemplateRead> => {
    // V02.2.1: reject non-UUID ids before they reach the URL.
    assertUuid(templateId);
    // V02.2.1: validate field lengths before sending.
    assertFieldLengths(promptData);
    // V15.3.3: build an explicit allow-list payload instead of forwarding the raw object.
    const payload: PromptTemplateUpdate = {};
    if (promptData.name !== undefined) payload.name = promptData.name;
    if (promptData.template_type !== undefined)
      payload.template_type = promptData.template_type;
    if (promptData.agent_name !== undefined)
      payload.agent_name = promptData.agent_name;
    if (promptData.variant !== undefined) payload.variant = promptData.variant;
    if (promptData.version !== undefined) payload.version = promptData.version;
    if (promptData.template_text !== undefined)
      payload.template_text = promptData.template_text;
    const response = await apiClient.patch<PromptTemplateRead>(
      // V01.2.2: encode templateId to prevent URL path manipulation.
      `/admin/prompts/${encodeURIComponent(templateId)}`,
      payload,
    );
    return response.data;
  },

  /**
   * Deletes a prompt template by its ID.
   */
  deletePrompt: async (templateId: string): Promise<void> => {
    // V02.2.1: reject non-UUID ids before they reach the URL.
    assertUuid(templateId);
    // V01.2.2: encode templateId to prevent URL path manipulation.
    await apiClient.delete(`/admin/prompts/${encodeURIComponent(templateId)}`);
  },
};