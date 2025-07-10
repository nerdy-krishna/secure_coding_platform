// src/shared/api/chatService.ts
import type {
    AskQuestionRequest,
    ChatMessage,
    ChatSession,
    ChatSessionCreateRequest,
} from "../types/api";
import apiClient from "./apiClient";

export const chatService = {
  /**
   * Creates a new chat session.
   */
  createSession: async (
    payload: ChatSessionCreateRequest,
  ): Promise<ChatSession> => {
    const response = await apiClient.post<ChatSession>("/chat/sessions", payload);
    return response.data;
  },

  /**
   * Fetches all chat sessions for the current user.
   */
  getSessions: async (): Promise<ChatSession[]> => {
    const response = await apiClient.get<ChatSession[]>("/chat/sessions");
    return response.data;
  },

  /**
   * Fetches all messages for a specific session.
   */
  getSessionMessages: async (sessionId: string): Promise<ChatMessage[]> => {
    const response = await apiClient.get<ChatMessage[]>(
      `/chat/sessions/${sessionId}/messages`,
    );
    return response.data;
  },

  /**
   * Posts a question to a session and gets the AI's response.
   */
  askQuestion: async (
    sessionId: string,
    question: string,
    llmConfigId?: string,
  ): Promise<ChatMessage> => {
    const payload: AskQuestionRequest = { question, llm_config_id: llmConfigId };
    const response = await apiClient.post<ChatMessage>(
      `/chat/sessions/${sessionId}/ask`,
      payload,
    );
    return response.data;
  },

  /**
   * Deletes a chat session by its ID.
   */
  deleteSession: async (sessionId: string): Promise<void> => {
    await apiClient.delete(`/chat/sessions/${sessionId}`);
  },
};