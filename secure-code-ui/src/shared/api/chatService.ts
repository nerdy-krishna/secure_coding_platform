// src/shared/api/chatService.ts
import type {
  AskQuestionRequest,
  ChatMessage,
  ChatSession,
  ChatSessionCreateRequest,
} from "../types/api";
import apiClient from "./apiClient";

function validateSessionId(id: string): void {
  if (typeof id !== "string" || !/^[0-9a-fA-F-]{8,36}$/.test(id)) {
    throw new Error("Invalid session id");
  }
}

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
    validateSessionId(sessionId);
    const response = await apiClient.get<ChatMessage[]>(
      `/chat/sessions/${encodeURIComponent(sessionId)}/messages`,
    );
    return response.data;
  },

  /**
   * Posts a question to a session and gets the AI's response.
   */
  askQuestion: async (
    sessionId: string,
    question: string,
  ): Promise<ChatMessage> => {
    validateSessionId(sessionId);
    if (typeof question !== "string" || question.trim().length === 0 || question.length > 8000) {
      throw new Error("Question must be 1-8000 chars");
    }
    const payload: AskQuestionRequest = { question };
    const response = await apiClient.post<ChatMessage>(
      `/chat/sessions/${encodeURIComponent(sessionId)}/ask`,
      payload,
    );
    return response.data;
  },

  /**
   * Deletes a chat session by its ID.
   */
  deleteSession: async (sessionId: string): Promise<void> => {
    validateSessionId(sessionId);
    await apiClient.delete(`/chat/sessions/${encodeURIComponent(sessionId)}`);
  },

  /**
   * Fetches the right-rail context blob for a session.
   */
  getSessionContext: async (sessionId: string): Promise<ChatSessionContext> => {
    validateSessionId(sessionId);
    const response = await apiClient.get<ChatSessionContext>(
      `/chat/sessions/${encodeURIComponent(sessionId)}/context`,
    );
    return response.data;
  },
};

export interface ChatContextFinding {
  id: number;
  title: string;
  severity: string | null;
  scan_id: string;
}

export interface ChatContextFile {
  path: string;
  scan_id: string;
}

export interface ChatContextKnowledgeSource {
  name: string;
  type: string;
}

export interface ChatSessionContext {
  referenced_findings: ChatContextFinding[];
  referenced_files: ChatContextFile[];
  knowledge_sources: ChatContextKnowledgeSource[];
}