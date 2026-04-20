// secure-code-ui/src/pages/chat/SecurityAdvisorPage.tsx
//
// SCCAP Security Advisor. Port of the design bundle's Misc.jsx Advisor
// wired to chatService (/chat/sessions, /chat/sessions/:id/messages,
// /chat/sessions/:id/ask, /chat/sessions/:id DELETE).
//
// Layout (3 columns):
//   - Left rail: session list grouped by today / yesterday / older,
//     with a "New chat" button that opens a small modal to pick the
//     LLM config + framework scope.
//   - Center: message thread with user/AI bubbles, quick-reply chips,
//     and a textarea + send button at the bottom.
//   - Right rail: context stub (referenced findings / files / knowledge
//     sources). This is currently static text — wiring it to real scan
//     context per session needs a backend endpoint and will follow when
//     the Advisor grows a "drop finding into chat" affordance.

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Modal, Select, Checkbox, message as antdMessage } from "antd";
import { chatService } from "../../shared/api/chatService";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { Icon } from "../../shared/ui/Icon";
import type {
  ChatMessage,
  ChatSession,
  FrameworkRead,
  LLMConfiguration,
} from "../../shared/types/api";

function bucketSessions(sessions: ChatSession[]): Record<string, ChatSession[]> {
  const now = Date.now();
  const buckets: Record<string, ChatSession[]> = {
    Today: [],
    Yesterday: [],
    Older: [],
  };
  for (const s of sessions) {
    const t = new Date(s.created_at).getTime();
    const daysAgo = Math.floor((now - t) / (24 * 60 * 60 * 1000));
    if (daysAgo < 1) buckets.Today.push(s);
    else if (daysAgo < 2) buckets.Yesterday.push(s);
    else buckets.Older.push(s);
  }
  return buckets;
}

const QUICK_REPLIES = [
  "Explain this finding",
  "Map findings to SOC 2",
  "Summarize the scan",
];

const SecurityAdvisorPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [newChatOpen, setNewChatOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newLlmId, setNewLlmId] = useState<string>("");
  const [newFrameworks, setNewFrameworks] = useState<string[]>([]);
  const threadRef = useRef<HTMLDivElement | null>(null);

  const { data: sessions = [], isLoading: loadingSessions } = useQuery<
    ChatSession[]
  >({
    queryKey: ["chatSessions"],
    queryFn: chatService.getSessions,
  });

  const { data: llmConfigs } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const { data: frameworks } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  // Select the newest session whenever the list loads or changes if none
  // is currently selected.
  useEffect(() => {
    if (!activeSessionId && sessions.length > 0) {
      setActiveSessionId(sessions[0].id);
    }
  }, [sessions, activeSessionId]);

  const { data: messages = [], isLoading: loadingMessages } = useQuery<
    ChatMessage[]
  >({
    queryKey: ["chatMessages", activeSessionId],
    queryFn: () => chatService.getSessionMessages(activeSessionId!),
    enabled: !!activeSessionId,
  });

  // Auto-scroll to bottom when messages arrive.
  useEffect(() => {
    if (threadRef.current) {
      threadRef.current.scrollTop = threadRef.current.scrollHeight;
    }
  }, [messages]);

  const askMutation = useMutation({
    mutationFn: (question: string) =>
      chatService.askQuestion(activeSessionId!, question),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["chatMessages", activeSessionId],
      });
      setDraft("");
    },
    onError: (err: Error) => antdMessage.error(err.message || "Ask failed"),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      chatService.createSession({
        title: newTitle.trim() || "New conversation",
        llm_config_id: newLlmId,
        frameworks: newFrameworks,
      }),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      setActiveSessionId(created.id);
      setNewChatOpen(false);
      setNewTitle("");
      setNewFrameworks([]);
    },
    onError: (err: Error) =>
      antdMessage.error(err.message || "Could not create session"),
  });

  const deleteMutation = useMutation({
    mutationFn: (sessionId: string) => chatService.deleteSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      setActiveSessionId(null);
    },
    onError: (err: Error) => antdMessage.error(err.message || "Delete failed"),
  });

  const buckets = useMemo(() => bucketSessions(sessions), [sessions]);
  const activeSession =
    sessions.find((s) => s.id === activeSessionId) ?? null;

  const canSend =
    !!activeSessionId && draft.trim().length > 0 && !askMutation.isPending;

  const handleSend = () => {
    if (!canSend) return;
    askMutation.mutate(draft.trim());
  };

  const openNewChat = () => {
    setNewTitle("");
    setNewLlmId(llmConfigs?.[0]?.id ?? "");
    setNewFrameworks([]);
    setNewChatOpen(true);
  };

  return (
    <div
      className="fade-in"
      style={{
        display: "grid",
        gridTemplateColumns: "240px 1fr 280px",
        gap: 16,
        height: "calc(100vh - 110px)",
      }}
    >
      {/* Sessions rail */}
      <div
        className="surface"
        style={{
          padding: 10,
          display: "flex",
          flexDirection: "column",
          gap: 4,
          overflow: "hidden",
        }}
      >
        <button
          className="sccap-btn sccap-btn-primary"
          style={{ margin: 6 }}
          onClick={openNewChat}
        >
          <Icon.Plus size={12} /> New chat
        </button>
        <div style={{ overflow: "auto", flex: 1 }}>
          {loadingSessions && (
            <div
              style={{
                padding: "20px 10px",
                color: "var(--fg-subtle)",
                fontSize: 12,
              }}
            >
              Loading…
            </div>
          )}
          {!loadingSessions && sessions.length === 0 && (
            <div
              style={{
                padding: "20px 10px",
                color: "var(--fg-subtle)",
                fontSize: 12,
              }}
            >
              No chats yet — click <b>New chat</b> to start one.
            </div>
          )}
          {(["Today", "Yesterday", "Older"] as const).map((k) => {
            const list = buckets[k];
            if (!list.length) return null;
            return (
              <div key={k}>
                <div
                  style={{
                    fontSize: 10.5,
                    color: "var(--fg-subtle)",
                    textTransform: "uppercase",
                    letterSpacing: ".06em",
                    padding: "10px 10px 6px",
                  }}
                >
                  {k}
                </div>
                {list.map((s) => {
                  const active = s.id === activeSessionId;
                  return (
                    <div
                      key={s.id}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                      }}
                    >
                      <button
                        className="sccap-btn sccap-btn-ghost"
                        style={{
                          flex: 1,
                          justifyContent: "flex-start",
                          padding: "8px 10px",
                          fontSize: 12.5,
                          background: active
                            ? "var(--bg-soft)"
                            : "transparent",
                          color: active ? "var(--fg)" : "var(--fg-muted)",
                          overflow: "hidden",
                          textAlign: "left",
                        }}
                        onClick={() => setActiveSessionId(s.id)}
                      >
                        <Icon.Chat size={12} />
                        <span
                          style={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            flex: 1,
                          }}
                        >
                          {s.title}
                        </span>
                      </button>
                      {active && (
                        <button
                          className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                          onClick={() => deleteMutation.mutate(s.id)}
                          title="Delete session"
                          style={{ padding: 4 }}
                          aria-label="Delete session"
                        >
                          <Icon.Trash size={12} />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>

      {/* Thread */}
      <div
        className="surface"
        style={{
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "14px 20px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              background: "var(--primary)",
              color: "var(--primary-ink)",
              display: "grid",
              placeItems: "center",
            }}
          >
            <Icon.Sparkle size={14} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, color: "var(--fg)" }}>
              {activeSession?.title ?? "Security Advisor"}
            </div>
            <div style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
              {activeSession
                ? `${activeSession.frameworks?.length ?? 0} framework${
                    activeSession.frameworks?.length === 1 ? "" : "s"
                  } in scope`
                : "Pick or start a conversation"}
            </div>
          </div>
          <span
            className="chip chip-success"
            style={{ marginLeft: "auto" }}
          >
            <span
              className="dot"
              style={{ background: "currentColor" }}
            />{" "}
            online
          </span>
        </div>

        <div
          ref={threadRef}
          style={{
            flex: 1,
            overflow: "auto",
            padding: 24,
            display: "flex",
            flexDirection: "column",
            gap: 18,
          }}
        >
          {!activeSessionId ? (
            <div
              style={{
                color: "var(--fg-muted)",
                textAlign: "center",
                padding: 40,
              }}
            >
              Select or start a conversation to begin.
            </div>
          ) : loadingMessages ? (
            <div
              style={{
                color: "var(--fg-muted)",
                textAlign: "center",
                padding: 40,
              }}
            >
              Loading messages…
            </div>
          ) : messages.length === 0 ? (
            <div
              style={{
                color: "var(--fg-muted)",
                textAlign: "center",
                padding: 40,
              }}
            >
              New conversation — ask the advisor anything about a finding,
              fix, or framework gap.
            </div>
          ) : (
            messages.map((m) => {
              const isUser = m.role === "user";
              return (
                <div
                  key={m.id}
                  style={{
                    display: "flex",
                    gap: 12,
                    alignItems: "flex-start",
                    justifyContent: isUser ? "flex-end" : "flex-start",
                  }}
                >
                  {!isUser && (
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: 8,
                        background: "var(--primary)",
                        color: "var(--primary-ink)",
                        display: "grid",
                        placeItems: "center",
                        flex: "none",
                      }}
                    >
                      <Icon.Sparkle size={13} />
                    </div>
                  )}
                  <div
                    style={{
                      maxWidth: "70%",
                      padding: "10px 14px",
                      borderRadius: isUser
                        ? "14px 14px 4px 14px"
                        : "14px 14px 14px 4px",
                      background: isUser
                        ? "var(--primary)"
                        : "var(--bg-soft)",
                      color: isUser ? "var(--primary-ink)" : "var(--fg)",
                      fontSize: 13.5,
                      lineHeight: 1.55,
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {m.content}
                  </div>
                  {isUser && (
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: 8,
                        background: "var(--bg-soft)",
                        color: "var(--fg-muted)",
                        display: "grid",
                        placeItems: "center",
                        flex: "none",
                        fontSize: 11,
                        fontWeight: 600,
                      }}
                    >
                      <Icon.User size={14} />
                    </div>
                  )}
                </div>
              );
            })
          )}
          {askMutation.isPending && (
            <div
              style={{
                display: "flex",
                gap: 12,
                alignItems: "center",
                color: "var(--fg-muted)",
                fontSize: 12.5,
              }}
            >
              <div
                className="sccap-spin"
                style={{
                  width: 12,
                  height: 12,
                  border: "2px solid var(--primary)",
                  borderTopColor: "transparent",
                  borderRadius: "50%",
                }}
              />
              Advisor is thinking…
            </div>
          )}
        </div>

        <div
          style={{
            padding: 14,
            borderTop: "1px solid var(--border)",
          }}
        >
          <div
            style={{
              display: "flex",
              gap: 6,
              marginBottom: 8,
              flexWrap: "wrap",
            }}
          >
            {QUICK_REPLIES.map((s) => (
              <button
                key={s}
                className="sccap-btn sccap-btn-sm"
                onClick={() => setDraft(s)}
                disabled={!activeSessionId}
                style={{ fontSize: 11.5 }}
              >
                {s}
              </button>
            ))}
          </div>
          <div
            style={{ display: "flex", gap: 8, alignItems: "flex-end" }}
          >
            <textarea
              className="sccap-textarea"
              rows={2}
              placeholder={
                activeSessionId
                  ? "Ask about a finding, fix, or compliance gap…"
                  : "Start a chat to enable the advisor."
              }
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              disabled={!activeSessionId || askMutation.isPending}
              style={{ resize: "none" }}
            />
            <button
              className="sccap-btn sccap-btn-primary"
              style={{ height: 38 }}
              onClick={handleSend}
              disabled={!canSend}
              aria-label="Send"
            >
              <Icon.Send size={13} />
            </button>
          </div>
        </div>
      </div>

      {/* Context rail */}
      <div className="surface" style={{ padding: 16, overflow: "auto" }}>
        <h4 style={{ marginBottom: 10, color: "var(--fg)" }}>Context</h4>
        {activeSession ? (
          <>
            <div
              style={{
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 6,
              }}
            >
              Frameworks in scope
            </div>
            <div style={{ display: "grid", gap: 6, marginBottom: 16 }}>
              {activeSession.frameworks?.length ? (
                activeSession.frameworks.map((r, i) => (
                  <div
                    key={i}
                    className="inset"
                    style={{ padding: "8px 10px", fontSize: 12 }}
                  >
                    {r}
                  </div>
                ))
              ) : (
                <div
                  style={{ fontSize: 12, color: "var(--fg-subtle)" }}
                >
                  No frameworks — advisor answers against the general
                  knowledge base.
                </div>
              )}
            </div>
            <div
              style={{
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 6,
              }}
            >
              Session
            </div>
            <div
              style={{
                fontSize: 11.5,
                color: "var(--fg-subtle)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {activeSession.id}
            </div>
            <div
              style={{
                fontSize: 11.5,
                color: "var(--fg-subtle)",
                marginTop: 4,
              }}
            >
              Created{" "}
              {new Date(activeSession.created_at).toLocaleString(undefined, {
                dateStyle: "medium",
                timeStyle: "short",
              })}
            </div>
          </>
        ) : (
          <div style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
            Pick a conversation to see its scope.
          </div>
        )}
      </div>

      {/* New chat modal (Ant Modal styled as a minimal dialog — kept here
          because rolling our own modal is out of scope for G.5) */}
      <Modal
        title="New conversation"
        open={newChatOpen}
        onCancel={() => setNewChatOpen(false)}
        onOk={() => createMutation.mutate()}
        okText="Create"
        okButtonProps={{
          disabled:
            !newLlmId ||
            !newTitle.trim() ||
            createMutation.isPending,
          loading: createMutation.isPending,
        }}
      >
        <div style={{ display: "grid", gap: 14, marginTop: 8 }}>
          <div>
            <label
              style={{
                display: "block",
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 6,
              }}
            >
              Title
            </label>
            <input
              className="sccap-input"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="e.g., SQL injection walk-through"
              autoFocus
            />
          </div>
          <div>
            <label
              style={{
                display: "block",
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 6,
              }}
            >
              LLM
            </label>
            <Select
              style={{ width: "100%" }}
              value={newLlmId}
              onChange={setNewLlmId}
              placeholder="Select LLM"
              options={llmConfigs?.map((c) => ({
                value: c.id,
                label: `${c.name} · ${c.provider}/${c.model_name}`,
              }))}
            />
          </div>
          <div>
            <label
              style={{
                display: "block",
                fontSize: 12,
                color: "var(--fg-muted)",
                marginBottom: 6,
              }}
            >
              Frameworks in scope
            </label>
            <Checkbox.Group
              value={newFrameworks}
              onChange={(v) => setNewFrameworks(v as string[])}
              style={{ display: "flex", flexWrap: "wrap", gap: 8 }}
              options={frameworks?.map((f) => ({
                label: f.name,
                value: f.name,
              }))}
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default SecurityAdvisorPage;
