// secure-code-ui/src/pages/admin/FrameworkManagementPage.tsx
//
// Admin surface for security frameworks + the agents mapped to them.
// CRUD stays on frameworkService (/admin/frameworks/); presentation is
// ported to SCCAP primitives — card grid, chip-style agent mappings,
// multi-select via a lightweight chip-list component.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import React, { useEffect, useMemo, useState } from "react";
import { agentService } from "../../shared/api/agentService";
import { frameworkService } from "../../shared/api/frameworkService";
import type {
  AgentRead,
  FrameworkCreate,
  FrameworkRead,
  FrameworkUpdate,
} from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

interface FormState {
  name: string;
  description: string;
  agent_ids: string[];
}

const EMPTY_FORM: FormState = { name: "", description: "", agent_ids: [] };

const FrameworkManagementPage: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<FrameworkRead | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const { data: frameworks, isLoading, isError, error } = useQuery<
    FrameworkRead[],
    Error
  >({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: agents = [] } = useQuery<AgentRead[], Error>({
    queryKey: ["agents"],
    queryFn: agentService.getAgents,
  });

  useEffect(() => {
    if (isError) {
      toast.error(`Failed to load frameworks: ${error.message}`);
    }
  }, [isError, error, toast]);

  useEffect(() => {
    if (editing) {
      setForm({
        name: editing.name,
        description: editing.description,
        agent_ids: editing.agents.map((a) => a.id),
      });
      setModalOpen(true);
    }
  }, [editing]);

  const onApiError = (err: unknown, verb: string) => {
    const detail =
      err instanceof AxiosError
        ? (err.response?.data as { detail?: string })?.detail
        : "Unknown error";
    toast.error(`Failed to ${verb} framework: ${detail ?? "unknown error"}`);
  };

  const createMutation = useMutation({
    mutationFn: async (data: FrameworkCreate & { agent_ids: string[] }) => {
      const { agent_ids, ...rest } = data;
      const fw = await frameworkService.createFramework(rest);
      if (agent_ids.length > 0) {
        await frameworkService.updateAgentMappings(fw.id, agent_ids);
      }
      return fw;
    },
    onSuccess: () => {
      toast.success("Framework created.");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      closeModal();
    },
    onError: (err) => onApiError(err, "create"),
  });

  const updateMutation = useMutation({
    mutationFn: async (data: {
      id: string;
      values: FrameworkUpdate;
      agent_ids: string[];
    }) => {
      const fw = await frameworkService.updateFramework(data.id, data.values);
      return frameworkService.updateAgentMappings(fw.id, data.agent_ids);
    },
    onSuccess: () => {
      toast.success("Framework updated.");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      closeModal();
    },
    onError: (err) => onApiError(err, "update"),
  });

  const deleteMutation = useMutation({
    mutationFn: frameworkService.deleteFramework,
    onSuccess: () => {
      toast.success("Framework deleted.");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
    },
    onError: (err) => onApiError(err, "delete"),
  });

  const closeModal = () => {
    setModalOpen(false);
    setEditing(null);
    setForm(EMPTY_FORM);
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.description) {
      toast.error("Name and description are required.");
      return;
    }
    if (editing) {
      updateMutation.mutate({
        id: editing.id,
        values: { name: form.name, description: form.description },
        agent_ids: form.agent_ids,
      });
    } else {
      createMutation.mutate({
        name: form.name,
        description: form.description,
        agent_ids: form.agent_ids,
      });
    }
  };

  const pending = createMutation.isPending || updateMutation.isPending;

  const agentById = useMemo(
    () => new Map(agents.map((a) => [a.id, a])),
    [agents],
  );

  const toggleAgent = (id: string) => {
    setForm((f) => ({
      ...f,
      agent_ids: f.agent_ids.includes(id)
        ? f.agent_ids.filter((x) => x !== id)
        : [...f.agent_ids, id],
    }));
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>
            <Icon.Shield size={18} /> Frameworks
          </h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Security frameworks and the agents mapped to each.
          </div>
        </div>
        <button
          className="sccap-btn sccap-btn-primary"
          onClick={() => {
            setEditing(null);
            setForm(EMPTY_FORM);
            setModalOpen(true);
          }}
        >
          <Icon.Plus size={13} /> Create framework
        </button>
      </div>

      {isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading frameworks…
        </div>
      ) : !frameworks || frameworks.length === 0 ? (
        <div
          className="sccap-card"
          style={{ padding: 60, textAlign: "center" }}
        >
          <div style={{ color: "var(--fg)", fontWeight: 500, marginBottom: 4 }}>
            No frameworks yet
          </div>
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            Create your first framework and map agents to it.
          </div>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: 14,
          }}
        >
          {frameworks.map((fw) => (
            <div key={fw.id} className="sccap-card">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: 10,
                }}
              >
                <div>
                  <div
                    style={{
                      fontSize: 10.5,
                      color: "var(--fg-subtle)",
                      textTransform: "uppercase",
                      letterSpacing: ".06em",
                    }}
                  >
                    Framework
                  </div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: "var(--fg)",
                      marginTop: 2,
                    }}
                  >
                    {fw.name}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    aria-label="Edit"
                    onClick={() => setEditing(fw)}
                  >
                    <Icon.Edit size={13} />
                  </button>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    aria-label="Delete"
                    onClick={() => setConfirmDeleteId(fw.id)}
                  >
                    <Icon.Trash size={13} />
                  </button>
                </div>
              </div>
              <div
                style={{
                  fontSize: 12.5,
                  color: "var(--fg-muted)",
                  lineHeight: 1.5,
                  marginBottom: 12,
                  minHeight: 36,
                }}
              >
                {fw.description}
              </div>
              <div
                style={{
                  fontSize: 10.5,
                  color: "var(--fg-subtle)",
                  textTransform: "uppercase",
                  letterSpacing: ".06em",
                  marginBottom: 6,
                }}
              >
                {fw.agents.length} agent
                {fw.agents.length === 1 ? "" : "s"} mapped
              </div>
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 6,
                }}
              >
                {fw.agents.length === 0 ? (
                  <span
                    style={{
                      color: "var(--fg-subtle)",
                      fontSize: 12,
                    }}
                  >
                    No agents mapped.
                  </span>
                ) : (
                  fw.agents.map((a) => (
                    <span key={a.id} className="chip chip-ai">
                      {a.name}
                    </span>
                  ))
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={editing ? "Edit framework" : "Create new framework"}
        width={640}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={closeModal}
              disabled={pending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onSubmit}
              disabled={pending}
            >
              {pending
                ? "Saving…"
                : editing
                  ? "Save changes"
                  : "Create framework"}
            </button>
          </>
        }
      >
        <form onSubmit={onSubmit} style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Framework name
            </span>
            <input
              className="sccap-input"
              placeholder="e.g. OWASP ASVS v5.0"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
              autoFocus
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Description
            </span>
            <textarea
              className="sccap-input"
              rows={3}
              placeholder="What does this framework cover?"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              required
            />
          </label>
          <div style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Associated agents
            </span>
            {agents.length === 0 ? (
              <div style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                No agents available. Create agents first under Agents.
              </div>
            ) : (
              <div
                className="inset"
                style={{
                  padding: 10,
                  display: "flex",
                  flexWrap: "wrap",
                  gap: 6,
                  maxHeight: 180,
                  overflowY: "auto",
                }}
              >
                {agents.map((a) => {
                  const selected = form.agent_ids.includes(a.id);
                  return (
                    <button
                      type="button"
                      key={a.id}
                      onClick={() => toggleAgent(a.id)}
                      className={`chip ${selected ? "chip-ai" : ""}`}
                      style={{
                        cursor: "pointer",
                        border: selected
                          ? "1px solid var(--primary)"
                          : "1px solid var(--border)",
                        background: selected
                          ? "var(--primary-weak)"
                          : "transparent",
                        color: selected ? "var(--primary)" : "var(--fg-muted)",
                      }}
                    >
                      {selected && <Icon.Check size={10} />} {a.name}
                    </button>
                  );
                })}
              </div>
            )}
            <div
              style={{
                fontSize: 11,
                color: "var(--fg-subtle)",
              }}
            >
              {form.agent_ids.length} selected —{" "}
              {form.agent_ids
                .map((id) => agentById.get(id)?.name ?? "?")
                .join(", ") || "none"}
            </div>
          </div>
          <button type="submit" style={{ display: "none" }} />
        </form>
      </Modal>

      <Modal
        open={confirmDeleteId !== null}
        onClose={() => setConfirmDeleteId(null)}
        title="Delete framework?"
        width={420}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmDeleteId(null)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() => {
                if (confirmDeleteId) {
                  deleteMutation.mutate(confirmDeleteId);
                  setConfirmDeleteId(null);
                }
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
          Past scans that referenced this framework remain intact. Future
          scans will no longer apply its agent mappings.
        </div>
      </Modal>
    </div>
  );
};

export default FrameworkManagementPage;
