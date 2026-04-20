// secure-code-ui/src/pages/submission/SubmitPage.tsx
//
// SCCAP-styled submission flow. Port of the design bundle's Submit.jsx
// adapted to the real backend: project name + scan type + LLM config +
// frameworks + one of (files | git repo | archive). Uses Ant's Upload
// under the hood for drag-drop + the file-browser dialog since hand-
// rolling those from scratch is outside this phase's scope, but every
// surrounding surface uses SCCAP design primitives.
//
// The file-exclusion tree (previously built with antd Tree) is deferred
// to a later pass — by default all staged files are submitted. If we
// need selective exclusion before Phase G.4's Results redesign, we'll
// add a lightweight tree component then.

import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Upload, message as antdMessage, type UploadFile } from "antd";
import { InboxOutlined } from "@ant-design/icons";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { scanService } from "../../shared/api/scanService";
import { Icon } from "../../shared/ui/Icon";
import type { FrameworkRead, LLMConfiguration } from "../../shared/types/api";

type SubmissionMode = "upload" | "git" | "archive";
type ScanType = "AUDIT" | "SUGGEST" | "REMEDIATE";

interface ScanTypeOption {
  id: ScanType;
  name: string;
  desc: string;
  recommended?: boolean;
}

const SCAN_TYPES: ScanTypeOption[] = [
  {
    id: "AUDIT",
    name: "Audit",
    desc: "Find vulnerabilities; no fix suggestions.",
    recommended: true,
  },
  {
    id: "SUGGEST",
    name: "Audit + Suggest",
    desc: "Find vulnerabilities and propose fixes for review.",
  },
  {
    id: "REMEDIATE",
    name: "Audit + Remediate",
    desc: "Find, fix, and apply patches to a new code snapshot.",
  },
];

const TAB_DEFS: { id: SubmissionMode; icon: React.ReactNode; label: string }[] = [
  { id: "upload", icon: <Icon.Upload size={14} />, label: "Upload files" },
  { id: "git", icon: <Icon.Github size={14} />, label: "Connect git" },
  { id: "archive", icon: <Icon.Folder size={14} />, label: "Upload archive" },
];

const SubmitPage: React.FC = () => {
  const navigate = useNavigate();

  const [mode, setMode] = useState<SubmissionMode>("upload");
  const [projectName, setProjectName] = useState("");
  const [scanType, setScanType] = useState<ScanType>("AUDIT");
  const [llmConfigId, setLlmConfigId] = useState<string>("");
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [archiveFile, setArchiveFile] = useState<UploadFile | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { data: llmConfigs, isLoading: loadingLlms } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const { data: frameworks, isLoading: loadingFrameworks } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  // Auto-select the first LLM config when the list loads so users with a
  // single config aren't blocked on picking one.
  React.useEffect(() => {
    if (!llmConfigId && llmConfigs && llmConfigs.length > 0) {
      setLlmConfigId(llmConfigs[0].id);
    }
  }, [llmConfigs, llmConfigId]);

  const canSubmit = useMemo(() => {
    if (!projectName.trim()) return false;
    if (!llmConfigId) return false;
    if (selectedFrameworks.length === 0) return false;
    if (mode === "upload") return fileList.length > 0;
    if (mode === "git") return repoUrl.trim().length > 0;
    if (mode === "archive") return archiveFile !== null;
    return false;
  }, [projectName, llmConfigId, selectedFrameworks, mode, fileList, repoUrl, archiveFile]);

  const toggleFramework = (name: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(name) ? prev.filter((f) => f !== name) : [...prev, name],
    );
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      const payload = new FormData();
      payload.append("project_name", projectName.trim());
      payload.append("scan_type", scanType);
      payload.append("utility_llm_config_id", llmConfigId);
      // The Phase F.5.1c router fallback fills fast + reasoning from the
      // utility slot when they're absent, so passing just one config id is
      // enough for most users.
      payload.append("frameworks", selectedFrameworks.join(","));

      if (mode === "upload") {
        for (const f of fileList) {
          if (f.originFileObj) {
            payload.append("files", f.originFileObj);
          }
        }
      } else if (mode === "git") {
        payload.append("repo_url", repoUrl.trim());
      } else if (mode === "archive" && archiveFile?.originFileObj) {
        payload.append("archive_file", archiveFile.originFileObj);
      }

      const response = await scanService.createScan(payload);
      antdMessage.success("Scan submitted. Tracking progress…");
      navigate(`/analysis/scanning/${response.scan_id}`);
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: string | unknown[] } };
        message?: string;
      };
      const detail =
        typeof e.response?.data?.detail === "string"
          ? e.response.data.detail
          : e.message || "Submission failed";
      antdMessage.error(detail);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fade-in"
      style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 20 }}
    >
      <div style={{ display: "grid", gap: 16 }}>
        <div>
          <h1 style={{ color: "var(--fg)" }}>New scan</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Submit code via upload, git repo, or archive. SCCAP runs SAST + AI
            triage and (optionally) applies fixes.
          </div>
        </div>

        {/* project name */}
        <div className="surface" style={{ padding: 20 }}>
          <label
            style={{
              display: "block",
              fontSize: 12,
              color: "var(--fg-muted)",
              marginBottom: 6,
              fontWeight: 500,
            }}
          >
            Project name
          </label>
          <input
            className="sccap-input"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder="e.g., payments-api"
            autoFocus
          />
        </div>

        {/* source tabs */}
        <div className="surface" style={{ padding: 0, overflow: "hidden" }}>
          <div
            className="sccap-tabs"
            style={{ padding: "0 18px", background: "var(--bg-soft)" }}
          >
            {TAB_DEFS.map((t) => (
              <div
                key={t.id}
                className={"sccap-tab " + (mode === t.id ? "active" : "")}
                onClick={() => setMode(t.id)}
              >
                {t.icon} {t.label}
              </div>
            ))}
          </div>

          <div style={{ padding: 20 }}>
            {mode === "upload" && (
              <div>
                <Upload.Dragger
                  multiple
                  beforeUpload={() => false /* let us handle at submit time */}
                  fileList={fileList}
                  onChange={({ fileList: fl }) => setFileList(fl)}
                  style={{
                    background: "var(--bg-soft)",
                    border: "2px dashed var(--border-strong)",
                    borderRadius: "var(--r-md)",
                  }}
                >
                  <p className="ant-upload-drag-icon">
                    <InboxOutlined style={{ color: "var(--primary)" }} />
                  </p>
                  <p
                    className="ant-upload-text"
                    style={{ color: "var(--fg)", fontWeight: 500 }}
                  >
                    Drop files here or click to browse
                  </p>
                  <p
                    className="ant-upload-hint"
                    style={{ color: "var(--fg-muted)" }}
                  >
                    Any number of source files. Binary files are ignored.
                  </p>
                </Upload.Dragger>
                {fileList.length > 0 && (
                  <div
                    style={{
                      marginTop: 12,
                      fontSize: 12.5,
                      color: "var(--fg-muted)",
                    }}
                  >
                    {fileList.length} file{fileList.length === 1 ? "" : "s"} staged.
                  </div>
                )}
              </div>
            )}

            {mode === "git" && (
              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: 12,
                    color: "var(--fg-muted)",
                    marginBottom: 6,
                  }}
                >
                  Repository URL
                </label>
                <div className="input-with-icon">
                  <Icon.Github size={14} />
                  <input
                    className="sccap-input"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo.git"
                    style={{ paddingLeft: 32 }}
                  />
                </div>
                <div
                  style={{
                    marginTop: 8,
                    fontSize: 11.5,
                    color: "var(--fg-subtle)",
                  }}
                >
                  Public repos are cloned shallow; private repos require a PAT
                  configured in Admin → LLM settings.
                </div>
              </div>
            )}

            {mode === "archive" && (
              <div>
                <Upload.Dragger
                  beforeUpload={() => false}
                  maxCount={1}
                  fileList={archiveFile ? [archiveFile] : []}
                  onChange={({ fileList: fl }) =>
                    setArchiveFile(fl.length ? fl[fl.length - 1] : null)
                  }
                  accept=".zip,.tar,.tar.gz,.tgz"
                  style={{
                    background: "var(--bg-soft)",
                    border: "2px dashed var(--border-strong)",
                    borderRadius: "var(--r-md)",
                  }}
                >
                  <p className="ant-upload-drag-icon">
                    <InboxOutlined style={{ color: "var(--primary)" }} />
                  </p>
                  <p
                    className="ant-upload-text"
                    style={{ color: "var(--fg)", fontWeight: 500 }}
                  >
                    Drop a .zip or .tar.gz
                  </p>
                  <p
                    className="ant-upload-hint"
                    style={{ color: "var(--fg-muted)" }}
                  >
                    Single archive, up to 500 MB.
                  </p>
                </Upload.Dragger>
              </div>
            )}
          </div>
        </div>

        {/* scan config */}
        <div className="surface" style={{ padding: 20 }}>
          <h3 style={{ marginBottom: 12, color: "var(--fg)" }}>Scan configuration</h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 20,
            }}
          >
            <div>
              <label
                style={{
                  display: "block",
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginBottom: 6,
                  fontWeight: 500,
                }}
              >
                Scan mode
              </label>
              <div style={{ display: "grid", gap: 6 }}>
                {SCAN_TYPES.map((o) => {
                  const active = scanType === o.id;
                  return (
                    <label
                      key={o.id}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "auto 1fr",
                        gap: 10,
                        alignItems: "flex-start",
                        padding: 10,
                        border:
                          "1px solid " +
                          (active ? "var(--primary)" : "var(--border)"),
                        background: active ? "var(--primary-weak)" : "var(--bg-elev)",
                        borderRadius: "var(--r-sm)",
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="radio"
                        name="scan-type"
                        checked={active}
                        onChange={() => setScanType(o.id)}
                        style={{ accentColor: "var(--primary)", marginTop: 3 }}
                      />
                      <div>
                        <div
                          style={{
                            fontSize: 13.5,
                            fontWeight: 500,
                            color: "var(--fg)",
                          }}
                        >
                          {o.name}{" "}
                          {o.recommended && (
                            <span
                              className="chip chip-ai"
                              style={{ marginLeft: 6, fontSize: 10 }}
                            >
                              recommended
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
                          {o.desc}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            <div>
              <label
                style={{
                  display: "block",
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginBottom: 6,
                  fontWeight: 500,
                }}
              >
                LLM configuration
              </label>
              <select
                className="sccap-select"
                value={llmConfigId}
                onChange={(e) => setLlmConfigId(e.target.value)}
                disabled={loadingLlms || !llmConfigs?.length}
              >
                {loadingLlms && <option>Loading…</option>}
                {!loadingLlms && !llmConfigs?.length && (
                  <option value="">No LLMs configured — see Admin → LLM</option>
                )}
                {llmConfigs?.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} · {c.provider}/{c.model_name}
                  </option>
                ))}
              </select>
              <div
                style={{
                  marginTop: 6,
                  fontSize: 11,
                  color: "var(--fg-subtle)",
                }}
              >
                The same config powers utility, fast, and reasoning slots by
                default.
              </div>

              <label
                style={{
                  display: "block",
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginTop: 18,
                  marginBottom: 6,
                  fontWeight: 500,
                }}
              >
                Compliance frameworks
              </label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {loadingFrameworks && (
                  <span style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                    Loading frameworks…
                  </span>
                )}
                {!loadingFrameworks && !frameworks?.length && (
                  <span style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                    No frameworks configured — see Admin → Frameworks.
                  </span>
                )}
                {frameworks?.map((f) => {
                  const on = selectedFrameworks.includes(f.name);
                  return (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => toggleFramework(f.name)}
                      className="chip"
                      style={{
                        cursor: "pointer",
                        background: on ? "var(--primary-weak)" : "var(--bg-soft)",
                        color: on ? "var(--primary)" : "var(--fg-muted)",
                        border: "none",
                        padding: "5px 12px",
                      }}
                    >
                      {on && <Icon.Check size={10} />} {f.name}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="sccap-divider" />
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
              You'll approve the cost before the full analysis runs.
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="sccap-btn"
                onClick={() => navigate("/account/dashboard")}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                onClick={handleSubmit}
                disabled={!canSubmit || submitting}
              >
                <Icon.Play size={12} /> {submitting ? "Submitting…" : "Start scan"}
              </button>
            </div>
          </div>
        </div>
      </div>

      <aside style={{ display: "grid", gap: 16, alignContent: "start" }}>
        <div className="sccap-card">
          <h4 style={{ marginBottom: 10, color: "var(--fg)" }}>What we scan for</h4>
          <div style={{ display: "grid", gap: 8, fontSize: 12.5 }}>
            {[
              { icon: <Icon.Lock size={12} />, label: "Vulnerabilities (SAST)" },
              { icon: <Icon.Box size={12} />, label: "Dependencies (where configured)" },
              { icon: <Icon.Key size={12} />, label: "Secrets & credentials" },
              { icon: <Icon.Shield size={12} />, label: "Compliance framework mappings" },
              { icon: <Icon.Sparkle size={12} />, label: "AI-suggested fixes" },
            ].map((r, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  color: "var(--fg-muted)",
                }}
              >
                <span style={{ color: "var(--primary)" }}>{r.icon}</span>
                {r.label}
              </div>
            ))}
          </div>
        </div>
        <div
          className="sccap-card"
          style={{ background: "var(--primary-weak)", borderColor: "transparent" }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 6,
            }}
          >
            <Icon.Info size={14} color="var(--primary)" />
            <div style={{ fontWeight: 600, color: "var(--primary-strong)" }}>
              Cost approval
            </div>
          </div>
          <div
            style={{
              fontSize: 12.5,
              color: "var(--fg)",
              lineHeight: 1.55,
            }}
          >
            After submission, SCCAP runs a quick cost estimate and pauses for
            your approval before running the full scan. You'll see the estimate
            on the next screen.
          </div>
        </div>
      </aside>
    </div>
  );
};

export default SubmitPage;
