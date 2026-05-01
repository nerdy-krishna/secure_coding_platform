// secure-code-ui/src/pages/submission/SubmitPage.tsx
//
// SCCAP-styled submission flow. Port of the design bundle's Submit.jsx,
// fully on SCCAP primitives — no antd. Native HTML5 drag-and-drop is
// used for the file / archive dropzones; file state is plain File[].
//
// The file-exclusion tree is still deferred to a later pass; by default
// all staged files are submitted. If selective exclusion is needed before
// that lands, a lightweight tree can be added here.

import React, { useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { scanService } from "../../shared/api/scanService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
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

const ARCHIVE_ACCEPT = ".zip,.tar,.tar.gz,.tgz";

// V05.1.1 / V05.2.1 size caps (enforced at drop-time and again in handleSubmit)
const MAX_FILE_BYTES = 50_000_000;     // 50 MB per file
const MAX_TOTAL_BYTES = 200_000_000;   // 200 MB aggregate upload
const MAX_ARCHIVE_BYTES = 500_000_000; // 500 MB compressed archive

// V05.2.2 allowed source-code extensions for upload mode
const ALLOWED_UPLOAD_EXTENSIONS = new Set([
  ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
  ".cs", ".c", ".cpp", ".h", ".hpp", ".swift", ".kt", ".yml", ".yaml",
  ".json", ".toml", ".md", ".rs", ".scala", ".sh", ".bash", ".zsh",
  ".css", ".scss", ".html", ".xml", ".sql", ".tf", ".hcl",
]);

const Dropzone: React.FC<{
  onFiles: (files: File[]) => void | Promise<void>;
  multiple?: boolean;
  accept?: string;
  hint: string;
  helper: string;
}> = ({ onFiles, multiple = false, accept, hint, helper }) => {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const files = Array.from(e.dataTransfer.files ?? []);
        if (files.length) onFiles(files);
      }}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      style={{
        background: dragging ? "var(--primary-weak)" : "var(--bg-soft)",
        border:
          "2px dashed " +
          (dragging ? "var(--primary)" : "var(--border-strong)"),
        borderRadius: "var(--r-md)",
        padding: "36px 24px",
        textAlign: "center",
        cursor: "pointer",
        transition: "all .15s var(--ease)",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        multiple={multiple}
        accept={accept}
        style={{ display: "none" }}
        onChange={(e) => {
          const files = Array.from(e.target.files ?? []);
          if (files.length) onFiles(files);
          e.target.value = "";
        }}
      />
      <div style={{ color: "var(--primary)", marginBottom: 8 }}>
        <Icon.Upload size={22} />
      </div>
      <div style={{ fontWeight: 500, color: "var(--fg)" }}>{hint}</div>
      <div style={{ color: "var(--fg-muted)", fontSize: 12.5, marginTop: 4 }}>
        {helper}
      </div>
    </div>
  );
};

const SubmitPage: React.FC = () => {
  const navigate = useNavigate();
  const toast = useToast();

  const [mode, setMode] = useState<SubmissionMode>("upload");
  const [projectName, setProjectName] = useState("");
  const [scanType, setScanType] = useState<ScanType>("AUDIT");
  const [llmConfigId, setLlmConfigId] = useState<string>("");
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [files, setFiles] = useState<File[]>([]);
  const [archiveFile, setArchiveFile] = useState<File | null>(null);
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

  React.useEffect(() => {
    if (!llmConfigId && llmConfigs && llmConfigs.length > 0) {
      setLlmConfigId(llmConfigs[0].id);
    }
  }, [llmConfigs, llmConfigId]);

  const canSubmit = useMemo(() => {
    if (!projectName.trim()) return false;
    if (!llmConfigId) return false;
    if (selectedFrameworks.length === 0) return false;
    if (mode === "upload") return files.length > 0;
    if (mode === "git") {
      // V12.3.1: only HTTPS git URLs are accepted from the UI
      const v = repoUrl.trim();
      try { const u = new URL(v); return u.protocol === "https:"; } catch { return false; }
    }
    if (mode === "archive") return archiveFile !== null;
    return false;
  }, [projectName, llmConfigId, selectedFrameworks, mode, files, repoUrl, archiveFile]);

  const toggleFramework = (name: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(name) ? prev.filter((f) => f !== name) : [...prev, name],
    );
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;

    // V02.2.1: project name length + charset validation
    const trimmedName = projectName.trim();
    if (trimmedName.length > 100) { toast.error("Project name too long (max 100 characters)"); return; }
    if (!/^[A-Za-z0-9 ._-]+$/.test(trimmedName)) { toast.error("Project name has invalid characters (use letters, numbers, spaces, . _ -)"); return; }

    // V02.2.1 / V12.3.1: git URL must be https and within length limit
    if (mode === "git") {
      const v = repoUrl.trim();
      if (v.length > 512) { toast.error("Repository URL too long (max 512 characters)"); return; }
      try { const u = new URL(v); if (u.protocol !== "https:") { toast.error("Only HTTPS git URLs are accepted"); return; } }
      catch { toast.error("Invalid repository URL"); return; }
    }

    // V02.2.1 / V05.2.1: per-file and aggregate size defense-in-depth check
    if (mode === "upload") {
      for (const f of files) {
        if (f.size > MAX_FILE_BYTES) { toast.error(`File "${f.name}" exceeds 50 MB limit`); return; }
      }
      const totalSize = files.reduce((s, f) => s + f.size, 0);
      if (totalSize > MAX_TOTAL_BYTES) { toast.error("Total upload size exceeds 200 MB limit"); return; }
    }

    // V02.2.1 / V05.2.1: archive size defense-in-depth check
    if (mode === "archive" && archiveFile) {
      if (archiveFile.size > MAX_ARCHIVE_BYTES) { toast.error("Archive exceeds 500 MB limit"); return; }
    }

    setSubmitting(true);
    try {
      const payload = new FormData();
      payload.append("project_name", trimmedName);
      payload.append("scan_type", scanType);
      payload.append("reasoning_llm_config_id", llmConfigId);
      // V02.2.1: intersect selectedFrameworks with the loaded allowlist before submitting
      const safeFrameworks = selectedFrameworks.filter((n) => frameworks?.some((f) => f.name === n));
      payload.append("frameworks", safeFrameworks.join(","));
      if (mode === "upload") {
        for (const f of files) payload.append("files", f);
      } else if (mode === "git") {
        payload.append("repo_url", repoUrl.trim());
      } else if (mode === "archive" && archiveFile) {
        payload.append("archive_file", archiveFile);
      }

      const response = await scanService.createScan(payload);
      toast.success("Scan submitted. Tracking progress…");
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
      toast.error(detail);
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
                <Dropzone
                  multiple
                  onFiles={(next) => {
                    // V05.2.2: extension allowlist
                    const allowed: File[] = [];
                    for (const f of next) {
                      const ext = "." + f.name.split(".").pop()?.toLowerCase();
                      if (!ALLOWED_UPLOAD_EXTENSIONS.has(ext)) {
                        toast.error(`"${f.name}" has an unsupported extension and was skipped`);
                        continue;
                      }
                      // V05.2.1: per-file size cap at drop time
                      if (f.size > MAX_FILE_BYTES) {
                        toast.error(`"${f.name}" exceeds 50 MB and was skipped`);
                        continue;
                      }
                      allowed.push(f);
                    }
                    if (allowed.length === 0) return;
                    setFiles((prev) => {
                      // V05.2.1: aggregate size cap at drop time
                      const currentTotal = prev.reduce((s, f) => s + f.size, 0);
                      const accepted: File[] = [];
                      let running = currentTotal;
                      for (const f of allowed) {
                        if (running + f.size > MAX_TOTAL_BYTES) {
                          toast.error(`Adding "${f.name}" would exceed the 200 MB total limit; it was skipped`);
                          continue;
                        }
                        running += f.size;
                        accepted.push(f);
                      }
                      return [...prev, ...accepted];
                    });
                  }}
                  hint="Drop files here or click to browse"
                  helper="Up to 200 files, 50 MB each, 200 MB total. Supported source-code extensions only. Binary files are ignored; potentially-malicious files are quarantined and reported."
                />
                {files.length > 0 && (
                  <div
                    style={{
                      marginTop: 12,
                      display: "grid",
                      gap: 4,
                      maxHeight: 200,
                      overflowY: "auto",
                    }}
                  >
                    {files.map((f, i) => (
                      <div
                        key={`${f.name}-${i}`}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          fontSize: 12.5,
                          color: "var(--fg-muted)",
                          padding: "4px 0",
                        }}
                      >
                        <span
                          className="mono"
                          style={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: 360,
                          }}
                        >
                          {f.name}
                        </span>
                        <span
                          onClick={() =>
                            setFiles((prev) => prev.filter((_, j) => j !== i))
                          }
                          style={{
                            cursor: "pointer",
                            color: "var(--fg-subtle)",
                            fontSize: 11,
                          }}
                        >
                          Remove
                        </span>
                      </div>
                    ))}
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
                {/* V12.3.1: HTTPS-only gate */}
                {repoUrl.trim().length > 0 && (() => {
                  try { const u = new URL(repoUrl.trim()); if (u.protocol !== "https:") return (
                    <div style={{ marginTop: 6, fontSize: 11.5, color: "var(--danger, #c0392b)" }}>
                      HTTPS git URLs only — http://, git://, and ssh:// are not accepted from the UI.
                    </div>
                  ); } catch { return null; } return null;
                })()}
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
                {/* V05.2.3: server enforces max uncompressed size (2 GB) and file count (50 000)
                    before extraction; it also rejects archives with a compressed:uncompressed
                    ratio exceeding 1:100 and archives containing symlinks. This client-side
                    check is a UX guard only — backend validation is authoritative. */}
                <Dropzone
                  accept={ARCHIVE_ACCEPT}
                  onFiles={async (next) => {
                    const file = next[0];
                    if (!file) return;
                    // V05.2.1: archive size cap at drop time
                    if (file.size > MAX_ARCHIVE_BYTES) {
                      toast.error("Archive exceeds the 500 MB limit");
                      return;
                    }
                    // V05.2.2: magic-byte validation (zip / gzip / tar)
                    try {
                      const buf = await file.slice(0, 262).arrayBuffer();
                      const bytes = new Uint8Array(buf);
                      const isZip = bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;
                      const isGzip = bytes[0] === 0x1F && bytes[1] === 0x8B;
                      // ustar marker at offset 257
                      const isTar = buf.byteLength >= 262 &&
                        bytes[257] === 0x75 && bytes[258] === 0x73 && bytes[259] === 0x74 &&
                        bytes[260] === 0x61 && bytes[261] === 0x72;
                      if (!isZip && !isGzip && !isTar) {
                        toast.error("File does not appear to be a valid zip, gzip, or tar archive");
                        return;
                      }
                    } catch {
                      toast.error("Could not read archive header; please try again");
                      return;
                    }
                    setArchiveFile(file);
                  }}
                  hint="Drop a .zip or .tar.gz"
                  helper="Single .zip/.tar/.tar.gz, up to 500 MB compressed and 2 GB uncompressed. Symlinks are rejected by the server."
                />
                {archiveFile && (
                  <div
                    style={{
                      marginTop: 12,
                      display: "flex",
                      justifyContent: "space-between",
                      fontSize: 12.5,
                      color: "var(--fg-muted)",
                    }}
                  >
                    <span className="mono">{archiveFile.name}</span>
                    <span
                      onClick={() => setArchiveFile(null)}
                      style={{
                        cursor: "pointer",
                        color: "var(--fg-subtle)",
                        fontSize: 11,
                      }}
                    >
                      Remove
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="surface" style={{ padding: 20 }}>
          <h3 style={{ marginBottom: 12, color: "var(--fg)" }}>
            Scan configuration
          </h3>
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
                        background: active
                          ? "var(--primary-weak)"
                          : "var(--bg-elev)",
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
                        <div
                          style={{ fontSize: 11.5, color: "var(--fg-muted)" }}
                        >
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
                        background: on
                          ? "var(--primary-weak)"
                          : "var(--bg-soft)",
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
                <Icon.Play size={12} />{" "}
                {submitting ? "Submitting…" : "Start scan"}
              </button>
            </div>
          </div>
        </div>
      </div>

      <aside style={{ display: "grid", gap: 16, alignContent: "start" }}>
        <div className="sccap-card">
          <h4 style={{ marginBottom: 10, color: "var(--fg)" }}>
            What we scan for
          </h4>
          <div style={{ display: "grid", gap: 8, fontSize: 12.5 }}>
            {[
              { icon: <Icon.Lock size={12} />, label: "Vulnerabilities (SAST)" },
              {
                icon: <Icon.Box size={12} />,
                label: "Dependencies (where configured)",
              },
              { icon: <Icon.Key size={12} />, label: "Secrets & credentials" },
              {
                icon: <Icon.Shield size={12} />,
                label: "Compliance framework mappings",
              },
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
          style={{
            background: "var(--primary-weak)",
            borderColor: "transparent",
          }}
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
