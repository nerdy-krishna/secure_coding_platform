// secure-code-ui/src/pages/admin/FrameworkIngestionModal.tsx
//
// Framework ingestion wizard. Ported off antd to SCCAP primitives.
// Two steps: configure (name, CSV, languages, LLM) → review cost.
// Endpoint contract with ragService is unchanged.

import React, { useEffect, useState } from "react";
import { saveAs } from "file-saver";
import { ragService } from "../../shared/api/ragService";
import type {
  LLMConfiguration,
  RAGJobStartResponse,
} from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

interface FrameworkIngestionModalProps {
  visible: boolean;
  onCancel: () => void;
  onSuccess: (jobId: string) => void;
  initialValues?: {
    frameworkName: string;
    isEdit?: boolean;
  };
  llmConfigs: LLMConfiguration[];
}

const SUPPORTED_LANGUAGES: { label: string; value: string }[] = [
  { label: "Python", value: "python" },
  { label: "JavaScript / TypeScript", value: "javascript" },
  { label: "Java", value: "java" },
  { label: "C# / .NET", value: "csharp" },
  { label: "Go", value: "go" },
  { label: "C / C++", value: "cpp" },
  { label: "Ruby", value: "ruby" },
  { label: "PHP", value: "php" },
  { label: "Swift", value: "swift" },
  { label: "Kotlin", value: "kotlin" },
];

export const FrameworkIngestionModal: React.FC<FrameworkIngestionModalProps> = ({
  visible,
  onCancel,
  onSuccess,
  initialValues,
  llmConfigs,
}) => {
  const toast = useToast();
  const [step, setStep] = useState<0 | 1>(0);
  const [loading, setLoading] = useState(false);
  const [jobData, setJobData] = useState<RAGJobStartResponse | null>(null);

  const [frameworkName, setFrameworkName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [targetLanguages, setTargetLanguages] = useState<string[]>([]);
  const [llmConfigId, setLlmConfigId] = useState<string>("");

  const isEdit = !!initialValues?.isEdit;

  useEffect(() => {
    if (visible) {
      setFrameworkName(initialValues?.frameworkName ?? "");
      setFile(null);
      setTargetLanguages([]);
      setLlmConfigId(llmConfigs[0]?.id ?? "");
      setJobData(null);
      setStep(0);
    }
  }, [visible, initialValues, llmConfigs]);

  const handleDownloadTemplate = () => {
    const csv =
      "id,document\n1,Authentication guidelines...\n2,Input validation rules...";
    saveAs(
      new Blob([csv], { type: "text/csv;charset=utf-8;" }),
      "framework_template.csv",
    );
  };

  const onGetEstimate = async () => {
    if (!frameworkName) {
      toast.error("Framework name is required.");
      return;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(frameworkName)) {
      toast.error(
        "Framework name may only contain letters, numbers, _ and -.",
      );
      return;
    }
    if (!llmConfigId) {
      toast.error("Select an LLM configuration.");
      return;
    }
    setLoading(true);
    try {
      let response: RAGJobStartResponse;
      if (file) {
        const fd = new FormData();
        fd.append("file", file);
        fd.append("framework_name", frameworkName);
        fd.append("llm_config_id", llmConfigId);
        response = await ragService.startPreprocessing(fd, targetLanguages);
      } else if (isEdit) {
        response = await ragService.reprocessFramework(
          frameworkName,
          targetLanguages,
          llmConfigId,
        );
      } else {
        toast.error("Please upload a CSV file.");
        setLoading(false);
        return;
      }
      setJobData(response);
      setStep(1);
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      toast.error(
        e.response?.data?.detail ||
          e.message ||
          "Failed to get cost estimate.",
      );
    } finally {
      setLoading(false);
    }
  };

  const onSubmitJob = async () => {
    if (!jobData) return;
    setLoading(true);
    try {
      await ragService.approveJob(jobData.job_id);
      toast.success("Ingestion job started.");
      onSuccess(jobData.job_id);
      onCancel();
    } catch {
      toast.error("Failed to start job.");
    } finally {
      setLoading(false);
    }
  };

  const toggleLanguage = (value: string) => {
    setTargetLanguages((prev) =>
      prev.includes(value)
        ? prev.filter((l) => l !== value)
        : [...prev, value],
    );
  };

  const renderHeader = () => (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(2, 1fr)",
        gap: 4,
        marginBottom: 18,
      }}
    >
      {["Configure", "Review cost"].map((label, i) => {
        const active = i === step;
        const done = i < step;
        return (
          <div key={label} style={{ textAlign: "center" }}>
            <div
              style={{
                margin: "0 auto 6px",
                width: 24,
                height: 24,
                borderRadius: 12,
                display: "grid",
                placeItems: "center",
                background:
                  done || active ? "var(--primary)" : "var(--bg-soft)",
                color: done || active ? "white" : "var(--fg-muted)",
                fontSize: 11,
                fontWeight: 600,
              }}
            >
              {done ? <Icon.Check size={11} /> : i + 1}
            </div>
            <div
              style={{
                fontSize: 11,
                color: active
                  ? "var(--fg)"
                  : done
                    ? "var(--fg-muted)"
                    : "var(--fg-subtle)",
                fontWeight: active ? 600 : 400,
              }}
            >
              {label}
            </div>
          </div>
        );
      })}
    </div>
  );

  return (
    <Modal
      open={visible}
      onClose={onCancel}
      title={isEdit ? "Update framework" : "Add custom framework"}
      width={700}
    >
      {renderHeader()}

      {step === 0 ? (
        <div style={{ display: "grid", gap: 14 }}>
          <div
            className="sccap-card"
            style={{
              padding: 12,
              background: "var(--info-weak)",
              borderColor: "var(--info)",
              color: "var(--info)",
              fontSize: 12.5,
              lineHeight: 1.55,
            }}
          >
            {isEdit
              ? "Update your framework by adding language-specific patterns. Use existing documents or upload a new CSV."
              : "Upload a CSV with your security standards. SCCAP will generate code patterns for the selected languages."}
          </div>

          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Framework name
            </span>
            <input
              className="sccap-input mono"
              placeholder="e.g. custom_security_standard"
              value={frameworkName}
              onChange={(e) => setFrameworkName(e.target.value)}
              disabled={isEdit}
            />
          </label>

          <div style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Source file (CSV)
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <input
                type="file"
                accept=".csv"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                style={{ fontSize: 12 }}
              />
              <button
                type="button"
                className="sccap-btn sccap-btn-ghost sccap-btn-sm"
                onClick={handleDownloadTemplate}
              >
                <Icon.Download size={12} /> Sample template
              </button>
            </div>
            {!file && isEdit && (
              <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
                Leave empty to reuse existing documents from previous jobs.
              </span>
            )}
          </div>

          <div style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Target languages for code patterns
            </span>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(2, 1fr)",
                gap: 6,
              }}
            >
              {SUPPORTED_LANGUAGES.map((l) => {
                const on = targetLanguages.includes(l.value);
                return (
                  <button
                    key={l.value}
                    type="button"
                    onClick={() => toggleLanguage(l.value)}
                    className="chip"
                    style={{
                      cursor: "pointer",
                      justifyContent: "flex-start",
                      background: on
                        ? "var(--primary-weak)"
                        : "transparent",
                      color: on ? "var(--primary)" : "var(--fg-muted)",
                      border: on
                        ? "1px solid var(--primary)"
                        : "1px solid var(--border)",
                    }}
                  >
                    {on && <Icon.Check size={10} />} {l.label}
                  </button>
                );
              })}
            </div>
          </div>

          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              LLM configuration
            </span>
            <select
              className="sccap-input"
              value={llmConfigId}
              onChange={(e) => setLlmConfigId(e.target.value)}
            >
              <option value="">Select LLM Configuration</option>
              {llmConfigs.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.provider} · {c.model_name})
                </option>
              ))}
            </select>
            <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
              Used to analyze documents and generate patterns.
            </span>
          </label>

          <div className="sccap-divider" />
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={onCancel}
              disabled={loading}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onGetEstimate}
              disabled={loading}
            >
              {loading ? "Estimating…" : "Get cost estimate"}
            </button>
          </div>
        </div>
      ) : jobData ? (
        <div style={{ display: "grid", gap: 14 }}>
          <div
            className="sccap-card"
            style={{
              padding: 12,
              background: "var(--success-weak)",
              borderColor: "var(--success)",
              color: "var(--success)",
              fontSize: 12.5,
            }}
          >
            Ready to process. Review the estimated cost before starting the job.
          </div>
          <div
            className="inset"
            style={{ padding: 16, display: "grid", gap: 8 }}
          >
            <div
              style={{
                fontSize: 10.5,
                color: "var(--fg-subtle)",
                textTransform: "uppercase",
                letterSpacing: ".06em",
              }}
            >
              Job summary
            </div>
            <Row label="Framework">{jobData.framework_name}</Row>
            <Row label="Estimated cost">
              $
              {jobData.estimated_cost?.total_estimated_cost
                ? Number(jobData.estimated_cost.total_estimated_cost) > 0 &&
                  Number(jobData.estimated_cost.total_estimated_cost) < 0.0001
                  ? "< 0.0001"
                  : Number(
                      jobData.estimated_cost.total_estimated_cost,
                    ).toFixed(4)
                : "0.0000"}
            </Row>
            <Row label="Input tokens">
              {Number(jobData.estimated_cost?.total_input_tokens) || 0}
            </Row>
            <Row label="Predicted output tokens">
              {Number(jobData.estimated_cost?.predicted_output_tokens) || 0}
            </Row>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setStep(0)}
              disabled={loading}
            >
              <Icon.ChevronL size={12} /> Back
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onSubmitJob}
              disabled={loading}
            >
              {loading ? "Submitting…" : "Submit job"}
            </button>
          </div>
        </div>
      ) : null}
    </Modal>
  );
};

const Row: React.FC<{ label: string; children: React.ReactNode }> = ({
  label,
  children,
}) => (
  <div
    style={{
      display: "flex",
      justifyContent: "space-between",
      fontSize: 12.5,
    }}
  >
    <span style={{ color: "var(--fg-muted)" }}>{label}</span>
    <span
      style={{
        color: "var(--fg)",
        fontVariantNumeric: "tabular-nums",
      }}
      className="mono"
    >
      {children}
    </span>
  </div>
);
