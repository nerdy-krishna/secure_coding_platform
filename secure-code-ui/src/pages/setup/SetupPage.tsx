// secure-code-ui/src/pages/setup/SetupPage.tsx
//
// SCCAP first-run setup wizard. Ported off antd Steps/Form/Radio/Select;
// form state is a single useState object, step-level validation is done
// in JS before advancing. Endpoint contract (/setup) unchanged.

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../../shared/api/apiClient";
import { useAuth } from "../../shared/hooks/useAuth";
import { Icon } from "../../shared/ui/Icon";

type DeploymentType = "local" | "cloud";
type LLMMode = "multi_provider" | "anthropic_optimized";

interface SetupFormValues {
  deployment_type: DeploymentType;
  frontend_url: string;
  admin_email: string;
  admin_password: string;
  llm_optimization_mode: LLMMode;
  llm_provider: string;
  llm_model: string;
  llm_api_key: string;
}

const STEPS = ["Deployment", "Admin", "LLM mode", "LLM config"] as const;

const DEFAULTS: SetupFormValues = {
  deployment_type: "local",
  frontend_url: "",
  admin_email: "",
  admin_password: "",
  llm_optimization_mode: "multi_provider",
  llm_provider: "openai",
  llm_model: "gpt-4o",
  llm_api_key: "",
};

const SetupPage: React.FC = () => {
  const navigate = useNavigate();
  const { isSetupCompleted, isLoading, checkSetupStatus } = useAuth();

  const [step, setStep] = useState(0);
  const [form, setForm] = useState<SetupFormValues>(DEFAULTS);
  const [stepError, setStepError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isLoading && isSetupCompleted) {
      navigate("/login");
    }
  }, [isSetupCompleted, isLoading, navigate]);

  useEffect(() => {
    if (form.llm_optimization_mode === "anthropic_optimized") {
      if (form.llm_provider !== "anthropic") {
        setForm((f) => ({
          ...f,
          llm_provider: "anthropic",
          llm_model: "claude-sonnet-4-6",
        }));
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.llm_optimization_mode]);

  if (isLoading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          color: "var(--fg-muted)",
        }}
      >
        Loading…
      </div>
    );
  }

  const validateStep = (): boolean => {
    if (step === 0) {
      if (!form.deployment_type) {
        setStepError("Select a deployment environment.");
        return false;
      }
      if (form.deployment_type === "cloud") {
        if (!form.frontend_url || !/^https?:\/\//.test(form.frontend_url)) {
          setStepError("Enter a valid frontend URL (http[s]://…).");
          return false;
        }
      }
    }
    if (step === 1) {
      if (!form.admin_email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.admin_email)) {
        setStepError("Enter a valid admin email.");
        return false;
      }
      if (!form.admin_password || form.admin_password.length < 8) {
        setStepError("Admin password must be at least 8 characters.");
        return false;
      }
    }
    if (step === 3) {
      if (!form.llm_provider || !form.llm_model || !form.llm_api_key) {
        setStepError("LLM provider, model, and API key are required.");
        return false;
      }
    }
    setStepError(null);
    return true;
  };

  const goNext = () => {
    if (!validateStep()) return;
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  };
  const goBack = () => setStep((s) => Math.max(s - 1, 0));

  const onSubmit = async () => {
    if (!validateStep()) return;
    setSubmitting(true);
    setError(null);
    try {
      await apiClient.post("/setup", form);
      await checkSetupStatus();
      navigate("/login");
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: unknown } };
        message?: string;
      };
      const detail = e.response?.data?.detail;
      const msg =
        typeof detail === "string"
          ? detail
          : detail
            ? JSON.stringify(detail)
            : e.message || "Setup failed. Please try again.";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div
        className="surface"
        style={{ width: "100%", maxWidth: 640, padding: 32 }}
      >
        <div style={{ textAlign: "center", marginBottom: 14 }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              color: "var(--fg)",
              fontSize: 20,
              fontWeight: 600,
            }}
          >
            <Icon.Shield size={22} color="var(--primary)" /> SCCAP setup
          </div>
          <div
            style={{
              color: "var(--fg-muted)",
              fontSize: 12.5,
              marginTop: 4,
            }}
          >
            Configure deployment, the admin account, and your LLM provider.
          </div>
        </div>

        <StepsHeader current={step} />

        {error && (
          <div
            className="sccap-card"
            style={{
              padding: 12,
              marginBottom: 14,
              background: "var(--critical-weak)",
              borderColor: "var(--critical)",
              color: "var(--critical)",
              fontSize: 13,
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>{error}</span>
            <button
              className="sccap-btn sccap-btn-icon sccap-btn-ghost"
              onClick={() => setError(null)}
            >
              <Icon.X size={12} />
            </button>
          </div>
        )}

        {stepError && (
          <div
            style={{
              color: "var(--critical)",
              fontSize: 12,
              marginBottom: 12,
            }}
          >
            {stepError}
          </div>
        )}

        <div style={{ display: "grid", gap: 14 }}>
          {step === 0 && (
            <>
              <Field label="Deployment environment">
                <RadioCard
                  checked={form.deployment_type === "local"}
                  onChange={() =>
                    setForm({ ...form, deployment_type: "local" })
                  }
                  title="Local development"
                  desc="App runs on your machine with default CORS."
                />
                <RadioCard
                  checked={form.deployment_type === "cloud"}
                  onChange={() =>
                    setForm({ ...form, deployment_type: "cloud" })
                  }
                  title="Cloud / VPS"
                  desc="Expose via a public URL."
                />
              </Field>
              {form.deployment_type === "cloud" && (
                <Field
                  label="Public frontend URL"
                  hint="Where users will access the UI."
                >
                  <input
                    className="sccap-input"
                    placeholder="https://yourdomain.com"
                    value={form.frontend_url}
                    onChange={(e) =>
                      setForm({ ...form, frontend_url: e.target.value })
                    }
                  />
                </Field>
              )}
            </>
          )}

          {step === 1 && (
            <>
              <Field label="Admin email">
                <input
                  className="sccap-input"
                  type="email"
                  autoComplete="email"
                  value={form.admin_email}
                  onChange={(e) =>
                    setForm({ ...form, admin_email: e.target.value })
                  }
                />
              </Field>
              <Field label="Admin password" hint="Minimum 8 characters.">
                <input
                  className="sccap-input"
                  type="password"
                  autoComplete="new-password"
                  value={form.admin_password}
                  onChange={(e) =>
                    setForm({ ...form, admin_password: e.target.value })
                  }
                />
              </Field>
            </>
          )}

          {step === 2 && (
            <Field label="LLM optimization mode">
              <RadioCard
                checked={form.llm_optimization_mode === "anthropic_optimized"}
                onChange={() =>
                  setForm({
                    ...form,
                    llm_optimization_mode: "anthropic_optimized",
                  })
                }
                title="Anthropic optimized (recommended)"
                desc="Prompt caching, tuned prompt variants, tool use. Locks the provider to Anthropic. Typical 70%+ cost drop on repeated-agent-per-file scans."
              />
              <RadioCard
                checked={form.llm_optimization_mode === "multi_provider"}
                onChange={() =>
                  setForm({
                    ...form,
                    llm_optimization_mode: "multi_provider",
                  })
                }
                title="Multi-provider (generic)"
                desc="Portable prompts across OpenAI, Anthropic, and Google. No caching; broader model choice."
              />
            </Field>
          )}

          {step === 3 && (
            <>
              <Field
                label="LLM provider"
                hint={
                  form.llm_optimization_mode === "anthropic_optimized"
                    ? "Locked to Anthropic by the optimization mode."
                    : undefined
                }
              >
                <select
                  className="sccap-input"
                  value={form.llm_provider}
                  disabled={
                    form.llm_optimization_mode === "anthropic_optimized"
                  }
                  onChange={(e) =>
                    setForm({ ...form, llm_provider: e.target.value })
                  }
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="gemini">Google Gemini</option>
                </select>
              </Field>
              <Field label="Model name">
                <input
                  className="sccap-input mono"
                  placeholder="e.g. gpt-4o, claude-sonnet-4-6"
                  value={form.llm_model}
                  onChange={(e) =>
                    setForm({ ...form, llm_model: e.target.value })
                  }
                />
              </Field>
              <Field label="API key">
                <input
                  className="sccap-input mono"
                  type="password"
                  autoComplete="off"
                  value={form.llm_api_key}
                  onChange={(e) =>
                    setForm({ ...form, llm_api_key: e.target.value })
                  }
                />
              </Field>
            </>
          )}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            marginTop: 24,
          }}
        >
          <button
            className="sccap-btn"
            onClick={goBack}
            disabled={step === 0 || submitting}
          >
            <Icon.ChevronL size={12} /> Back
          </button>
          {step < STEPS.length - 1 ? (
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={goNext}
            >
              Next <Icon.ChevronR size={12} />
            </button>
          ) : (
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={onSubmit}
              disabled={submitting}
            >
              {submitting ? "Finishing…" : "Finish setup"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

const StepsHeader: React.FC<{ current: number }> = ({ current }) => (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: `repeat(${STEPS.length}, 1fr)`,
      gap: 4,
      margin: "20px 0 24px",
    }}
  >
    {STEPS.map((label, i) => {
      const active = i === current;
      const done = i < current;
      return (
        <div key={label} style={{ textAlign: "center" }}>
          <div
            style={{
              margin: "0 auto 6px",
              width: 26,
              height: 26,
              borderRadius: 13,
              display: "grid",
              placeItems: "center",
              background: done || active ? "var(--primary)" : "var(--bg-soft)",
              color: done || active ? "white" : "var(--fg-muted)",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {done ? <Icon.Check size={13} /> : i + 1}
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

const Field: React.FC<{
  label: string;
  hint?: string;
  children: React.ReactNode;
}> = ({ label, hint, children }) => (
  <label style={{ display: "grid", gap: 6 }}>
    <span style={{ fontSize: 12, color: "var(--fg-muted)", fontWeight: 500 }}>
      {label}
      {hint && (
        <span
          style={{
            marginLeft: 8,
            color: "var(--fg-subtle)",
            fontWeight: 400,
          }}
        >
          {hint}
        </span>
      )}
    </span>
    {children}
  </label>
);

const RadioCard: React.FC<{
  checked: boolean;
  onChange: () => void;
  title: string;
  desc: string;
}> = ({ checked, onChange, title, desc }) => (
  <label
    onClick={onChange}
    style={{
      display: "grid",
      gridTemplateColumns: "auto 1fr",
      gap: 10,
      padding: 12,
      border:
        "1px solid " + (checked ? "var(--primary)" : "var(--border)"),
      background: checked ? "var(--primary-weak)" : "var(--bg-elev)",
      borderRadius: "var(--r-sm)",
      cursor: "pointer",
      marginTop: 6,
    }}
  >
    <input
      type="radio"
      checked={checked}
      onChange={onChange}
      style={{ accentColor: "var(--primary)", marginTop: 3 }}
    />
    <div>
      <div style={{ fontSize: 13.5, fontWeight: 500, color: "var(--fg)" }}>
        {title}
      </div>
      <div
        style={{
          fontSize: 11.5,
          color: "var(--fg-muted)",
          marginTop: 2,
          lineHeight: 1.5,
        }}
      >
        {desc}
      </div>
    </div>
  </label>
);

export default SetupPage;
