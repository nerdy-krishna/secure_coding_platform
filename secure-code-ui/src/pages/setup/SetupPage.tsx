import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../../shared/api/apiClient";
import { useAuth } from "../../shared/hooks/useAuth";

const SetupPage: React.FC = () => {
  const navigate = useNavigate();
  const { isSetupCompleted, isLoading, checkSetupStatus } = useAuth(); // Get setup status from auth context
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [deploymentType, setDeploymentType] = useState<"local" | "cloud">(
    "local",
  );

  interface SetupFormData {
    admin_email: string;
    admin_password: string;
    llm_provider: string;
    llm_api_key: string;
    llm_model: string;
    llm_optimization_mode: "multi_provider" | "anthropic_optimized";
    deployment_type: "local" | "cloud";
    frontend_url: string;
  }

  const [formData, setFormData] = useState<SetupFormData>({
    admin_email: "",
    admin_password: "",
    llm_provider: "openai",
    llm_api_key: "",
    llm_model: "gpt-4o",
    llm_optimization_mode: "multi_provider",
    deployment_type: "local",
    frontend_url: "",
  });

  const setMode = (mode: "multi_provider" | "anthropic_optimized") => {
    if (mode === "anthropic_optimized") {
      // Anthropic optimized locks the provider; suggest a sensible default model.
      setFormData((prev) => ({
        ...prev,
        llm_optimization_mode: mode,
        llm_provider: "anthropic",
        llm_model:
          prev.llm_provider === "anthropic" ? prev.llm_model : "claude-sonnet-4-6",
      }));
    } else {
      setFormData((prev) => ({ ...prev, llm_optimization_mode: mode }));
    }
  };

  // Redirect to login if setup is already completed
  React.useEffect(() => {
    if (!isLoading && isSetupCompleted) {
      navigate("/login");
    }
  }, [isSetupCompleted, isLoading, navigate]);

  // Show loading state while checking status
  if (isLoading) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        {" "}
        Loading...
      </div>
    );
  }

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>,
  ) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleDeploymentTypeChange = (type: "local" | "cloud") => {
    setDeploymentType(type);
    setFormData({ ...formData, deployment_type: type });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const payload = {
        ...formData,
        deployment_type: deploymentType,
      };
      if (deploymentType === "cloud" && !formData.frontend_url) {
        setError(
          "Please provide your public frontend URL for the cloud deployment.",
        );
        setLoading(false);
        return;
      }
      await apiClient.post("/setup", payload);
      await checkSetupStatus();
      navigate("/login");
    } catch (err: any) {
      console.error("Setup failed details:", err);
      const msg = err.response?.data?.detail
        ? typeof err.response.data.detail === "string"
          ? err.response.data.detail
          : JSON.stringify(err.response.data.detail)
        : err.message || "Setup failed. Please try again.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        backgroundColor: "#f3f4f6",
        fontFamily: "Inter, sans-serif",
      }}
    >
      <div
        style={{
          backgroundColor: "white",
          padding: "2rem",
          borderRadius: "8px",
          boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
          width: "100%",
          maxWidth: "500px",
        }}
      >
        <h1
          style={{
            textAlign: "center",
            marginBottom: "1.5rem",
            color: "#111827",
          }}
        >
          Secure Coding Platform Setup
        </h1>

        {error && (
          <div
            style={{
              backgroundColor: "#fee2e2",
              color: "#b91c1c",
              padding: "1rem",
              borderRadius: "4px",
              marginBottom: "1rem",
            }}
          >
            {error}
          </div>
        )}

        <div
          style={{
            marginBottom: "1.5rem",
            display: "flex",
            justifyContent: "center",
          }}
        >
          <div style={{ display: "flex", gap: "1rem" }}>
            <span
              style={{
                fontWeight: step === 1 ? "bold" : "normal",
                color: step === 1 ? "#2563eb" : "#9ca3af",
              }}
            >
              {" "}
              1. Deployment{" "}
            </span>
            <span style={{ color: "#9ca3af" }}>& rarr; </span>
            <span
              style={{
                fontWeight: step === 2 ? "bold" : "normal",
                color: step === 2 ? "#2563eb" : "#9ca3af",
              }}
            >
              {" "}
              2. Admin{" "}
            </span>
            <span style={{ color: "#9ca3af" }}>& rarr; </span>
            <span
              style={{
                fontWeight: step === 3 ? "bold" : "normal",
                color: step === 3 ? "#2563eb" : "#9ca3af",
              }}
            >
              {" "}
              3. LLM Mode{" "}
            </span>
            <span style={{ color: "#9ca3af" }}>& rarr; </span>
            <span
              style={{
                fontWeight: step === 4 ? "bold" : "normal",
                color: step === 4 ? "#2563eb" : "#9ca3af",
              }}
            >
              {" "}
              4. LLM Config{" "}
            </span>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          {step === 1 && (
            <>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                    fontWeight: "bold",
                  }}
                >
                  Deployment Environment
                </label>

                <div
                  style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}
                >
                  <div
                    onClick={() => handleDeploymentTypeChange("local")}
                    style={{
                      flex: 1,
                      padding: "1rem",
                      border:
                        deploymentType === "local"
                          ? "2px solid #2563eb"
                          : "1px solid #d1d5db",
                      borderRadius: "8px",
                      cursor: "pointer",
                      backgroundColor:
                        deploymentType === "local" ? "#eff6ff" : "white",
                    }}
                  >
                    <h3 style={{ margin: "0 0 0.5rem 0", color: "#111827" }}>
                      {" "}
                      Local Development{" "}
                    </h3>
                    <p
                      style={{
                        margin: 0,
                        fontSize: "0.875rem",
                        color: "#6b7280",
                      }}
                    >
                      App is running locally on your machine.Default local
                      configurations will be applied.
                    </p>
                  </div>

                  <div
                    onClick={() => handleDeploymentTypeChange("cloud")}
                    style={{
                      flex: 1,
                      padding: "1rem",
                      border:
                        deploymentType === "cloud"
                          ? "2px solid #2563eb"
                          : "1px solid #d1d5db",
                      borderRadius: "8px",
                      cursor: "pointer",
                      backgroundColor:
                        deploymentType === "cloud" ? "#eff6ff" : "white",
                    }}
                  >
                    <h3 style={{ margin: "0 0 0.5rem 0", color: "#111827" }}>
                      {" "}
                      Cloud / VPS{" "}
                    </h3>
                    <p
                      style={{
                        margin: 0,
                        fontSize: "0.875rem",
                        color: "#6b7280",
                      }}
                    >
                      App is deployed online.You will need to provide your
                      public domain / IP.
                    </p>
                  </div>
                </div>

                {deploymentType === "cloud" && (
                  <div style={{ marginTop: "1.5rem" }}>
                    <label
                      style={{
                        display: "block",
                        marginBottom: "0.5rem",
                        color: "#374151",
                      }}
                    >
                      {" "}
                      Public Frontend URL{" "}
                    </label>
                    <input
                      type="text"
                      name="frontend_url"
                      placeholder="e.g., http://123.45.67.89 or https://yourdomain.com"
                      value={formData.frontend_url}
                      onChange={handleChange}
                      required
                      style={{
                        width: "100%",
                        padding: "0.75rem",
                        borderRadius: "4px",
                        border: "1px solid #d1d5db",
                      }}
                    />
                    <p
                      style={{
                        marginTop: "0.5rem",
                        fontSize: "0.8rem",
                        color: "#6b7280",
                      }}
                    >
                      This is the URL where users will access the
                      platform.Omitting the port is recommended if deploying on
                      standard HTTP / HTTPS(port 80 / 443).
                    </p>
                  </div>
                )}
              </div>

              <div style={{ display: "flex", gap: "1rem" }}>
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  disabled={
                    deploymentType === "cloud" && !formData.frontend_url
                  }
                  style={{
                    flex: 1,
                    backgroundColor: "#2563eb",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                    opacity:
                      deploymentType === "cloud" && !formData.frontend_url
                        ? 0.5
                        : 1,
                  }}
                >
                  Next
                </button>
              </div>
            </>
          )}

          {step === 2 && (
            <>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                  }}
                >
                  {" "}
                  Admin Email{" "}
                </label>
                <input
                  type="email"
                  name="admin_email"
                  value={formData.admin_email}
                  onChange={handleChange}
                  required
                  style={{
                    width: "100%",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "1px solid #d1d5db",
                  }}
                />
              </div>
              <div style={{ marginBottom: "1.5rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                  }}
                >
                  {" "}
                  Admin Password{" "}
                </label>
                <input
                  type="password"
                  name="admin_password"
                  value={formData.admin_password}
                  onChange={handleChange}
                  required
                  minLength={8}
                  style={{
                    width: "100%",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "1px solid #d1d5db",
                  }}
                />
              </div>
              <div style={{ display: "flex", gap: "1rem" }}>
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  style={{
                    flex: 1,
                    backgroundColor: "#9ca3af",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                  }}
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={() => setStep(3)}
                  disabled={!formData.admin_email || !formData.admin_password}
                  style={{
                    flex: 1,
                    backgroundColor: "#2563eb",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                    opacity:
                      !formData.admin_email || !formData.admin_password
                        ? 0.5
                        : 1,
                  }}
                >
                  Next
                </button>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                    fontWeight: "bold",
                  }}
                >
                  LLM Optimization Mode
                </label>
                <p
                  style={{
                    margin: "0 0 1rem 0",
                    fontSize: "0.85rem",
                    color: "#6b7280",
                  }}
                >
                  Pick how the platform tunes prompts and features for your
                  model. You can change this later in System Settings.
                </p>

                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.75rem",
                  }}
                >
                  <div
                    onClick={() => setMode("anthropic_optimized")}
                    style={{
                      padding: "1rem",
                      border:
                        formData.llm_optimization_mode === "anthropic_optimized"
                          ? "2px solid #2563eb"
                          : "1px solid #d1d5db",
                      borderRadius: "8px",
                      cursor: "pointer",
                      backgroundColor:
                        formData.llm_optimization_mode === "anthropic_optimized"
                          ? "#eff6ff"
                          : "white",
                    }}
                  >
                    <h3 style={{ margin: "0 0 0.5rem 0", color: "#111827" }}>
                      Anthropic Optimized (recommended)
                    </h3>
                    <p
                      style={{
                        margin: 0,
                        fontSize: "0.875rem",
                        color: "#6b7280",
                      }}
                    >
                      Enables prompt caching, tuned prompt variants, and tool
                      use. Locks the provider to Anthropic. Typical cost drop
                      of 70%+ on repeated-agent-per-file scans.
                    </p>
                  </div>

                  <div
                    onClick={() => setMode("multi_provider")}
                    style={{
                      padding: "1rem",
                      border:
                        formData.llm_optimization_mode === "multi_provider"
                          ? "2px solid #2563eb"
                          : "1px solid #d1d5db",
                      borderRadius: "8px",
                      cursor: "pointer",
                      backgroundColor:
                        formData.llm_optimization_mode === "multi_provider"
                          ? "#eff6ff"
                          : "white",
                    }}
                  >
                    <h3 style={{ margin: "0 0 0.5rem 0", color: "#111827" }}>
                      Multi-Provider (Generic)
                    </h3>
                    <p
                      style={{
                        margin: 0,
                        fontSize: "0.875rem",
                        color: "#6b7280",
                      }}
                    >
                      Works with OpenAI, Anthropic, or Google. Portable
                      prompts, no caching, broader model choice.
                    </p>
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", gap: "1rem" }}>
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  style={{
                    flex: 1,
                    backgroundColor: "#9ca3af",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                  }}
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={() => setStep(4)}
                  style={{
                    flex: 1,
                    backgroundColor: "#2563eb",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                  }}
                >
                  Next
                </button>
              </div>
            </>
          )}

          {step === 4 && (
            <>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                  }}
                >
                  {" "}
                  LLM Provider{" "}
                </label>
                <select
                  name="llm_provider"
                  value={formData.llm_provider}
                  onChange={handleChange}
                  disabled={
                    formData.llm_optimization_mode === "anthropic_optimized"
                  }
                  style={{
                    width: "100%",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "1px solid #d1d5db",
                    backgroundColor:
                      formData.llm_optimization_mode === "anthropic_optimized"
                        ? "#f3f4f6"
                        : "white",
                  }}
                >
                  <option value="openai"> OpenAI </option>
                  <option value="anthropic"> Anthropic </option>
                  <option value="gemini"> Google Gemini </option>
                </select>
                {formData.llm_optimization_mode === "anthropic_optimized" && (
                  <p
                    style={{
                      marginTop: "0.25rem",
                      fontSize: "0.8rem",
                      color: "#6b7280",
                    }}
                  >
                    Provider is locked to Anthropic because you chose the
                    Anthropic-optimized mode.
                  </p>
                )}
              </div>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                  }}
                >
                  {" "}
                  Model Name{" "}
                </label>
                <input
                  type="text"
                  name="llm_model"
                  value={formData.llm_model}
                  onChange={handleChange}
                  required
                  style={{
                    width: "100%",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "1px solid #d1d5db",
                  }}
                />
              </div>
              <div style={{ marginBottom: "1.5rem" }}>
                <label
                  style={{
                    display: "block",
                    marginBottom: "0.5rem",
                    color: "#374151",
                  }}
                >
                  {" "}
                  API Key{" "}
                </label>
                <input
                  type="password"
                  name="llm_api_key"
                  value={formData.llm_api_key}
                  onChange={handleChange}
                  required
                  style={{
                    width: "100%",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "1px solid #d1d5db",
                  }}
                />
              </div>
              <div style={{ display: "flex", gap: "1rem" }}>
                <button
                  type="button"
                  onClick={() => setStep(3)}
                  style={{
                    flex: 1,
                    backgroundColor: "#9ca3af",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                  }}
                >
                  Back
                </button>
                <button
                  type="submit"
                  disabled={!formData.llm_api_key || loading}
                  style={{
                    flex: 1,
                    backgroundColor: "#2563eb",
                    color: "white",
                    padding: "0.75rem",
                    borderRadius: "4px",
                    border: "none",
                    cursor: "pointer",
                    opacity: !formData.llm_api_key || loading ? 0.5 : 1,
                  }}
                >
                  {loading ? "Completing Setup..." : "Finish Setup"}
                </button>
              </div>
            </>
          )}
        </form>
      </div>
    </div>
  );
};

export default SetupPage;
