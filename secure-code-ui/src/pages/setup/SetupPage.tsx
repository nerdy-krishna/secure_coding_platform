import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  Layout,
  Radio,
  Select,
  Space,
  Steps,
  Typography,
} from "antd";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../../shared/api/apiClient";
import { useAuth } from "../../shared/hooks/useAuth";

const { Title, Paragraph, Text } = Typography;

type DeploymentType = "local" | "cloud";
type LLMMode = "multi_provider" | "anthropic_optimized";

interface SetupFormValues {
  deployment_type: DeploymentType;
  frontend_url?: string;
  admin_email: string;
  admin_password: string;
  llm_optimization_mode: LLMMode;
  llm_provider: string;
  llm_model: string;
  llm_api_key: string;
}

const WIZARD_STEPS = [
  { title: "Deployment" },
  { title: "Admin" },
  { title: "LLM Mode" },
  { title: "LLM Config" },
];

const SetupPage: React.FC = () => {
  const navigate = useNavigate();
  const { isSetupCompleted, isLoading, checkSetupStatus } = useAuth();
  const [form] = Form.useForm<SetupFormValues>();

  const [step, setStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // `Form.useWatch` re-renders the component when the watched fields change,
  // so the provider dropdown on step 4 can react to the mode selected on step 3.
  const deploymentType = Form.useWatch("deployment_type", form);
  const llmMode = Form.useWatch("llm_optimization_mode", form);

  useEffect(() => {
    if (!isLoading && isSetupCompleted) {
      navigate("/login");
    }
  }, [isSetupCompleted, isLoading, navigate]);

  // Anthropic-optimized mode locks provider to "anthropic" and nudges a sensible model.
  useEffect(() => {
    if (llmMode === "anthropic_optimized") {
      const currentProvider = form.getFieldValue("llm_provider");
      if (currentProvider !== "anthropic") {
        form.setFieldsValue({
          llm_provider: "anthropic",
          llm_model: "claude-sonnet-4-6",
        });
      }
    }
  }, [llmMode, form]);

  if (isLoading) {
    return (
      <Layout
        style={{
          minHeight: "100vh",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <Text>Loading…</Text>
      </Layout>
    );
  }

  const stepFields: Array<Array<keyof SetupFormValues>> = [
    ["deployment_type", "frontend_url"],
    ["admin_email", "admin_password"],
    ["llm_optimization_mode"],
    ["llm_provider", "llm_model", "llm_api_key"],
  ];

  const goNext = async () => {
    try {
      await form.validateFields(stepFields[step]);
      setStep((s) => Math.min(s + 1, WIZARD_STEPS.length - 1));
    } catch {
      // Ant Design renders field-level validation errors inline.
    }
  };

  const goBack = () => setStep((s) => Math.max(s - 1, 0));

  const onSubmit = async (values: SetupFormValues) => {
    setSubmitting(true);
    setError(null);
    try {
      await apiClient.post("/setup", values);
      await checkSetupStatus();
      navigate("/login");
    } catch (err) {
      const e = err as { response?: { data?: { detail?: unknown } }; message?: string };
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
    <Layout
      style={{
        minHeight: "100vh",
        background: "#f0f2f5",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        padding: "24px",
      }}
    >
      <Card style={{ width: "100%", maxWidth: 640 }}>
        <Title level={3} style={{ textAlign: "center", marginBottom: 8 }}>
          SCCAP Setup
        </Title>
        <Paragraph type="secondary" style={{ textAlign: "center" }}>
          Configure deployment, the admin account, and your LLM provider.
        </Paragraph>

        <Steps
          current={step}
          items={WIZARD_STEPS}
          size="small"
          style={{ margin: "24px 0" }}
        />

        {error && (
          <Alert
            type="error"
            message={error}
            closable
            onClose={() => setError(null)}
            style={{ marginBottom: 16 }}
          />
        )}

        <Form<SetupFormValues>
          form={form}
          layout="vertical"
          initialValues={{
            deployment_type: "local",
            frontend_url: "",
            llm_optimization_mode: "multi_provider",
            llm_provider: "openai",
            llm_model: "gpt-4o",
          }}
          onFinish={onSubmit}
          requiredMark="optional"
        >
          {/* Step 1: Deployment */}
          <div style={{ display: step === 0 ? "block" : "none" }}>
            <Form.Item
              name="deployment_type"
              label="Deployment Environment"
              rules={[{ required: true }]}
            >
              <Radio.Group>
                <Space direction="vertical" style={{ width: "100%" }}>
                  <Radio value="local">
                    <strong>Local Development</strong> — app runs on your
                    machine with default CORS.
                  </Radio>
                  <Radio value="cloud">
                    <strong>Cloud / VPS</strong> — expose via a public URL.
                  </Radio>
                </Space>
              </Radio.Group>
            </Form.Item>

            {deploymentType === "cloud" && (
              <Form.Item
                name="frontend_url"
                label="Public Frontend URL"
                tooltip="Where users will access the UI (e.g., https://yourdomain.com)."
                rules={[
                  {
                    required: true,
                    message: "Frontend URL is required for cloud deployments.",
                  },
                  { type: "url", message: "Enter a valid URL." },
                ]}
              >
                <Input placeholder="https://yourdomain.com" />
              </Form.Item>
            )}
          </div>

          {/* Step 2: Admin */}
          <div style={{ display: step === 1 ? "block" : "none" }}>
            <Form.Item
              name="admin_email"
              label="Admin Email"
              rules={[
                { required: true, message: "Admin email is required." },
                { type: "email", message: "Enter a valid email address." },
              ]}
            >
              <Input autoComplete="email" />
            </Form.Item>
            <Form.Item
              name="admin_password"
              label="Admin Password"
              rules={[
                { required: true, message: "Admin password is required." },
                { min: 8, message: "Password must be at least 8 characters." },
              ]}
            >
              <Input.Password autoComplete="new-password" />
            </Form.Item>
          </div>

          {/* Step 3: LLM Optimization Mode */}
          <div style={{ display: step === 2 ? "block" : "none" }}>
            <Form.Item
              name="llm_optimization_mode"
              label="LLM Optimization Mode"
              tooltip="Switchable later in System Settings."
              rules={[{ required: true }]}
            >
              <Radio.Group>
                <Space direction="vertical" style={{ width: "100%" }}>
                  <Radio value="anthropic_optimized">
                    <strong>Anthropic Optimized (recommended)</strong>
                    <div style={{ color: "#6b7280", fontSize: 13 }}>
                      Prompt caching, tuned prompt variants, tool use. Locks
                      the provider to Anthropic. Typical 70%+ cost drop on
                      repeated-agent-per-file scans.
                    </div>
                  </Radio>
                  <Radio value="multi_provider">
                    <strong>Multi-Provider (Generic)</strong>
                    <div style={{ color: "#6b7280", fontSize: 13 }}>
                      Portable prompts across OpenAI, Anthropic, and Google.
                      No caching; broader model choice.
                    </div>
                  </Radio>
                </Space>
              </Radio.Group>
            </Form.Item>
          </div>

          {/* Step 4: LLM Config */}
          <div style={{ display: step === 3 ? "block" : "none" }}>
            <Form.Item
              name="llm_provider"
              label="LLM Provider"
              extra={
                llmMode === "anthropic_optimized"
                  ? "Locked to Anthropic by the optimization mode."
                  : undefined
              }
              rules={[{ required: true }]}
            >
              <Select
                disabled={llmMode === "anthropic_optimized"}
                options={[
                  { value: "openai", label: "OpenAI" },
                  { value: "anthropic", label: "Anthropic" },
                  { value: "gemini", label: "Google Gemini" },
                ]}
              />
            </Form.Item>
            <Form.Item
              name="llm_model"
              label="Model Name"
              rules={[{ required: true, message: "Model name is required." }]}
            >
              <Input placeholder="e.g., gpt-4o, claude-sonnet-4-6" />
            </Form.Item>
            <Form.Item
              name="llm_api_key"
              label="API Key"
              rules={[{ required: true, message: "API key is required." }]}
            >
              <Input.Password autoComplete="off" />
            </Form.Item>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginTop: 24,
            }}
          >
            <Button onClick={goBack} disabled={step === 0}>
              Back
            </Button>
            {step < WIZARD_STEPS.length - 1 ? (
              <Button type="primary" onClick={goNext}>
                Next
              </Button>
            ) : (
              <Button type="primary" htmlType="submit" loading={submitting}>
                Finish Setup
              </Button>
            )}
          </div>
        </Form>
      </Card>
    </Layout>
  );
};

export default SetupPage;
