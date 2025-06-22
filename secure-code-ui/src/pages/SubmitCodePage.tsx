import {
  GithubOutlined,
  InboxOutlined,
  RobotOutlined,
  ToolOutlined,
  UploadOutlined
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Input,
  Radio, // Import Radio
  Row,
  Select,
  Spin,
  Typography,
  Upload,
  message,
} from "antd";
import { type RcFile } from "antd/es/upload";
import { AxiosError } from "axios";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { llmConfigService } from "../services/llmConfigService";
import { submissionService } from "../services/submissionService";
import type { LLMConfiguration } from "../types/api";

const { Dragger } = Upload;
const { Title, Paragraph, Text } = Typography;
const { Option } = Select;

// Define a type for our form values for better type safety
interface SubmissionFormValues {
  main_llm_config_id: string;
  specialized_llm_config_id: string;
  repo_url?: string;
  frameworks: string[];
}

// Define a type for the submission mode
type SubmissionMode = "upload" | "repo";

const SubmitCodePage: React.FC = () => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const [fileList, setFileList] = useState<RcFile[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionMode, setSubmissionMode] =
    useState<SubmissionMode>("upload");

  const {
    data: llmConfigs,
    isLoading: isLoadingLLMs,
    isError: isLlmError,
    error: llmError,
  } = useQuery<LLMConfiguration[], Error>({
    queryKey: ["llmConfigs"],
    queryFn: () => llmConfigService.getLlmConfigs(),
  });

  const handleSubmissionModeChange = (e: any) => {
    const newMode = e.target.value as SubmissionMode;
    setSubmissionMode(newMode);
    // Clear the alternative input's value when switching modes
    if (newMode === "upload") {
      form.setFieldsValue({ repo_url: "" });
    } else {
      setFileList([]);
    }
  };

  const handleSubmit = async (values: SubmissionFormValues) => {
    if (submissionMode === "upload" && fileList.length === 0) {
      message.error("Please upload at least one file to analyze.");
      return;
    }
    if (
      submissionMode === "repo" &&
      (!values.repo_url || values.repo_url.trim() === "")
    ) {
      message.error("Please provide a repository URL to analyze.");
      return;
    }

    setIsSubmitting(true);
    try {
      const formData = new FormData();

      if (submissionMode === "upload") {
        fileList.forEach((file) => {
          formData.append("files", file);
        });
      } else if (values.repo_url) {
        formData.append("repo_url", values.repo_url.trim());
      }

      const selectedFrameworks = values.frameworks.filter(Boolean);
      if (selectedFrameworks.length === 0) {
        message.error("Please select at least one security framework.");
        setIsSubmitting(false);
        return;
      }

      formData.append("frameworks", selectedFrameworks.join(","));
      formData.append("main_llm_config_id", values.main_llm_config_id);
      formData.append(
        "specialized_llm_config_id",
        values.specialized_llm_config_id,
      );

      const response = await submissionService.submitCode(formData);
      message.success(response.message);
      navigate("/history");
    } catch (error: unknown) {
      console.error("Submission failed:", error);
      let errorMessage = "An unknown error occurred during submission.";

      if (error instanceof AxiosError && error.response?.data?.detail) {
        const detail = error.response.data.detail;
        if (Array.isArray(detail)) {
          errorMessage = detail
            .map((err) => `${err.loc.join(".")} - ${err.msg}`)
            .join("; ");
        } else {
          errorMessage = detail.toString();
        }
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }
      message.error(`Submission failed: ${errorMessage}`, 6);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Spin spinning={isSubmitting} tip="Submitting your code for analysis...">
      <Card>
        <Title level={2}>Submit Code for Analysis</Title>
        <Paragraph>
          Select your submission method, choose your frameworks and AI models,
          and submit your code for a comprehensive security analysis.
        </Paragraph>
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{ frameworks: ["OWASP ASVS v5.0"] }}
        >
          {isLlmError && (
            <Alert
              message="Error"
              description={`Could not fetch LLM configurations: ${llmError.message}. Please try again later.`}
              type="error"
              showIcon
              style={{ marginBottom: 24 }}
            />
          )}

          <Row gutter={24}>
            <Col xs={24} md={12}>
              <Form.Item
                name="main_llm_config_id"
                label={
                  <>
                    <RobotOutlined style={{ marginRight: 8 }} />
                    Main Analysis LLM
                  </>
                }
                rules={[
                  {
                    required: true,
                    message: "Please select the main analysis LLM.",
                  },
                ]}
              >
                <Select
                  loading={isLoadingLLMs}
                  placeholder="Select an LLM for primary analysis"
                  disabled={isLoadingLLMs || isLlmError}
                >
                  {llmConfigs?.map((config) => (
                    <Option key={config.id} value={config.id}>
                      {config.name} ({config.provider})
                    </Option>
                  ))}
                </Select>
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="specialized_llm_config_id"
                label={
                  <>
                    <ToolOutlined style={{ marginRight: 8 }} />
                    Specialized Agent LLM
                  </>
                }
                rules={[
                  {
                    required: true,
                    message: "Please select the LLM for specialized agents.",
                  },
                ]}
              >
                <Select
                  loading={isLoadingLLMs}
                  placeholder="Select an LLM for specialized agents"
                  disabled={isLoadingLLMs || isLlmError}
                >
                  {llmConfigs?.map((config) => (
                    <Option key={config.id} value={config.id}>
                      {config.name} ({config.provider})
                    </Option>
                  ))}
                </Select>
              </Form.Item>
            </Col>
          </Row>

          <Form.Item
            label="Security Framework"
          >
            <Form.Item
              name={["frameworks", 0]}
              valuePropName="checked"
              noStyle
              getValueFromEvent={(e) =>
                e.target.checked ? "OWASP ASVS v5.0" : false
              }
            >
              <Checkbox defaultChecked disabled>
                OWASP ASVS v5.0
              </Checkbox>
            </Form.Item>
            <Text type="secondary" style={{ display: "block", marginTop: 8 }}>
              (More frameworks will be available soon)
            </Text>
          </Form.Item>

          <Form.Item label="Submission Method" style={{ marginBottom: 0 }}>
            <Radio.Group
              onChange={handleSubmissionModeChange}
              value={submissionMode}
              optionType="button"
              buttonStyle="solid"
            >
              <Radio.Button value="upload">
                <UploadOutlined /> Upload Files
              </Radio.Button>
              <Radio.Button value="repo">
                <GithubOutlined /> Git Repository
              </Radio.Button>
            </Radio.Group>
          </Form.Item>

          {submissionMode === "repo" && (
            <Form.Item
              name="repo_url"
              label="Repository URL"
              rules={[
                {
                  required: true,
                  message: "Please enter a valid repository URL.",
                },
                {
                  type: "url",
                  message: "The input is not a valid URL!",
                },
              ]}
              style={{ marginTop: 16 }}
            >
              <Input placeholder="e.g., https://github.com/user/repo.git" />
            </Form.Item>
          )}

          {submissionMode === "upload" && (
            <Form.Item label="Upload Source Code" style={{ marginTop: 16 }}>
              <Dragger
                name="files"
                multiple={true}
                beforeUpload={(file) => {
                  setFileList((prevList) => [...prevList, file]);
                  return false; // Prevent auto-upload
                }}
                onRemove={(file) => {
                  setFileList((prevList) =>
                    prevList.filter((item) => item.uid !== file.uid),
                  );
                }}
                fileList={fileList}
              >
                <p className="ant-upload-drag-icon">
                  <InboxOutlined />
                </p>
                <p className="ant-upload-text">
                  Click or drag file(s) to this area to upload
                </p>
                <p className="ant-upload-hint">
                  Support for a single or bulk upload of your source code files.
                </p>
              </Dragger>
            </Form.Item>
          )}

          <Form.Item style={{ marginTop: 24 }}>
            <Button
              type="primary"
              htmlType="submit"
              loading={isSubmitting}
              disabled={isLoadingLLMs || isLlmError}
              size="large"
              block
            >
              Start Analysis
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </Spin>
  );
};

export default SubmitCodePage;