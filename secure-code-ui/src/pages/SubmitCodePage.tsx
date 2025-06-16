import {
  GithubOutlined, // Added GithubOutlined
  InboxOutlined,
  RobotOutlined,
  SafetyOutlined,
  ToolOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Input, // Added Input
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
  repo_url?: string; // Added repository URL field
  frameworks: string[];
}

const SubmitCodePage: React.FC = () => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const [fileList, setFileList] = useState<RcFile[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    data: llmConfigs,
    isLoading: isLoadingLLMs,
    isError: isLlmError,
    error: llmError,
  } = useQuery<LLMConfiguration[], Error>({
    queryKey: ["llmConfigs"],
    queryFn: () => llmConfigService.getLlmConfigs(),
  });

const handleSubmit = async (values: SubmissionFormValues) => {
    if (fileList.length === 0 && (!values.repo_url || values.repo_url.trim() === "")) {
      message.error("Please upload files or provide a repository URL.");
      return;
    }
    setIsSubmitting(true);
    try {
      const formData = new FormData();
      fileList.forEach((file) => {
        formData.append("files", file);
      });

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
        values.specialized_llm_config_id
      );

      if (values.repo_url && values.repo_url.trim() !== "") {
        formData.append("repo_url", values.repo_url.trim());
      }

      console.log("--- [Frontend] Data being sent: ---");
      for (const entry of formData.entries()) {
        // Log each key-value pair. For files, it will log the File object.
        console.log(`[Frontend] Key: "${entry[0]}", Value:`, entry[1]);
      }
      console.log("---------------------------------");
      
      const response = await submissionService.submitCode(formData);
      message.success(response.message);
      navigate("/history"); // Changed navigation to /history
    } catch (error: unknown) {
      console.error("Submission failed:", error);
      let errorMessage = "An unknown error occurred during submission.";

      // --- FIX #2: Enhanced error handling for FastAPI validation errors ---
      if (error instanceof AxiosError && error.response?.data?.detail) {
        const detail = error.response.data.detail;
        if (Array.isArray(detail)) {
          // This handles the [{ loc: [...], msg: "...", type: "..." }] format
          errorMessage = detail
            .map((err) => `${err.loc.join(".")} - ${err.msg}`)
            .join("; ");
        } else {
          // Handles simple string details
          errorMessage = detail.toString();
        }
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }
      message.error(`Submission failed: ${errorMessage}`, 6); // Show for 6 seconds
    } finally {
      setIsSubmitting(false);
    }
};

  return (
    <Spin spinning={isSubmitting} tip="Submitting your code for analysis...">
      <Card>
        <Title level={2}>Submit Code for Analysis</Title>
        <Paragraph>
          Upload your source code files to be analyzed for security
          vulnerabilities based on your selected frameworks and AI models.
        </Paragraph>
        <Form form={form} layout="vertical" onFinish={handleSubmit} initialValues={{ frameworks: ["OWASP ASVS v5.0"] }}>
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
                rules={[{ required: true, message: "Please select the main analysis LLM." }]}
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
                rules={[{ required: true, message: "Please select the LLM for specialized agents." }]}
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
            name="repo_url"
            label={
              <>
                <GithubOutlined style={{ marginRight: 8 }} />
                Repository URL (Optional)
              </>
            }
            rules={[
              {
                type: "url",
                message: "Please enter a valid URL.",
              },
            ]}
          >
            <Input placeholder="e.g., https://github.com/user/repo.git" />
          </Form.Item>

          <Form.Item
            label={
              <>
                <SafetyOutlined style={{ marginRight: 8 }} />
                Security Framework
              </>
            }
          >
            <Form.Item
              name={["frameworks", 0]}
              valuePropName="checked"
              noStyle
              getValueFromEvent={(e) => e.target.checked ? "OWASP ASVS v5.0" : false}
            >
              <Checkbox defaultChecked disabled>
                OWASP ASVS v5.0
              </Checkbox>
            </Form.Item>
            <Text type="secondary" style={{ display: "block", marginTop: 8 }}>
              (More frameworks will be available soon)
            </Text>
          </Form.Item>

          <Form.Item label="Upload Source Code">
            <Dragger
              name="files"
              multiple={true}
              beforeUpload={(file) => {
                setFileList((prevList) => [...prevList, file]);
                return false;
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
                Support for a single or bulk upload.
              </p>
            </Dragger>
          </Form.Item>

          <Form.Item>
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
