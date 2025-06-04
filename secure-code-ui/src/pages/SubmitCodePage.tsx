// secure-code-ui/src/pages/SubmitCodePage.tsx
import { CodeOutlined, InboxOutlined } from "@ant-design/icons";
import {
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Input,
  message,
  Row,
  Select,
  Typography,
  Upload,
} from "antd";
import type { RcFile, UploadFile, UploadProps } from "antd/es/upload/interface";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { submissionService } from "../services/submissionService";
import {
  type CodeSubmissionRequest,
  type FileForSubmission,
} from "../types/api";

const { Title } = Typography;
const { Dragger } = Upload;
const { Option } = Select;

// Supported languages - you can extend this list
const supportedLanguages = [
  { value: "python", label: "Python" },
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "java", label: "Java" },
  { value: "go", label: "Go" },
  { value: "rust", label: "Rust" },
  { value: "php", label: "PHP" },
  // Add more languages your backend supports
];

// Available security frameworks - this should ideally come from an API or config
// Using placeholder values for now. Ensure these IDs match backend expectations.
const availableFrameworks = [
  { id: "OWASP_TOP_10_2021", name: "OWASP Top 10 2021" },
  { id: "ASVS_L1", name: "OWASP ASVS Level 1" },
  { id: "ASVS_L2", name: "OWASP ASVS Level 2" },
  { id: "ASVS_L3", name: "OWASP ASVS Level 3" },
  { id: "SANS_TOP_25", name: "SANS Top 25" },
  { id: "NIST_SSDF", name: "NIST SSDF" },
  // Add other frameworks your platform supports
];

const SubmitCodePage: React.FC = () => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [fileList, setFileList] = useState<UploadFile[]>([]);

  const handleFileRead = async (file: RcFile): Promise<FileForSubmission> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsText(file); // Read as text
      reader.onload = () => {
        resolve({
          file_name: file.name,
          content: reader.result as string,
        });
      };
      reader.onerror = (error) => {
        reject(error);
      };
    });
  };

  const onFinish = async (values: {
    projectName: string;
    targetLanguage: string;
    frameworks: string[];
    // 'upload' field from Form.Item will not be directly used here as we manage files separately
  }) => {
    if (fileList.length === 0) {
      message.error("Please upload at least one code file.");
      return;
    }

    setLoading(true);
    message.loading({ content: "Processing files...", key: "fileProcessing" });

    try {
      const filesToSubmit: FileForSubmission[] = await Promise.all(
        fileList.map(async (uploadFile) => {
          if (uploadFile.originFileObj) {
            return handleFileRead(uploadFile.originFileObj as RcFile);
          }
          // This case should ideally not happen if beforeUpload returns false
          // and we manage fileList properly
          throw new Error(`Could not read file: ${uploadFile.name}`);
        }),
      );

      message.success({
        content: "Files processed. Submitting for analysis...",
        key: "fileProcessing",
        duration: 2,
      });

      const payload: CodeSubmissionRequest = {
        project_name: values.projectName,
        target_language: values.targetLanguage,
        files: filesToSubmit,
        selected_framework_ids: values.frameworks,
      };

      const response = await submissionService.submitCode(payload);
      setLoading(false);
      message.success(
        `Analysis submitted successfully! Submission ID: ${response.submission_id}`,
      );
      form.resetFields();
      setFileList([]); // Clear file list
      // Navigate to the results page or a submission history page
      navigate(`/results/${response.submission_id}`);
    } catch (error) {
      setLoading(false);
      message.destroy("fileProcessing");
      console.error("Submission failed:", error);
      message.error(
        `Submission failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  };

  const uploadProps: UploadProps = {
    onRemove: (file) => {
      const index = fileList.indexOf(file);
      const newFileList = fileList.slice();
      newFileList.splice(index, 1);
      setFileList(newFileList);
    },
    beforeUpload: (file) => {
      // Read file content here if needed, or just add to list for later processing
      // Prevent automatic upload by returning false or a Promise
      setFileList((prevFileList) => [...prevFileList, file]);
      return false; // Prevent antd from uploading automatically
    },
    fileList,
    multiple: true,
    accept:
      ".py,.js,.ts,.java,.go,.php,.txt,text/*,application/zip,application/x-zip-compressed", // Adjust accepted file types
  };

  return (
    <div style={{ maxWidth: "800px", margin: "40px auto", padding: "20px" }}>
      <Card>
        <Title level={2} style={{ textAlign: "center", marginBottom: "30px" }}>
          <CodeOutlined /> Submit Code for Analysis
        </Title>
        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
          initialValues={{ frameworks: ["OWASP_TOP_10_2021"] }} // Default framework
        >
          <Form.Item
            name="projectName"
            label="Project Name"
            rules={[
              { required: true, message: "Please input the project name!" },
            ]}
          >
            <Input placeholder="e.g., My Awesome Web App" />
          </Form.Item>

          <Form.Item
            name="targetLanguage"
            label="Primary Target Language"
            rules={[
              { required: true, message: "Please select the target language!" },
            ]}
          >
            <Select placeholder="Select language">
              {supportedLanguages.map((lang) => (
                <Option key={lang.value} value={lang.value}>
                  {lang.label}
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item
            name="frameworks"
            label="Security Frameworks / Guidelines"
            rules={[
              {
                required: true,
                message: "Please select at least one framework!",
              },
            ]}
          >
            <Checkbox.Group style={{ width: "100%" }}>
              <Row>
                {availableFrameworks.map((fw) => (
                  <Col span={8} key={fw.id}>
                    <Checkbox value={fw.id}>{fw.name}</Checkbox>
                  </Col>
                ))}
              </Row>
            </Checkbox.Group>
          </Form.Item>

          <Form.Item
            name="upload"
            label="Upload Code Files"
            rules={[
              {
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                validator: async (_rule, _value) => {
                  if (fileList.length === 0) {
                    return Promise.reject(
                      new Error("Please upload at least one file."),
                    );
                  }
                  return Promise.resolve();
                },
              },
            ]}
          >
            <Dragger {...uploadProps}>
              <p className="ant-upload-drag-icon">
                <InboxOutlined />
              </p>
              <p className="ant-upload-text">
                Click or drag file(s) to this area to upload
              </p>
              <p className="ant-upload-hint">
                Support for single or multiple files.
              </p>
            </Dragger>
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Submit for Analysis
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export default SubmitCodePage;
