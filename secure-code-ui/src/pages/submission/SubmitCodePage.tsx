// secure-code-ui/src/pages/submission/SubmitCodePage.tsx

import {
  FileZipOutlined,
  GithubOutlined,
  InboxOutlined,
  RobotOutlined,
  ToolOutlined,
  UploadOutlined,
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
  Radio,
  type RadioChangeEvent,
  Row,
  Select,
  Spin,
  Typography,
  Upload,
  message,
} from "antd";
import { type RcFile } from "antd/es/upload";
import { AxiosError } from "axios";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { LLMConfiguration } from "../..//shared/types/api";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { submissionService } from "../../shared/api/submissionService";

import FileTree from "../../features/submit-code/components/FileTree";

const { Dragger } = Upload;
const { Title, Paragraph, Text } = Typography;
const { Option } = Select;



interface SubmissionFormValues {
  project_name: string;
  main_llm_config_id: string;
  specialized_llm_config_id: string;
  repo_url?: string;
  frameworks: string[];
  workflow_mode: "audit" | "audit_and_remediate";
}

type SubmissionMode = "upload" | "repo" | "archive";

const SubmitCodePage: React.FC = () => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const [fileList, setFileList] = useState<RcFile[]>([]);
  const [archiveFileList, setArchiveFileList] = useState<RcFile[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionMode, setSubmissionMode] = useState<SubmissionMode>("upload");
  const [treeCheckedKeys, setTreeCheckedKeys] = useState<React.Key[]>([]);

  const [isPreviewLoading, setIsPreviewLoading] = useState(false);
  const [previewFilePaths, setPreviewFilePaths] = useState<string[]>([]);
  const [isPreviewComplete, setIsPreviewComplete] = useState(false);

  const {
    data: llmConfigs,
    isLoading: isLoadingLLMs,
    isError: isLlmError,
    error: llmError,
  } = useQuery<LLMConfiguration[], Error>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const getPathsFromRcFiles = (files: RcFile[]): string[] => {
      return files.map(file => file.webkitRelativePath || file.name);
  }

  useEffect(() => {
    const allFileKeys = submissionMode === 'upload' ? getPathsFromRcFiles(fileList) : previewFilePaths;
    setTreeCheckedKeys(allFileKeys);
  }, [fileList, previewFilePaths, submissionMode]);

  const handleSubmissionModeChange = (e: RadioChangeEvent) => {
    const newMode = e.target.value as SubmissionMode;
    setSubmissionMode(newMode);
    form.resetFields(['repo_url']);
    setFileList([]);
    setArchiveFileList([]);
    setPreviewFilePaths([]);
    setIsPreviewComplete(false);
  };

  const handleFetchPreview = async () => {
    setIsPreviewLoading(true);
    try {
      let fetchedPaths: string[] = [];
      if (submissionMode === 'repo') {
        const repoUrl = form.getFieldValue('repo_url');
        if (!repoUrl || !repoUrl.trim()) {
            message.error("Please enter a valid repository URL.");
            setIsPreviewLoading(false);
            return;
        }
        fetchedPaths = await submissionService.previewGitRepo(repoUrl);
      } else if (submissionMode === 'archive') {
        if (archiveFileList.length === 0) {
            message.error("Please upload an archive file.");
            setIsPreviewLoading(false);
            return;
        }
        fetchedPaths = await submissionService.previewArchive(archiveFileList[0]);
      }

      setPreviewFilePaths(fetchedPaths); // Store the fetched strings directly
      setIsPreviewComplete(true);
    } catch (err) {
      const errorMessage = err instanceof AxiosError 
        ? err.response?.data?.detail || err.message 
        : 'An unknown error occurred while fetching files.';
      message.error(`Failed to fetch files: ${errorMessage}`);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const handleTreeCheck = (
    checked: React.Key[] | { checked: React.Key[]; halfChecked: React.Key[] },
  ) => {
    // The onCheck callback can provide an object, so we extract just the checked keys array.
    if (Array.isArray(checked)) {
      setTreeCheckedKeys(checked);
    } else {
      setTreeCheckedKeys(checked.checked);
    }
  };

  const isArchiveFile = (fileName: string): boolean => {
    return /\.(zip|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar)$/i.test(fileName);
  };

  const handleSubmit = async (values: SubmissionFormValues) => {
    if (submissionMode === "upload" && fileList.length === 0) {
      message.error("Please upload at least one file for direct analysis.");
      return;
    }
    if (submissionMode === "archive" && archiveFileList.length === 0) {
      message.error("Please upload an archive file.");
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

      const allFileKeys = new Set(
        submissionMode === 'upload' ? getPathsFromRcFiles(fileList) : previewFilePaths
      );
      const checkedFileKeys = new Set(treeCheckedKeys);
      const excludedFiles: string[] = [];
      allFileKeys.forEach(key => {
        if (!checkedFileKeys.has(key)) {
            excludedFiles.push(key as string);
        }
      });
      formData.append("excluded_files", excludedFiles.join(","));

      if (submissionMode === "upload") {
        fileList.forEach((file) => formData.append("files", file));
      } else if (submissionMode === "repo" && values.repo_url) {
        formData.append("repo_url", values.repo_url.trim());
      } else if (submissionMode === "archive" && archiveFileList.length > 0) {
        formData.append("archive_file", archiveFileList[0]);
      }
      
      const selectedFrameworks = values.frameworks.filter(Boolean);
      if (selectedFrameworks.length === 0) {
        message.error("Please select at least one security framework.");
        setIsSubmitting(false);
        return;
      }
      formData.append("project_name", values.project_name);
      formData.append("frameworks", selectedFrameworks.join(","));
      formData.append("main_llm_config_id", values.main_llm_config_id);
      formData.append("specialized_llm_config_id", values.specialized_llm_config_id);
      formData.append("workflow_mode", values.workflow_mode);

      const response = await submissionService.submitCode(formData);
      message.success(response.message);
      navigate("/account/history");
    } catch (error: unknown) {
      console.error("Submission failed:", error);
      let errorMessage = "An unknown error occurred during submission.";

      if (error instanceof AxiosError && error.response?.data) {
        const responseData = error.response.data as { detail?: string | { msg: string, loc: (string | number)[] }[] };
        const detail = responseData.detail;
        if (typeof detail === 'string') {
          errorMessage = detail;
        } else if (Array.isArray(detail)) {
          errorMessage = detail
            .map((err) => `${err.loc.join(".")} - ${err.msg}`)
            .join("; ");
        }
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }
      message.error(`Submission failed: ${errorMessage}`, 6);
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderContent = () => {
    // Git Repo Mode
    if (submissionMode === 'repo') {
        return isPreviewComplete ? (
            <>
              {/* This Form.Item is hidden but keeps the repo_url value in the form state for submission */}
              <Form.Item name="repo_url" style={{ display: 'none' }}>
                <Input />
              </Form.Item>
              <FileTree files={previewFilePaths} checkedKeys={treeCheckedKeys} onCheck={handleTreeCheck} />
            </>
        ) : (
            <Form.Item name="repo_url" label="Repository URL" style={{ marginTop: 16 }} rules={[{ required: true, message: "Please enter a valid repository URL."}, { type: "url", message: "The input is not a valid URL!"}]}>
                <Input placeholder="e.g., https://github.com/user/repo.git" />
            </Form.Item>
        );
    }
    // Archive Mode
    if (submissionMode === 'archive') {
        return isPreviewComplete ? (
            <FileTree files={previewFilePaths} checkedKeys={treeCheckedKeys} onCheck={handleTreeCheck} />
        ) : (
            <Form.Item label="Upload Archive File" style={{ marginTop: 16 }}>
              <Dragger name="archiveFile" multiple={false} maxCount={1} accept=".zip,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz,.tar" beforeUpload={(file) => { if (!isArchiveFile(file.name)) { message.error(`File '${file.name}' is not a recognized archive type.`); return Upload.LIST_IGNORE; } setArchiveFileList([file]); return false; }} onRemove={() => setArchiveFileList([])} fileList={archiveFileList}>
                <p className="ant-upload-drag-icon"><FileZipOutlined /></p>
                <p className="ant-upload-text">Click or drag a single archive file to this area</p>
              </Dragger>
            </Form.Item>
        );
    }
    // Upload Mode
    return (
        <>
          <Form.Item label="Upload Source Code" style={{ marginTop: 16 }}>
            <Dragger 
                name="files" 
                multiple={true} 
                itemRender={() => null} 
                beforeUpload={(_, newFileList) => { const filtered = newFileList.filter(f => !isArchiveFile(f.name)); if (filtered.length !== newFileList.length) { message.error("Archive files are not allowed here. Use the 'Upload Archive' tab."); } setFileList(prev => [...prev, ...filtered]); return false; }} 
                onRemove={(file) => setFileList(p => p.filter(i => i.uid !== file.uid))}>
                 <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                <p className="ant-upload-text">Click or drag files or folders to this area to upload</p>
            </Dragger>
          </Form.Item>
          {/* This line is now corrected to pass string[] */}
          <FileTree files={getPathsFromRcFiles(fileList)} checkedKeys={treeCheckedKeys} onCheck={handleTreeCheck}/>
        </>
    );
  }
  

  return (
    <Spin spinning={isSubmitting || isPreviewLoading} tip={isPreviewLoading ? "Fetching file list..." : "Submitting your code for analysis..."}>
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
          initialValues={{ frameworks: ["OWASP ASVS v5.0"], workflow_mode: "audit" }}
        >
          <Form.Item
            name="project_name"
            label="Project Name"
            rules={[{ required: true, message: "Please enter a name for your project." }]}
          >
            <Input placeholder="e.g., My E-Commerce Website" />
          </Form.Item>

          <Form.Item name="workflow_mode" label="Workflow Type" rules={[{required: true}]}>
            <Radio.Group>
              <Radio.Button value="audit">Audit Only</Radio.Button>
              <Radio.Button value="audit_and_remediate">Audit & Remediate</Radio.Button>
            </Radio.Group>
          </Form.Item>

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
            {/* LLM Selection */}
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
            <Radio.Group onChange={handleSubmissionModeChange} value={submissionMode} optionType="button" buttonStyle="solid">
                <Radio.Button value="upload"><UploadOutlined /> Upload Files</Radio.Button>
                <Radio.Button value="archive"><FileZipOutlined /> Upload Archive</Radio.Button>
                <Radio.Button value="repo"><GithubOutlined /> Git Repository</Radio.Button>
            </Radio.Group>
          </Form.Item>

          {renderContent()}

          <Form.Item style={{ marginTop: 24 }}>
          {submissionMode !== 'upload' && !isPreviewComplete ? (
              <Button type="default" size="large" block onClick={handleFetchPreview} loading={isPreviewLoading}>
                Fetch Files for Selection
              </Button>
            ) : (
              <Button type="primary" htmlType="submit" loading={isSubmitting} disabled={isLoadingLLMs || isLlmError} size="large" block>
                Start Analysis
              </Button>
            )}
            {isPreviewComplete && (
                <Button type="link" onClick={() => { setIsPreviewComplete(false); setPreviewFilePaths([]); }} style={{marginTop: '10px'}}>
                    Change Repository/Archive
                </Button>
            )}
          </Form.Item>
          {/* --- END: DYNAMIC BUTTONS --- */}
        </Form>
      </Card>
    </Spin>
  );
};

export default SubmitCodePage;