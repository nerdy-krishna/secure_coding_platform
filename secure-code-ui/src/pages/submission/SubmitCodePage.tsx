// src/pages/submission/SubmitCodePage.tsx
import {
  FileZipOutlined,
  GithubOutlined,
  InboxOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  ToolOutlined,
  UploadOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  AutoComplete,
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Input,
  Radio,
  Row,
  Select,
  Skeleton,
  Space,
  Spin,
  Tooltip,
  Typography,
  Upload,
  message,
  type RadioChangeEvent,
  type UploadFile,
} from "antd";
import { type RcFile } from "antd/es/upload";
import { AxiosError } from "axios";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import FileTree from "../../features/submit-code/components/FileTree";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { scanService } from "../../shared/api/scanService";
import type { FrameworkRead, LLMConfiguration, SubmissionFormValues } from "../../shared/types/api";

const { Dragger } = Upload;
const { Title, Paragraph } = Typography;
const { Option } = Select;

type SubmissionMode = "upload" | "repo" | "archive";

const SubmitCodePage: React.FC = () => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [archiveFileList, setArchiveFileList] = useState<UploadFile[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionMode, setSubmissionMode] = useState<SubmissionMode>("upload");
  const [treeCheckedKeys, setTreeCheckedKeys] = useState<React.Key[]>([]);
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);
  const [previewFilePaths, setPreviewFilePaths] = useState<string[]>([]);
  const [isPreviewComplete, setIsPreviewComplete] = useState(false);
  const [projectOptions, setProjectOptions] = useState<{ value: string }[]>([]);

  const {
    data: llmConfigs,
    isLoading: isLoadingLLMs,
    isError: isLlmError,
  } = useQuery<LLMConfiguration[], Error>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const {
    data: frameworks,
    isLoading: isLoadingFrameworks,
  } = useQuery<FrameworkRead[], Error>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const getPathsFromUploadFiles = (files: UploadFile[]): string[] => {
    return files.map((file) => (file.originFileObj as RcFile)?.webkitRelativePath || file.name);
  };

  useEffect(() => {
    const allFileKeys =
      submissionMode === "upload"
        ? getPathsFromUploadFiles(fileList)
        : previewFilePaths;
    setTreeCheckedKeys(allFileKeys);
  }, [fileList, previewFilePaths, submissionMode]);

  const handleSubmissionModeChange = (e: RadioChangeEvent) => {
    const newMode = e.target.value as SubmissionMode;
    setSubmissionMode(newMode);
    form.resetFields(["repo_url"]);
    setFileList([]);
    setArchiveFileList([]);
    setPreviewFilePaths([]);
    setIsPreviewComplete(false);
  };

  const handleFetchPreview = async () => {
    setIsPreviewLoading(true);
    try {
      let fetchedPaths: string[] = [];
      if (submissionMode === "repo") {
        const repoUrl = form.getFieldValue("repo_url");
        if (!repoUrl || !repoUrl.trim()) {
          message.error("Please enter a valid repository URL.");
          setIsPreviewLoading(false);
          return;
        }
        fetchedPaths = await scanService.previewGitRepo(repoUrl);
      } else if (submissionMode === "archive") {
        if (archiveFileList.length === 0) {
          message.error("Please upload an archive file.");
          setIsPreviewLoading(false);
          return;
        }
        fetchedPaths = await scanService.previewArchive(archiveFileList[0] as RcFile);
      }
      setPreviewFilePaths(fetchedPaths);
      setIsPreviewComplete(true);
    } catch (err) {
      const errorMessage =
        err instanceof AxiosError
          ? err.response?.data?.detail || err.message
          : "An unknown error occurred while fetching files.";
      message.error(`Failed to fetch files: ${errorMessage}`);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const handleTreeCheck = (
    checked: React.Key[] | { checked: React.Key[]; halfChecked: React.Key[] }
  ) => {
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
      message.error("Please upload at least one file or folder.");
      return;
    }
    if (submissionMode === "archive" && archiveFileList.length === 0) {
      message.error("Please upload an archive file.");
      return;
    }
    if (submissionMode === "repo" && (!values.repo_url || values.repo_url.trim() === "")) {
      message.error("Please provide a repository URL.");
      return;
    }

    setIsSubmitting(true);
    try {
      const formData = new FormData();
      formData.append("project_name", values.project_name);
      formData.append("scan_type", values.scan_type);
      formData.append("utility_llm_config_id", values.utility_llm_config_id);
      formData.append("fast_llm_config_id", values.fast_llm_config_id);
      formData.append("reasoning_llm_config_id", values.reasoning_llm_config_id);
      formData.append("frameworks", values.frameworks.join(','));

      if (submissionMode === "upload") {
        const checkedFilePaths = new Set(treeCheckedKeys as string[]);
        const filesToSubmit = fileList.filter((file) =>
          checkedFilePaths.has((file.originFileObj as RcFile)?.webkitRelativePath || file.name)
        );

        if (filesToSubmit.length === 0) {
          message.error("Please select at least one file for analysis.");
          setIsSubmitting(false);
          return;
        }
        
        filesToSubmit.forEach((file) => {
          if (file.originFileObj) {
            formData.append("files", file.originFileObj as RcFile);
          }
        });

      } else if (submissionMode === "repo" && values.repo_url) {
        formData.append("repo_url", values.repo_url.trim());
      } else if (submissionMode === "archive" && archiveFileList.length > 0) {
        if(archiveFileList[0].originFileObj) {
            formData.append("archive_file", archiveFileList[0].originFileObj as RcFile);
        }
      }

      const response = await scanService.createScan(formData);
      message.success(response.message);
      // Navigate with the project ID to auto-expand it on the history page
      navigate("/account/history", { state: { newProjectId: response.project_id } });
    } catch (error: unknown) {
      console.error("Submission failed:", error);
      let errorMessage = "An unknown error occurred during submission.";
      if (error instanceof AxiosError && error.response?.data) {
        const detail = (error.response.data as { detail?: string | {msg: string, loc: (string | number)[]}[] }).detail;
        if (typeof detail === "string") {
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
    if (submissionMode === "repo") {
      return (
        <Form.Item name="repo_url" label="Repository URL" style={{ marginTop: 16 }} rules={[{ required: true, message: "Please enter a valid repository URL."}, { type: "url", message: "The input is not a valid URL!"}]}>
          <Input placeholder="e.g., https://github.com/user/repo.git" />
        </Form.Item>
      );
    }
    if (submissionMode === "archive") {
      return (
        <Form.Item label="Upload Archive File" style={{ marginTop: 16 }}>
          <Dragger
             name="archiveFile"
             multiple={false}
             maxCount={1}
             accept=".zip,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz,.tar"
             fileList={archiveFileList}
             onChange={(info) => {
                // Allow only one file and check type
                const latestFile = info.fileList.slice(-1);
                if (latestFile[0] && !isArchiveFile(latestFile[0].name)) {
                    message.error(`File '${latestFile[0].name}' is not a recognized archive type.`);
                    setArchiveFileList([]);
                } else {
                    setArchiveFileList(latestFile);
                }
             }}
             beforeUpload={() => false} // Prevent auto-upload
          >
            <p className="ant-upload-drag-icon"><FileZipOutlined /></p>
            <p className="ant-upload-text">Click or drag a single archive file to this area</p>
          </Dragger>
        </Form.Item>
      );
    }
    return (
      <Form.Item label="Upload Source Code Files" style={{ marginTop: 16 }}>
        <Dragger
          name="files"
          multiple={true}
          fileList={fileList}
          onChange={(info) => {
            setFileList(info.fileList);
          }}
          beforeUpload={() => false}
        >
          <p className="ant-upload-drag-icon"><InboxOutlined /></p>
          <p className="ant-upload-text">Click or drag files or a folder to this area to upload</p>
        </Dragger>
      </Form.Item>
    );
  };

  return (
    <Spin spinning={isSubmitting || isPreviewLoading} tip={isPreviewLoading ? "Fetching file list..." : "Submitting your code for analysis..."}>
      <Card>
        <Title level={2}>Submit Code for Analysis</Title>
        <Paragraph>
          Create or select a project, choose a scan type, and submit your code for a comprehensive security analysis.
        </Paragraph>
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{ scan_type: "AUDIT" }}
        >
          <Form.Item name="project_name" label="Project Name" rules={[{ required: true, message: "Please enter or select a project name." }]}>
            <AutoComplete
              options={projectOptions}
              onSearch={async (text) => {
                const results = await scanService.searchProjects(text);
                setProjectOptions(results.map(name => ({ value: name })));
              }}
              placeholder="Select an existing project or type to create a new one"
            />
          </Form.Item>

          <Row gutter={24}>
            <Col xs={24} md={8}>
                <Tooltip title="Used for high-throughput, simple tasks like pre-analysis triage and code summarization.">
                    <Form.Item name="utility_llm_config_id" label={<><ToolOutlined style={{ marginRight: 8 }} /> Utility Model</>} rules={[{ required: true, message: "Please select the Utility LLM." }]}>
                        <Select loading={isLoadingLLMs} placeholder="Select a lightweight LLM" disabled={isLoadingLLMs || isLlmError}>
                        {llmConfigs?.map((config) => (
                            <Option key={config.id} value={config.id}>{config.name} ({config.provider})</Option>
                        ))}
                        </Select>
                    </Form.Item>
                </Tooltip>
            </Col>
            <Col xs={24} md={8}>
                <Tooltip title="A balanced model for interactive tasks like the Security Advisor Chat and RAG data processing.">
                    <Form.Item name="fast_llm_config_id" label={<><RobotOutlined style={{ marginRight: 8 }} /> Fast Model</>} rules={[{ required: true, message: "Please select the Fast LLM." }]}>
                        <Select loading={isLoadingLLMs} placeholder="Select a balanced LLM" disabled={isLoadingLLMs || isLlmError}>
                        {llmConfigs?.map((config) => (
                            <Option key={config.id} value={config.id}>{config.name} ({config.provider})</Option>
                        ))}
                        </Select>
                    </Form.Item>
                </Tooltip>
            </Col>
            <Col xs={24} md={8}>
                <Tooltip title="The most powerful model, used for core security analysis, generating fixes, and writing the executive summary.">
                    <Form.Item name="reasoning_llm_config_id" label={<><SafetyCertificateOutlined style={{ marginRight: 8 }} /> Reasoning Model</>} rules={[{ required: true, message: "Please select the Reasoning LLM."}]}>
                        <Select loading={isLoadingLLMs} placeholder="Select a powerful LLM" disabled={isLoadingLLMs || isLlmError}>
                        {llmConfigs?.map((config) => (
                            <Option key={config.id} value={config.id}>{config.name} ({config.provider})</Option>
                        ))}
                        </Select>
                    </Form.Item>
                </Tooltip>
            </Col>
          </Row>

          <Form.Item name="scan_type" label="Scan Type" rules={[{ required: true }]}>
            <Radio.Group>
              <Tooltip title="Performs a security audit and generates a report of findings. No code will be changed.">
                <Radio.Button value="AUDIT">Audit</Radio.Button>
              </Tooltip>
              <Tooltip title="Audits the code and provides AI-generated fix suggestions without applying them.">
                <Radio.Button value="SUGGEST">Suggest Fixes</Radio.Button>
              </Tooltip>
              <Tooltip title="Performs a full remediation scan, generating verified fixes and creating a final, patched version of the code.">
                <Radio.Button value="REMEDIATE">Remediate</Radio.Button>
              </Tooltip>
            </Radio.Group>
          </Form.Item>

          <Form.Item
            name="frameworks"
            label={
              <Space>
                <SafetyCertificateOutlined />
                Security Frameworks
              </Space>
            }
            rules={[{ required: true, message: "Please select at least one framework."}]}
          >
            {isLoadingFrameworks ? (
              <Skeleton active paragraph={{rows: 2}} />
            ) : (
              <Checkbox.Group style={{ width: '100%' }}>
                  <Row>
                      {(frameworks || []).map((fw) => (
                          <Col span={8} key={fw.id}>
                              <Checkbox value={fw.name}>{fw.name}</Checkbox>
                          </Col>
                      ))}
                  </Row>
              </Checkbox.Group>
            )}
          </Form.Item>

          <Form.Item label="Submission Method" style={{ marginBottom: 0 }}>
            <Radio.Group onChange={handleSubmissionModeChange} value={submissionMode} optionType="button" buttonStyle="solid">
              <Radio.Button value="upload"><UploadOutlined /> Upload Files</Radio.Button>
              <Radio.Button value="archive"><FileZipOutlined /> Upload Archive</Radio.Button>
              <Radio.Button value="repo"><GithubOutlined /> Git Repository</Radio.Button>
            </Radio.Group>
           </Form.Item>

          {renderContent()}

          {(submissionMode === 'repo' || submissionMode === 'archive') && !isPreviewComplete && (
            <Button block onClick={handleFetchPreview} loading={isPreviewLoading} style={{ marginTop: 16 }}>
              Preview Files
            </Button>
          )}

          {(submissionMode === 'upload' && fileList.length > 0) || isPreviewComplete ? (
            <div style={{ marginTop: 16 }}>
              <FileTree files={submissionMode === 'upload' ? getPathsFromUploadFiles(fileList) : previewFilePaths} checkedKeys={treeCheckedKeys} onCheck={handleTreeCheck}/>
            </div>
          ) : null}

          <Form.Item style={{ marginTop: 24 }}>
            <Button type="primary" htmlType="submit" loading={isSubmitting} disabled={isLoadingLLMs || isLlmError} size="large" block>
              Start Scan
            </Button>
            {isPreviewComplete && (
                <Button type="link" onClick={() => { setIsPreviewComplete(false); setPreviewFilePaths([]); }} style={{ marginTop: '10px' }} block>
                    Change Repository/Archive
                </Button>
            )}
          </Form.Item>
        </Form>
      </Card>
    </Spin>
  );
};

export default SubmitCodePage;