// src/pages/admin/RAGManagementPage.tsx
import {
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  EyeOutlined,
  InboxOutlined,
  PlusOutlined,
  SendOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TableProps } from "antd";
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Empty,
  Form,
  Input,
  Modal,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tooltip,
  Typography,
  Upload,
  message,
} from "antd";
import type { RcFile } from "antd/es/upload";
import { AxiosError } from "axios";
import { saveAs } from "file-saver";
import React, { useEffect, useRef, useState } from "react";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { ragService } from "../../shared/api/ragService";
import type {
  EnrichedDocument,
  FrameworkRead,
  LLMConfiguration,
  PreprocessingResponse,
  RAGDocument,
  RAGJobStartResponse,
  RAGJobStatusResponse,
} from "../../shared/types/api";

const { Title, Paragraph, Text } = Typography;

interface PreprocessorFormValues {
  llm_config_id: string;
  frameworkName?: string;
  newFrameworkName?: string;
}

// --- Sub-component for Viewing Documents ---
const ViewDocumentsModal: React.FC<{
  framework: FrameworkRead;
  visible: boolean;
  onClose: () => void;
}> = ({ framework, visible, onClose }) => {
  const {
    data: documents,
    isLoading,
    isError,
  } = useQuery<RAGDocument[], Error>({
    queryKey: ["ragDocuments", framework.id],
    queryFn: () => ragService.getDocuments(framework.name),
    enabled: visible,
  });

  const columns: TableProps<RAGDocument>["columns"] = React.useMemo(() => {
    if (!documents || documents.length === 0) {
      return [
        { title: "ID", dataIndex: "id", key: "id" },
        { title: "Document", dataIndex: "document", key: "document" },
      ];
    }
    const metadataKeys = [
      ...new Set(documents.flatMap((doc) => Object.keys(doc.metadata))),
    ];
    const metadataColumns = metadataKeys.map((key) => ({
      title: key.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()),
      dataIndex: ["metadata", key],
      key: key,
      ellipsis: true,
    }));

    return [
      { title: "ID", dataIndex: "id", key: "id", fixed: "left", width: 150 },
      {
        title: "Document Content",
        dataIndex: "document",
        key: "document",
        ellipsis: true,
      },
      ...metadataColumns,
    ];
  }, [documents]);

  return (
    <Modal
      title={`Documents for "${framework.name}"`}
      open={visible}
      onCancel={onClose}
      footer={<Button onClick={onClose}>Close</Button>}
      width={1200}
      destroyOnClose
    >
      <Table
        loading={isLoading}
        dataSource={documents}
        rowKey="id"
        columns={columns}
        scroll={{ x: true }}
        locale={{
          emptyText: isError
            ? "Error loading documents."
            : "No documents found for this framework.",
        }}
      />
    </Modal>
  );
};

// --- Sub-component for the main card ---
const FrameworkCard: React.FC<{
  framework: FrameworkRead;
  onUpdate: (name: string) => void;
}> = ({ framework, onUpdate }) => {
  const [isViewModalVisible, setIsViewModalVisible] = useState(false);
  const queryClient = useQueryClient();

  const deleteMutation = useMutation({
    mutationFn: () => frameworkService.deleteFramework(framework.id),
    onSuccess: () => {
      message.success(`Framework "${framework.name}" deleted successfully.`);
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      // Note: A more robust delete would also clean up associated RAG documents.
    },
    onError: (error: AxiosError) => {
      message.error(`Failed to delete framework: ${error.message}`);
    },
  });

  const actions = [
    <Tooltip title="View Documents" key="view">
      <Button
        type="text"
        icon={<EyeOutlined />}
        onClick={() => setIsViewModalVisible(true)}
      />
    </Tooltip>,
    <Tooltip title="Update Documents" key="update">
      <Button
        type="text"
        icon={<EditOutlined />}
        onClick={() => onUpdate(framework.name)}
      />
    </Tooltip>,
    <Popconfirm
      key="delete"
      title="Delete Framework?"
      description="This action cannot be undone. It will remove the framework and its associations."
      onConfirm={() => deleteMutation.mutate()}
      okText="Yes, Delete"
      cancelText="No"
    >
      <Tooltip title="Delete Framework">
        <Button
          danger
          type="text"
          icon={<DeleteOutlined />}
          loading={deleteMutation.isPending}
        />
      </Tooltip>
    </Popconfirm>,
  ];

  return (
    <Col xs={24} sm={12} md={8}>
      <Card
        title={framework.name}
        actions={actions}
        style={{ height: "100%", minHeight: 160 }}
      >
        <Paragraph ellipsis={{ rows: 3 }}>{framework.description}</Paragraph>
      </Card>
      {isViewModalVisible && (
        <ViewDocumentsModal
          framework={framework}
          visible={isViewModalVisible}
          onClose={() => setIsViewModalVisible(false)}
        />
      )}
    </Col>
  );
};

// --- Main Page Component ---
const RAGManagementPage: React.FC = () => {
  const [form] = Form.useForm();
  const preprocessorRef = useRef<HTMLDivElement>(null);

  const [file, setFile] = useState<RcFile | null>(null);
  const [job, setJob] = useState<RAGJobStartResponse | null>(null);
  const [frameworkMode, setFrameworkMode] = useState<"existing" | "new">(
    "existing",
  );

  const { data: frameworks = [], isLoading: isLoadingFrameworks } = useQuery<
    FrameworkRead[]
  >({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: llmConfigs = [], isLoading: isLoadingLLMs } = useQuery<
    LLMConfiguration[]
  >({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const {
    data: jobStatus,
    isFetching: isPolling,
    refetch: pollStatus,
  } = useQuery<RAGJobStatusResponse, Error>({
    queryKey: ["ragJobStatus", job?.job_id],
    queryFn: () => ragService.getJobStatus(job!.job_id),
    enabled: false, // Important: only poll manually
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    // Polling logic
    if (jobStatus?.status === "PROCESSING") {
      const timer = setTimeout(() => pollStatus(), 3000); // Poll every 3 seconds
      return () => clearTimeout(timer);
    }
  }, [jobStatus, pollStatus]);

  const startMutation = useMutation({
    mutationFn: (vars: FormData) => ragService.startPreprocessing(vars),
    onSuccess: (data) => {
      setJob(data);
      message.info(data.message);
    },
    onError: (error: AxiosError) => {
      message.error(
        `Failed to start job: ${
          (error.response?.data as { detail: string })?.detail || error.message
        }`,
      );
    },
  });

  const approveMutation = useMutation({
    mutationFn: (jobId: string) => ragService.approveJob(jobId),
    onSuccess: () => {
      message.success("Job approved and is now processing in the background.");
      pollStatus(); // Start polling immediately
    },
    onError: (error: AxiosError) => {
      message.error(
        `Failed to approve job: ${
          (error.response?.data as { detail: string })?.detail || error.message
        }`,
      );
    },
  });

  const ingestMutation = useMutation({
    mutationFn: (payload: PreprocessingResponse) =>
      ragService.ingestProcessed(payload),
    onSuccess: (data: { message: string }) => {
      message.success(data.message);
      handleReset();
    },
    onError: (error: AxiosError) => {
      message.error(
        `Ingestion failed: ${
          (error.response?.data as { detail: string })?.detail || error.message
        }`,
      );
    },
  });

  const handleDownloadSampleCsv = () => {
    const csvContent = [
      "id,document,control_family,control_title", // Headers
      '"REQUIRED: A unique ID for the control (e.g., NIST-AC-1)","REQUIRED: The full text of the security control.","RECOMMENDED: The high-level category (e.g., Access Control).","RECOMMENDED: A short, human-readable title for the control."', // Descriptions
    ].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, "framework_template.csv");
  };

  const handleStart = async (values: PreprocessorFormValues) => {
    if (!file) {
      message.error("Please upload a CSV file.");
      return;
    }
    const formData = new FormData();
    formData.append("file", file);
    formData.append("llm_config_id", values.llm_config_id);
    const frameworkName =
      frameworkMode === "new" ? values.newFrameworkName : values.frameworkName;
    if (!frameworkName) {
      message.error("Framework name is required.");
      return;
    }
    formData.append("framework_name", frameworkName);
    startMutation.mutate(formData);
  };

  const handleDownload = () => {
    if (!jobStatus?.processed_documents) return;
    const { processed_documents } = jobStatus;
    const header = Object.keys(processed_documents[0].metadata).join(",");
    const rows = processed_documents.map((doc: EnrichedDocument) =>
      [
        doc.id,
        `"${doc.enriched_content.replace(/"/g, '""')}"`,
        ...Object.values(doc.metadata).map((val) =>
          `"${String(val).replace(/"/g, '""')}"`,
        ),
      ].join(","),
    );
    const csvContent = `id,document,${header}\n${rows.join("\n")}`;
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, `${jobStatus.framework_name}_processed.csv`);
  };

  const handleUpdate = (name: string) => {
    form.setFieldsValue({ frameworkName: name });
    setFrameworkMode("existing");
    preprocessorRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleReset = () => {
    setJob(null);
    setFile(null);
    form.resetFields();
  };

  const renderContent = () => {
    if (job?.status === "PENDING_APPROVAL" || (job?.status === "COMPLETED" && jobStatus?.status !== "COMPLETED")) {
      // Approval View
      return (
        <Card
          type="inner"
          title={`Cost Estimation for "${job?.framework_name || "New Framework"}"`}
        >
          <Statistic
            title="Total Estimated Cost"
            value={Number(job.estimated_cost?.total_estimated_cost) || 0}
            precision={6}
            prefix="$"
          />
          <Paragraph type="secondary" style={{ marginTop: 16 }}>
            {job.message}
          </Paragraph>
          <Space style={{ marginTop: 16 }}>
            <Button onClick={handleReset}>Cancel</Button>
            <Button
              type="primary"
              onClick={() => approveMutation.mutate(job.job_id)}
              loading={approveMutation.isPending}
            >
              Approve & Process
            </Button>
          </Space>
        </Card>
      );
    }

    if (jobStatus?.status === "COMPLETED") {
      // Result View
      const finalPayload: PreprocessingResponse = {
        framework_name: jobStatus.framework_name,
        llm_config_name: "", // Not available here, can be added to status response
        processed_documents: jobStatus.processed_documents || [],
      };
      return (
        <Card
          type="inner"
          title="Processing Complete"
        >
          <Alert
            type="success"
            showIcon
            message={`Successfully processed ${
              jobStatus.processed_documents?.length || 0
            } documents for "${jobStatus.framework_name}".`}
            description="You can now download the processed file or ingest it directly into the knowledge base."
          />
          <Statistic
            title="Final Actual Cost"
            value={jobStatus.actual_cost}
            precision={6}
            prefix="$"
            style={{ margin: "16px 0" }}
          />
          <Space>
            <Button icon={<DownloadOutlined />} onClick={handleDownload}>
              Download CSV
            </Button>
            <Button
              type="primary"
              icon={<SendOutlined />}
              onClick={() => ingestMutation.mutate(finalPayload)}
              loading={ingestMutation.isPending}
            >
              Ingest into Database
            </Button>
            <Button onClick={handleReset}>Start New Job</Button>
          </Space>
        </Card>
      );
    }

    // Default: Initial Form View
    return (
      <Form form={form} layout="vertical" onFinish={handleStart}>
        <Row gutter={24}>
          <Col xs={24} md={12}>
            <Form.Item label="Framework">
              <Radio.Group
                value={frameworkMode}
                onChange={(e) => setFrameworkMode(e.target.value)}
              >
                <Radio value="existing">Update Existing</Radio>
                <Radio value="new">Create New</Radio>
              </Radio.Group>
            </Form.Item>
            {frameworkMode === "existing" ? (
              <Form.Item
                name="frameworkName"
                rules={[{ required: true, message: "Please select a framework." }]}
              >
                <Select
                  showSearch
                  placeholder="Select framework to update"
                  loading={isLoadingFrameworks}
                  options={frameworks.map((f) => ({
                    label: f.name,
                    value: f.name,
                  }))}
                />
              </Form.Item>
            ) : (
              <Form.Item
                name="newFrameworkName"
                rules={[{ required: true, message: "Please enter a name." }]}
              >
                <Input placeholder="Enter name for the new framework" />
              </Form.Item>
            )}
          </Col>
          <Col xs={24} md={12}>
            <Form.Item
              name="llm_config_id"
              label="LLM for Processing"
              rules={[{ required: true, message: "Please select an LLM." }]}
            >
              <Select
                placeholder="Select LLM"
                loading={isLoadingLLMs}
                options={llmConfigs.map((c) => ({
                  label: c.name,
                  value: c.id,
                }))}
              />
            </Form.Item>
          </Col>
          <Col span={24}>
            <Alert
              type="info"
              style={{ marginBottom: 16 }}
              message={
                <Space>
                  <span>CSV Format Requirements</span>
                  {/* Download button will be added here */}
                </Space>
              }
              description="Your CSV must contain 'id' and 'document' columns. Recommended: 'control_family', 'control_title'."
            />
            <Form.Item label="Upload Raw Framework CSV" required>
              <Upload.Dragger
                name="file"
                multiple={false}
                accept=".csv"
                fileList={file ? [file] : []}
                beforeUpload={(f) => {
                  setFile(f);
                  return false;
                }}
                onRemove={() => setFile(null)}
              >
                <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                <p>Click or drag CSV file to this area</p>
              </Upload.Dragger>
            </Form.Item>
          </Col>
        </Row>
        <Button
          type="primary"
          htmlType="submit"
          loading={startMutation.isPending}
        >
          Get Cost Estimate
        </Button>
      </Form>
    );
  };

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <div ref={preprocessorRef}>
        <Card
          title={
            <Space>
              <EditOutlined />
              <Title level={4} style={{ margin: 0 }}>
                Framework Pre-processor & Ingestion
              </Title>
            </Space>
          }
        >
          <Spin
            spinning={startMutation.isPending || isPolling}
            tip={isPolling ? "Processing in background..." : "Estimating cost..."}
          >
            {renderContent()}
          </Spin>
        </Card>
      </div>

      <Divider />

      <Title level={4}>Existing Frameworks</Title>
      <Spin spinning={isLoadingFrameworks}>
        <Row gutter={[16, 16]}>
          {frameworks.length > 0 ? (
            frameworks.map((fw) => (
              <FrameworkCard key={fw.id} framework={fw} onUpdate={handleUpdate} />
            ))
          ) : (
            !isLoadingFrameworks && (
              <Col span={24}>
                <Empty description="No frameworks found. Use the pre-processor above to create one." />
              </Col>
            )
          )}
          <Col xs={24} sm={12} md={8}>
            <Card
              hoverable
              style={{
                height: "100%",
                border: "2px dashed #d9d9d9",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                minHeight: 150,
              }}
              onClick={() => {
                handleReset();
                setFrameworkMode("new");
                preprocessorRef.current?.scrollIntoView({
                  behavior: "smooth",
                });
              }}
            >
              <Space direction="vertical" align="center">
                <PlusOutlined style={{ fontSize: 24, color: "#d9d9d9" }} />
                <Text type="secondary">Add New Framework</Text>
              </Space>
            </Card>
          </Col>
        </Row>
      </Spin>
    </Space>
  );
};

export default RAGManagementPage;