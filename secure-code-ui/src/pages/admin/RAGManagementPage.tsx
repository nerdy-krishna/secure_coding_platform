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
  RAGJobStatusResponse
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
  const [pollingJobId, setPollingJobId] = useState<string | null>(null);
  const [frameworkMode, setFrameworkMode] = useState<"existing" | "new">("existing");
  const queryClient = useQueryClient();

  useEffect(() => {
    const storedJobId = sessionStorage.getItem("rag_processing_job_id");
    if (storedJobId) {
      setPollingJobId(storedJobId);
    }
  }, []);

  const { data: frameworks = [], isLoading: isLoadingFrameworks } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: llmConfigs = [], isLoading: isLoadingLLMs } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const {
    data: jobStatus,
    isFetching: isPolling,
    refetch: pollStatus,
  } = useQuery<RAGJobStatusResponse, Error>({
    queryKey: ["ragJobStatus", pollingJobId],
    queryFn: () => {
      if (!pollingJobId) throw new Error("No job ID to poll");
      return ragService.getJobStatus(pollingJobId);
    },
    enabled: !!pollingJobId,
    refetchOnWindowFocus: true,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "PROCESSING" ? 3000 : false;
    },
  });

  const startMutation = useMutation({
    mutationFn: (vars: FormData) => ragService.startPreprocessing(vars),
    onSuccess: (data) => {
      message.info(data.message);
      sessionStorage.setItem("rag_processing_job_id", data.job_id);
      setPollingJobId(data.job_id);
    },
    onError: (error: AxiosError) => {
      const errorDetail = (error.response?.data as { detail?: string })?.detail || error.message;
      message.error(`Failed to start job: ${errorDetail}`);
    },
  });

  const approveMutation = useMutation({
    mutationFn: (jobId: string) => ragService.approveJob(jobId),
    onSuccess: () => {
      message.success("Job approved and is now processing in the background.");
      pollStatus();
    },
    onError: (error: AxiosError) => {
      const errorDetail = (error.response?.data as { detail?: string })?.detail || error.message;
      message.error(`Failed to approve job: ${errorDetail}`);
    },
  });

  const ingestMutation = useMutation({
    mutationFn: (payload: PreprocessingResponse) => ragService.ingestProcessed(payload),
    onSuccess: (data: { message: string }) => {
      message.success(data.message);
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      handleReset();
    },
    onError: (error: AxiosError) => {
      const errorDetail = (error.response?.data as { detail: string })?.detail || error.message;
      message.error(`Ingestion failed: ${errorDetail}`);
    },
  });

  const handleDownloadSampleCsv = () => {
    const csvContent = [
      "id,document,control_family,control_title",
      '"CWE-79","The web application does not properly neutralize user-controllable input before it is placed in output that is used as a web page that is served to other users.","Improper Neutralization of Input","Cross-site Scripting (XSS)"',
      '"NIST-AC-1","The organization develops, documents, and disseminates to [Assignment: organization-defined personnel or roles] an access control policy that: a. Is consistent with applicable laws, Executive Orders, directives, policies, regulations, standards, and guidelines; and b. Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance.","Access Control","Access Control Policy and Procedures"',
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
    const frameworkName = frameworkMode === "new" ? values.newFrameworkName : values.frameworkName;
    if (!frameworkName) {
      message.error("Framework name is required.");
      return;
    }
    formData.append("framework_name", frameworkName);
    startMutation.mutate(formData);
  };

  const handleDownload = () => {
    if (!jobStatus?.processed_documents || jobStatus.processed_documents.length === 0) return;
    const { processed_documents, framework_name } = jobStatus;

    const metadataKeys = Object.keys(processed_documents[0].metadata || {}).sort();
    const header = ["id", "document", ...metadataKeys].join(",");

    const rows = processed_documents.map((doc: EnrichedDocument) => {
      const metadataValues = metadataKeys.map(key => {
        const value = doc.metadata[key as keyof typeof doc.metadata] ?? '';
        return `"${String(value).replace(/"/g, '""')}"`;
      });

      return [
          `"${doc.id}"`,
          `"${doc.enriched_content.replace(/"/g, '""')}"`,
          ...metadataValues
      ].join(',');
    });
    
    const csvContent = `${header}\n${rows.join("\n")}`;
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, `${framework_name}_processed.csv`);
  };

  const handleUpdate = (name: string) => {
    form.setFieldsValue({ frameworkName: name });
    setFrameworkMode("existing");
    preprocessorRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleReset = () => {
    setPollingJobId(null);
    sessionStorage.removeItem("rag_processing_job_id");
    setFile(null);
    form.resetFields();
  };

  const renderContent = () => {
    const currentJob = jobStatus;

    if (!pollingJobId || !currentJob) {
      return (
        <Form form={form} layout="vertical" onFinish={handleStart}>
          <Row gutter={24} align="bottom">
            <Col xs={24} md={12}>
              <Form.Item label="Framework">
                <Radio.Group value={frameworkMode} onChange={(e) => setFrameworkMode(e.target.value)}>
                  <Radio value="existing">Update Existing</Radio>
                  <Radio value="new">Create New</Radio>
                </Radio.Group>
              </Form.Item>
              {frameworkMode === "existing" ? (
                <Form.Item name="frameworkName" rules={[{ required: true, message: "Please select a framework." }]}>
                  <Select
                    showSearch
                    placeholder="Select framework to update"
                    loading={isLoadingFrameworks}
                    options={frameworks.map((f) => ({ label: f.name, value: f.name }))}
                  />
                </Form.Item>
              ) : (
                <Form.Item name="newFrameworkName" rules={[{ required: true, message: "Please enter a name." }]}>
                  <Input placeholder="Enter name for the new framework" />
                </Form.Item>
              )}
            </Col>
            <Col xs={24} md={12}>
              <Form.Item label="LLM for Processing" name="llm_config_id" rules={[{ required: true, message: "Please select an LLM." }]}>
                <Select
                  placeholder="Select LLM"
                  loading={isLoadingLLMs}
                  options={llmConfigs.map((c) => ({ label: c.name, value: c.id }))}
                />
              </Form.Item>
            </Col>
            <Col span={24}>
              <Alert
                type="info"
                style={{ marginBottom: 16 }}
                message="CSV Format Requirements"
                description={
                  <>
                    Your CSV file <b>must</b> contain an <b>`id`</b> column (for a unique control ID) and a <b>`document`</b> column (for the full control text).
                    You can add any other columns for metadata (e.g., `control_family`, `cwe`). These will be used to enrich the knowledge base.
                    <Button size="small" type="link" onClick={handleDownloadSampleCsv} style={{ display: 'block', paddingLeft: 0, marginTop: '8px' }}>
                      Download Sample Template
                    </Button>
                  </>
                }
              />
              <Form.Item label="Upload Raw Framework CSV" required>
                <Upload.Dragger
                  name="file"
                  multiple={false}
                  accept=".csv"
                  fileList={file ? [file] : []}
                  beforeUpload={(f) => { setFile(f); return false; }}
                  onRemove={() => setFile(null)}
                >
                  <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                  <p>Click or drag CSV file to this area</p>
                </Upload.Dragger>
              </Form.Item>
            </Col>
          </Row>
          <Button type="primary" htmlType="submit" loading={startMutation.isPending} disabled={!file}>
            Get Cost Estimate
          </Button>
        </Form>
      );
    }

    if (currentJob.status === "PENDING_APPROVAL") {
      return (
        <Card type="inner" title={`Cost Estimation for "${currentJob.framework_name}"`}>
          <Statistic
            title="Total Estimated Cost"
            value={Number(currentJob.estimated_cost?.total_estimated_cost) || 0}
            precision={6}
            prefix="$"
          />
          <Paragraph type="secondary" style={{ marginTop: 16 }}>
            Please approve to start processing. This action will incur the estimated cost.
          </Paragraph>
          <Space style={{ marginTop: 16 }}>
            <Popconfirm
              title="Cancel this job?"
              description="Are you sure you want to cancel this operation? This cannot be undone."
              onConfirm={handleReset}
              okText="Yes, Cancel"
              cancelText="No"
            >
              <Button danger loading={approveMutation.isPending}>Cancel</Button>
            </Popconfirm>
            <Button
              type="primary"
              onClick={() => approveMutation.mutate(pollingJobId!)}
              loading={approveMutation.isPending}
            >
              Approve & Process
            </Button>
          </Space>
        </Card>
      );
    }

    if (currentJob.status === "PROCESSING" || isPolling) {
      return (
        <Card type="inner" title={`Processing Job for "${currentJob?.framework_name || '...'}"`}>
          <Spin tip="Processing in background... Status will update automatically.">
            <Alert
              message="Job is processing"
              description="This may take a few minutes. You can safely navigate away from this page and come back later to check the status."
              type="info"
              showIcon
            />
          </Spin>
        </Card>
      );
    }

    if (currentJob.status === "COMPLETED") {
      const finalPayload: PreprocessingResponse = {
        framework_name: currentJob.framework_name,
        llm_config_name: "",
        processed_documents: currentJob.processed_documents || [],
      };
      return (
        <Card type="inner" title="Processing Complete">
          <Alert
            type="success"
            showIcon
            message={`Successfully processed ${currentJob.processed_documents?.length || 0} documents for "${currentJob.framework_name}".`}
            description="You can now download the processed file or ingest it directly into the knowledge base."
          />
          <Statistic
            title="Final Actual Cost"
            value={currentJob.actual_cost}
            precision={6}
            prefix="$"
            style={{ margin: "16px 0" }}
          />
          <Space>
            <Button icon={<DownloadOutlined />} onClick={handleDownload}>Download CSV</Button>
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

    if (currentJob.status === "FAILED") {
      return (
        <Card type="inner" title="Job Failed">
          <Alert
            type="error"
            showIcon
            message={`Processing failed for framework "${currentJob.framework_name}".`}
            description={currentJob.error_message || "An unknown error occurred."}
          />
          <Button onClick={handleReset} style={{ marginTop: 16 }}>
            Start New Job
          </Button>
        </Card>
      );
    }

    return <Spin tip="Loading job status..."/>;
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
            spinning={startMutation.isPending || (isPolling && !jobStatus)}
            tip={startMutation.isPending ? "Estimating cost..." : "Checking job status..."}
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