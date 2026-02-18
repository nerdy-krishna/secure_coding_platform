import {
  CloudUploadOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  EyeOutlined,
  PlusOutlined,
  SecurityScanOutlined,
  CheckOutlined,
  CloseOutlined,
  GlobalOutlined,
  FileTextOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TableProps } from "antd";
import {
  Alert,
  Button,
  Card,
  Col,

  Form,
  Input,
  Modal,
  Popconfirm,
  Row,

  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
  Switch,
} from "antd";
import type { RcFile } from "antd/es/upload";
import { AxiosError } from "axios";
import { saveAs } from "file-saver";
import React, { useEffect, useState } from "react";
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
import { FrameworkIngestionModal } from "./FrameworkIngestionModal";

const { Title, Paragraph } = Typography;

// --- Sub-component for Viewing Documents ---
const ViewDocumentsModal: React.FC<{
  frameworkName: string;
  visible: boolean;
  onClose: () => void;
}> = ({ frameworkName, visible, onClose }) => {
  const {
    data: documents,
    isLoading,
    isError,
  } = useQuery<RAGDocument[], Error>({
    queryKey: ["ragDocuments", frameworkName],
    queryFn: () => ragService.getDocuments(frameworkName),
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
      ...new Set(documents.flatMap((doc: RAGDocument) => Object.keys(doc.metadata))),
    ];
    const metadataColumns = metadataKeys.map((key: string) => ({
      title: key.replace(/_/g, " ").replace(/\b\w/g, (l: string) => l.toUpperCase()),
      dataIndex: ["metadata", key],
      key: key,
      ellipsis: true,
      render: (text: unknown) => {
        if (typeof text === 'boolean') {
          return text ? <Tag color="green" > Yes </Tag> : <Tag color="red">No</Tag >;
        }
        return text?.toString();
      }
    }));

    return [
      { title: "ID", dataIndex: "id", key: "id", fixed: "left", width: 150 },
      {
        title: "Document Content",
        dataIndex: "document",
        key: "document",
        ellipsis: true,
        width: 400,
      },
      ...metadataColumns,
    ];
  }, [documents]);

  return (
    <Modal
      title= {`Documents for "${frameworkName}"`
}
open = { visible }
onCancel = { onClose }
footer = {< Button onClick = { onClose } > Close </Button>}
width = { 1200}
destroyOnClose
  >
  <Table
        loading={ isLoading }
dataSource = { documents }
rowKey = "id"
columns = { columns }
scroll = {{ x: true }}
locale = {{
  emptyText: isError
    ? "Error loading documents."
    : "No documents found for this framework.",
        }}
      />
  </Modal>
  );
};

// --- Standard Framework Card ---
const StandardFrameworkCard: React.FC<{
  name: string;
  displayName: string;
  description: string;
  docCount: number;
  type: 'scanning' | 'knowledge';
  onUpdate: (name: string) => void;
  onDelete: (name: string) => void;
  onIngest: () => void; // Trigger ingestion/upload
  isLoading?: boolean;
}> = ({ name, displayName, description, docCount, type, onUpdate, onDelete, onIngest, isLoading }) => {
  const [isViewModalVisible, setIsViewModalVisible] = useState(false);
  const isInstalled = docCount > 0;

  const actions = [];

  if (isInstalled) {
    actions.push(
      <Tooltip title="View Documents" key = "view" >
      <Button
          type="text"
          icon = {< EyeOutlined />}
  onClick = {() => setIsViewModalVisible(true)}
        />
  </Tooltip>
    );

actions.push(
  <Tooltip title="Edit / Add Languages" key = "update" >
  <Button
          type="text"
          icon = {< EditOutlined />}
  onClick = {() => onUpdate(name)}
        />
  </Tooltip>
);
  }

// Update/Install Action (Re-upload / Re-fetch)
actions.push(
  <Tooltip title={ isInstalled? "Re-upload / Re-fetch Source": "Upload Framework" } key = "ingest" >
  <Button
        type="text"
        icon = {< CloudUploadOutlined />}
  onClick = { onIngest }
        loading = { isLoading }
  >
  {!isInstalled && "Upload"}
  </Button>
  </Tooltip>
);

if (isInstalled) {
  actions.push(
    <Popconfirm
        key="delete"
        title = "Delete Standard Framework?"
        description = "This will remove all ingested documents for this standard. You can re-ingest them later."
        onConfirm = {() => onDelete(name)}
okText = "Yes, Delete"
cancelText = "No"
  >
  <Tooltip title="Delete Documents" >
    <Button
            danger
type = "text"
icon = {< DeleteOutlined />}
          />
  </Tooltip>
  </Popconfirm>
    );
  }

return (
  <Col xs= { 24} sm = { 12} md = { 8} >
    <Card
        title={
  <Space>
    { displayName }
  { docCount > 0 && <Tag color="green" > { docCount } docs </Tag> }
  </Space>
}
actions = { actions }
style = {{ height: "100%", minHeight: 180 }}
      >
  <div style={ { marginBottom: 8 } }>
    { type === 'scanning' ? (
      <Tag color= "blue" icon = {< SecurityScanOutlined />}> Scanning Standard </Tag>
          ) : (
  <Tag color= "orange" icon = {< FileTextOutlined />}> Knowledge Base </Tag>
          )}
</div>
  < Paragraph ellipsis = {{ rows: 3 }}> { description } </Paragraph>
    </Card>
{
  isViewModalVisible && (
    <ViewDocumentsModal
          frameworkName={ name }
  visible = { isViewModalVisible }
  onClose = {() => setIsViewModalVisible(false)
}
        />
      )}
</Col>
  );
};

// --- Custom Framework Card ---
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
    <Tooltip title="View Documents" key = "view" >
    <Button
        type="text"
        icon = {< EyeOutlined />}
onClick = {() => setIsViewModalVisible(true)}
      />
  </Tooltip>,
  < Tooltip title = "Edit / Add Languages" key = "update" >
    <Button
        type="text"
icon = {< EditOutlined />}
onClick = {() => onUpdate(framework.name)}
      />
  </Tooltip>,
  < Popconfirm
key = "delete"
title = "Delete Framework?"
description = "This action cannot be undone. It will remove the framework and its associations."
onConfirm = {() => deleteMutation.mutate()}
okText = "Yes, Delete"
cancelText = "No"
  >
  <Tooltip title="Delete Framework" >
    <Button
          danger
type = "text"
icon = {< DeleteOutlined />}
loading = { deleteMutation.isPending }
  />
  </Tooltip>
  </Popconfirm>,
  ];

return (
  <Col xs= { 24} sm = { 12} md = { 8} >
    <Card
        title={ framework.name }
actions = { actions }
style = {{ height: "100%", minHeight: 180 }}
      >
  <div style={ { marginBottom: 8 } }>
    <Tag color="purple" icon = {< GlobalOutlined />}> Custom Framework </Tag>
      </div>
      < Paragraph ellipsis = {{ rows: 3 }}> { framework.description } </Paragraph>
        </Card>
{
  isViewModalVisible && (
    <ViewDocumentsModal
          frameworkName={ framework.name }
  visible = { isViewModalVisible }
  onClose = {() => setIsViewModalVisible(false)
}
        />
      )}
</Col>
  );
};

// --- Add New Framework Card ---
const AddFrameworkCard: React.FC<{ onClick: () => void }> = ({ onClick }) => (
  <Col xs= { 24} sm = { 12} md = { 8} >
    <Card
      hoverable
style = {{
  height: "100%",
    minHeight: 180,
      borderStyle: 'dashed',
        display: 'flex',
          justifyContent: 'center',
            alignItems: 'center',
              background: '#fafafa'
}}
onClick = { onClick }
  >
  <div style={ { textAlign: 'center' } }>
    <PlusOutlined style={ { fontSize: 32, color: '#1890ff', marginBottom: 16 } } />
      < Paragraph strong style = {{ fontSize: 16, marginBottom: 0 }}> Add Custom Framework </Paragraph>
        < Paragraph type = "secondary" > Upload CSV or define a new standard </Paragraph>
          </div>
          </Card>
          </Col>
);

const RAGManagementPage: React.FC = () => {
  const queryClient = useQueryClient();

  // State
  const [pollingJobId, setPollingJobId] = useState<string | null>(null);
  const [ingestionModalVisible, setIngestionModalVisible] = useState(false);
  const [ingestionInitialValues, setIngestionInitialValues] = useState<{ frameworkName: string; isEdit?: boolean } | undefined>(undefined);

  // Standard Framework Loading States
  const [ingestLoading, setIngestLoading] = useState<string | null>(null);

  // Modals for Standard Fetch
  const [proactiveModalVisible, setProactiveModalVisible] = useState(false);
  const [cheatsheetModalVisible, setCheatsheetModalVisible] = useState(false);
  const [proactiveUrl, setProactiveUrl] = useState("https://github.com/OWASP/www-project-proactive-controls/tree/master/docs/the-top-10");
  const [cheatsheetUrl, setCheatsheetUrl] = useState("https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets");

  const [scanReady, setScanReady] = useState(true);

  useEffect(() => {
    const storedJobId = sessionStorage.getItem("rag_processing_job_id");
    if (storedJobId) {
      setPollingJobId(storedJobId);
    }
  }, []);

  // Queries
  const { data: frameworks = [], isLoading: isLoadingFrameworks } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: llmConfigs = [] } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const { data: stats = { asvs: 0, proactive_controls: 0, cheatsheets: 0 }, isLoading: isLoadingStats, refetch: refetchStats } = useQuery<Record<string, number>>({
    queryKey: ["ragStats"],
    queryFn: ragService.getStats
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
    refetchInterval: (query: any /* eslint-disable-line @typescript-eslint/no-explicit-any */) => {
      const status = query.state.data?.status;
      return status === "PROCESSING" || status === "PENDING_APPROVAL" ? 3000 : false;
    },
  });

  const approveMutation = useMutation({
    mutationFn: (jobId: string) => ragService.approveJob(jobId),
    onSuccess: () => {
      message.success("Job approved and is now processing in the background.");
      pollStatus();
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

  // Actions
  const handleOpenIngestionModal = (frameworkName?: string, isEdit: boolean = false) => {
    setIngestionInitialValues(frameworkName ? { frameworkName, isEdit } : undefined);
    setIngestionModalVisible(true);
  };

  const handleIngestionSuccess = (jobId: string) => {
    setPollingJobId(jobId);
    sessionStorage.setItem("rag_processing_job_id", jobId);
    pollStatus();
  };

  const handleReset = () => {
    setPollingJobId(null);
    sessionStorage.removeItem("rag_processing_job_id");
    setScanReady(true);
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

  // Standard Framework Handlers
  const handleUploadASVS = async (file: RcFile) => {
    setIngestLoading('asvs');
    try {
      const res = await ragService.ingestASVS(file);
      message.success(res.message);
      refetchStats();
      queryClient.invalidateQueries({ queryKey: ["ragDocuments", "asvs"] });
    } catch (error: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
      const errorDetail = (error.response?.data as { detail?: string })?.detail || error.message;
      message.error(`ASVS ingestion failed: ${errorDetail}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleFetchProactive = async () => {
    setIngestLoading('proactive');
    try {
      const res = await ragService.ingestProactiveControls(proactiveUrl);
      message.success(res.message);
      refetchStats();
      setProactiveModalVisible(false);
      queryClient.invalidateQueries({ queryKey: ["ragDocuments", "proactive_controls"] });
    } catch (error: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
      const errorDetail = (error.response?.data as { detail?: string })?.detail || error.message;
      message.error(`Proactive Controls fetch failed: ${errorDetail}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleFetchCheatsheets = async () => {
    setIngestLoading('cheatsheet');
    try {
      const res = await ragService.ingestCheatsheet(cheatsheetUrl);
      message.success(res.message);
      refetchStats();
      setCheatsheetModalVisible(false);
      queryClient.invalidateQueries({ queryKey: ["ragDocuments", "cheatsheets"] });
    } catch (error: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
      const errorDetail = (error.response?.data as { detail?: string })?.detail || error.message;
      message.error(`Cheatsheets fetch failed: ${errorDetail}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleDeleteStandard = async (frameworkName: string) => {
    try {
      const docs = await ragService.getDocuments(frameworkName);
      if (docs && docs.length > 0) {
        const ids = docs.map(d => d.id);
        await ragService.deleteDocuments(ids);
        message.success(`Deleted ${ids.length} documents for ${frameworkName}.`);
        refetchStats(); // Update counts
      } else {
        message.info("No documents to delete.");
      }
    } catch (error: any) { // eslint-disable-line @typescript-eslint/no-explicit-any
      message.error(`Failed to delete standard documents: ${error.message}`);
    }
  };

  // --- Render Job Status Banner ---
  const renderJobStatus = () => {
    if (!pollingJobId || !jobStatus) return null;

    if (jobStatus.status === "PENDING_APPROVAL") {
      // This state is mostly handled by the modal now, but if the user closes it early:
      return (
        <Alert
          type= "warning"
      message = {`Job Pending Approval: ${jobStatus.framework_name}`
    }
    action = {
            < Button size = "small" type = "primary" onClick = {() => approveMutation.mutate(pollingJobId!)} loading = { approveMutation.isPending } >
  Approve
  </Button>
          }
style = {{ marginBottom: 24 }}
        />
      );
    }

if (jobStatus.status === "PROCESSING" || isPolling) {
  return (
    <Alert
          type= "info"
  message = {`Processing Framework: ${jobStatus.framework_name || '...'} `
}
description = "Enriching documents with LLM patterns. This may take a few minutes."
icon = {< Spin />}
showIcon
style = {{ marginBottom: 24 }}
        />
      );
    }

if (jobStatus.status === "COMPLETED") {
  const finalPayload: PreprocessingResponse = {
    framework_name: jobStatus.framework_name,
    llm_config_name: "",
    processed_documents: jobStatus.processed_documents || [],
    scan_ready: scanReady
  };

  return (
    <Card style= {{ marginBottom: 24, borderColor: '#52c41a' }
}>
  <Space direction="vertical" style = {{ width: '100%' }}>
    <Alert type="success" message = {`Preprocessing Complete for ${jobStatus.framework_name}`} showIcon />

      <div style={ { display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 } }>
        <span>Mark as Scan Ready ? </span>
          < Switch
                checkedChildren = {< CheckOutlined />}
unCheckedChildren = {< CloseOutlined />}
checked = { scanReady }
onChange = { setScanReady }
  />
  <Tooltip title="If enabled, this framework will be used by the security scanner agent. If disabled, it will be used for chat context only." >
    <Typography.Text type="secondary" style = {{ fontSize: 12 }}> (?) </Typography.Text>
      </Tooltip>
      </div>

      < Space >
      <Button icon={
  <DownloadOutlined />} onClick={handleDownload}>Download Processed CSV</Button >
    <Button
                type="primary"
  icon = {< PlusOutlined />}
onClick = {() => ingestMutation.mutate(finalPayload)}
loading = { ingestMutation.isPending }
  >
  Finalize Ingestion(Save to DB)
    </Button>
    < Button onClick = { handleReset } > Cancel / New </Button>
      </Space>
      </Space>
      </Card>
      );
    }

if (jobStatus.status === "FAILED") {
  return (
    <Alert
          type= "error"
  message = "Job Failed"
  description = { jobStatus.error_message }
  action = {< Button size = "small" type = "primary" onClick = { handleReset } > Close </Button>
}
style = {{ marginBottom: 24 }}
        />
      );
    }

return null;
  };

return (
  <Space direction= "vertical" style = {{ width: "100%" }} size = "large" >
    <Title level={ 2 }> Framework Management </Title>

{/* Global Job Status */ }
{ renderJobStatus() }

{/* Grid of Frameworks */ }
<Spin spinning={ isLoadingFrameworks || isLoadingStats }>
  <Row gutter={ [16, 16] }>

    {/* 1. Add Custom Framework Card */ }
    < AddFrameworkCard onClick = {() => handleOpenIngestionModal()} />

{/* 2. Standard Frameworks */ }
<StandardFrameworkCard
            name="asvs"
displayName = "OWASP ASVS"
description = "Application Security Verification Standard. Best for comprehensive auditing."
docCount = { stats.asvs || 0 }
type = "scanning"
onUpdate = {(name) => handleOpenIngestionModal(name, true)} // ASVS ignores this? No, we need explicit handler.
onDelete = { handleDeleteStandard }
onIngest = {() => {
  document.getElementById('hidden-asvs-input')?.click();
}}
isLoading = { ingestLoading === 'asvs'}
          />
{/* Hidden Upload for ASVS */ }
<input
            type="file"
id = "hidden-asvs-input"
accept = ".csv"
style = {{ display: 'none' }}
onChange = {(e) => {
  const file = e.target.files?.[0];
  if (file) {
    handleUploadASVS(file as unknown as RcFile);
  }
  e.target.value = ''; // Reset
}}
          />

  < StandardFrameworkCard
name = "proactive_controls"
displayName = "OWASP Proactive Controls"
description = "Developer-focused controls (C1-C10). Great for chat context."
docCount = { stats.proactive_controls || 0 }
type = "knowledge"
onUpdate = {() => setProactiveModalVisible(true)}
onDelete = { handleDeleteStandard }
onIngest = {() => setProactiveModalVisible(true)}
isLoading = { ingestLoading === 'proactive'}
          />

  < StandardFrameworkCard
name = "cheatsheets"
displayName = "OWASP Cheatsheets"
description = "Topic-specific security cheatsheets."
docCount = { stats.cheatsheets || 0 }
type = "knowledge"
onUpdate = {() => setCheatsheetModalVisible(true)}
onDelete = { handleDeleteStandard }
onIngest = {() => setCheatsheetModalVisible(true)}
isLoading = { ingestLoading === 'cheatsheet'}
          />

{/* 3. Custom Frameworks */ }
{
  frameworks
    .filter(fw => !['asvs', 'proactive_controls', 'cheatsheets'].includes(fw.name))
    .map((fw) => (
      <FrameworkCard
                key= { fw.id }
                framework = { fw }
                onUpdate = {(name) => handleOpenIngestionModal(name, true)}
              />
            ))}
</Row>
  </Spin>

{/* Modals */ }
<FrameworkIngestionModal
        visible={ ingestionModalVisible }
onCancel = {() => setIngestionModalVisible(false)}
onSuccess = { handleIngestionSuccess }
initialValues = { ingestionInitialValues }
llmConfigs = { llmConfigs }
  />

  <Modal
        title="Fetch Proactive Controls"
open = { proactiveModalVisible }
onCancel = {() => setProactiveModalVisible(false)}
onOk = { handleFetchProactive }
confirmLoading = { ingestLoading === 'proactive'}
okText = "Start Fetch"
  >
  <Form layout="vertical" >
    <Form.Item label="GitHub URL" >
      <Input value={ proactiveUrl } onChange = {(e) => setProactiveUrl(e.target.value)} />
        </Form.Item>
        </Form>
        </Modal>

        < Modal
title = "Fetch Cheatsheets"
open = { cheatsheetModalVisible }
onCancel = {() => setCheatsheetModalVisible(false)}
onOk = { handleFetchCheatsheets }
confirmLoading = { ingestLoading === 'cheatsheet'}
okText = "Start Fetch"
  >
  <Form layout="vertical" >
    <Form.Item label="GitHub URL" >
      <Input value={ cheatsheetUrl } onChange = {(e) => setCheatsheetUrl(e.target.value)} />
        </Form.Item>
        </Form>
        </Modal>

        </Space>
  );
};

export default RAGManagementPage;