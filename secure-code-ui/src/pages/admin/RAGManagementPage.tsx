// src/pages/admin/RAGManagementPage.tsx
import {
    BookOutlined,
    CloudUploadOutlined,
    DeleteOutlined,
    SearchOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TableProps } from "antd";
import {
    Alert,
    Button,
    Card,
    Col,
    Empty,
    Form,
    Popconfirm,
    Row,
    Select,
    Space,
    Table,
    Tabs,
    Typography,
    Upload,
    message,
} from "antd";
import type { RcFile, UploadFile } from "antd/es/upload";
import React, { useState } from "react";
import { frameworkService } from "../../shared/api/frameworkService";
import { ragService } from "../../shared/api/ragService";
import type { FrameworkRead, RAGDocument } from "../../shared/types/api";

const { Title, Paragraph } = Typography;
const { Dragger } = Upload;
const { Option } = Select;

const IngestTab: React.FC<{ frameworks: FrameworkRead[] }> = ({
  frameworks,
}) => {
  const [form] = Form.useForm();
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const queryClient = useQueryClient();

  const ingestionMutation = useMutation({
    mutationFn: (variables: { frameworkName: string; file: File }) =>
      ragService.ingestDocuments(variables.frameworkName, variables.file),
    onSuccess: (data) => {
      message.success(data.message);
      form.resetFields();
      setFileList([]);
      queryClient.invalidateQueries({ queryKey: ["ragDocuments"] });
    },
    onError: (error) => {
      message.error(`Ingestion failed: ${error.message}`);
    },
  });

  const handleIngest = async () => {
    try {
      const values = await form.validateFields();
      if (fileList.length === 0) {
        message.error("Please select a CSV file to upload.");
        return;
      }
      const file = fileList[0] as RcFile;
      ingestionMutation.mutate({ frameworkName: values.frameworkName, file });
    } catch (error) {
      console.log("Validation Failed:", error);
    }
  };

  return (
    <Form form={form} layout="vertical" onFinish={handleIngest}>
      <Row gutter={16}>
        <Col xs={24} sm={12}>
          <Form.Item
            name="frameworkName"
            label="Select Framework"
            rules={[
              { required: true, message: "Please select a framework." },
            ]}
          >
            <Select placeholder="Choose the framework to associate documents with">
              {frameworks.map((fw) => (
                <Option key={fw.id} value={fw.name}>
                  {fw.name}
                </Option>
              ))}
            </Select>
          </Form.Item>
        </Col>
        <Col xs={24} sm={12}>
          <Form.Item
            label="Upload Knowledge File (CSV)"
            required
          >
            <Dragger
              name="file"
              multiple={false}
              accept=".csv"
              fileList={fileList}
              beforeUpload={(file) => {
                setFileList([file]);
                return false; // Prevent auto-upload
              }}
              onRemove={() => setFileList([])}
            >
              <p className="ant-upload-drag-icon">
                <CloudUploadOutlined />
              </p>
              <p className="ant-upload-text">
                Click or drag a single CSV file to this area
              </p>
              <p className="ant-upload-hint">
                The CSV must contain 'id' and 'document' columns.
              </p>
            </Dragger>
          </Form.Item>
        </Col>
      </Row>
      <Form.Item>
        <Button
          type="primary"
          htmlType="submit"
          loading={ingestionMutation.isPending}
        >
          Start Ingestion
        </Button>
      </Form.Item>
    </Form>
  );
};

const BrowseTab: React.FC<{ frameworks: FrameworkRead[] }> = ({
  frameworks,
}) => {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(
    null,
  );
  const queryClient = useQueryClient();

  const {
    data: documents,
    isLoading,
    isFetching,
  } = useQuery<RAGDocument[], Error>({
    queryKey: ["ragDocuments", selectedFramework],
    queryFn: () => {
      if (!selectedFramework) return Promise.resolve([]);
      return ragService.getDocuments(selectedFramework);
    },
    enabled: !!selectedFramework,
  });

  const deleteMutation = useMutation({
    mutationFn: (docId: string) => ragService.deleteDocuments([docId]),
    onSuccess: () => {
      message.success("Document deleted successfully.");
      queryClient.invalidateQueries({
        queryKey: ["ragDocuments", selectedFramework],
      });
    },
    onError: (error) => {
      message.error(`Failed to delete document: ${error.message}`);
    },
  });

  const columns: TableProps<RAGDocument>["columns"] = [
    {
      title: "ID",
      dataIndex: "id",
      key: "id",
      width: 150,
    },
    {
      title: "Document Content",
      dataIndex: "document",
      key: "document",
    },
    {
      title: "Action",
      key: "action",
      width: 120,
      render: (_, record) => (
        <Popconfirm
          title="Delete Document"
          description="Are you sure you want to delete this document from the knowledge base?"
          onConfirm={() => deleteMutation.mutate(record.id)}
        >
          <Button danger icon={<DeleteOutlined />}>
            Delete
          </Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <Select
        showSearch
        placeholder="Select a framework to browse its documents"
        style={{ width: "100%" }}
        onChange={(value) => setSelectedFramework(value)}
        loading={frameworks.length === 0}
        suffixIcon={<SearchOutlined />}
      >
        {frameworks.map((fw) => (
          <Option key={fw.id} value={fw.name}>
            {fw.name}
          </Option>
        ))}
      </Select>
      <Table
        columns={columns}
        dataSource={documents}
        loading={isLoading || isFetching}
        rowKey="id"
        locale={{
          emptyText: (
            <Empty
              description={
                selectedFramework
                  ? `No documents found for '${selectedFramework}'.`
                  : "Please select a framework to view its documents."
              }
            />
          ),
        }}
      />
    </Space>
  );
};

const RAGManagementPage: React.FC = () => {
  const {
    data: frameworks,
    isError,
    error,
  } = useQuery<FrameworkRead[], Error>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  if (isError) {
    return <Alert message="Error" description={error.message} type="error" />;
  }

  const tabItems = [
    {
      key: "ingest",
      label: "Ingest New Documents",
      children: <IngestTab frameworks={frameworks || []} />,
    },
    {
      key: "browse",
      label: "Browse Knowledge Base",
      children: <BrowseTab frameworks={frameworks || []} />,
    },
  ];

  return (
    <Card>
      <Title level={2}>
        <BookOutlined style={{ marginRight: 8 }} />
        RAG Knowledge Base Management
      </Title>
      <Paragraph type="secondary">
        Manage the knowledge base documents that power the Retrieval-Augmented
        Generation (RAG) service.
      </Paragraph>
      <Tabs defaultActiveKey="ingest" items={tabItems} />
    </Card>
  );
};

export default RAGManagementPage;