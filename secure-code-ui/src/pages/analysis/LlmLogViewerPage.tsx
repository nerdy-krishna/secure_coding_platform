import {
  ArrowLeftOutlined,
  LoadingOutlined,
  RobotOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Layout,
  Menu,
  Row,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
  type TableProps,
} from "antd";
import React, { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import type { LLMInteractionResponse } from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Text, Paragraph } = Typography;

const LlmLogViewerPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [selectedFilePath, setSelectedFilePath] = useState<string>("All Files");

  const {
    data: interactions,
    isLoading,
    isError,
    error,
  } = useQuery<LLMInteractionResponse[], Error>({
    queryKey: ["llmInteractionsForScan", scanId],
    queryFn: () => {
      if (!scanId) throw new Error("Scan ID is missing");
      return scanService.getLlmInteractionsForScan(scanId);
    },
    enabled: !!scanId,
  });

  const { filePaths, agentNames } = useMemo(() => {
    if (!interactions) return { filePaths: [], agentNames: [] };
    const paths = new Set<string>();
    const agents = new Set<string>();
    interactions.forEach(i => {
      if (i.file_path) {
        paths.add(i.file_path);
      }
      agents.add(i.agent_name);
    });
    return {
      filePaths: ["All Files", ...Array.from(paths).sort()],
      agentNames: Array.from(agents).sort()
    };
  }, [interactions]);

  const filteredInteractions = useMemo(() => {
    if (!interactions) return [];
    if (selectedFilePath === "All Files") {
      return interactions;
    }
    return interactions.filter(i => i.file_path === selectedFilePath);
  }, [interactions, selectedFilePath]);

  const columns: TableProps<LLMInteractionResponse>["columns"] = [
    {
      title: "Timestamp",
      dataIndex: "timestamp",
      key: "timestamp",
      render: (text) => new Date(text).toLocaleString(),
      sorter: (a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      defaultSortOrder: "ascend",
      width: 200,
    },
    {
      title: "Agent",
      dataIndex: "agent_name",
      key: "agent_name",
      render: (agent) => <Tag color="cyan">{agent}</Tag>,
      filters: agentNames.map((agent) => ({ text: agent, value: agent })),
      onFilter: (value, record) => record.agent_name === value,
      width: 220,
    },
    {
      title: "Tokens (I/O/T)",
      key: "tokens",
      align: "right",
      width: 150,
      render: (_, record) => (
        <Space direction="vertical" size={0} style={{ textAlign: "right", width: '100%' }}>
          <Text>
            {(record.input_tokens || 0).toLocaleString()} /{" "}
            {(record.output_tokens || 0).toLocaleString()}
          </Text>
          <Text strong>
            {(record.total_tokens || 0).toLocaleString()}
          </Text>
        </Space>
      ),
      sorter: (a, b) => (a.total_tokens || 0) - (b.total_tokens || 0),
    },
    {
      title: "Cost (USD)",
      dataIndex: "cost",
      key: "cost",
      align: "right",
      width: 150,
      render: (cost) =>
        cost ? `$${cost.toFixed(6)}` : <Text type="secondary">N/A</Text>,
      sorter: (a, b) => (a.cost || 0) - (b.cost || 0),
    },
  ];

  if (isLoading) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        <Spin
          indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />}
          tip="Loading LLM Interaction Logs..."
        />
      </div>
    );
  }

  if (isError) {
    return (
      <Content style={{ padding: "20px" }}>
        <Alert
          message="Error"
          description={error.message}
          type="error"
          showIcon
        />
      </Content>
    );
  }

  return (
    <Layout style={{ background: "#fff", padding: 0, height: 'calc(100vh - 180px)' }}>
        <Sider width={300} style={{ background: "#fafafa", padding: "16px", borderRight: '1px solid #f0f0f0' }}>
            <Title level={5} style={{marginTop: 0, marginBottom: 16}}>Files Involved</Title>
            <Menu
                mode="inline"
                selectedKeys={[selectedFilePath]}
                onClick={(e) => setSelectedFilePath(e.key)}
                items={filePaths.map(path => ({
                    key: path,
                    label: path === 'All Files' ? <b>All Files</b> : <Text ellipsis={{tooltip: path}}>{path}</Text>
                }))}
                style={{ background: 'transparent', border: 'none' }}
            />
        </Sider>
        <Content style={{ padding: '16px 24px', display: 'flex', flexDirection: 'column' }}>
          <Row justify="space-between" align="middle" style={{ marginBottom: 16, flexShrink: 0 }}>
            <Col>
              <Title level={3} style={{ margin: 0 }}>
                <RobotOutlined style={{ marginRight: 8 }} />
                LLM Interaction Logs
              </Title>
              <Text copyable={{ text: scanId }} type="secondary" code>
                Scan ID: {scanId}
              </Text>
            </Col>
            <Col>
              <Button
                onClick={() => navigate(-1)}
                icon={<ArrowLeftOutlined />}
              >
                Back
              </Button>
            </Col>
          </Row>

          <Table
            columns={columns}
            dataSource={filteredInteractions}
            rowKey="id"
            loading={isLoading}
            expandable={{
              expandedRowRender: (record) => (
                <Card size="small" title="Interaction Details">
                  <Descriptions
                    bordered
                    column={1}
                    size="small"
                  >
                    <Descriptions.Item label="Prompt Template">
                      {record.prompt_template_name || "N/A"}
                    </Descriptions.Item>
                    <Descriptions.Item label="Prompt Context">
                      <pre
                        style={{
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                          background: "#f5f5f5",
                          color: "#333",
                          padding: "10px",
                          borderRadius: "4px",
                          maxHeight: "400px",
                          overflowY: "auto",
                        }}
                      >
                        {JSON.stringify(record.prompt_context, null, 2)}
                      </pre>
                    </Descriptions.Item>
                    <Descriptions.Item label="Parsed Output">
                      <pre
                        style={{
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                          background: "#f5f5f5",
                          color: "#333",
                          padding: "10px",
                          borderRadius: "4px",
                          maxHeight: "400px",
                          overflowY: "auto",
                        }}
                      >
                        {JSON.stringify(record.parsed_output, null, 2)}
                      </pre>
                    </Descriptions.Item>
                    {record.error && (
                       <Descriptions.Item label="Error">
                        <Alert message={record.error} type="error" showIcon/>
                       </Descriptions.Item>
                    )}
                  </Descriptions>
                </Card>
              ),
            }}
            locale={{
              emptyText: (
                <Empty
                  description={
                    <>
                      <Title level={5}>No LLM Interactions Logged</Title>
                      <Paragraph>
                        {selectedFilePath === 'All Files' 
                            ? "This scan may not have reached the analysis stage, or no AI interactions were required."
                            : `No interactions found for file: ${selectedFilePath}`
                        }
                      </Paragraph>
                    </>
                  }
                />
              ),
            }}
            scroll={{ y: 'calc(100vh - 400px)' }}
          />
      </Content>
    </Layout>
  );
};

export default LlmLogViewerPage;