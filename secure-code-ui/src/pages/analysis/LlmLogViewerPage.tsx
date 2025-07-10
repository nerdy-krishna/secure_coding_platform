// src/pages/analysis/LlmLogViewerPage.tsx
import {
    ArrowLeftOutlined,
    LoadingOutlined,
    RobotOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import type { TableProps } from "antd";
import {
    Alert,
    Button,
    Card,
    Col,
    Descriptions,
    Empty,
    Layout,
    Row,
    Space,
    Spin,
    Table,
    Tag,
    Typography,
} from "antd";
import React from "react";
import { useNavigate, useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import type { LLMInteractionResponse } from "../../shared/types/api";

const { Content } = Layout;
const { Title, Text, Paragraph } = Typography;

const LlmLogViewerPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

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

  const columns: TableProps<LLMInteractionResponse>["columns"] = [
    {
      title: "Timestamp",
      dataIndex: "timestamp",
      key: "timestamp",
      render: (text) => new Date(text).toLocaleString(),
      sorter: (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      defaultSortOrder: "ascend",
    },
    {
      title: "Agent",
      dataIndex: "agent_name",
      key: "agent_name",
      render: (agent) => <Tag color="cyan">{agent}</Tag>,
      filters: [
        ...new Set(interactions?.map((i) => i.agent_name) || []),
      ].map((agent) => ({ text: agent, value: agent })),
      onFilter: (value, record) => record.agent_name === value,
    },
    {
      title: "File Path",
      dataIndex: "file_path",
      key: "file_path",
      render: (path) => (path ? <Text code>{path}</Text> : "N/A"),
    },
    {
      title: "Cost (USD)",
      dataIndex: "cost",
      key: "cost",
      align: "right",
      render: (cost) =>
        cost ? `$${cost.toFixed(6)}` : <Text type="secondary">N/A</Text>,
      sorter: (a, b) => (a.cost || 0) - (b.cost || 0),
    },
    {
      title: "Tokens (I/O/T)",
      key: "tokens",
      align: "right",
      render: (_, record) => (
        <Space direction="vertical" size={0} style={{ textAlign: "right" }}>
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
    <Layout style={{ background: "#fff", padding: 24 }}>
      <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
        <Col>
          <Title level={3} style={{ margin: 0 }}>
            <RobotOutlined style={{ marginRight: 8 }} />
            LLM Interaction Logs
          </Title>
          <Text copyable type="secondary" code>
            Scan ID: {scanId}
          </Text>
        </Col>
        <Col>
          <Button
            onClick={() => navigate("/account/history")}
            icon={<ArrowLeftOutlined />}
          >
            Back to History
          </Button>
        </Col>
      </Row>
      <Paragraph type="secondary">
        This log provides a detailed, chronological record of every interaction
        with a Large Language Model (LLM) that occurred during this scan. Use
        it to debug agent behavior, analyze costs, and trace the analysis
        process.
      </Paragraph>

      <Table
        columns={columns}
        dataSource={interactions}
        rowKey="id"
        loading={isLoading}
        expandable={{
          expandedRowRender: (record) => (
            <Card size="small">
              <Descriptions
                bordered
                column={1}
                title="Interaction Details"
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
                      background: "#2b2b2b",
                      color: "#f8f8f2",
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
                      background: "#2b2b2b",
                      color: "#f8f8f2",
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
                    This scan may not have reached the analysis stage, or no AI
                    interactions were required.
                  </Paragraph>
                </>
              }
            />
          ),
        }}
        scroll={{ x: true }}
      />
    </Layout>
  );
};

export default LlmLogViewerPage;