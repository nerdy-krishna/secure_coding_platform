// secure-code-ui/src/pages/account/CostUsagePage.tsx
import { useQuery } from "@tanstack/react-query";
import type { TablePaginationConfig, TableProps } from "antd";
import { Alert, Card, Col, Row, Space, Spin, Statistic, Table, Tag, Typography } from "antd";
import React, { useMemo, useState } from "react";
import { llmConfigService } from "../../shared/api/llmConfigService";
import type { LLMInteractionResponse } from "../../shared/types/api";

const { Title, Text } = Typography;

const CostUsagePage: React.FC = () => {
  
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 20,
  });

  const { data, isLoading, isError, error } = useQuery<LLMInteractionResponse[], Error>({
    queryKey: ["llmInteractions"],
    queryFn: llmConfigService.getLlmInteractions,
  });

  const { totalCost, totalInputTokens, totalOutputTokens, totalTokens } = useMemo(() => {
    let totalCost = 0;
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalTokens = 0;

    if (data) {
      for (const item of data) {
        totalCost += item.cost || 0;
        totalInputTokens += item.input_tokens || 0;
        totalOutputTokens += item.output_tokens || 0;
        totalTokens += item.total_tokens || 0;
      }
    }
    return { totalCost, totalInputTokens, totalOutputTokens, totalTokens };
  }, [data]);

  const columns: TableProps<LLMInteractionResponse>['columns'] = [
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (text: string) => new Date(text).toLocaleString(),
      sorter: (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      defaultSortOrder: 'descend',
    },
    {
      title: 'Agent',
      dataIndex: 'agent_name',
      key: 'agent_name',
      render: (agent) => <Tag color="blue">{agent}</Tag>,
    },
    {
      title: 'Submission ID',
      dataIndex: 'submission_id',
      key: 'submission_id',
      render: (id) => id ? <Text copyable style={{fontFamily: 'monospace'}}>{id.substring(0,8)}...</Text> : <Text type="secondary">N/A</Text>
    },
    {
      title: 'Cost (USD)',
      dataIndex: 'cost',
      key: 'cost',
      render: (cost) => cost ? `$${cost.toFixed(6)}` : '$0.00',
      sorter: (a, b) => (a.cost || 0) - (b.cost || 0),
      align: 'right',
    },
    {
      title: 'Input Tokens',
      dataIndex: 'input_tokens',
      key: 'input_tokens',
      render: (tokens) => (tokens || 0).toLocaleString(),
      sorter: (a, b) => (a.input_tokens || 0) - (b.input_tokens || 0),
      align: 'right',
    },
    {
      title: 'Output Tokens',
      dataIndex: 'output_tokens',
      key: 'output_tokens',
      render: (tokens) => (tokens || 0).toLocaleString(),
      sorter: (a, b) => (a.output_tokens || 0) - (b.output_tokens || 0),
      align: 'right',
    },
    {
      title: 'Total Tokens',
      dataIndex: 'total_tokens',
      key: 'total_tokens',
      render: (tokens) => (tokens || 0).toLocaleString(),
      sorter: (a, b) => (a.total_tokens || 0) - (b.total_tokens || 0),
      align: 'right',
    },
  ];
  
  if (isLoading) {
    return <Spin tip="Loading usage data..." size="large" />;
  }

  if (isError) {
    return <Alert message="Error" description={`Could not fetch usage data: ${error.message}`} type="error" showIcon />;
  }

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
        <Title level={2}>Cost & Usage Details</Title>
        <Card>
            <Row gutter={16}>
                <Col span={6}>
                    <Statistic title="Total Estimated Cost" value={totalCost} precision={4} prefix="$" />
                </Col>
                <Col span={6}>
                    <Statistic title="Total Input Tokens" value={totalInputTokens.toLocaleString()} />
                </Col>
                <Col span={6}>
                    <Statistic title="Total Output Tokens" value={totalOutputTokens.toLocaleString()} />
                </Col>
                 <Col span={6}>
                    <Statistic title="Total Tokens Processed" value={totalTokens.toLocaleString()} />
                </Col>
            </Row>
        </Card>
        <Card title="Detailed LLM Interaction Log">
            <Table
                columns={columns}
                dataSource={data}
                loading={isLoading}
                rowKey="id"
                pagination={{
                    ...pagination,
                    showSizeChanger: true,
                    pageSizeOptions: ['10', '20', '50', '100'],
                  }}
                onChange={(newPagination: TablePaginationConfig) => {
                    setPagination({
                      current: newPagination.current ?? 1,
                      pageSize: newPagination.pageSize ?? 20,
                    });
                }}
                scroll={{ x: true }}
            />
        </Card>
    </Space>
  );
};

export default CostUsagePage;