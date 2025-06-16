import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import { Alert, Button, Space, Table, Tag, Typography } from "antd";
import React from "react";
import { Link } from "react-router-dom";
import { submissionService } from "../../services/submissionService";
import type { SubmissionHistoryItem } from "../../types/api";

const { Title } = Typography;

const statusMap: { [key: string]: { color: string; icon: React.ReactNode } } = {
    Pending: { color: "gold", icon: <ClockCircleOutlined /> },
    Processing: { color: "blue", icon: <ClockCircleOutlined /> },
    Completed: { color: "green", icon: <CheckCircleOutlined /> },
    Failed: { color: "red", icon: <ExclamationCircleOutlined /> },
};

const SubmissionHistoryPage: React.FC = () => {
  const { data, isLoading, isError, error } = useQuery<
    SubmissionHistoryItem[],
    Error
  >({
    queryKey: ["submissionHistory"],
    queryFn: submissionService.getSubmissionHistory,
  });

  const columns = [
    {
      title: "Submission ID",
      dataIndex: "id",
      key: "id",
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: "Status",
      dataIndex: "status",
      key: "status",
      render: (status: string) => {
        const statusInfo = statusMap[status] || { color: "default", icon: null };
        return (
          <Tag color={statusInfo.color} icon={statusInfo.icon}>
            {status}
          </Tag>
        );
      },
    },
    {
      title: "Submitted At",
      dataIndex: "submitted_at",
      key: "submitted_at",
      render: (text: string) => new Date(text).toLocaleString(),
    },
    {
      title: "Completed At",
      dataIndex: "completed_at",
      key: "completed_at",
      render: (text: string | null) => text ? new Date(text).toLocaleString() : "N/A",
    },
    {
      title: "Action",
      key: "action",
      render: (_: unknown, record: SubmissionHistoryItem) => (
        <Link to={`/results/${record.id}`}>
          <Button type="primary">View Results</Button>
        </Link>
      ),
    },
  ];

  if (isError) {
    return (
      <Alert
        message="Error"
        description={`Could not fetch submission history: ${error.message}`}
        type="error"
        showIcon
      />
    );
  }

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <Title level={2}>Submission History</Title>
      <Table
        columns={columns}
        dataSource={data}
        loading={isLoading}
        rowKey="id"
        pagination={{ pageSize: 10 }}
      />
    </Space>
  );
};

export default SubmissionHistoryPage;