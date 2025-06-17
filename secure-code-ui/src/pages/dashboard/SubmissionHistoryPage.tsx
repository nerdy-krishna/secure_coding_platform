import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import { Alert, Button, Space, Spin, Table, Tag, Typography } from "antd";
import React, { useMemo, useCallback } from "react"; // Added useCallback
import { Link } from "react-router-dom";
import { submissionService } from "../../services/submissionService";
import type { SubmissionHistoryItem } from "../../types/api";
// Removed import of TimeDisplayPreference and TIME_DISPLAY_PREFERENCE_KEY

const { Title } = Typography;

const statusMap: { [key: string]: { color: string; icon: React.ReactNode } } = {
    Pending: { color: "gold", icon: <ClockCircleOutlined /> },
    Processing: { color: "blue", icon: <ClockCircleOutlined /> },
    Completed: { color: "green", icon: <CheckCircleOutlined /> },
    Failed: { color: "red", icon: <ExclamationCircleOutlined /> },
    // Add other statuses if necessary
};

const SubmissionHistoryPage: React.FC = () => {
  const formatDisplayDate = useCallback((dateString: string | null): string => {
    if (!dateString) return "N/A";
    const date = new Date(dateString);
    // For debugging:
    console.log(`Original dateString: ${dateString}, Parsed Date object: ${date.toString()}, LocaleString: ${date.toLocaleString()}`);
    return date.toLocaleString(); // Always use system's local time formatting
  }, []); // No dependencies needed as it's self-contained now

  const { data, isLoading, isError, error } = useQuery<
    SubmissionHistoryItem[],
    Error
  >({
    queryKey: ["submissionHistory"],
    queryFn: submissionService.getSubmissionHistory,
    refetchInterval: (query) => {
      // Check if any item is still pending or processing
      const shouldPoll = query.state.data?.some(
        (item) => item.status === "Pending" || item.status === "Processing"
      );
      return shouldPoll ? 5000 : false; // Poll every 5 seconds if needed
    },
    refetchIntervalInBackground: true,
  });

  const columns = useMemo(() => [
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
      render: (text: string) => formatDisplayDate(text),
    },
    {
      title: "Completed At",
      dataIndex: "completed_at",
      key: "completed_at",
      render: (text: string | null) => formatDisplayDate(text),
    },
    {
      title: "Action",
      key: "action",
      render: (_: unknown, record: SubmissionHistoryItem) => {
        const isCompleted = record.status === "Completed";
        return (
          <Link to={`/results/${record.id}`} onClick={(e) => !isCompleted && e.preventDefault()}>
            <Button type="primary" disabled={!isCompleted}>
              View Results
            </Button>
          </Link>
        );
      },
    },
  ], [formatDisplayDate]); // Now depends on the memoized formatDisplayDate
                                 // For a more reactive approach, preference could be in context or Zustand/Redux.

  if (isLoading && !data) { // Show main spinner only on initial load without data
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 'calc(100vh - 200px)' /* Adjust height as needed */ }}>
        <Spin tip="Loading submission history..." size="large" />
      </div>
    );
  }

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
