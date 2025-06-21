// src/pages/dashboard/SubmissionHistoryPage.tsx

import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined, StopOutlined, SyncOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import { Alert, Button, Space, Spin, Table, Tag, Typography } from "antd";
import React, { useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { submissionService } from "../../services/submissionService";
import type { SubmissionHistoryItem } from "../../types/api";

// Import the new component we created
import CostApproval from '../../components/CostApproval';

const { Title, Text } = Typography;

// Expanded status map to include our new workflow statuses
const statusMap: { [key: string]: { color: string; icon: React.ReactNode; text: string } } = {
    'Pending': { color: 'default', icon: <ClockCircleOutlined />, text: 'Queued' },
    'Processing': { color: 'processing', icon: <SyncOutlined spin />, text: 'Processing' },
    'Pending Cost Approval': { color: 'warning', icon: <ExclamationCircleOutlined />, text: 'Pending Approval' },
    'Approved - Queued': { color: 'processing', icon: <SyncOutlined spin />, text: 'Queued for Analysis' },
    'Completed': { color: 'success', icon: <CheckCircleOutlined />, text: 'Completed' },
    'Failed': { color: 'error', icon: <StopOutlined />, text: 'Failed' },
};

const SubmissionHistoryPage: React.FC = () => {
    // Preserved your self-contained date formatting function
    const formatDisplayDate = useCallback((dateString: string | null): string => {
        if (!dateString) return "N/A";
        let utcDateString = dateString;
        if (!/Z|[+-]\d{2}:\d{2}$/.test(dateString)) {
            utcDateString += "Z";
        }
        const date = new Date(utcDateString);
        return date.toLocaleString(); // Use system's local time formatting
    }, []);

    // Updated to destructure `refetch` for the approval callback
    const { data, isLoading, isError, error, refetch } = useQuery<
        SubmissionHistoryItem[],
        Error
    >({
        queryKey: ["submissionHistory"],
        queryFn: submissionService.getSubmissionHistory,
        // Preserved and updated your smart polling logic
        refetchInterval: (query) => {
            const shouldPoll = query.state.data?.some(
                (item) => ["Pending", "Processing", "Approved - Queued"].includes(item.status)
            );
            return shouldPoll ? 5000 : false;
        },
        refetchIntervalInBackground: true,
    });

    const columns = useMemo(() => [
        {
            title: "Submission ID",
            dataIndex: "id",
            key: "id",
            render: (id: string) => <Text copyable={{ tooltips: ['Copy', 'Copied'] }} style={{ fontFamily: 'monospace' }}>{id.substring(0, 8)}...</Text>,
        },
        {
            title: "Status",
            dataIndex: "status",
            key: "status",
            render: (status: string) => {
                const statusInfo = statusMap[status] || { color: "default", icon: <ClockCircleOutlined />, text: status };
                return (
                    <Tag color={statusInfo.color} icon={statusInfo.icon}>
                        {statusInfo.text}
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
            title: "Action",
            key: "action",
            render: (_: unknown, record: SubmissionHistoryItem) => {
                const isCompleted = record.status === "Completed";
                return (
                    <Link to={`/results/${record.id}`} onClick={(e) => !isCompleted && e.preventDefault()}>
                        <Button type="primary" disabled={!isCompleted}>
                            View Report
                        </Button>
                    </Link>
                );
            },
        },
    ], [formatDisplayDate]);

    // This function determines what to render when a row is expanded.
    const expandedRowRender = (record: SubmissionHistoryItem) => {
        if (record.status === 'Pending Cost Approval' && record.estimated_cost) {
            // We pass the `refetch` function so the child component can trigger a data refresh
            return <CostApproval submission={record} onApprovalSuccess={() => refetch()} />;
        }
        return <Text type="secondary">No further actions available for this submission.</Text>;
    };

    // This function determines if a row should have an expand icon.
    const rowExpandable = (record: SubmissionHistoryItem) => {
        return record.status === 'Pending Cost Approval';
    };

    if (isLoading && !data) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 'calc(100vh - 200px)' }}>
                <Spin size="large" />
            </div>
        );
    }

    if (isError) {
        return <Alert message="Error" description={`Could not fetch submission history: ${error.message}`} type="error" showIcon />;
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
                // ADDED: The expandable prop to integrate the CostApproval component
                expandable={{
                    expandedRowRender,
                    rowExpandable,
                }}
            />
        </Space>
    );
};

export default SubmissionHistoryPage;