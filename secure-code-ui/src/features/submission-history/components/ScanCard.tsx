import {
    CheckCircleFilled,
    CloseCircleOutlined,
    DeleteOutlined,
    ExclamationCircleOutlined,
    FileSearchOutlined,
    HistoryOutlined,
    ProjectOutlined,
    RightOutlined,
    SyncOutlined,
} from "@ant-design/icons";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Card, Col, Popconfirm, Row, Space, Tag, Typography, message } from "antd";
import React from "react";
import { Link } from "react-router-dom";
import { scanService } from "../../../shared/api/scanService";
import { useAuth } from "../../../shared/hooks/useAuth";
import type { ScanHistoryItem } from "../../../shared/types/api";
import CostApproval from "./CostApproval";
import ScanStatusTimeline from "./ScanStatusTimeline";

const { Text, Paragraph } = Typography;

const getStatusInfo = (status: string): { color: string; icon: React.ReactNode; text: string } => {
    const upperStatus = status.toUpperCase().replace(/[\s-]/g, "_");
    switch (upperStatus) {
        case "COMPLETED":
        case "REMEDIATION_COMPLETED":
            return { color: "green", icon: <CheckCircleFilled />, text: "Completed" };
        case "ANALYZING_CONTEXT":
        case "RUNNING_AGENTS":
        case "GENERATING_REPORTS":
        case "REMEDIATING":
        case "ANALYZING":
        case "QUEUED_FOR_SCAN":
            return { color: "blue", icon: <SyncOutlined spin />, text: "In Progress" };
        case "PENDING_COST_APPROVAL":
            return { color: "gold", icon: <ExclamationCircleOutlined />, text: "Pending Approval" };
        case "QUEUED":
            return { color: "default", icon: <HistoryOutlined />, text: "Queued" };
        case "FAILED":
        case "REMEDIATION_FAILED":
            return { color: "red", icon: <CloseCircleOutlined />, text: "Failed" };
        case "CANCELLED":
            return { color: "default", icon: <CloseCircleOutlined />, text: "Cancelled"};
        default:
            return { color: "default", icon: <HistoryOutlined />, text: status };
    }
};


interface ScanCardProps {
  scan: ScanHistoryItem;
}

const ScanCard: React.FC<ScanCardProps> = ({ scan }) => {
    const { user } = useAuth();
    const queryClient = useQueryClient();

    const deleteScanMutation = useMutation({
        mutationFn: () => scanService.deleteScan(scan.id),
        onSuccess: () => {
            message.success(`Scan ${scan.id} deleted.`);
            queryClient.invalidateQueries({ queryKey: ["scanHistory"] });
        },
        onError: (error: Error) => message.error(`Failed to delete scan: ${error.message}`),
    });

    const cancelMutation = useMutation({
        mutationFn: () => scanService.cancelScan(scan.id),
        onSuccess: (data) => {
            message.info(data.message || "Scan has been cancelled.");
            queryClient.invalidateQueries({ queryKey: ["scanHistory"] });
        },
        onError: (error: Error) => message.error(`Failed to cancel scan: ${error.message}`),
    });

    const statusInfo = getStatusInfo(scan.status);
    const isCompleted = scan.status.toLowerCase().includes('completed');
    const isPendingApproval = scan.status === 'PENDING_COST_APPROVAL';
    const isCancellable = !isCompleted && !isPendingApproval && scan.status !== 'FAILED' && scan.status !== 'CANCELLED';
    
    const resultPath = `/analysis/results/${scan.id}`;
    const logsPath = `/scans/${scan.id}/llm-logs`;

  return (
    <Card style={{ marginBottom: 16 }}>
      <Row align="top" justify="space-between">
        <Col xs={24} md={16}>
          <Space direction="vertical" size="small">
            <Space align="center" wrap>
                <ProjectOutlined />
                <Text strong>{scan.project_name}</Text>
                <Paragraph copyable={{ text: scan.project_id }} type="secondary" style={{ margin: 0 }}>
                    Project ID: {scan.project_id}
                </Paragraph>
            </Space>
            <Paragraph copyable={{ text: scan.id }} style={{ marginBottom: 0, color: '#888' }}>
                Scan ID: {scan.id}
            </Paragraph>
             <Text type="secondary">
                Submitted: {new Date(scan.created_at).toLocaleString()}
            </Text>
            {scan.completed_at && (
                <Text type="secondary">
                    Completed: {new Date(scan.completed_at).toLocaleString()}
                </Text>
            )}
          </Space>
        </Col>
        <Col xs={24} md={8} style={{ textAlign: 'right' }}>
            <Space>
                <Tag icon={statusInfo.icon} color={statusInfo.color} style={{fontSize: 14, padding: '4px 8px'}}>
                    {statusInfo.text}
                </Tag>
                {user?.is_superuser && (
                    <Popconfirm
                        title="Delete Scan?"
                        description="This action cannot be undone."
                        onConfirm={() => deleteScanMutation.mutate()}
                        okText="Yes"
                        cancelText="No"
                    >
                        <Button danger type="text" size="small" icon={<DeleteOutlined />} loading={deleteScanMutation.isPending} />
                    </Popconfirm>
                )}
                {isCancellable && (
                    <Popconfirm
                        title="Cancel this scan?"
                        description="The current process will be halted."
                        onConfirm={() => cancelMutation.mutate()}
                        okText="Yes, Cancel"
                        cancelText="No"
                    >
                        <Button danger size="small" loading={cancelMutation.isPending}>Cancel</Button>
                    </Popconfirm>
                )}
                 <Link to={logsPath}>
                    <Button size="small" icon={<FileSearchOutlined />}>View Logs</Button>
                </Link>
                {isCompleted ? (
                    <Link to={resultPath}>
                        <Button type="primary" size="small" icon={<RightOutlined />}>View Report</Button>
                    </Link>
                ) : (
                    <Button size="small" disabled icon={<RightOutlined />}>
                        {isPendingApproval ? "Awaiting Approval" : "View Report"}
                    </Button>
                )}
            </Space>
        </Col>
      </Row>

      <ScanStatusTimeline events={scan.events} currentStatus={scan.status} />

      {isPendingApproval && (
          <div style={{marginTop: 16, borderTop: '1px solid #f0f0f0', paddingTop: 16}}>
            <CostApproval scan={scan} onApprovalSuccess={() => queryClient.invalidateQueries({queryKey: ['scanHistory']})} />
          </div>
      )}
    </Card>
  );
};

export default ScanCard;