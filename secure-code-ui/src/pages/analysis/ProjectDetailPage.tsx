// src/pages/analysis/ProjectDetailPage.tsx
import { ArrowLeftOutlined, ProjectOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import type { TableProps } from "antd";
import { Alert, Button, Card, Empty, Space, Spin, Table, Typography } from "antd";
import React from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { scanService } from "../../shared/api/scanService";
import type { PaginatedScanHistoryResponse, ScanHistoryItem } from "../../shared/types/api";

const { Title, Paragraph } = Typography;

const ProjectDetailPage: React.FC = () => {
    const { projectId } = useParams<{ projectId: string }>();
    const navigate = useNavigate();

    const { data, isLoading, isError, error } = useQuery<PaginatedScanHistoryResponse, Error>({
        queryKey: ["scansForProject", projectId],
        queryFn: () => {
            if (!projectId) throw new Error("Project ID is missing");
            return scanService.getScansForProject(projectId, 1, 100); // Fetch up to 100 scans
        },
        enabled: !!projectId,
    });
    
    // This is a placeholder for fetching project-specific details if an endpoint exists
    // For now, we'll just display the scans.

    const columns: TableProps<ScanHistoryItem>['columns'] = [
        { title: 'Scan ID', dataIndex: 'id', key: 'id', render: (id) => <Link to={`/analysis/results/${id}`}>{id.substring(0,8)}...</Link> },
        { title: 'Scan Type', dataIndex: 'scan_type', key: 'scan_type' },
        { title: 'Status', dataIndex: 'status', key: 'status' },
        { title: 'Submitted At', dataIndex: 'created_at', key: 'created_at', render: (date) => new Date(date).toLocaleString() },
        { title: 'Cost (Est.)', dataIndex: 'cost_details', key: 'cost', render: (cost) => cost ? `$${cost.total_estimated_cost.toFixed(6)}` : 'N/A' },
        { 
            title: 'Actions', 
            key: 'actions',
            render: (_, record) => (
                <Space>
                    <Link to={`/analysis/results/${record.id}`}><Button type="primary" size="small">View Report</Button></Link>
                    <Link to={`/scans/${record.id}/llm-logs`}><Button size="small">View Logs</Button></Link>
                </Space>
            )
        }
    ];

    if (isLoading) return <Spin tip="Loading project details..." />;
    if (isError) return <Alert message="Error" description={error.message} type="error" showIcon />;

    return (
        <Card>
            <Space direction="vertical" style={{width: '100%'}}>
                 <Button onClick={() => navigate('/analysis/results')} icon={<ArrowLeftOutlined />}>Back to Projects</Button>
                <Title level={2}><ProjectOutlined /> Project Details</Title>
                <Paragraph>Project ID: {projectId}</Paragraph>
                <Table 
                    columns={columns}
                    dataSource={data?.items || []}
                    rowKey="id"
                    locale={{ emptyText: <Empty description="No scans found for this project." /> }}
                />
            </Space>
        </Card>
    );
};

export default ProjectDetailPage;