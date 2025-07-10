// secure-code-ui/src/pages/account/CostUsagePage.tsx
import { DollarCircleOutlined, DownOutlined, ProjectOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import type { TableProps } from 'antd';
import { Alert, Card, Col, Collapse, Empty, Row, Space, Spin, Statistic, Table, Tag, Typography } from "antd";
import React, { useMemo } from "react";
import { scanService } from "../../shared/api/scanService";
import type { LLMInteractionResponse, ProjectHistoryItem, ScanHistoryItem } from "../../shared/types/api";

const { Title, Text, Paragraph } = Typography;
const { Panel } = Collapse;

// Reusable component to display details for a single scan
const ScanCostDetails: React.FC<{ scan: ScanHistoryItem }> = ({ scan }) => {
    const {
        data: interactions,
        isLoading,
        isError,
        error,
    } = useQuery<LLMInteractionResponse[], Error>({
        queryKey: ["llmInteractionsForScan", scan.id],
        queryFn: () => scanService.getLlmInteractionsForScan(scan.id),
        // This query will only run when the panel is expanded and this component is rendered.
    });

    const totalScanCost = useMemo(() => {
        return interactions?.reduce((acc, item) => acc + (item.cost || 0), 0) ?? 0;
    }, [interactions]);

    const columns: TableProps<LLMInteractionResponse>['columns'] = [
        { title: 'Timestamp', dataIndex: 'timestamp', key: 'timestamp', render: (text) => new Date(text).toLocaleString(), sorter: (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(), defaultSortOrder: 'descend' },
        { title: 'Agent', dataIndex: 'agent_name', key: 'agent_name', render: (agent) => <Tag color="blue">{agent}</Tag> },
        { title: 'Cost (USD)', dataIndex: 'cost', key: 'cost', render: (cost) => cost ? `$${cost.toFixed(6)}` : '$0.00', sorter: (a, b) => (a.cost || 0) - (b.cost || 0), align: 'right' },
        { title: 'Total Tokens', dataIndex: 'total_tokens', key: 'total_tokens', render: (tokens) => (tokens || 0).toLocaleString(), sorter: (a, b) => (a.total_tokens || 0) - (b.total_tokens || 0), align: 'right' },
    ];

    if (isLoading) {
        return <Spin tip="Loading interactions..." />;
    }

    if (isError) {
        return <Alert message="Error loading interactions" description={error.message} type="error" showIcon />;
    }

    return (
        <Space direction="vertical" style={{ width: '100%' }}>
            <Statistic title="Total Scan Cost" value={totalScanCost} precision={6} prefix="$" />
            <Table
                columns={columns}
                dataSource={interactions}
                rowKey="id"
                pagination={{ pageSize: 5, showSizeChanger: false }}
                size="small"
            />
        </Space>
    );
};

const CostUsagePage: React.FC = () => {
    const {
        data: projectsResponse,
        isLoading,
        isError,
        error,
    } = useQuery<ProjectHistoryItem[], Error>({
        queryKey: ["allProjectsForCost"],
        queryFn: async () => {
            const response = await scanService.getProjectHistory(1, 1000); // Fetch all projects
            return response.items;
        },
    });

    const { totalOverallCost, totalProjects } = useMemo(() => {
        let totalCost = 0;
        projectsResponse?.forEach(proj => {
            proj.scans.forEach(scan => {
                totalCost += scan.cost_details?.total_estimated_cost ?? 0;
            });
        });
        return {
            totalOverallCost: totalCost,
            totalProjects: projectsResponse?.length ?? 0
        };
    }, [projectsResponse]);


    if (isLoading) {
        return <Spin tip="Loading projects..." size="large" style={{ display: 'block', marginTop: '50px' }} />;
    }

    if (isError) {
        return <Alert message="Error" description={`Could not fetch project data: ${error.message}`} type="error" showIcon />;
    }

    return (
        <Space direction="vertical" style={{ width: "100%" }} size="large">
            <Title level={2}><DollarCircleOutlined /> Cost & Usage</Title>
            <Paragraph type="secondary">
                Review the estimated costs associated with your projects. Costs are grouped by project and broken down by individual scan runs.
            </Paragraph>
            <Card>
                <Row gutter={16}>
                    <Col span={12}>
                        <Statistic title="Total Projects" value={totalProjects} />
                    </Col>
                    <Col span={12}>
                        <Statistic title="Total Estimated Cost Across All Projects" value={totalOverallCost} precision={6} prefix="$" />
                    </Col>
                </Row>
            </Card>

            {projectsResponse && projectsResponse.length > 0 ? (
                <Collapse expandIcon={({ isActive }) => <DownOutlined rotate={isActive ? 180 : 0} />}>
                    {projectsResponse.map(project => (
                        <Panel
                            header={
                                <Space>
                                    <ProjectOutlined />
                                    <Text strong>{project.name}</Text>
                                    <Text copyable type="secondary" code>{project.id}</Text>
                                </Space>
                            }
                            key={project.id}
                        >
                            {project.scans && project.scans.length > 0 ? (
                                <Collapse bordered={false} ghost>
                                    {project.scans.map(scan => (
                                        <Panel
                                            header={
                                                <Row justify="space-between" style={{ width: '100%' }}>
                                                    <Col>
                                                        <Text>Scan ({scan.scan_type}) - {new Date(scan.created_at).toLocaleString()}</Text>
                                                        <Text copyable type="secondary" style={{ marginLeft: 16 }}>ID: {scan.id}</Text>
                                                    </Col>
                                                    <Col>
                                                        <Tag color={scan.status.includes('Completed') ? 'green' : 'blue'}>{scan.status}</Tag>
                                                    </Col>
                                                </Row>
                                            }
                                            key={scan.id}
                                        >
                                            <ScanCostDetails scan={scan} />
                                        </Panel>
                                    ))}
                                </Collapse>
                            ) : (
                                <Text type="secondary">No scans found for this project.</Text>
                            )}
                        </Panel>
                    ))}
                </Collapse>
            ) : (
                <Empty description="No projects found. Submit your first scan to see usage data." />
            )}
        </Space>
    );
};

export default CostUsagePage;