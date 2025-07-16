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

    const { totalScanCost, totalInputTokens, totalOutputTokens, totalOverallTokens } = useMemo(() => {
        if (!interactions) return { totalScanCost: 0, totalInputTokens: 0, totalOutputTokens: 0, totalOverallTokens: 0 };
        return interactions.reduce((acc, item) => {
            acc.totalScanCost += item.cost || 0;
            acc.totalInputTokens += item.input_tokens || 0;
            acc.totalOutputTokens += item.output_tokens || 0;
            acc.totalOverallTokens += item.total_tokens || 0;
            return acc;
        }, { totalScanCost: 0, totalInputTokens: 0, totalOutputTokens: 0, totalOverallTokens: 0 });
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
        <Space direction="vertical" style={{ width: '100%' }} size="middle">
            <Card size="small" bordered={false} style={{background: '#fafafa'}}>
                <Row gutter={16}>
                    <Col span={6}><Statistic title="Total Scan Cost (Actual)" value={totalScanCost} precision={6} prefix="$" /></Col>
                    <Col span={6}><Statistic title="Total Input Tokens" value={totalInputTokens} /></Col>
                    <Col span={6}><Statistic title="Total Output Tokens" value={totalOutputTokens} /></Col>
                    <Col span={6}><Statistic title="Total Overall Tokens" value={totalOverallTokens} /></Col>
                </Row>
            </Card>
            <Table
                columns={columns}
                dataSource={interactions}
                rowKey="id"
                pagination={false}
                size="small"
                summary={() => (
                    <Table.Summary.Row>
                        <Table.Summary.Cell index={0} colSpan={1}><strong>Totals</strong></Table.Summary.Cell>
                        <Table.Summary.Cell index={1} />
                        <Table.Summary.Cell index={2} align="right"><strong>${totalScanCost.toFixed(6)}</strong></Table.Summary.Cell>
                        <Table.Summary.Cell index={3} align="right"><strong>{totalOverallTokens.toLocaleString()}</strong></Table.Summary.Cell>
                    </Table.Summary.Row>
                )}
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
                        <Statistic title="Total Estimated Cost Across All Scans" value={totalOverallCost} precision={6} prefix="$" />
                    </Col>
                </Row>
            </Card>

            {projectsResponse && projectsResponse.length > 0 ? (
                <Collapse 
                    expandIcon={({ isActive }) => <DownOutlined rotate={isActive ? 180 : 0} />}
                    defaultActiveKey={projectsResponse.map(p => p.id)}
                >
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
                                <Collapse bordered={false} ghost accordion>
                                    {project.scans.map(scan => (
                                        <Panel
                                            header={
                                                <Row justify="space-between" align="middle" style={{ width: '100%' }}>
                                                    <Col>
                                                        <Space>
                                                            <Text strong>{scan.scan_type}</Text>
                                                            <Text type="secondary"> - Scanned on {new Date(scan.created_at).toLocaleString()}</Text>
                                                        </Space>
                                                    </Col>
                                                    <Col>
                                                        <Space>
                                                            {scan.cost_details && <Statistic title="Est. Cost" value={scan.cost_details.total_estimated_cost} precision={6} prefix="$" valueStyle={{fontSize: 14}}/>}
                                                            <Tag color={scan.status.includes('Completed') ? 'green' : 'blue'}>{scan.status}</Tag>
                                                        </Space>
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