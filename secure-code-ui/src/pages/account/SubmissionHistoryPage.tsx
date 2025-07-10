// secure-code-ui/src/pages/account/SubmissionHistoryPage.tsx
import {
    CheckCircleFilled,
    CloseCircleOutlined,
    ExclamationCircleOutlined,
    HistoryOutlined,
    ProjectOutlined,
    RightOutlined,
    SyncOutlined,
} from "@ant-design/icons";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Alert,
    Button,
    Card,
    Col,
    Collapse,
    Empty,
    Input,
    List,
    Row,
    Space,
    Spin,
    Tag,
    Typography,
} from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import CostApproval from "../../features/submission-history/components/CostApproval";
import { scanService } from "../../shared/api/scanService";
import { useNotifications } from "../../shared/hooks/useNotifications";
import type {
    PaginatedProjectHistoryResponse,
    ProjectHistoryItem,
    ScanHistoryItem,
} from "../../shared/types/api";

const { Title, Paragraph, Text } = Typography;
const { Panel } = Collapse;

const getStatusInfo = (status: string): { color: string; icon: React.ReactNode; text: string } => {
    const upperStatus = status.toUpperCase().replace(/[\s-]/g, "_");
    switch (upperStatus) {
        case "COMPLETED":
        case "REMEDIATION_COMPLETED":
            return { color: "green", icon: <CheckCircleFilled />, text: "Completed" };
        case "ANALYZING_CONTEXT":
        case "RUNNING_AGENTS":
        case "REMEDIATING":
        case "ANALYZING":
            return { color: "blue", icon: <SyncOutlined spin />, text: "In Progress" };
        case "PENDING_COST_APPROVAL":
            return { color: "gold", icon: <ExclamationCircleOutlined />, text: "Pending Approval" };
        case "QUEUED_FOR_SCAN":
        case "QUEUED":
            return { color: "default", icon: <HistoryOutlined />, text: "Queued" };
        case "FAILED":
        case "REMEDIATION_FAILED":
            return { color: "red", icon: <CloseCircleOutlined />, text: "Failed" };
        default:
            return { color: "default", icon: <HistoryOutlined />, text: status };
    }
};

const ScanListItem: React.FC<{ scan: ScanHistoryItem; onApprovalSuccess: () => void; }> = ({ scan, onApprovalSuccess }) => {
    const statusInfo = getStatusInfo(scan.status);
    const isCompleted = scan.status.trim().toLowerCase().includes('completed');
    const isPendingApproval = scan.status === 'PENDING_COST_APPROVAL';
    
    // Always point to the generic results page router
    const resultPath = `/analysis/results/${scan.id}`;

    return (
      <List.Item style={{ padding: '16px 8px', borderBottom: '1px solid #f0f0f0', display: 'block' }}>
        <Row align="middle" justify="space-between" style={{ width: '100%' }}>
                <Col xs={24} sm={12} md={10}>
                    <Space direction="vertical" size={0}>
                        <Text strong>{scan.scan_type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</Text>
                        <Text copyable type="secondary" style={{ fontSize: '12px' }}>ID: {scan.id}</Text>
                        <Text type="secondary" style={{ fontSize: '12px' }}>
                            Scanned: {new Date(scan.created_at).toLocaleString()}
                        </Text>
                </Space>
            </Col>
            <Col xs={12} sm={6} md={6} style={{ textAlign: 'center' }}>
                <Tag icon={statusInfo.icon} color={statusInfo.color}>
                    {statusInfo.text}
                </Tag>
            </Col>
            <Col xs={12} sm={6} md={8} style={{ textAlign: 'right' }}>
                {isCompleted ? (
                    <Link to={resultPath}>
                        <Button type="primary" size="small" icon={<RightOutlined />}>View Report</Button>
                    </Link>
                ) : (
                    <Button size="small" disabled icon={<RightOutlined />}>
                        {isPendingApproval ? "Approve Below" : "View Report"}
                    </Button>
                )}
            </Col>
        </Row>
        {isPendingApproval && (
            <CostApproval scan={scan} onApprovalSuccess={onApprovalSuccess} />
        )}
      </List.Item>
    );
};

function usePrevious<T>(value: T): T | undefined {
  const ref = useRef<T | undefined>(undefined);
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

const SubmissionHistoryPage: React.FC = () => {
    const location = useLocation();
    const queryClient = useQueryClient();
    const [searchTerm, setSearchTerm] = useState("");
    const [debouncedSearchTerm, setDebouncedSearchTerm] = useState("");
    const { permission, requestPermission, showNotification } = useNotifications();
    const [activeProjectKey, setActiveProjectKey] = useState<string | string[] | undefined>();

    useEffect(() => {
        const hash = location.hash.replace('#', '');
        if (hash) {
            setActiveProjectKey(hash);
        }
    }, [location]);
    
    useEffect(() => {
        const timer = setTimeout(() => setDebouncedSearchTerm(searchTerm), 500);
        return () => clearTimeout(timer);
    }, [searchTerm]);

    const { data, isLoading, isError, error, isFetching } = useQuery<PaginatedProjectHistoryResponse, Error>({
        queryKey: ["projectHistory", debouncedSearchTerm],
        queryFn: () => scanService.getProjectHistory(1, 100, debouncedSearchTerm),
        placeholderData: keepPreviousData,
        refetchInterval: (query) => {
             const hasActiveScans = query.state.data?.items.some(proj => 
                proj.scans.some(scan => !['COMPLETED', 'FAILED', 'REMEDIATION_COMPLETED', 'PENDING_COST_APPROVAL'].includes(scan.status))
            );
            return hasActiveScans ? 5000 : false;
        },
    });

    const previousData = usePrevious(data);
    useEffect(() => {
        if (!previousData || !data) return;

        data.items.forEach(currentProject => {
            const previousProject = previousData.items.find(p => p.id === currentProject.id);
            if (!previousProject) return;

            currentProject.scans.forEach(currentScan => {
                const previousScan = previousProject.scans.find(s => s.id === currentScan.id);
                if (previousScan && previousScan.status !== currentScan.status) {
                    if (currentScan.status.includes('Completed')) {
                        showNotification(
                            `Scan Completed`,
                            `Analysis for project "${currentProject.name}" has finished.`
                        );
                    } else if (currentScan.status === 'PENDING_COST_APPROVAL') {
                        showNotification(
                            `Action Required`,
                            `Project "${currentProject.name}" requires cost approval.`
                        );
                    }
                }
            });
        });
    }, [data, previousData, showNotification]);
    
    if (isError) {
        return <Alert message="Error" description={`Could not fetch project history: ${error.message}`} type="error" showIcon />;
    }

    return (
        <Space direction="vertical" style={{ width: "100%" }} size="large">
            <Row justify="space-between" align="middle">
                <Col>
                    <Title level={2}><HistoryOutlined /> Submission History</Title>
                    <Paragraph type="secondary">View all your projects and their associated scan histories.</Paragraph>
                </Col>
                <Col>
                    {permission === 'default' && (
                        <Button onClick={requestPermission}>Enable Notifications</Button>
                    )}
                </Col>
            </Row>

            <Input.Search
                placeholder="Search Projects..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                loading={isFetching}
                enterButton
            />
            
            {isLoading && <Spin tip="Loading projects..." size="large" style={{ display: 'block', marginTop: '20px' }} />}

            {!isLoading && !isError && data?.items.length === 0 && (
                <Card>
                    <Empty description={
                        <>
                            <Title level={4}>No Projects Found</Title>
                            <Paragraph>Get started by submitting code for your first project.</Paragraph>
                            <Link to="/submission/submit">
                                <Button type="primary">Start Your First Scan</Button>
                            </Link>
                        </>
                    } />
                </Card>
            )}

            {!isLoading && data && data.items.length > 0 && (
                 <Collapse accordion activeKey={activeProjectKey} onChange={(key) => setActiveProjectKey(key as string | string[])}>
                    {data.items.map((project: ProjectHistoryItem) => (
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
                            <List
                                dataSource={project.scans || []}
                                renderItem={(scan) => <ScanListItem scan={scan} onApprovalSuccess={() => queryClient.invalidateQueries({queryKey: ['projectHistory']})} />}
                                locale={{ emptyText: 'No scans found for this project.' }}
                            />
                        </Panel>
                    ))}
                </Collapse>
            )}
        </Space>
    );
};

export default SubmissionHistoryPage;