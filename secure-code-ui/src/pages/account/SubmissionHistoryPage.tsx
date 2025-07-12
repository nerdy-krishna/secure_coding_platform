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
import { keepPreviousData, useMutation, useQuery, useQueryClient, type Query } from "@tanstack/react-query";
import {
    Alert,
    Button,
    Card,
    Col,
    Collapse,
    Empty,
    Input,
    List,
    Popconfirm,
    Row,
    Space,
    Spin,
    Tag,
    Typography,
    message,
} from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import CostApproval from "../../features/submission-history/components/CostApproval";
import ScanTimeline from "../../features/submission-history/components/ScanTimeline";
import { scanService } from "../../shared/api/scanService";
import { useAuth } from "../../shared/hooks/useAuth";
import { useDebounce } from "../../shared/hooks/useDebounce";
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

const ScanListItem: React.FC<{ scan: ScanHistoryItem; onApprovalSuccess: () => void; }> = ({ scan, onApprovalSuccess }) => {
    const { user } = useAuth();
    const queryClient = useQueryClient();

    const deleteScanMutation = useMutation({
        mutationFn: () => scanService.deleteScan(scan.id),
        onSuccess: () => {
            message.success(`Scan ${scan.id} deleted.`);
            queryClient.invalidateQueries({ queryKey: ["projectHistory"] });
        },
        onError: (error: Error) => message.error(`Failed to delete scan: ${error.message}`),
    });

    const statusInfo = getStatusInfo(scan.status);
    const isCompleted = scan.status.trim().toLowerCase().includes('completed');
    const isPendingApproval = scan.status === 'PENDING_COST_APPROVAL';
    
    const resultPath = `/analysis/results/${scan.id}`;
    const logsPath = `/scans/${scan.id}/llm-logs`;

    return (
      <List.Item style={{ padding: '16px 8px', borderBottom: '1px solid #f0f0f0', display: 'block' }}>
        <Row align="middle" justify="space-between" style={{ width: '100%' }}>
            <Col xs={24} sm={12} md={10}>
                <Space direction="vertical" size={0}>
                    <Text strong>{scan.scan_type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</Text>
                    <Text copyable={{ text: scan.id, onCopy: () => message.success("Scan ID Copied!") }} style={{ fontSize: '12px' }}>ID: {scan.id}</Text>
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
                <Space>
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
                    <Link to={logsPath}>
                        <Button size="small" icon={<FileSearchOutlined />}>View Logs</Button>
                    </Link>
                    {isCompleted ? (
                        <Link to={resultPath}>
                            <Button type="primary" size="small" icon={<RightOutlined />}>View Report</Button>
                        </Link>
                    ) : (
                        <Button size="small" disabled icon={<RightOutlined />}>
                            {isPendingApproval ? "Approve Below" : "View Report"}
                        </Button>
                    )}
                </Space>
            </Col>
        </Row>
  
        {isPendingApproval && (
            <CostApproval scan={scan} onApprovalSuccess={onApprovalSuccess} />
        )}
        <ScanTimeline events={scan.events} currentStatus={scan.status} />
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
    const { user } = useAuth();
    const location = useLocation();
    const queryClient = useQueryClient();
    const [searchTerm, setSearchTerm] = useState("");
    const debouncedSearchTerm = useDebounce(searchTerm, 500);
    const { permission, requestPermission, showNotification } = useNotifications();
    const [activeProjectKey, setActiveProjectKey] = useState<string | string[] | undefined>();

    const deleteProjectMutation = useMutation({
        mutationFn: (projectId: string) => scanService.deleteProject(projectId),
        onSuccess: () => {
            message.success("Project deleted successfully.");
            queryClient.invalidateQueries({ queryKey: ["projectHistory"] });
        },
        onError: (error: Error) => message.error(`Failed to delete project: ${error.message}`),
    });

    useEffect(() => {
        const hash = location.hash.replace('#', '');
        const state = location.state as { newProjectId?: string };
        const keyToExpand = state?.newProjectId || hash;

        if (keyToExpand) {
            setActiveProjectKey(keyToExpand);
            window.history.replaceState({}, document.title)
        }
    }, [location]);

    const { data, isLoading, isError, error, isFetching } = useQuery<PaginatedProjectHistoryResponse, Error>({
        queryKey: ["projectHistory", debouncedSearchTerm],
        queryFn: () => scanService.getProjectHistory(1, 100, debouncedSearchTerm),
        placeholderData: keepPreviousData,
        refetchInterval: (query: Query<PaginatedProjectHistoryResponse, Error>) => {
             const hasActiveScans = query.state.data?.items.some((proj: ProjectHistoryItem) => 
                proj.scans.some((scan: ScanHistoryItem) => !['COMPLETED', 'FAILED', 'REMEDIATION_COMPLETED', 'PENDING_COST_APPROVAL', 'CANCELLED'].includes(scan.status))
            );
            return hasActiveScans ? 5000 : false;
        },
    });
    
    const previousData = usePrevious(data);
    useEffect(() => {
        if (!previousData || !data) return;

        data.items.forEach((currentProject: ProjectHistoryItem) => {
            const prevProject = previousData.items.find((p: ProjectHistoryItem) => p.id === currentProject.id);
            if (!prevProject) return;

            currentProject.scans.forEach((currentScan: ScanHistoryItem) => {
                const prevScan = prevProject.scans.find((s: ScanHistoryItem) => s.id === currentScan.id);
                if (prevScan && prevScan.status !== currentScan.status) {
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
                                <Row justify="space-between" align="middle" style={{width: '100%'}}>
                                    <Col>
                                        <Space>
                                            <ProjectOutlined />
                                            <Text strong>{project.name}</Text>
                                            <Text copyable={{ text: project.id, onCopy: () => message.success("Project ID Copied!") }}>{project.id}</Text>
                                        </Space>
                                    </Col>
                                    {user?.is_superuser && (
                                        <Col>
                                            <Popconfirm
                                                title={`Delete project "${project.name}"?`}
                                                description="This will delete the project and ALL its scans. This action cannot be undone."
                                                onConfirm={(e) => {
                                                    e?.stopPropagation();
                                                    deleteProjectMutation.mutate(project.id);
                                                }}
                                                onCancel={(e) => e?.stopPropagation()}
                                                okText="Yes"
                                                cancelText="No"
                                            >
                                                <Button danger size="small" icon={<DeleteOutlined />} onClick={(e) => e.stopPropagation()} loading={deleteProjectMutation.isPending && deleteProjectMutation.variables === project.id}>
                                                    Delete Project
                                                </Button>
                                            </Popconfirm>
                                        </Col>
                                    )}
                                </Row>
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