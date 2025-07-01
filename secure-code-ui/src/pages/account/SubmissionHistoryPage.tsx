// secure-code-ui/src/pages/account/SubmissionHistoryPage.tsx
import {
  CheckCircleFilled,
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  DeleteOutlined,
  ExclamationCircleOutlined,
  FileSyncOutlined,
  FileTextOutlined,
  SearchOutlined,
  StopOutlined,
  SyncOutlined
} from "@ant-design/icons";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Input,
  List,
  message,
  Popconfirm,
  Row,
  Space,
  Statistic,
  Steps,
  Typography
} from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  approveSubmission,
  cancelSubmission,
  deleteSubmission,
  submissionService,
} from "../../shared/api/submissionService";
import { useAuth } from "../../shared/hooks/useAuth";
import { useNotifications } from "../../shared/hooks/useNotifications";
import type { PaginatedSubmissionHistoryResponse, SubmissionHistoryItem } from "../../shared/types/api";

const { Title, Text } = Typography;

// --- START: REFINED 6-STEP TIMELINE AND STATUS MAPPING ---

// Type definition for the status object to ensure type safety
type StatusInfo = {
  step: number;
  status: "wait" | "process" | "finish" | "error";
  text: string;
  icon?: React.ReactNode;
};

const timelineSteps = [
  { title: "Submitted", icon: <FileTextOutlined /> },
  { title: "Context Analysis", icon: <SearchOutlined /> },
  { title: "Pending Approval", icon: <ExclamationCircleOutlined /> },
  { title: "Security Scan", icon: <FileSyncOutlined /> },
  { title: "Reporting", icon: <CheckCircleOutlined /> },
  { title: "Completed", icon: <CheckCircleOutlined /> },
];

const statusDetails: { [key: string]: StatusInfo } = {
  PENDING: { step: 0, status: "process", text: "Queued for Analysis", icon: <ClockCircleOutlined /> },
  SUBMITTED: { step: 0, status: "finish", text: "Submitted", icon: <FileTextOutlined /> },
  ANALYZING_CONTEXT: { step: 1, status: "process", text: "Analyzing Context", icon: <SyncOutlined spin /> },
  PENDING_COST_APPROVAL: { step: 2, status: "wait", text: "Pending Cost Approval", icon: <ClockCircleOutlined /> },
  APPROVED_QUEUED: { step: 3, status: "wait", text: "Queued for Scan", icon: <ClockCircleOutlined /> },
  ANALYZING: { step: 3, status: "process", text: "Security Scan in Progress", icon: <FileSyncOutlined spin /> },
  REMEDIATING: { step: 3, status: "process", text: "Remediation in Progress", icon: <FileSyncOutlined spin /> },
  COMPLETED: { step: 5, status: "finish", text: "Completed", icon: <CheckCircleFilled /> },
  FAILED: { step: 3, status: "error", text: "Failed", icon: <CloseCircleOutlined /> },
  CANCELLED: { step: 2, status: "error", text: "Cancelled", icon: <StopOutlined /> },
  DEFAULT: { step: 0, status: "process", text: "Processing", icon: <SyncOutlined spin /> },
};

// This function now accepts the full submission item to make contextual decisions
const getStatusInfo = (item: SubmissionHistoryItem): StatusInfo => {
  const upperStatus = item.status.toUpperCase().replace(/[\s-]/g, "_");

  // This console log will show you the exact status string being processed for each item
  // console.log(`Processing item ID: ${item.id}, Original Status: "${item.status}", Normalized Status: "${upperStatus}"`);

  // Handle the initial analysis phase before cost estimation is available
  if (upperStatus === "ANALYZING" && !item.estimated_cost) {
    return statusDetails.ANALYZING_CONTEXT;
  }
  
  const details = statusDetails[upperStatus];
  if (details) {
      return details;
  }

  // Fallback for any unknown statuses
  console.warn(`Unknown status encountered for item ${item.id}: "${item.status}". Using default.`);
  return { ...statusDetails.DEFAULT, text: item.status };
};
// --- END: REFINED 6-STEP TIMELINE AND STATUS MAPPING ---

const ActionButtons: React.FC<{ record: SubmissionHistoryItem }> = ({ record }) => {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const approveMutation = useMutation({
    mutationFn: () => approveSubmission(record.id),
    onSuccess: () => {
      message.success(`Submission approved and queued for analysis.`);
      queryClient.invalidateQueries({ queryKey: ["submissionHistory"] });
    },
    onError: (error) => message.error(`Approval failed: ${error.message}`),
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelSubmission(record.id),
    onSuccess: () => {
      message.success(`Submission has been cancelled.`);
      queryClient.invalidateQueries({ queryKey: ["submissionHistory"] });
    },
    onError: (error) => message.error(`Cancellation failed: ${error.message}`),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteSubmission(record.id),
    onSuccess: () => {
      message.success("Submission successfully deleted.");
      queryClient.invalidateQueries({ queryKey: ["submissionHistory"] });
    },
    onError: (error) => message.error(`Deletion failed: ${error.message}`),
  });

  const isCancellable = ["PENDING_COST_APPROVAL", "ANALYZING_CONTEXT", "Approved - Queued", "ANALYZING"].includes(record.status);

  return (
    <Space wrap align="center" style={{ justifyContent: 'flex-end', width: '100%' }}>
      {isCancellable && (
         <Button
            danger
            icon={<CloseCircleOutlined />}
            loading={cancelMutation.isPending}
            onClick={() => cancelMutation.mutate()}
          >
            Cancel
          </Button>
      )}

      {record.status === "PENDING_COST_APPROVAL" && (
        <Button
          type="primary"
          icon={<CheckCircleOutlined />}
          loading={approveMutation.isPending}
          onClick={() => approveMutation.mutate()}
        >
          Approve
        </Button>
      )}

      {record.status === "Completed" && (
        <Link to={`/analysis/results/${record.id}`}>
          <Button type="primary">View Report</Button>
        </Link>
      )}

      {/* Superuser Delete Button */}
      {user?.is_superuser && (
        <Popconfirm
          title="Delete Submission"
          description="This will permanently delete the submission and all its data. Are you sure?"
          onConfirm={() => deleteMutation.mutate()}
          okText="Yes, Delete"
          cancelText="No"
          placement="topLeft"
        >
          <Button
            danger
            type="primary"
            icon={<DeleteOutlined />}
            loading={deleteMutation.isPending}
          >
            Delete
          </Button>
        </Popconfirm>
      )}
    </Space>
  );
};

// Custom hook to get the previous value of a prop or state
function usePrevious<T>(value: T): T | undefined {
  const ref = useRef<T | undefined>(undefined);
  useEffect(() => {
    ref.current = value;
  });
  return ref.current;
}

const SubmissionHistoryPage: React.FC = () => {
  const [pagination, setPagination] = useState({ page: 1, pageSize: 5 });
  const [searchTerm, setSearchTerm] = useState("");
  const [debouncedSearchTerm, setDebouncedSearchTerm] = useState("");
  const { permission, requestPermission, showNotification } = useNotifications();

  // Debouncing effect remains the same
  useEffect(() => {
    const timer = setTimeout(() => {
        setDebouncedSearchTerm(searchTerm);
        setPagination(p => ({...p, page: 1}));
    }, 500);

    return () => {
      clearTimeout(timer);
    };
  }, [searchTerm]);

  const { data, isLoading, isError, error, isFetching } = useQuery<PaginatedSubmissionHistoryResponse, Error>({
    queryKey: ["submissionHistory", pagination.page, pagination.pageSize, debouncedSearchTerm],
    queryFn: () => submissionService.getSubmissionHistory(pagination.page, pagination.pageSize, debouncedSearchTerm),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => {
      // Get the latest data and fetch status from the query object argument
      const currentData = query.state.data;
      const isCurrentlyFetching = query.state.fetchStatus === 'fetching';

      // Disable polling when a search term is active or while a fetch is in progress.
      if (debouncedSearchTerm || isCurrentlyFetching) {
        return false;
      }

      const terminalStates = ["COMPLETED", "FAILED", "CANCELLED"];
      const shouldPoll = currentData?.items.some(
        (item) => !terminalStates.includes(item.status.toUpperCase().replace(/[\s-]/g, "_"))
      );
      return shouldPoll ? 5000 : false;
    },
  });

  // Effect to detect status changes and show notifications
  const previousData = usePrevious(data);
  useEffect(() => {
    // The permission check is now removed from here, as the hook handles it.
    if (!previousData || !data) {
      return;
    }

    const inProgressStates = ["SUBMITTED", "PENDING", "ANALYZING", "APPROVED_QUEUED", "REMEDIATING", "ANALYZING_CONTEXT"];
    const terminalStates = ["COMPLETED", "FAILED"];

    data.items.forEach(currentItem => {
      const previousItem = previousData.items.find(p => p.id === currentItem.id);
      
      // --- START: MODIFIED LOGIC ---
      if (previousItem && previousItem.status !== currentItem.status) {
        const currentStatus = currentItem.status.toUpperCase().replace(/[\s-]/g, "_");
        const previousStatus = previousItem.status.toUpperCase().replace(/[\s-]/g, "_");

        // Case 1: Notification for Scan Completion
        if (inProgressStates.includes(previousStatus) && terminalStates.includes(currentStatus)) {
          const notificationTitle = `Scan ${currentStatus.charAt(0) + currentStatus.slice(1).toLowerCase()}`;
          const notificationBody = `Your analysis for project "${currentItem.project_name}" has finished.`;
          showNotification(notificationTitle, notificationBody);
        }

        // Case 2: Notification for Cost Approval
        if (currentStatus === "PENDING_COST_APPROVAL") {
            const notificationTitle = `Action Required`;
            const notificationBody = `Project "${currentItem.project_name}" requires cost approval before scanning can proceed.`;
            showNotification(notificationTitle, notificationBody);
        }
      }
    });
  }, [data, previousData, showNotification]);

  const formatDate = (dateString: string | null) => {
    if (!dateString) return "N/A";
    return new Date(dateString).toLocaleString();
  };

  if (isError) {
    return <Alert message="Error" description={`Could not fetch submission history: ${error.message}`} type="error" showIcon />;
  }

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <Row justify="space-between" align="middle">
        <Col>
          <Title level={2}>Submission History</Title>
        </Col>
        <Col>
          {permission === 'default' && (
            <Button onClick={requestPermission}>Enable Notifications</Button>
          )}
        </Col>
      </Row>

      <Input.Search
          placeholder="Search by Project Name or Submission ID..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onSearch={(value) => {
            setDebouncedSearchTerm(value);
            setPagination(p => ({...p, page: 1}));
          }}
          style={{ width: '100%' }}
          allowClear
          enterButton
          loading={isFetching} // Use isFetching for the subtle background indicator
        />

      <List
        loading={isLoading} // Use isLoading, which is now only true on the initial load
        itemLayout="vertical"
        size="large"
        pagination={{
          current: pagination.page,
          pageSize: pagination.pageSize,
          total: data?.total || 0,
          onChange: (page, pageSize) => setPagination({ page, pageSize }),
          showSizeChanger: true,
          pageSizeOptions: ['5', '10', '20'],
        }}
        dataSource={data?.items}
        renderItem={(item: SubmissionHistoryItem) => {
            const statusInfo = getStatusInfo(item);
            const isPendingApproval = item.status === "PENDING_COST_APPROVAL";
            const cardBorderColor = isPendingApproval ? "#faad14" : "#d9d9d9";

            return (
              <List.Item key={item.id}>
                <Card
                  style={{ width: '100%', border: `1px solid ${cardBorderColor}` }}
                  styles={{ body: { padding: "20px" } }}
                >
                  {/* --- Row 1: Project Name --- */}
                  <Row style={{ marginBottom: 4 }}>
                    <Col span={24}>
                      <Title 
                        level={5} 
                        style={{ margin: 0, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}
                        title={item.project_name}
                      >
                        {item.project_name}
                      </Title>
                    </Col>
                  </Row>

                  {/* --- Row 2: Submission ID --- */}
                  <Row style={{ marginBottom: 20 }}>
                    <Col>
                      <Text copyable={{ tooltips: ['Copy ID', 'Copied'] }} style={{ fontFamily: 'monospace' }}>
                        {item.id}
                      </Text>
                    </Col>
                  </Row>

                  {/* --- Row 3: Workflow Steps --- */}
                  <Row style={{ marginBottom: 20 }}>
                    <Col span={24}>
                        <Steps
                          current={statusInfo.step}
                          status={statusInfo.status}
                          items={timelineSteps.map((step, index) => {
                            let stepStatus: "wait" | "process" | "finish" | "error" = "wait";
                            if (index < statusInfo.step) {
                              stepStatus = "finish";
                            } else if (index === statusInfo.step) {
                              stepStatus = statusInfo.status;
                            }
                            return {
                              ...step,
                              status: stepStatus,
                              icon: index === statusInfo.step ? statusInfo.icon : undefined,
                            };
                          })}
                          size="small"
                          labelPlacement="vertical"
                        />
                    </Col>
                  </Row>
                  
                  {/* --- Row 4: Costs --- */}
                  <Row style={{ marginBottom: 16 }}>
                    <Col span={24}>
                      <Space direction="vertical" style={{width: '100%'}}>
                        {item.estimated_cost && (
                          <Card size="small" type="inner" title="Estimated Cost">
                             <Descriptions size="small" column={4}>
                                <Descriptions.Item label="Total Est. Cost"><Statistic value={item.estimated_cost.total_estimated_cost} precision={6} prefix="$" valueStyle={{fontSize: '1em'}} /></Descriptions.Item>
                                <Descriptions.Item label="Input Cost"><Statistic value={item.estimated_cost.input_cost} precision={6} prefix="$" valueStyle={{fontSize: '1em'}}/></Descriptions.Item>
                                <Descriptions.Item label="Output Cost"><Statistic value={item.estimated_cost.predicted_output_cost} precision={6} prefix="$" valueStyle={{fontSize: '1em'}}/></Descriptions.Item>
                                <Descriptions.Item label="Output Tokens"><Statistic value={item.estimated_cost.predicted_output_tokens} valueStyle={{fontSize: '1em'}}/></Descriptions.Item>
                            </Descriptions>
                          </Card>
                        )}

                        {item.status === 'Completed' && item.actual_cost && (
                           <Card size="small" type="inner" title="Actual Cost" headStyle={{ background: '#f6ffed', border: '1px solid #b7eb8f' }}>
                            <Descriptions size="small" column={4}>
                                <Descriptions.Item label="Total Cost"><Statistic value={item.actual_cost.total_cost} precision={6} prefix="$" valueStyle={{fontSize: '1em', color: '#3f8600', fontWeight: 500}} /></Descriptions.Item>
                                <Descriptions.Item label="Input Tokens"><Statistic value={item.actual_cost.total_input_tokens} valueStyle={{fontSize: '1em'}} /></Descriptions.Item>
                                <Descriptions.Item label="Output Tokens"><Statistic value={item.actual_cost.total_output_tokens} valueStyle={{fontSize: '1em'}}/></Descriptions.Item>
                                <Descriptions.Item label="Total Tokens"><Statistic value={item.actual_cost.total_tokens} valueStyle={{fontSize: '1em'}}/></Descriptions.Item>
                            </Descriptions>
                           </Card>
                        )}
                        
                        {!item.estimated_cost && item.status !== 'Completed' &&(
                            <Text type="secondary">Cost information will be available soon.</Text>
                        )}
                      </Space>
                    </Col>
                  </Row>

                  {/* --- Row 5: Timestamps and Actions --- */}
                  <Row justify="space-between" align="middle">
                    <Col>
                        <Space direction="vertical" size={0}>
                            <Text type="secondary" style={{fontSize: '12px'}}>Submitted: {formatDate(item.submitted_at)}</Text>
                            {item.completed_at && <Text type="secondary" style={{fontSize: '12px'}}>Completed: {formatDate(item.completed_at)}</Text>}
                        </Space>
                    </Col>
                    <Col>
                      <ActionButtons record={item} />
                    </Col>
                  </Row>
                </Card>
              </List.Item>
            );
        }}
    />
    </Space>
  );
};

export default SubmissionHistoryPage;