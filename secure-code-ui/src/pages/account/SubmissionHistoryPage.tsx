// src/pages/account/SubmissionHistoryPage.tsx
import {
  CheckCircleFilled,
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  DollarCircleOutlined,
  ExclamationCircleOutlined,
  FileSyncOutlined,
  FileTextOutlined,
  SearchOutlined,
  StopOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  message,
  Row,
  Space,
  Spin,
  Statistic,
  Steps,
  Tag,
  Typography,
} from "antd";
import React from "react";
import { Link } from "react-router-dom";
import {
  approveSubmission,
  cancelSubmission,
  submissionService,
} from "../../services/submissionService";
import type { SubmissionHistoryItem } from "../../types/api";

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

  // Handle the initial analysis phase before cost estimation is available
  if (upperStatus === "ANALYZING" && !item.estimated_cost) {
    return statusDetails.ANALYZING_CONTEXT;
  }
  
  const details = statusDetails[upperStatus];
  if (details) {
      return details;
  }

  // Fallback for any unknown statuses
  return { ...statusDetails.DEFAULT, text: item.status };
};
// --- END: REFINED 6-STEP TIMELINE AND STATUS MAPPING ---

const ActionButtons: React.FC<{ record: SubmissionHistoryItem }> = ({ record }) => {
  const queryClient = useQueryClient();

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

  if (record.status === "PENDING_COST_APPROVAL") {
    return (
      <Space>
        <Button
          type="primary"
          icon={<CheckCircleOutlined />}
          loading={approveMutation.isPending}
          onClick={() => approveMutation.mutate()}
        >
          Approve
        </Button>
        <Button
          danger
          icon={<CloseCircleOutlined />}
          loading={cancelMutation.isPending}
          onClick={() => cancelMutation.mutate()}
        >
          Cancel
        </Button>
      </Space>
    );
  }

  if (record.status === "Completed") {
    return (
      <Link to={`/analysis/results/${record.id}`}>
        <Button type="primary">View Report</Button>
      </Link>
    );
  }

  return <Text type="secondary">No actions available</Text>;
};

const SubmissionHistoryPage: React.FC = () => {
  const { data, isLoading, isError, error } = useQuery<SubmissionHistoryItem[], Error>({
    queryKey: ["submissionHistory"],
    queryFn: submissionService.getSubmissionHistory,
    refetchInterval: (query) => {
      const terminalStates = ["COMPLETED", "FAILED", "CANCELLED"];
      const shouldPoll = query.state.data?.some(
        (item) => !terminalStates.includes(item.status.toUpperCase().replace(/[\s-]/g, "_"))
      );
      return shouldPoll ? 5000 : false;
    },
  });

  if (isLoading && !data) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "calc(100vh - 200px)" }}>
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
      <div className="submission-list">
        {data?.map((item) => {
          const statusInfo = getStatusInfo(item);
          const isPendingApproval = item.status === "PENDING_COST_APPROVAL";
          const cardBorderColor = isPendingApproval ? "#faad14" : "#d9d9d9";

          return (
            <Card
              key={item.id}
              style={{ marginBottom: 16, border: `1px solid ${cardBorderColor}` }}
              bodyStyle={{ padding: "20px" }}
            >
              <Row gutter={[24, 16]} align="middle">
                <Col xs={24} md={10} lg={12}>
                  <Title level={5} style={{ margin: 0 }}>{item.project_name || "Code Submission"}</Title>
                  <Text copyable={{ tooltips: ['Copy ID', 'Copied'] }} style={{ fontFamily: 'monospace' }}>
                    {item.id}
                  </Text>
                  <div style={{ marginTop: '16px' }}>
                    <Steps
                      current={statusInfo.step}
                      status={statusInfo.status}
                      items={timelineSteps.map((step, index) => {
                        let stepStatus: "wait" | "process" | "finish" | "error" = "wait";
                        
                        if (index < statusInfo.step) {
                          // Mark all steps before the current one as "finish"
                          stepStatus = "finish";
                        } else if (index === statusInfo.step) {
                          // Use the status for the current step
                          stepStatus = statusInfo.status;
                        }

                        return {
                          ...step,
                          status: stepStatus,
                          // Show the icon only for the current step, allowing default icons (like checkmarks) for others
                          icon: index === statusInfo.step ? statusInfo.icon : undefined,
                        };
                      })}
                      size="small"
                      labelPlacement="vertical"
                    />
                  </div>
                </Col>
                <Col xs={24} md={14} lg={12}>
                  <Row gutter={[16, 16]} align="middle">
                    <Col xs={24} xl={16}>
                      {item.estimated_cost ? (
                        <Space direction="vertical" style={{ width: "100%" }}>
                           <Statistic
                              title={<Text type="secondary">Total Estimated Cost</Text>}
                              value={item.estimated_cost.total_estimated_cost}
                              precision={6}
                              prefix={<DollarCircleOutlined />}
                              valueStyle={{ fontSize: '24px' }}
                            />
                          <Row>
                            <Col span={12}>
                              <Statistic
                                title={<Text type="secondary">Input Cost</Text>}
                                value={item.estimated_cost.input_cost}
                                precision={6}
                                prefix="$"
                                valueStyle={{ fontSize: '14px' }}
                              />
                            </Col>
                            <Col span={12}>
                              <Statistic
                                  title={<Text type="secondary">Output Cost (Est.)</Text>}
                                  value={item.estimated_cost.total_estimated_cost}
                                  precision={6}
                                  prefix="$"
                                  valueStyle={{ fontSize: '14px' }}
                              />
                            </Col>
                          </Row>
                        </Space>
                      ) : (
                        <Tag icon={statusInfo.icon}>{statusInfo.text}</Tag>
                      )}
                    </Col>
                    <Col xs={24} xl={8} style={{ textAlign: "right", alignSelf: 'center' }}>
                      <ActionButtons record={item} />
                    </Col>
                  </Row>
                </Col>
              </Row>
            </Card>
          );
        })}
      </div>
    </Space>
  );
};

export default SubmissionHistoryPage;