// src/pages/account/SubmissionHistoryPage.tsx
import {
    CheckCircleOutlined,
    ClockCircleOutlined,
    CloseCircleOutlined,
    DollarCircleOutlined,
    ExclamationCircleOutlined,
    FileSyncOutlined,
    StopOutlined,
    SyncOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery } from "@tanstack/react-query";
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

// Enhanced status map to power the new timeline view
const statusDetails: {
  [key: string]: {
    step: number;
    status: "wait" | "process" | "finish" | "error";
    text: string;
    icon: React.ReactNode;
  };
} = {
  SUBMITTED: { step: 0, status: "process", text: "Submitted", icon: <ClockCircleOutlined /> },
  PENDING_COST_APPROVAL: { step: 1, status: "process", text: "Pending Approval", icon: <ExclamationCircleOutlined /> },
  APPROVED_QUEUED: { step: 2, status: "process", text: "Queued", icon: <SyncOutlined spin /> },
  ANALYZING: { step: 2, status: "process", text: "Analyzing", icon: <FileSyncOutlined spin /> },
  REMEDIATING: { step: 2, status: "process", text: "Remediating", icon: <FileSyncOutlined spin /> },
  COMPLETED: { step: 3, status: "finish", text: "Completed", icon: <CheckCircleOutlined /> },
  FAILED: { step: 1, status: "error", text: "Failed", icon: <CloseCircleOutlined /> },
  CANCELLED: { step: 1, status: "error", text: "Cancelled", icon: <StopOutlined /> },
  DEFAULT: { step: 0, status: "process", text: "Processing", icon: <SyncOutlined spin /> },
};

const getStatusInfo = (status: string) => {
  const upperStatus = status.toUpperCase().replace(/[\s-]/g, "_");
  return statusDetails[upperStatus] || { ...statusDetails.DEFAULT, text: status };
};

const ActionButtons: React.FC<{ record: SubmissionHistoryItem; refetch: () => void }> = ({ record, refetch }) => {

  const approveMutation = useMutation({
    mutationFn: () => approveSubmission(record.id),
    onSuccess: () => {
      message.success(`Submission approved and queued for analysis.`);
      refetch();
    },
    onError: (error) => message.error(`Approval failed: ${error.message}`),
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelSubmission(record.id),
    onSuccess: () => {
      message.success(`Submission has been cancelled.`);
      refetch();
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

  const { data, isLoading, isError, error, refetch } = useQuery<SubmissionHistoryItem[], Error>({
    queryKey: ["submissionHistory"],
    queryFn: submissionService.getSubmissionHistory,
    refetchInterval: (query) => {
      const shouldPoll = query.state.data?.some((item) =>
        ["SUBMITTED", "APPROVED_QUEUED", "ANALYZING", "REMEDIATING"].includes(
          item.status.toUpperCase().replace(/[\s-]/g, "_"),
        ),
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
          const statusInfo = getStatusInfo(item.status);
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
                      items={[
                        { title: "Submitted", icon: statusInfo.step === 0 ? statusInfo.icon : undefined },
                        { title: "Approval", icon: statusInfo.step === 1 ? statusInfo.icon : undefined },
                        { title: "In Progress", icon: statusInfo.step === 2 ? statusInfo.icon : undefined },
                        { title: "Completed", icon: statusInfo.step === 3 ? statusInfo.icon : undefined },
                      ]}
                      size="small"
                      labelPlacement="vertical"
                    />
                  </div>
                </Col>
                <Col xs={24} md={14} lg={12}>
                  <Row gutter={[16, 16]}>
                    <Col xs={24} lg={16}>
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
                                  value={item.estimated_cost.predicted_output_cost}
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
                    <Col xs={24} lg={8} style={{ textAlign: "right", alignSelf: 'center' }}>
                      <ActionButtons record={item} refetch={refetch} />
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