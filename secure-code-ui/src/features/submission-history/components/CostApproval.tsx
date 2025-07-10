// secure-code-ui/src/features/submission-history/components/CostApproval.tsx

import { CheckCircleOutlined, DollarCircleOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button, Card, Col, message, Popconfirm, Row, Space, Statistic, Tooltip, Typography } from 'antd';
import React from 'react';

import { scanService } from '../../../shared/api/scanService';
import type { ScanHistoryItem } from '../../../shared/types/api';

const { Text } = Typography;

interface CostApprovalProps {
  scan: ScanHistoryItem;
  onApprovalSuccess: () => void;
}

const CostApproval: React.FC<CostApprovalProps> = ({ scan, onApprovalSuccess }) => {
  const queryClient = useQueryClient();

  const approveMutation = useMutation({
    mutationFn: () => scanService.approveScan(scan.id),
    onSuccess: () => {
      message.success(`Scan for project approved and queued for analysis.`);
      onApprovalSuccess();
      queryClient.invalidateQueries({ queryKey: ["projectHistory"] });
    },
    onError: (error) => {
      console.error("Approval failed", error);
      const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred.';
      message.error(`Approval failed: ${errorMessage}`);
    }
  });

  const cancelMutation = useMutation({
    mutationFn: () => scanService.cancelScan(scan.id),
    onSuccess: (data) => {
      message.info(data.message || "Scan has been cancelled.");
      onApprovalSuccess();
      queryClient.invalidateQueries({ queryKey: ["projectHistory"] });
    },
    onError: (error) => {
      console.error("Cancellation failed", error);
      const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred.';
      message.error(`Cancellation failed: ${errorMessage}`);
    },
  });

  const handleApprove = () => {
    approveMutation.mutate();
  };

  if (!scan.cost_details) {
    return <Text type="warning">Cost estimation data is missing.</Text>;
  }

  const { input_cost, predicted_output_cost, total_estimated_cost } = scan.cost_details;

  return (
    <Card
      size="small"
      title="Analysis Cost Approval Required"
      headStyle={{ backgroundColor: '#fffbe6', borderBottom: '1px solid #ffe58f' }}
      style={{ marginTop: '8px', borderColor: '#ffe58f' }}
    >
      <Row gutter={16} align="middle">
        <Col span={16}>
          <Row gutter={16}>
            <Col span={12}>
              <Tooltip title="Estimated cost for processing the input code.">
                <Statistic
                  title="Input Cost"
                  value={input_cost}
                  precision={6}
                  prefix="$"
                  valueStyle={{ color: '#616161', fontSize: '16px' }}
                />
              </Tooltip>
            </Col>
            <Col span={12}>
              <Tooltip title="Predicted cost for the AI's response based on input size.">
                <Statistic
                  title="Predicted Output Cost"
                  value={predicted_output_cost}
                  precision={6}
                  prefix="$"
                  valueStyle={{ color: '#616161', fontSize: '16px' }}
                />
              </Tooltip>
            </Col>
          </Row>
          <Row style={{ marginTop: '12px' }}>
            <Col span={24}>
              <Statistic
                title="Total Estimated Cost"
                value={total_estimated_cost}
                precision={6}
                prefix={<DollarCircleOutlined style={{ marginRight: '4px' }} />}
                valueStyle={{ color: '#3f8600', fontSize: '20px' }}
              />
            </Col>
          </Row>
        </Col>
        <Col span={8} style={{ textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end' }}>
          <Space>
            <Popconfirm
              title="Cancel Scan"
              description="Are you sure you want to cancel this scan? This action cannot be undone."
              onConfirm={() => cancelMutation.mutate()}
              okText="Yes, Cancel"
              cancelText="No"
            >
              <Button danger size="large" loading={cancelMutation.isPending}>
                Cancel
              </Button>
            </Popconfirm>
            <Button
              type="primary"
              icon={<CheckCircleOutlined />}
              loading={approveMutation.isPending}
              onClick={handleApprove}
              size="large"
            >
              Approve & Run Scan
            </Button>
          </Space>
        </Col>
      </Row>
    </Card>
  );
};

export default CostApproval;