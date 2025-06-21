// src/components/CostApproval.tsx

import { CheckCircleOutlined, DollarCircleOutlined } from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import { Button, Card, Col, message, Row, Statistic, Tooltip, Typography } from 'antd';
import { useState } from 'react';

import { approveSubmission } from '../services/submissionService';
import type { SubmissionHistoryItem } from '../types/api';

const { Text } = Typography;

interface CostApprovalProps {
  submission: SubmissionHistoryItem;
  onApprovalSuccess: () => void; // Callback to refetch the history list
}

const CostApproval: React.FC<CostApprovalProps> = ({ submission, onApprovalSuccess }) => {
  const [isApproving, setIsApproving] = useState(false);

  const approveMutation = useMutation({
    mutationFn: () => approveSubmission(submission.id),
    onSuccess: () => {
      message.success(`Submission ${submission.id} approved and queued for analysis.`);
      onApprovalSuccess();
    },
    onError: (error) => {
      console.error("Approval failed", error);
      const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred.';
      message.error(`Approval failed: ${errorMessage}`);
    },
    onSettled: () => {
      setIsApproving(false);
    }
  });

  const handleApprove = () => {
    setIsApproving(true);
    approveMutation.mutate();
  };

  if (!submission.estimated_cost) {
    return <Text type="warning">Cost estimation data is missing.</Text>;
  }

  const { input_cost, predicted_output_cost, total_estimated_cost } = submission.estimated_cost;

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
          <Button
            type="primary"
            icon={<CheckCircleOutlined />}
            loading={isApproving}
            onClick={handleApprove}
            size="large"
          >
            Approve & Run Scan
          </Button>
        </Col>
      </Row>
    </Card>
  );
};

export default CostApproval;