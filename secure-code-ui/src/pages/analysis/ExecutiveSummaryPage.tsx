// src/app/pages/analysis/ExecutiveSummaryPage.tsx

import {
  ArrowLeftOutlined,
  BuildOutlined,
  FilePdfOutlined,
  InfoCircleOutlined,
  SafetyCertificateOutlined,
  ToolOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Divider,
  List,
  Space,
  Spin,
  Tag,
  Typography,
} from 'antd';
import React from 'react';
import { Link, useParams } from 'react-router-dom';
import apiClient from '../../shared/api/apiClient';
import { submissionService } from '../../shared/api/submissionService';

const { Title, Paragraph, Text } = Typography;

const ExecutiveSummaryPage: React.FC = () => {
  const { submissionId } = useParams<{ submissionId: string }>();

  const {
    data: result,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ['analysisResult', submissionId],
    queryFn: () => {
      if (!submissionId) {
        throw new Error('Submission ID is required');
      }
      return submissionService.getAnalysisResult(submissionId);
    },
    enabled: !!submissionId, // Only run query if submissionId is present
  });

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="Loading Executive Summary..." />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert
        message="Error"
        description={`Failed to load report: ${error.message}`}
        type="error"
        showIcon
        style={{ margin: '20px' }}
      />
    );
  }

  if (!result || !result.impact_report) {
    return (
      <Alert
        message="Report Not Found"
        description="The executive summary for this submission could not be found."
        type="warning"
        showIcon
        style={{ margin: '20px' }}
      />
    );
  }

  const { impact_report, summary_report } = result;
  const downloadUrl = `${apiClient.defaults.baseURL}/result/${submissionId}/executive-summary/download`;

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto', padding: '24px' }}>
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        <Link to={`/analysis/results/${submissionId}`}>
          <Button icon={<ArrowLeftOutlined />}>Back to Full Report</Button>
        </Link>

        <Card>
          <Title level={2} style={{ textAlign: 'center', marginBottom: '8px' }}>
            Executive Security Summary
          </Title>
          <Paragraph style={{ textAlign: 'center' }} type="secondary">
            Project: {summary_report?.project_name || 'N/A'} | Submission ID: {submissionId}
          </Paragraph>
          <Divider />

          <Descriptions bordered column={1} size="small" style={{ marginBottom: 24 }}>
            <Descriptions.Item label={<><InfoCircleOutlined /> Executive Overview</>}>
              <Paragraph style={{ margin: 0 }}>{impact_report.executive_summary}</Paragraph>
            </Descriptions.Item>
          </Descriptions>

          <Title level={4}><UnorderedListOutlined /> Vulnerability Analysis</Title>
          <Paragraph>{impact_report.vulnerability_overview}</Paragraph>

          <Title level={4}><SafetyCertificateOutlined /> High-Risk Findings</Title>
          <List
            size="small"
            bordered
            dataSource={impact_report.high_risk_findings_summary}
            renderItem={(item) => <List.Item>{item}</List.Item>}
            style={{ marginBottom: 24 }}
          />

          <Title level={4}><ToolOutlined /> Remediation Strategy</Title>
          <Paragraph>{impact_report.remediation_strategy}</Paragraph>
          
          <Descriptions layout="vertical" bordered>
             <Descriptions.Item label={<><BuildOutlined /> Architectural Changes Required</>}>
                {impact_report.required_architectural_changes.length > 0 && impact_report.required_architectural_changes[0] !== 'None' ? (
                     <List
                        size="small"
                        dataSource={impact_report.required_architectural_changes}
                        renderItem={(item) => <List.Item>{item}</List.Item>}
                    />
                ) : (
                    <Text type="secondary">None</Text>
                )}
            </Descriptions.Item>
            <Descriptions.Item label="Estimated Effort">
                <Tag color="orange" style={{fontSize: '14px', padding: '4px 8px'}}>{impact_report.estimated_remediation_effort}</Tag>
            </Descriptions.Item>
             <Descriptions.Item label="Vulnerability Categories">
                 <Space wrap>
                    {impact_report.vulnerability_categories.map((cat, index) => <Tag key={index} color="blue">{cat}</Tag>)}
                 </Space>
            </Descriptions.Item>
          </Descriptions>

          <Divider />
          <div style={{ textAlign: 'center' }}>
            <a href={downloadUrl} download>
                <Button type="primary" icon={<FilePdfOutlined />} size="large">
                    Download as PDF
                </Button>
            </a>
          </div>
        </Card>
      </Space>
    </div>
  );
};

export default ExecutiveSummaryPage;